//! Device-facing endpoint: one address, automatic outbound peering, datagrams
//! to and from Yggdrasil addresses, TCP transport only.
//!
//! [`Endpoint`] is I/O-free. The platform drives it with four kinds of calls
//! and executes the returned [`Action`]s on its own TCP sockets:
//!
//! | platform event                    | call                                  |
//! |-----------------------------------|---------------------------------------|
//! | every ~100 ms                     | [`Endpoint::poll`]                    |
//! | `Dial` finished, TCP connected    | [`Endpoint::on_transport_up`]         |
//! | `Dial` failed / socket closed     | [`Endpoint::on_transport_failed`] / [`Endpoint::on_transport_closed`] |
//! | a listening socket got a client   | [`Endpoint::accept_transport`]        |
//! | bytes read from a socket          | [`Endpoint::on_bytes`]                |
//! | application wants to send         | [`Endpoint::send_to_address`]         |
//! | application wants to receive      | [`Endpoint::recv`]                    |
//!
//! Outbound peering is automatic: the endpoint keeps `target_outbound` TCP
//! connections to the best-measured candidates (see [`crate::pool`]). Add
//! candidates from a config list or from discovery with
//! [`Endpoint::add_peer_uri`]. Only `tcp://` URIs are accepted.
//!
//! The device does not need to be reachable: it only dials out. Traffic to the
//! device's address is routed back over the connections it opened.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use ed25519_dalek::SigningKey;
use rand_core::CryptoRngCore;

use crate::address::{self, Address};
use crate::forward::{self, Forward};
use crate::icmp::{self, ECHO_REPLY, ECHO_REQUEST};
use crate::tcp::{self, HttpServer};
use crate::crypto::PublicKey;
use crate::meta::{MetaError, Metadata};
use crate::node::{LiteConfig, NodeEvent, YggdrasilLite};
use crate::peer::PeerId;
use crate::pool::{CandidateInfo, CandidateSource, PeerPool, SlotId, DIAL_TIMEOUT_MS};
use crate::uri::{TcpPeerUri, UriError};

/// Metadata is a few hundred bytes; anything larger is not a valid handshake.
const MAX_HANDSHAKE_BYTES: usize = 1024;
/// Received datagrams kept until the application calls [`Endpoint::recv`].
const INBOX_CAP: usize = 16;
/// Outbound datagrams waiting for an address to be resolved.
const PENDING_CAP: usize = 8;
const PENDING_TTL_MS: u64 = 30_000;

/// I/O the platform must perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Open a TCP connection to `uri` for `slot`. On success call
    /// [`Endpoint::on_transport_up`]; on failure [`Endpoint::on_transport_failed`].
    Dial { slot: SlotId, uri: TcpPeerUri },
    /// Write `data` to the socket of `slot`.
    Write { slot: SlotId, data: Vec<u8> },
    /// Close the socket of `slot`. The endpoint has already forgotten it, so
    /// the platform must not report events for this slot afterwards.
    Close { slot: SlotId },
}

/// Whether a peer was dialed by this device or connected to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Dialed from the candidate list (public peer).
    Outbound,
    /// Connected to this device (accepted socket).
    Inbound,
}

/// A peer with an established session, for status display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub direction: Direction,
    /// Peer endpoint (outbound peers only).
    pub uri: Option<TcpPeerUri>,
    /// Peer's public key.
    pub key: PublicKey,
    /// Peer's Yggdrasil address.
    pub address: Address,
    /// Measured connect+handshake latency (outbound peers, if known).
    pub rtt_ms: Option<u64>,
    /// When the session came up, on the caller's clock.
    pub up_ms: u64,
    /// Outbound peer found by LAN discovery.
    pub lan: bool,
}

/// An application datagram delivered to this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// Yggdrasil address of the sender (reply to it with this).
    pub from: Address,
    /// Sender's full Ed25519 public key.
    pub from_key: PublicKey,
    pub data: Vec<u8>,
}

struct Conn {
    outbound: bool,
    started_ms: u64,
    /// When the handshake completed (ms, same clock as the caller's `now`).
    up_ms: u64,
    /// Set once the metadata handshake completed.
    peer: Option<PeerId>,
    key: Option<PublicKey>,
    /// Metadata bytes received so far (cleared after the handshake).
    buf: Vec<u8>,
}

struct Pending {
    dest: [u8; 16],
    data: Vec<u8>,
    queued_ms: u64,
}

/// Yggdrasil leaf endpoint for a device. See the module docs.
pub struct Endpoint {
    signing: SigningKey,
    public: PublicKey,
    password: Option<Vec<u8>>,
    node: YggdrasilLite,
    pool: PeerPool,
    /// Index `0..target` belongs to outbound pool slots; higher indices hold
    /// accepted inbound connections.
    conns: Vec<Option<Conn>>,
    inbox: VecDeque<Received>,
    pending: VecDeque<Pending>,
    /// Keys allowed to deliver datagrams to this device (set at provisioning).
    /// Empty by default: the device accepts nothing until a key is configured.
    allowed: Vec<PublicKey>,
    /// Answer ICMPv6 echo requests from allowed keys (default on).
    ping_replies: bool,
    /// Echo replies waiting to be sent: (destination key, IPv6 packet).
    outbox: VecDeque<(PublicKey, Vec<u8>)>,
    /// Optional static page served on TCP port 80.
    http: Option<HttpServer>,
    /// TCP port forwarding for the overlay ports given at startup.
    forward: Option<Forward>,
    /// Time of the last `poll`/`on_bytes` call, used to stamp forwarded segments.
    last_now_ms: u64,
}

/// Yggdrasil frames IPv6 packets with a one-byte prefix `0x01` on the wire
/// (confirmed on live traffic: every ICMPv6 and TCP packet from a yggstack peer
/// starts with it, and the IPv6 header begins at byte 1).
pub const IPV6_FRAME: u8 = 0x01;

/// Prepend the IPv6 frame byte to an IPv6 packet before sending it.
pub fn frame_ipv6(pkt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(pkt.len() + 1);
    out.push(IPV6_FRAME);
    out.extend_from_slice(pkt);
    out
}

/// Return the IPv6 packet inside a received datagram: strips the frame byte if
/// present, otherwise returns the data unchanged.
pub fn unframe_ipv6(data: &[u8]) -> &[u8] {
    if data.len() > 1 && data[0] == IPV6_FRAME && data[1] >> 4 == 6 {
        &data[1..]
    } else {
        data
    }
}

/// Payload used by [`Endpoint::ping`] (the classic 56-byte ping pattern).
pub const PING_PAYLOAD: [u8; 56] = {
    let mut p = [0u8; 56];
    let mut i = 0;
    while i < 56 {
        p[i] = 0x10 + i as u8;
        i += 1;
    }
    p
};

impl Endpoint {
    /// Create an endpoint from a 32-byte Ed25519 seed. The seed fixes the
    /// device's address, so store it once and reuse it.
    ///
    /// `target_outbound` is how many outbound peers to keep connected (one
    /// pool slot each). Use at least 1.
    pub fn new(private_key: [u8; 32], password: Option<Vec<u8>>, target_outbound: usize) -> Self {
        Self::new_with_lan(private_key, password, target_outbound, 0)
    }

    /// Like [`Endpoint::new`], plus `lan_slots` outbound slots that only take peers found
    /// by LAN discovery ([`CandidateSource::Discovered`]).
    pub fn new_with_lan(
        private_key: [u8; 32],
        password: Option<Vec<u8>>,
        target_outbound: usize,
        lan_slots: usize,
    ) -> Self {
        let signing = SigningKey::from_bytes(&private_key);
        let mut cfg = LiteConfig::new(private_key);
        cfg.password = password.clone();
        let node = YggdrasilLite::new(cfg);
        let public = *node.public_key();
        Self {
            signing,
            public,
            password,
            node,
            pool: PeerPool::with_lan_slots(target_outbound, lan_slots),
            conns: (0..target_outbound + lan_slots).map(|_| None).collect(),
            inbox: VecDeque::new(),
            pending: VecDeque::new(),
            allowed: Vec::new(),
            ping_replies: true,
            outbox: VecDeque::new(),
            http: None,
            forward: None,
            last_now_ms: 0,
        }
    }

    /// Serve `page` as HTML on TCP port 80 to allowed keys. Requires a
    /// client that speaks TCP over Yggdrasil (for example yggstack's SOCKS proxy).
    pub fn serve_http(&mut self, page: Vec<u8>) {
        match self.http.as_mut() {
            Some(srv) => srv.set_page(page),
            None => self.http = Some(HttpServer::new(page)),
        }
    }

    /// Enable or disable automatic replies to ICMPv6 echo requests.
    pub fn set_ping_replies(&mut self, on: bool) {
        self.ping_replies = on;
    }

    /// Send an ICMPv6 echo request to `dest`. The reply arrives through
    /// [`recv`](Self::recv) as a datagram whose `data` parses with
    /// [`crate::icmp::parse_echo`] (kind `ECHO_REPLY`, same `id` and `seq`).
    pub fn ping(
        &mut self,
        dest: &Address,
        id: u16,
        seq: u16,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        self.ping_payload(dest, id, seq, &PING_PAYLOAD, now_ms, rng)
    }

    /// Like [`Endpoint::ping`] but with a caller-chosen echo payload. A reply echoes
    /// the payload back, so the caller can match it to its own request.
    pub fn ping_payload(
        &mut self,
        dest: &Address,
        id: u16,
        seq: u16,
        payload: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        let pkt = icmp::build_echo(self.address().0, dest.0, ECHO_REQUEST, id, seq, payload);
        self.send_to_address(dest, &frame_ipv6(&pkt), now_ms, rng)
    }

    /// [`Endpoint::ping_payload`] addressed by public key.
    pub fn ping_key_payload(
        &mut self,
        key: &PublicKey,
        id: u16,
        seq: u16,
        payload: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        let dest = address::addr_for_key(key);
        self.ping_payload(&dest, id, seq, payload, now_ms, rng)
    }

    /// Set the measured round-trip time to a peer, in ms, used as its link weight in
    /// tree parent selection.
    pub fn set_link_latency(&mut self, key: PublicKey, rtt_ms: u64) {
        self.node.set_link_latency(key, rtt_ms);
    }

    /// Accept TCP connections on these overlay ports from allowed keys, and report
    /// them through [`forward_event`](Self::forward_event). An empty list turns forwarding off.
    pub fn set_forward_ports(&mut self, ports: &[u16]) {
        self.forward = if ports.is_empty() {
            None
        } else {
            Some(Forward::new(self.node.address().0, ports))
        };
    }

    /// Next forwarding event for the platform (open, data, remote close, closed).
    pub fn forward_event(&mut self) -> Option<forward::Event> {
        self.forward.as_mut()?.pop_event()
    }

    /// Send `data` to the remote client of session `id`. Returns `false` if nothing
    /// was queued (unknown session or full queue, see [`forward::SEND_QUEUE_MAX`]).
    pub fn forward_write(&mut self, id: forward::SessionId, data: &[u8]) -> bool {
        let now = self.last_now_ms;
        let ok = self.forward.as_mut().map_or(false, |f| f.write(id, data, now));
        self.flush_forward();
        ok
    }

    /// Bytes queued for the remote client of session `id`, waiting to be sent.
    pub fn forward_queued(&self, id: forward::SessionId) -> usize {
        self.forward.as_ref().map_or(0, |f| f.queued(id))
    }

    /// The local side is done sending: FIN after the queued bytes.
    pub fn forward_close(&mut self, id: forward::SessionId) {
        let now = self.last_now_ms;
        if let Some(f) = self.forward.as_mut() {
            f.close(id, now);
        }
        self.flush_forward();
    }

    /// The local side failed: reset the session towards the remote client.
    pub fn forward_abort(&mut self, id: forward::SessionId) {
        if let Some(f) = self.forward.as_mut() {
            f.reset(id);
        }
        self.flush_forward();
    }

    /// Send an echo request to the Yggdrasil address of `key` (a peer or the root).
    /// The reply arrives through [`recv`](Self::recv) with `from_key == key`.
    pub fn ping_key(
        &mut self,
        key: &PublicKey,
        id: u16,
        seq: u16,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        let dest = address::addr_for_key(key);
        self.ping(&dest, id, seq, now_ms, rng)
    }

    /// Root and hop count of `key`'s tree branch, as announced to us. `None`
    /// until we have that node's announcements.
    pub fn peer_root(&self, key: &PublicKey) -> Option<(PublicKey, usize)> {
        let tree = self.node.tree();
        if !tree.has_info(key) {
            return None;
        }
        let (root, path) = tree.get_root_and_path(key);
        Some((root, path.len()))
    }

    /// Close the outbound connection to `key` on purpose, and keep its candidate
    /// out of the schedule for `cooldown_ms`. Returns the socket close to perform.
    pub fn drop_peer(&mut self, key: &PublicKey, now_ms: u64, cooldown_ms: u64) -> Vec<Action> {
        let slot = self
            .conns
            .iter()
            .position(|c| matches!(c, Some(c) if c.outbound && c.key == Some(*key)));
        let Some(slot) = slot else { return Vec::new() };
        let uri = self.pool.slot_uri(slot).cloned();
        self.drop_conn(slot, now_ms);
        if let Some(uri) = uri {
            self.pool.cool_down_uri(&uri, now_ms + cooldown_ms);
        }
        alloc::vec![Action::Close { slot }]
    }

    /// Replace the set of node keys allowed to send datagrams to this device.
    /// Datagrams from any other key are dropped before reaching [`recv`](Self::recv).
    /// Intended for provisioning: set it once from the configured controller keys.
    pub fn set_allowed_keys(&mut self, keys: Vec<PublicKey>) {
        self.allowed = keys;
    }

    /// Add one allowed key (no-op if already present).
    pub fn allow_key(&mut self, key: PublicKey) {
        if !self.allowed.contains(&key) {
            self.allowed.push(key);
        }
    }

    pub fn is_allowed(&self, key: &PublicKey) -> bool {
        self.allowed.contains(key)
    }

    /// This device's Ed25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// This device's Yggdrasil IPv6 address (`200::/7`). Stable for the seed.
    pub fn address(&self) -> Address {
        self.node.address()
    }

    /// Add a peer candidate. Only `tcp://host:port` is accepted. Returns
    /// `Ok(true)` if it is new. Candidates are dialed automatically, best
    /// measured latency first.
    pub fn add_peer_uri(&mut self, uri: &str, source: CandidateSource) -> Result<bool, UriError> {
        let parsed = TcpPeerUri::parse(uri)?;
        Ok(self.pool.add_candidate(parsed, source))
    }

    /// Import the usable TCP peers from a public peer list document (JSON bytes
    /// downloaded by the platform, e.g. from [`DEFAULT_PUBLIC_PEERS_URL`]).
    /// Entries marked `up: false` are skipped. The list's `key` pins each
    /// peer's identity and its `response_ms` seeds the latency estimate.
    /// Returns how many candidates were new.
    pub fn import_peer_list(&mut self, json: &[u8], source: CandidateSource) -> usize {
        let mut added = 0;
        for entry in crate::peerlist::tcp_peers_from_json(json) {
            let uri = match entry.key {
                Some(k) => entry.uri.with_key(k),
                None => entry.uri,
            };
            if self.pool.add_candidate_with_rtt(uri, source, entry.response_ms) {
                added += 1;
            }
        }
        added
    }

    /// Peers with an established session, outbound first.
    pub fn connected_peers(&self) -> Vec<PeerInfo> {
        let mut out: Vec<PeerInfo> = self
            .conns
            .iter()
            .enumerate()
            .filter_map(|(slot, c)| {
                let c = c.as_ref()?;
                c.peer?;
                let key = c.key?;
                let (direction, uri, rtt_ms) = if c.outbound {
                    (Direction::Outbound, self.pool.slot_uri(slot).cloned(), self.pool.slot_rtt(slot))
                } else {
                    (Direction::Inbound, None, None)
                };
                Some(PeerInfo {
                    direction,
                    uri,
                    key,
                    address: address::addr_for_key(&key),
                    rtt_ms,
                    up_ms: c.up_ms,
                    lan: c.outbound && self.pool.slot_is_lan(slot),
                })
            })
            .collect();
        out.sort_by_key(|p| p.direction == Direction::Inbound);
        out
    }

    /// Hold back or release outbound dialing (see [`PeerPool::set_dial_enabled`]).
    pub fn set_dial_enabled(&mut self, on: bool) {
        self.pool.set_dial_enabled(on);
    }

    /// Record a pre-dial probe to a candidate: `Some(ms)` on success, `None` on failure.
    pub fn record_candidate_probe(&mut self, uri: &TcpPeerUri, rtt_ms: Option<u64>) {
        self.pool.record_probe(uri, rtt_ms);
    }

    /// Candidates with their measured latency and failure counts.
    pub fn candidates(&self) -> Vec<CandidateInfo> {
        self.pool.candidates_info()
    }

    /// Number of peers the node currently has an established session with
    /// (outbound and accepted).
    pub fn peer_count(&self) -> usize {
        self.node.peer_count()
    }

    /// Spanning-tree root key (for status output).
    pub fn root(&self) -> PublicKey {
        self.node.root()
    }

    /// Current tree coordinates (for status output).
    pub fn coords(&self) -> alloc::vec::Vec<crate::wire::PeerPort> {
        self.node.coords()
    }

    /// Established encrypted sessions.
    pub fn session_count(&self) -> usize {
        self.node.session_count()
    }

    /// Cached path entries.
    pub fn path_count(&self) -> usize {
        self.node.path_count()
    }

    // -----------------------------------------------------------------------
    // Periodic driver
    // -----------------------------------------------------------------------

    /// Call every ~100 ms. Starts dials, enforces timeouts, runs protocol
    /// maintenance and retries pending datagrams.
    pub fn poll(&mut self, now_ms: u64, rng: &mut impl CryptoRngCore) -> Vec<Action> {
        self.last_now_ms = now_ms;
        let mut actions = Vec::new();
        if let Some(f) = self.forward.as_mut() {
            f.poll(now_ms);
        }
        self.flush_forward();

        // Dials that stalled past the timeout.
        for slot in self.pool.expire(now_ms) {
            if self.conns.get_mut(slot).and_then(Option::take).is_some() {
                actions.push(Action::Close { slot });
            }
        }

        // Inbound connections that never finished the handshake.
        for slot in 0..self.conns.len() {
            let stale = matches!(
                &self.conns[slot],
                Some(c) if !c.outbound && c.peer.is_none()
                    && now_ms.saturating_sub(c.started_ms) >= DIAL_TIMEOUT_MS
            );
            if stale {
                self.conns[slot] = None;
                actions.push(Action::Close { slot });
            }
        }

        // Fill outbound slots.
        for (slot, uri) in self.pool.schedule(now_ms) {
            self.conns[slot] = Some(Conn::new(true, now_ms));
            actions.push(Action::Dial { slot, uri });
        }

        // Protocol maintenance.
        let events = self.node.poll(now_ms, rng);
        actions.extend(self.events_to_actions(events));

        // Retry datagrams waiting for an address.
        actions.extend(self.flush_pending(now_ms, rng));

        // Echo replies queued while delivering.
        while let Some((key, pkt)) = self.outbox.pop_front() {
            actions.extend(self.send_to_key(&key, &pkt, now_ms, rng));
        }

        actions
    }

    // -----------------------------------------------------------------------
    // Transport events (platform -> endpoint)
    // -----------------------------------------------------------------------

    /// The TCP connection for outbound `slot` is up. Returns the metadata
    /// handshake to write.
    pub fn on_transport_up(&mut self, slot: SlotId, _now_ms: u64) -> Vec<Action> {
        match self.conns.get(slot).and_then(Option::as_ref) {
            Some(c) if c.outbound && c.peer.is_none() => alloc::vec![self.hello(slot)],
            _ => Vec::new(),
        }
    }

    /// Dial failed (TCP connect error). Outbound slots go on backoff.
    pub fn on_transport_failed(&mut self, slot: SlotId, now_ms: u64) {
        self.drop_conn(slot, now_ms);
    }

    /// Socket closed by the remote side or by an error after it was up.
    pub fn on_transport_closed(&mut self, slot: SlotId, now_ms: u64) {
        self.drop_conn(slot, now_ms);
    }

    /// A client connected to a listening socket. Returns the slot to use for
    /// its bytes and the handshake to write. Only needed when the device also
    /// listens; a pure dial-out device never calls this.
    pub fn accept_transport(&mut self, now_ms: u64) -> (SlotId, Vec<Action>) {
        let target = self.pool.target();
        let slot = match self
            .conns
            .iter()
            .enumerate()
            .skip(target)
            .find(|(_, c)| c.is_none())
        {
            Some((i, _)) => i,
            None => {
                self.conns.push(None);
                self.conns.len() - 1
            }
        };
        self.conns[slot] = Some(Conn::new(false, now_ms));
        (slot, alloc::vec![self.hello(slot)])
    }

    /// Bytes read from the socket of `slot`.
    pub fn on_bytes(
        &mut self,
        slot: SlotId,
        data: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        self.last_now_ms = now_ms;
        let conn = match self.conns.get_mut(slot).and_then(Option::as_mut) {
            Some(c) => c,
            None => return Vec::new(),
        };

        if let Some(pid) = conn.peer {
            let events = self.node.handle_peer_data(pid, data, now_ms, rng);
            return self.events_to_actions(events);
        }

        // Handshake phase: accumulate until the metadata is complete.
        conn.buf.extend_from_slice(data);
        if conn.buf.len() > MAX_HANDSHAKE_BYTES {
            return self.fail_conn(slot, now_ms);
        }
        let outbound = conn.outbound;
        let decoded = Metadata::decode(&conn.buf, self.password.as_deref().unwrap_or(&[]));
        let (meta, consumed) = match decoded {
            Ok(v) => v,
            Err(MetaError::TooShort) | Err(MetaError::BufferTooSmall) => return Vec::new(),
            Err(_) => return self.fail_conn(slot, now_ms),
        };
        let rest = conn.buf[consumed..].to_vec();

        let key = meta.public_key;
        if !meta.check() || key == self.public || self.key_in_use(&key, slot) {
            return self.fail_conn(slot, now_ms);
        }
        if let Some(expected) = self.pool.expected_key(slot) {
            if expected != key {
                return self.fail_conn(slot, now_ms);
            }
        }
        if outbound && !self.pool.on_connected(slot, key, now_ms) {
            return self.fail_conn(slot, now_ms);
        }

        let pid = self.node.add_peer(key, 0);
        self.node.mark_handshake_done(pid);
        if let Some(c) = self.conns[slot].as_mut() {
            c.peer = Some(pid);
            c.key = Some(key);
            c.up_ms = now_ms;
            c.buf = Vec::new();
        }

        if rest.is_empty() {
            return Vec::new();
        }
        let events = self.node.handle_peer_data(pid, &rest, now_ms, rng);
        self.events_to_actions(events)
    }

    // -----------------------------------------------------------------------
    // Application API
    // -----------------------------------------------------------------------

    /// Send `data` to the device at `dest` (its Yggdrasil address). If the
    /// address is not yet known the datagram is held (up to a few seconds)
    /// while path discovery runs.
    pub fn send_to_address(
        &mut self,
        dest: &Address,
        data: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        if let Some(key) = self.node.resolve(&dest.0) {
            return self.send_to_key(&key, data, now_ms, rng);
        }
        if self.pending.len() >= PENDING_CAP {
            self.pending.pop_front();
        }
        self.pending.push_back(Pending {
            dest: dest.0,
            data: data.to_vec(),
            queued_ms: now_ms,
        });
        let partial = dest.get_key();
        let events = self.node.lookup(&partial, now_ms);
        self.events_to_actions(events)
    }

    /// Send `data` to a node by its full public key.
    pub fn send_to_key(
        &mut self,
        dest: &PublicKey,
        data: &[u8],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Action> {
        let _ = rng;
        let events = self.node.send(dest, data, now_ms, rng);
        self.events_to_actions(events)
    }

    /// Next datagram addressed to this device, if any.
    pub fn recv(&mut self) -> Option<Received> {
        self.inbox.pop_front()
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn hello(&self, slot: SlotId) -> Action {
        let meta = Metadata::new(self.public, 0);
        let data = meta.encode(&self.signing, self.password.as_deref().unwrap_or(&[]));
        Action::Write { slot, data }
    }

    fn key_in_use(&self, key: &PublicKey, except: SlotId) -> bool {
        self.conns.iter().enumerate().any(|(i, c)| {
            i != except && matches!(c, Some(conn) if conn.key.as_ref() == Some(key))
        })
    }

    fn slot_of_peer(&self, pid: PeerId) -> Option<SlotId> {
        self.conns
            .iter()
            .position(|c| matches!(c, Some(conn) if conn.peer == Some(pid)))
    }

    /// Forget a connection and tell the pool. No I/O: the platform already
    /// knows the socket is gone.
    /// Pass a TCP segment for a forwarded port to the forwarder. Returns `false`
    /// if the packet is not such a segment.
    fn forward_handle(&mut self, source: PublicKey, ip: &[u8]) -> bool {
        let now = self.last_now_ms;
        let our = self.node.address().0;
        let Some(fwd) = self.forward.as_mut() else { return false };
        let Some(seg) = tcp::parse(ip) else { return false };
        if seg.dst != our || !fwd.wants(seg.dport) {
            return false;
        }
        fwd.handle_segment(source, &seg, now);
        self.flush_forward();
        true
    }

    /// Queue the forwarder's packets for sending.
    fn flush_forward(&mut self) {
        if let Some(f) = self.forward.as_mut() {
            for (key, pkt) in f.drain_out() {
                self.outbox.push_back((key, frame_ipv6(&pkt)));
            }
        }
    }

    fn is_echo_reply_to_us(&self, data: &[u8]) -> bool {
        icmp::parse_echo(unframe_ipv6(data))
            .map_or(false, |echo| echo.kind == ECHO_REPLY && echo.dst == self.address().0)
    }

    fn drop_conn(&mut self, slot: SlotId, now_ms: u64) {
        if let Some(conn) = self.conns.get_mut(slot).and_then(Option::take) {
            if let Some(pid) = conn.peer {
                self.node.remove_peer(pid);
            }
            if conn.outbound {
                self.pool.on_closed(slot, now_ms);
            }
        }
    }

    /// Reject a connection and ask the platform to close its socket.
    fn fail_conn(&mut self, slot: SlotId, now_ms: u64) -> Vec<Action> {
        self.drop_conn(slot, now_ms);
        alloc::vec![Action::Close { slot }]
    }

    fn events_to_actions(&mut self, events: Vec<NodeEvent>) -> Vec<Action> {
        let mut out = Vec::new();
        for ev in events {
            match ev {
                NodeEvent::SendToPeer { peer_id, data } => {
                    if let Some(slot) = self.slot_of_peer(peer_id) {
                        out.push(Action::Write { slot, data });
                    }
                }
                NodeEvent::Deliver { source, data } => {
                    // Echo replies are accepted from any peer: they can only answer
                    // our own `ping_key` requests. Everything else needs an allowed key.
                    if !self.allowed.contains(&source) && !self.is_echo_reply_to_us(&data) {
                        continue;
                    }
                    let our = self.node.address().0;
                    let ip = unframe_ipv6(&data);
                    if self.forward_handle(source, ip) {
                        continue;
                    }
                    if let Some(seg) = tcp::parse(ip) {
                        if seg.dst == our && seg.dport == tcp::HTTP_PORT {
                            if let Some(srv) = self.http.as_mut() {
                                let pkts = srv.handle(our, &seg);
                                for pkt in pkts {
                                    self.outbox.push_back((source, frame_ipv6(&pkt)));
                                }
                                continue;
                            }
                        }
                    }
                    if let Some(echo) = icmp::parse_echo(ip) {
                        if echo.dst == self.address().0 && echo.kind == ECHO_REQUEST {
                            if self.ping_replies {
                                let reply = icmp::build_echo(
                                    echo.dst,
                                    echo.src,
                                    ECHO_REPLY,
                                    echo.id,
                                    echo.seq,
                                    &echo.payload,
                                );
                                self.outbox.push_back((source, frame_ipv6(&reply)));
                            }
                            continue;
                        }
                    }
                    if self.inbox.len() >= INBOX_CAP {
                        self.inbox.pop_front();
                    }
                    self.inbox.push_back(Received {
                        from: address::addr_for_key(&source),
                        from_key: source,
                        data,
                    });
                }
            }
        }
        out
    }

    fn flush_pending(&mut self, now_ms: u64, rng: &mut impl CryptoRngCore) -> Vec<Action> {
        let mut actions = Vec::new();
        let items: Vec<Pending> = self.pending.drain(..).collect();
        for p in items {
            if now_ms.saturating_sub(p.queued_ms) >= PENDING_TTL_MS {
                continue;
            }
            if let Some(key) = self.node.resolve(&p.dest) {
                actions.extend(self.send_to_key(&key, &p.data, now_ms, rng));
            } else {
                let partial = Address(p.dest).get_key();
                let events = self.node.lookup(&partial, now_ms);
                actions.extend(self.events_to_actions(events));
                self.pending.push_back(p);
            }
        }
        actions
    }
}

impl Conn {
    fn new(outbound: bool, now_ms: u64) -> Self {
        Self {
            outbound,
            started_ms: now_ms,
            up_ms: 0,
            peer: None,
            key: None,
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::collections::{HashMap, VecDeque as Queue};

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    /// Two endpoints: `eps[0]` dials out to `tcp://b.test:1514`, `eps[1]`
    /// accepts. Sockets are simulated by `links`.
    struct Net {
        eps: Vec<Endpoint>,
        links: HashMap<(usize, SlotId), (usize, SlotId)>,
        now: u64,
    }

    impl Net {
        fn new() -> Self {
            let mut a = Endpoint::new(seed(), None, 1);
            let b = Endpoint::new(seed(), None, 0);
            a.add_peer_uri("tcp://b.test:1514", CandidateSource::Config).unwrap();
            Self { eps: vec![a, b], links: HashMap::new(), now: 1_000 }
        }

        fn run(&mut self, steps: usize, rng: &mut OsRng) {
            for _ in 0..steps {
                self.now += 100;
                let mut work: Queue<(usize, Action)> = Queue::new();
                for i in 0..self.eps.len() {
                    for a in self.eps[i].poll(self.now, rng) {
                        work.push_back((i, a));
                    }
                }
                self.drain(work, rng);
            }
        }

        fn submit(&mut self, owner: usize, actions: Vec<Action>, rng: &mut OsRng) {
            let work: Queue<(usize, Action)> = actions.into_iter().map(|a| (owner, a)).collect();
            self.drain(work, rng);
        }

        fn drain(&mut self, mut work: Queue<(usize, Action)>, rng: &mut OsRng) {
            while let Some((owner, action)) = work.pop_front() {
                match action {
                    Action::Dial { slot, .. } => {
                        // Only one dial target in this test: eps[1].
                        let peer = 1 - owner;
                        let (s2, acts) = self.eps[peer].accept_transport(self.now);
                        self.links.insert((owner, slot), (peer, s2));
                        self.links.insert((peer, s2), (owner, slot));
                        work.extend(acts.into_iter().map(|a| (peer, a)));
                        let acts = self.eps[owner].on_transport_up(slot, self.now);
                        work.extend(acts.into_iter().map(|a| (owner, a)));
                    }
                    Action::Write { slot, data } => {
                        if let Some(&(other, oslot)) = self.links.get(&(owner, slot)) {
                            let acts = self.eps[other].on_bytes(oslot, &data, self.now, rng);
                            work.extend(acts.into_iter().map(|a| (other, a)));
                        }
                    }
                    Action::Close { slot } => {
                        if let Some((other, oslot)) = self.links.remove(&(owner, slot)) {
                            self.links.remove(&(other, oslot));
                            self.eps[other].on_transport_closed(oslot, self.now);
                        }
                    }
                }
            }
        }

        fn wait_recv(&mut self, idx: usize, rng: &mut OsRng, max_steps: usize) -> Option<Received> {
            for _ in 0..max_steps {
                if let Some(r) = self.eps[idx].recv() {
                    return Some(r);
                }
                self.run(1, rng);
            }
            self.eps[idx].recv()
        }
    }

    #[test]
    fn dials_out_automatically_and_connects() {
        let mut rng = OsRng;
        let mut net = Net::new();
        net.run(30, &mut rng);
        assert!(net.eps[0].peer_count() >= 1, "outbound peer established");
        assert_eq!(net.eps[0].candidates()[0].failures, 0);
        assert!(net.eps[0].candidates()[0].rtt_ms.is_some());
    }

    #[test]
    fn device_sends_and_receives_by_address() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let a_key = *net.eps[0].public_key();
        let b_key = *net.eps[1].public_key();
        net.eps[1].set_allowed_keys(vec![a_key]);
        net.eps[0].set_allowed_keys(vec![b_key]);
        net.run(30, &mut rng);

        let a_addr = net.eps[0].address();
        let b_addr = net.eps[1].address();
        assert_ne!(a_addr, b_addr);

        let acts = net.eps[0].send_to_address(&b_addr, b"hello", net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        let msg = net.wait_recv(1, &mut rng, 200).expect("B receives A's datagram");
        assert_eq!(msg.data, b"hello");
        assert_eq!(msg.from, a_addr);

        // B learned A's key from the traffic, so the reply resolves immediately.
        let acts = net.eps[1].send_to_address(&msg.from, b"pong", net.now, &mut rng);
        net.submit(1, acts, &mut rng);
        let reply = net.wait_recv(0, &mut rng, 200).expect("A receives reply");
        assert_eq!(reply.data, b"pong");
        assert_eq!(reply.from, b_addr);
    }

    /// Send a TCP packet from endpoint `from` to the node with key `to`.
    fn send_tcp(net: &mut Net, rng: &mut OsRng, from: usize, to: PublicKey, pkt: Vec<u8>) {
        let acts = net.eps[from].send_to_key(&to, &frame_ipv6(&pkt), net.now, rng);
        net.submit(from, acts, rng);
    }

    /// Next TCP segment that reaches endpoint `idx` and satisfies `want`.
    fn tcp_recv_where(net: &mut Net, rng: &mut OsRng, idx: usize, want: impl Fn(&tcp::Segment) -> bool) -> tcp::Segment {
        for _ in 0..20 {
            let r = net.wait_recv(idx, rng, 200).expect("segment reaches the client");
            if let Some(seg) = tcp::parse(unframe_ipv6(&r.data)) {
                if want(&seg) {
                    return seg;
                }
            }
        }
        panic!("no matching TCP segment");
    }

    #[test]
    fn forwarded_port_carries_bytes_both_ways() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let a_key = *net.eps[0].public_key();
        let b_key = *net.eps[1].public_key();
        let a_addr = net.eps[0].address().0;
        let b_addr = net.eps[1].address().0;
        net.eps[1].set_forward_ports(&[22]);
        net.eps[1].set_allowed_keys(vec![a_key]);
        net.eps[0].set_allowed_keys(vec![b_key]);
        net.run(30, &mut rng);

        // Client connects to B:22.
        send_tcp(&mut net, &mut rng, 0, b_key, tcp::build(a_addr, b_addr, 40000, 22, 100, 0, tcp::SYN, &[], true));
        let id = match net.eps[1].forward_event() {
            Some(forward::Event::Open { id, port: 22 }) => id,
            other => panic!("expected Open, got {other:?}"),
        };
        let synack = tcp_recv_where(&mut net, &mut rng, 0, |s| s.has(tcp::SYN));
        assert!(synack.has(tcp::ACK));
        let iss = synack.seq;

        // Client: ACK of the SYN-ACK plus "hello". B delivers it to the local side.
        send_tcp(&mut net, &mut rng, 0, b_key, tcp::build(a_addr, b_addr, 40000, 22, 101, iss.wrapping_add(1), tcp::PSH | tcp::ACK, b"hello", false));
        assert_eq!(net.eps[1].forward_event(), Some(forward::Event::Data { id, data: b"hello".to_vec() }));

        // Local side answers "world"; the client receives it.
        assert!(net.eps[1].forward_write(id, b"world"));
        let world = tcp_recv_where(&mut net, &mut rng, 0, |s| !s.payload.is_empty());
        assert_eq!(world.payload, b"world".to_vec());
        assert_eq!(world.seq, iss.wrapping_add(1));

        // Client closes: B reports RemoteFin; the local side closes, and the client acks B's FIN.
        send_tcp(&mut net, &mut rng, 0, b_key, tcp::build(a_addr, b_addr, 40000, 22, 106, iss.wrapping_add(6), tcp::FIN | tcp::ACK, &[], false));
        assert_eq!(net.eps[1].forward_event(), Some(forward::Event::RemoteFin { id }));
        net.eps[1].forward_close(id);
        let fin = tcp_recv_where(&mut net, &mut rng, 0, |s| s.has(tcp::FIN));
        send_tcp(&mut net, &mut rng, 0, b_key, tcp::build(a_addr, b_addr, 40000, 22, 107, fin.seq.wrapping_add(1), tcp::ACK, &[], false));
        assert_eq!(net.eps[1].forward_event(), Some(forward::Event::Closed { id }));
    }

    #[test]
    fn forwarding_ignores_keys_that_are_not_allowed() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let b_key = *net.eps[1].public_key();
        let a_addr = net.eps[0].address().0;
        let b_addr = net.eps[1].address().0;
        net.eps[1].set_forward_ports(&[22]);
        // B allows nobody: A's segments are dropped before the forwarder sees them.
        net.run(30, &mut rng);
        send_tcp(&mut net, &mut rng, 0, b_key, tcp::build(a_addr, b_addr, 40000, 22, 100, 0, tcp::SYN, &[], true));
        assert!(net.eps[1].forward_event().is_none());
    }

    #[test]
    fn probe_reply_from_unallowed_peer_is_delivered() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let a_key = *net.eps[0].public_key();
        let b_key = *net.eps[1].public_key();
        // B answers A's echo requests, but A does not allow B's traffic.
        net.eps[1].set_allowed_keys(vec![a_key]);
        net.run(30, &mut rng);

        let acts = net.eps[0].ping_key(&b_key, 0x5155, 7, net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        let reply = net.wait_recv(0, &mut rng, 200).expect("probe reply reaches A");
        assert_eq!(reply.from_key, b_key);
        let echo = icmp::parse_echo(unframe_ipv6(&reply.data)).expect("reply is an echo");
        assert_eq!((echo.kind, echo.id, echo.seq), (ECHO_REPLY, 0x5155, 7));
    }

    #[test]
    fn drop_peer_closes_slot_and_holds_candidate() {
        let mut rng = OsRng;
        let mut net = Net::new();
        net.run(30, &mut rng);
        let b_key = *net.eps[1].public_key();
        assert!(net.eps[0].peer_count() >= 1);

        let acts = net.eps[0].drop_peer(&b_key, net.now, 60_000);
        assert!(matches!(acts.as_slice(), [Action::Close { .. }]));
        assert_eq!(net.eps[0].peer_count(), 0);

        // Held for 60 s: no redial within the next 10 s.
        net.run(100, &mut rng);
        assert_eq!(net.eps[0].peer_count(), 0, "candidate is cooling down");
    }

    #[test]
    fn peer_root_is_known_after_connecting() {
        let mut rng = OsRng;
        let mut net = Net::new();
        net.run(60, &mut rng);
        let b_key = *net.eps[1].public_key();
        let (root, hops) = net.eps[0].peer_root(&b_key).expect("B's announcements are known");
        assert_eq!(root, net.eps[1].root(), "B is on the root we see");
        assert!(hops <= 64);
        assert!(net.eps[0].peer_root(&[9u8; 32]).is_none(), "unknown node has no root");
    }

    #[test]
    fn device_answers_ping_and_pings_back() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let a_key = *net.eps[0].public_key();
        let b_key = *net.eps[1].public_key();
        net.eps[1].set_allowed_keys(vec![a_key]);
        net.eps[0].set_allowed_keys(vec![b_key]);
        net.run(30, &mut rng);
        let b_addr = net.eps[1].address();

        // A pings B: B must reply without delivering the request to its inbox.
        let acts = net.eps[0].ping(&b_addr, 0x1234, 1, net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        let reply = net.wait_recv(0, &mut rng, 200).expect("echo reply reaches A");
        let echo = icmp::parse_echo(unframe_ipv6(&reply.data)).expect("reply is an echo");
        assert_eq!(echo.kind, ECHO_REPLY);
        assert_eq!((echo.id, echo.seq), (0x1234, 1));
        assert_eq!(echo.payload, PING_PAYLOAD.to_vec());
        assert!(net.eps[1].recv().is_none(), "requests are not delivered to the app");
        assert_eq!(reply.data[0], IPV6_FRAME, "replies are framed");
    }

    #[test]
    fn serves_html_page_over_tcp() {
        let mut rng = OsRng;
        let mut net = Net::new();
        let a_key = *net.eps[0].public_key();
        let b_key = *net.eps[1].public_key();
        net.eps[1].set_allowed_keys(vec![a_key]);
        net.eps[0].set_allowed_keys(vec![b_key]);
        net.eps[1].serve_http(b"<html>ok</html>".to_vec());
        net.run(30, &mut rng);
        let a_addr = net.eps[0].address().0;
        let b_addr = net.eps[1].address();

        let syn = frame_ipv6(&tcp::build(a_addr, b_addr.0, 50000, 80, 100, 0, 0x02, &[], true));
        let acts = net.eps[0].send_to_address(&b_addr, &syn, net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        let synack = next_tcp(&mut net, &mut rng).expect("SYN-ACK");
        assert!(synack.has(0x02) && synack.has(0x10));

        let get = tcp::build(a_addr, b_addr.0, 50000, 80, 101, synack.seq.wrapping_add(1), 0x18,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", false);
        let acts = net.eps[0].send_to_address(&b_addr, &get, net.now, &mut rng);
        net.submit(0, acts, &mut rng);

        let mut body = Vec::new();
        let mut saw_fin = false;
        while let Some(seg) = next_tcp(&mut net, &mut rng) {
            body.extend_from_slice(&seg.payload);
            if seg.has(0x01) { saw_fin = true; break; }
        }
        let text = String::from_utf8_lossy(&body).to_string();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(text.ends_with("<html>ok</html>"));
        assert!(saw_fin);
    }

    /// Next TCP segment delivered to node 0, pumping the network while waiting.
    fn next_tcp(net: &mut Net, rng: &mut OsRng) -> Option<tcp::Segment> {
        for _ in 0..200 {
            if let Some(msg) = net.eps[0].recv() {
                if let Some(seg) = tcp::parse(unframe_ipv6(&msg.data)) {
                    return Some(seg);
                }
                continue;
            }
            net.run(1, rng);
        }
        None
    }

    #[test]
    fn reports_connected_peers() {
        let mut rng = OsRng;
        let mut net = Net::new();
        net.run(30, &mut rng);

        let out = net.eps[0].connected_peers();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].direction, Direction::Outbound);
        assert_eq!(out[0].uri.as_ref().unwrap().host_port(), "b.test:1514");
        assert_eq!(out[0].key, *net.eps[1].public_key());
        assert!(out[0].rtt_ms.is_some());

        let inb = net.eps[1].connected_peers();
        assert_eq!(inb.len(), 1);
        assert_eq!(inb[0].direction, Direction::Inbound);
        assert_eq!(inb[0].key, *net.eps[0].public_key());
        assert!(inb[0].uri.is_none());
    }

    #[test]
    fn drops_datagrams_from_unlisted_keys() {
        let mut rng = OsRng;
        let mut net = Net::new();
        // B allows nobody: A's datagram must not surface.
        net.run(30, &mut rng);
        let b_addr = net.eps[1].address();
        let acts = net.eps[0].send_to_address(&b_addr, b"intruder", net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        assert!(net.wait_recv(1, &mut rng, 200).is_none());

        // Once A's key is provisioned, the same path delivers.
        let a_key = *net.eps[0].public_key();
        net.eps[1].allow_key(a_key);
        let acts = net.eps[0].send_to_address(&b_addr, b"ok", net.now, &mut rng);
        net.submit(0, acts, &mut rng);
        let msg = net.wait_recv(1, &mut rng, 200).expect("allowed key delivers");
        assert_eq!(msg.data, b"ok");
    }

    #[test]
    fn imports_public_peer_list_as_tcp_candidates() {
        let mut ep = Endpoint::new(seed(), None, 2);
        let json = br#"{"r.md": {"tcp://a.example:1514": {"up": true}, "tls://b.example:443": {"up": true}, "tcp://c.example:1514": {"up": true}}}"#;
        assert_eq!(ep.import_peer_list(json, CandidateSource::Discovered), 2);
        assert_eq!(ep.import_peer_list(json, CandidateSource::Discovered), 0, "idempotent");
        assert_eq!(ep.candidates().len(), 2);
    }

    #[test]
    fn rejects_non_tcp_candidates() {
        let mut ep = Endpoint::new(seed(), None, 1);
        assert_eq!(
            ep.add_peer_uri("tls://x.test:443", CandidateSource::Discovered),
            Err(UriError::UnsupportedScheme)
        );
        assert_eq!(ep.add_peer_uri("tcp://x.test:1514", CandidateSource::Discovered), Ok(true));
        assert_eq!(ep.add_peer_uri("tcp://x.test:1514", CandidateSource::Discovered), Ok(false));
    }

    #[test]
    fn pinned_key_mismatch_is_rejected() {
        let mut rng = OsRng;
        let mut net = Net::new();
        // Replace A's candidate with one pinned to a key B does not have.
        let wrong = alloc::format!("tcp://b.test:1514?key={}", "00".repeat(32));
        net.eps[0] = Endpoint::new(seed(), None, 1);
        net.eps[0].add_peer_uri(&wrong, CandidateSource::Config).unwrap();
        net.run(30, &mut rng);
        assert_eq!(net.eps[0].peer_count(), 0, "wrong identity must not peer");
        assert_eq!(net.eps[0].candidates()[0].failures > 0, true);
    }

    #[test]
    fn stalled_dial_times_out_and_closes_socket() {
        let mut rng = OsRng;
        let mut ep = Endpoint::new(seed(), None, 1);
        ep.add_peer_uri("tcp://dead.test:1514", CandidateSource::Config).unwrap();
        let first = ep.poll(0, &mut rng);
        assert!(matches!(first.as_slice(), [Action::Dial { slot: 0, .. }, ..]));
        // Never call on_transport_up: the dial must expire.
        let later = ep.poll(DIAL_TIMEOUT_MS + 1, &mut rng);
        assert!(later.contains(&Action::Close { slot: 0 }));
        assert_eq!(ep.candidates()[0].failures, 1);
    }
}
