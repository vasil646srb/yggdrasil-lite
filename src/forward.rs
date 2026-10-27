//! TCP port forwarding over Yggdrasil.
//!
//! A remote node connects to `[our address]:PORT` over Yggdrasil. The platform
//! opens a local connection for that session, and this module carries the
//! bytes both ways. Only ports given at startup are accepted; other ports get
//! RST. Only keys allowed by the endpoint reach this module, so the ports are
//! not open to the whole network.
//!
//! The TCP here is minimal and meant for interactive use, such as SSH:
//! - passive open only (remote clients connect to us);
//! - in-order delivery, out-of-order segments are dropped and re-acked;
//! - up to [`MAX_INFLIGHT`] unacknowledged segments of [`MSS`] bytes;
//! - retransmission with exponential timeout, reset after [`MAX_RETRIES`];
//! - no congestion control and no TIME_WAIT.
//!
//! The module does no I/O. The caller feeds it segments and local bytes, and
//! takes the packets to send ([`Forward::drain_out`]) and the events
//! ([`Forward::pop_event`]).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::crypto::PublicKey;
use crate::tcp::{self, Segment, ACK, FIN, MSS, PSH, RST, SYN};

/// Largest chunk the platform should pass to [`Forward::write`] at once.
pub const MAX_WRITE: usize = 4096;
/// Bytes queued from the local side per session before `write` refuses.
pub const SEND_QUEUE_MAX: usize = 64 * 1024;
/// Unacknowledged segments in flight per session.
pub const MAX_INFLIGHT: usize = 8;
/// Concurrent sessions across all ports.
pub const MAX_SESSIONS: usize = 32;
const RTO_MIN_MS: u64 = 1_000;
const RTO_MAX_MS: u64 = 8_000;
/// Retransmissions before a session is reset.
pub const MAX_RETRIES: u32 = 8;

/// Session identifier, unique per [`Forward`].
pub type SessionId = u32;

/// What the platform must do for a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A remote client connected to overlay `port`. Open the local side for it,
    /// or call [`Forward::reset`] if that fails.
    Open { id: SessionId, port: u16 },
    /// Bytes from the remote client, to write to the local socket in order.
    Data { id: SessionId, data: Vec<u8> },
    /// The remote client finished sending. Shut down the local write side.
    RemoteFin { id: SessionId },
    /// The session is over (both directions closed, reset by the peer, or
    /// retransmissions exhausted). Close the local side.
    Closed { id: SessionId },
}

#[derive(Debug)]
struct Inflight {
    seq: u32,
    flags: u8,
    data: Vec<u8>,
    sent_ms: u64,
    retries: u32,
    rto_ms: u64,
}

impl Inflight {
    /// Sequence space used: payload plus one each for SYN and FIN.
    fn span(&self) -> u32 {
        self.data.len() as u32
            + (self.flags & SYN != 0) as u32
            + (self.flags & FIN != 0) as u32
    }
}

#[derive(Debug)]
struct Session {
    peer: PublicKey,
    peer_addr: [u8; 16],
    client_port: u16,
    port: u16,
    established: bool,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    queue: VecDeque<u8>,
    inflight: VecDeque<Inflight>,
    local_fin: bool,
    fin_sent: bool,
    fin_acked: bool,
    remote_fin: bool,
}

/// Forwarding state for one endpoint.
pub struct Forward {
    our: [u8; 16],
    ports: Vec<u16>,
    sessions: BTreeMap<SessionId, Session>,
    index: BTreeMap<(PublicKey, u16, u16), SessionId>,
    next_id: SessionId,
    next_iss: u32,
    events: VecDeque<Event>,
    out: Vec<(PublicKey, Vec<u8>)>,
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// Build one IPv6 packet from `our` (port `port`) to the client of session `s`.
fn packet(our: [u8; 16], s: &Session, seq: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let ack = if flags & ACK != 0 { s.rcv_nxt } else { 0 };
    tcp::build(our, s.peer_addr, s.port, s.client_port, seq, ack, flags, data, flags & SYN != 0)
}

impl Forward {
    /// `our` is this endpoint's Yggdrasil address; `ports` are the overlay ports to accept.
    pub fn new(our: [u8; 16], ports: &[u16]) -> Self {
        Self {
            our,
            ports: ports.to_vec(),
            sessions: BTreeMap::new(),
            index: BTreeMap::new(),
            next_id: 1,
            next_iss: 0x2000_0000,
            events: VecDeque::new(),
            out: Vec::new(),
        }
    }

    /// Whether overlay port `port` is forwarded.
    pub fn wants(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Bytes from the remote side waiting for this session's local write (not yet sent to the remote).
    pub fn queued(&self, id: SessionId) -> usize {
        self.sessions.get(&id).map_or(0, |s| s.queue.len())
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Packets to send, as (destination key, IPv6 packet).
    pub fn drain_out(&mut self) -> Vec<(PublicKey, Vec<u8>)> {
        core::mem::take(&mut self.out)
    }

    /// Feed one TCP segment that arrived from `peer` for one of our forwarded ports.
    /// The caller checks the destination address and [`wants`](Self::wants) first.
    pub fn handle_segment(&mut self, peer: PublicKey, seg: &Segment, now: u64) {
        if seg.has(RST) {
            if let Some(&id) = self.index.get(&(peer, seg.sport, seg.dport)) {
                self.remove(id);
                self.events.push_back(Event::Closed { id });
            }
            return;
        }
        if !self.wants(seg.dport) {
            self.reject(peer, seg);
            return;
        }
        match self.index.get(&(peer, seg.sport, seg.dport)).copied() {
            Some(id) => {
                self.on_segment(id, seg, now);
                self.pump(id, now);
                self.maybe_finish(id);
            }
            None if seg.has(SYN) && !seg.has(ACK) && self.sessions.len() < MAX_SESSIONS => {
                self.open(peer, seg, now);
            }
            None => self.reject(peer, seg),
        }
    }

    /// Queue bytes from the local side for `id`. Returns `false` (queues nothing)
    /// if the session is unknown, its local side is closed, or the queue is full.
    pub fn write(&mut self, id: SessionId, data: &[u8], now: u64) -> bool {
        let Some(s) = self.sessions.get_mut(&id) else { return false };
        if s.local_fin || s.queue.len() + data.len() > SEND_QUEUE_MAX {
            return false;
        }
        s.queue.extend(data.iter().copied());
        self.pump(id, now);
        true
    }

    /// The local side has no more data: send FIN after the queued bytes.
    pub fn close(&mut self, id: SessionId, now: u64) {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.local_fin = true;
        }
        self.pump(id, now);
        self.maybe_finish(id);
    }

    /// Reset the session from our side, silently (no [`Event::Closed`]). Use when
    /// the local connection could not be opened or failed.
    pub fn reset(&mut self, id: SessionId) {
        if let Some(s) = self.sessions.get(&id) {
            let rst = packet(self.our, s, s.snd_nxt, RST | ACK, &[]);
            self.out.push((s.peer, rst));
        }
        self.remove(id);
    }

    /// Retransmit unacknowledged segments and send queued data. Call every few hundred ms.
    pub fn poll(&mut self, now: u64) {
        let ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for id in ids {
            let Some(s) = self.sessions.get_mut(&id) else { continue };
            let mut exhausted = false;
            let mut resend: Vec<(u32, u8, Vec<u8>)> = Vec::new();
            for f in s.inflight.iter_mut() {
                if now.saturating_sub(f.sent_ms) < f.rto_ms {
                    continue;
                }
                if f.retries >= MAX_RETRIES {
                    exhausted = true;
                    break;
                }
                f.retries += 1;
                f.sent_ms = now;
                f.rto_ms = (f.rto_ms * 2).min(RTO_MAX_MS);
                resend.push((f.seq, f.flags, f.data.clone()));
            }
            let peer = s.peer;
            for (seq, flags, data) in resend {
                let pkt = packet(self.our, self.sessions.get(&id).unwrap(), seq, flags, &data);
                self.out.push((peer, pkt));
            }
            if exhausted {
                self.reset(id);
                self.events.push_back(Event::Closed { id });
                continue;
            }
            self.pump(id, now);
        }
    }

    // -----------------------------------------------------------------------

    fn reject(&mut self, peer: PublicKey, seg: &Segment) {
        if seg.has(RST) {
            return;
        }
        let len = seg.payload.len() as u32 + seg.has(SYN) as u32 + seg.has(FIN) as u32;
        let (seq, ack, flags) = if seg.has(ACK) {
            (seg.ack, 0, RST)
        } else {
            (0, seg.seq.wrapping_add(len), RST | ACK)
        };
        let pkt = tcp::build(self.our, seg.src, seg.dport, seg.sport, seq, ack, flags, &[], false);
        self.out.push((peer, pkt));
    }

    fn open(&mut self, peer: PublicKey, seg: &Segment, now: u64) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let iss = self.next_iss;
        self.next_iss = self.next_iss.wrapping_add(64_000);
        let s = Session {
            peer,
            peer_addr: seg.src,
            client_port: seg.sport,
            port: seg.dport,
            established: false,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            rcv_nxt: seg.seq.wrapping_add(1),
            queue: VecDeque::new(),
            inflight: VecDeque::new(),
            local_fin: false,
            fin_sent: false,
            fin_acked: false,
            remote_fin: false,
        };
        self.index.insert((peer, seg.sport, seg.dport), id);
        self.sessions.insert(id, s);
        self.events.push_back(Event::Open { id, port: seg.dport });
        // SYN-ACK, kept in flight so it is retransmitted until acknowledged.
        self.send_new(id, SYN | ACK, &[], now);
    }

    /// Send a segment that occupies sequence space (data, SYN or FIN) and track it for retransmission.
    fn send_new(&mut self, id: SessionId, flags: u8, data: &[u8], now: u64) {
        let Some(s) = self.sessions.get_mut(&id) else { return };
        let seq = s.snd_nxt;
        let f = Inflight { seq, flags, data: data.to_vec(), sent_ms: now, retries: 0, rto_ms: RTO_MIN_MS };
        s.snd_nxt = s.snd_nxt.wrapping_add(f.span());
        let pkt = packet(self.our, s, seq, flags, data);
        s.inflight.push_back(f);
        self.out.push((s.peer, pkt));
    }

    fn on_segment(&mut self, id: SessionId, seg: &Segment, _now: u64) {
        let Some(s) = self.sessions.get_mut(&id) else { return };

        if !s.established {
            // Only the ACK of our SYN-ACK completes the handshake.
            if !(seg.has(ACK) && seg.ack == s.iss.wrapping_add(1)) {
                return;
            }
            s.established = true;
        }

        if seg.has(ACK) {
            ack_up_to(s, seg.ack);
        }

        let mut need_ack = false;
        if !seg.payload.is_empty() {
            need_ack = true;
            if seg.seq == s.rcv_nxt && !s.remote_fin {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                self.events.push_back(Event::Data { id, data: seg.payload.clone() });
            }
            // Otherwise a duplicate or out-of-order segment: dropped, re-acked below.
        }
        if seg.has(FIN) {
            need_ack = true;
            let end = seg.seq.wrapping_add(seg.payload.len() as u32);
            if end == s.rcv_nxt && !s.remote_fin {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                s.remote_fin = true;
                self.events.push_back(Event::RemoteFin { id });
            }
        }
        if need_ack {
            let ack = packet(self.our, s, s.snd_nxt, ACK, &[]);
            self.out.push((s.peer, ack));
        }
    }

    fn pump(&mut self, id: SessionId, now: u64) {
        loop {
            let Some(s) = self.sessions.get_mut(&id) else { return };
            if !s.established || s.inflight.len() >= MAX_INFLIGHT {
                return;
            }
            if !s.queue.is_empty() {
                let n = s.queue.len().min(MSS);
                let data: Vec<u8> = s.queue.drain(..n).collect();
                self.send_new(id, PSH | ACK, &data, now);
            } else if s.local_fin && !s.fin_sent {
                s.fin_sent = true;
                self.send_new(id, FIN | ACK, &[], now);
            } else {
                return;
            }
        }
    }

    fn maybe_finish(&mut self, id: SessionId) {
        let done = match self.sessions.get(&id) {
            Some(s) => s.remote_fin && s.fin_acked,
            None => false,
        };
        if done {
            self.remove(id);
            self.events.push_back(Event::Closed { id });
        }
    }

    fn remove(&mut self, id: SessionId) {
        if let Some(s) = self.sessions.remove(&id) {
            self.index.remove(&(s.peer, s.client_port, s.port));
        }
    }
}

/// Process a cumulative ACK: drop acknowledged segments and note when our FIN is acked.
fn ack_up_to(s: &mut Session, ack: u32) {
    if !(seq_lt(s.snd_una, ack) && seq_le(ack, s.snd_nxt)) {
        return;
    }
    s.snd_una = ack;
    while let Some(front) = s.inflight.front() {
        let end = front.seq.wrapping_add(front.span());
        if !seq_le(end, ack) {
            break;
        }
        if front.flags & FIN != 0 {
            s.fin_acked = true;
        }
        s.inflight.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUR: [u8; 16] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const PEER_ADDR: [u8; 16] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const PEER_KEY: PublicKey = [7; 32];

    fn syn(dport: u16, seq: u32) -> Segment {
        tcp::parse(&tcp::build(PEER_ADDR, OUR, 40000, dport, seq, 0, SYN, &[], true)).unwrap()
    }

    #[test]
    fn unlisted_port_gets_rst() {
        let mut f = Forward::new(OUR, &[22]);
        f.handle_segment(PEER_KEY, &syn(23, 100), 0);
        let out = f.drain_out();
        assert_eq!(out.len(), 1);
        let seg = tcp::parse(&out[0].1).unwrap();
        assert!(seg.has(RST));
        assert!(f.pop_event().is_none(), "no session for a refused port");
    }

    #[test]
    fn syn_ack_is_retransmitted_then_session_resets() {
        let mut f = Forward::new(OUR, &[22]);
        f.handle_segment(PEER_KEY, &syn(22, 100), 0);
        assert_eq!(f.pop_event(), Some(Event::Open { id: 1, port: 22 }));
        assert_eq!(f.drain_out().len(), 1, "SYN-ACK sent");

        let mut resends = 0;
        let mut closed = false;
        for t in (0..200_000u64).step_by(100) {
            f.poll(t);
            for (_, pkt) in f.drain_out() {
                let seg = tcp::parse(&pkt).unwrap();
                if seg.has(RST) {
                    continue;
                }
                resends += 1;
            }
            if let Some(Event::Closed { id: 1 }) = f.pop_event() {
                closed = true;
                break;
            }
        }
        assert_eq!(resends, MAX_RETRIES as usize, "SYN-ACK resent MAX_RETRIES times");
        assert!(closed, "session closed after retries are exhausted");
        assert_eq!(f.session_count(), 0);
    }

    #[test]
    fn data_round_trip_and_close() {
        let mut f = Forward::new(OUR, &[22]);
        f.handle_segment(PEER_KEY, &syn(22, 100), 0);
        let synack = tcp::parse(&f.drain_out()[0].1).unwrap();
        let iss = synack.seq;
        f.pop_event();

        // Client: ACK of SYN-ACK plus "hello".
        let hello = tcp::parse(&tcp::build(PEER_ADDR, OUR, 40000, 22, 101, iss.wrapping_add(1), PSH | ACK, b"hello", false)).unwrap();
        f.handle_segment(PEER_KEY, &hello, 10);
        assert!(f.session_count() == 1);
        assert_eq!(f.pop_event(), Some(Event::Data { id: 1, data: b"hello".to_vec() }));
        f.drain_out(); // ACK for "hello"

        // Local side writes "world": sent with seq iss+1.
        assert!(f.write(1, b"world", 20));
        let out = f.drain_out();
        let world = tcp::parse(&out[0].1).unwrap();
        assert_eq!(world.payload, b"world".to_vec());
        assert_eq!(world.seq, iss.wrapping_add(1));

        // Client ACKs "world" and sends FIN.
        let ack_world = tcp::parse(&tcp::build(PEER_ADDR, OUR, 40000, 22, 106, iss.wrapping_add(6), ACK, &[], false)).unwrap();
        f.handle_segment(PEER_KEY, &ack_world, 30);
        let fin = tcp::parse(&tcp::build(PEER_ADDR, OUR, 40000, 22, 106, iss.wrapping_add(6), FIN | ACK, &[], false)).unwrap();
        f.handle_segment(PEER_KEY, &fin, 40);
        assert_eq!(f.pop_event(), Some(Event::RemoteFin { id: 1 }));

        // Local side closes: FIN goes out, client acks it, session ends.
        f.close(1, 50);
        let out = f.drain_out();
        let our_fin = tcp::parse(&out.last().unwrap().1).unwrap();
        assert!(our_fin.has(FIN));
        let ack_fin = tcp::parse(&tcp::build(PEER_ADDR, OUR, 40000, 22, 107, our_fin.seq.wrapping_add(1), ACK, &[], false)).unwrap();
        f.handle_segment(PEER_KEY, &ack_fin, 60);
        assert_eq!(f.pop_event(), Some(Event::Closed { id: 1 }));
        assert_eq!(f.session_count(), 0);
    }

    #[test]
    fn write_is_refused_when_queue_is_full() {
        let mut f = Forward::new(OUR, &[22]);
        f.handle_segment(PEER_KEY, &syn(22, 100), 0);
        let big = alloc::vec![0u8; SEND_QUEUE_MAX];
        // Not established yet: data stays queued, so the queue fills up.
        assert!(f.write(1, &big, 0));
        assert!(!f.write(1, b"x", 0), "one more byte exceeds the queue limit");
        assert_eq!(f.queued(1), SEND_QUEUE_MAX);
    }
}
