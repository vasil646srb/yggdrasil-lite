//! TCP over the Yggdrasil overlay, without I/O.
//!
//! [`TcpStack`] implements TCP for one overlay address. It works both ways:
//! remote nodes connect to the ports set with [`TcpStack::listen`], and
//! [`TcpStack::connect`] opens connections to remote nodes.
//!
//! What it implements:
//! - the full RFC 9293 state machine, including simultaneous open and close,
//!   half-close and TIME-WAIT;
//! - MSS and window scale options (RFC 7323), so windows can exceed 64 KiB;
//! - flow control: the advertised window follows the receive buffer the
//!   application drains with [`TcpStack::read`]; zero-window probing;
//! - receiver silly-window avoidance and delayed ACKs (every second segment
//!   or after [`DELACK_MS`]);
//! - reassembly of out-of-order segments;
//! - RTT estimation and retransmission timeout (RFC 6298, Karn's rule);
//! - congestion control: slow start, congestion avoidance, fast retransmit
//!   and NewReno fast recovery (RFC 5681, RFC 6582), initial window RFC 6928;
//! - keepalive, so connections to vanished peers are reset;
//! - per-connection initial sequence numbers from a keyed hash (RFC 6528);
//! - RST and SYN checks against blind injection (RFC 5961).
//!
//! Not implemented: SACK, timestamps, urgent data, ECN.
//!
//! The caller feeds segments addressed to it ([`TcpStack::handle_segment`]),
//! calls [`TcpStack::poll`] every few milliseconds for timers, sends the
//! packets from [`TcpStack::drain_out`] and reacts to [`TcpStack::pop_event`].
//! The caller checks that the sender's key matches the source address.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::tcp::{self, Options, Segment, ACK, FIN, PSH, RST, SYN};

/// Connection handle, unique for the lifetime of a [`TcpStack`].
pub type ConnId = u32;
/// IPv6 address bytes.
pub type Addr = [u8; 16];

/// Initial retransmission timeout (RFC 6298).
pub const RTO_INIT_MS: u64 = 1_000;
/// Lower bound for the retransmission timeout. Overlay paths jitter, so this
/// sits above Linux's 200 ms.
pub const RTO_MIN_MS: u64 = 1_000;
pub const RTO_MAX_MS: u64 = 60_000;
/// Retransmissions of data before the connection is reset (~10 minutes with backoff).
pub const MAX_RETRIES: u32 = 15;
/// Retransmissions of SYN / SYN-ACK before giving up (~1 minute).
pub const SYN_RETRIES: u32 = 5;
/// Delayed ACK timeout.
pub const DELACK_MS: u64 = 40;
/// TIME-WAIT duration (2 × MSL with MSL = 15 s).
pub const TIME_WAIT_MS: u64 = 30_000;
/// Idle time before the first keepalive probe.
pub const KEEPALIVE_IDLE_MS: u64 = 120_000;
pub const KEEPALIVE_INTERVAL_MS: u64 = 15_000;
/// Unanswered keepalive probes before the connection is reset.
pub const KEEPALIVE_PROBES: u32 = 8;
/// Upper bound for the congestion window.
const CWND_MAX: u32 = 16 * 1024 * 1024;
/// Out-of-order segments kept per connection.
const OOO_MAX_SEGMENTS: usize = 128;
const EPHEMERAL_FIRST: u16 = 49152;

/// Stack limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConfig {
    /// Largest payload per segment this side sends or accepts.
    pub mss: u16,
    /// Receive buffer per connection (the largest window advertised).
    pub rcv_buf: usize,
    /// Send buffer per connection (bytes written but not yet acknowledged).
    pub snd_buf: usize,
    /// Open connections, not counting TIME-WAIT.
    pub max_conns: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self { mss: tcp::MSS as u16, rcv_buf: 256 * 1024, snd_buf: 256 * 1024, max_conns: 64 }
    }
}

/// Connection state (RFC 9293), plus `Closed` for a finished connection whose
/// received data the application has not read yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// Both sides closed and all data was delivered.
    Normal,
    /// The peer reset the connection.
    Reset,
    /// The peer refused the connection (RST in reply to our SYN).
    Refused,
    /// Retransmissions or keepalives went unanswered.
    Timeout,
}

/// What the application must react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A remote node opened a connection to listening `port`.
    Accepted { id: ConnId, port: u16 },
    /// A connection from [`TcpStack::connect`] is established.
    Connected { id: ConnId },
    /// Data arrived on a connection whose receive buffer was empty: call [`TcpStack::read`].
    Readable { id: ConnId },
    /// The peer finished sending and every byte before its FIN has been read.
    RemoteFin { id: ConnId },
    /// The connection is over. The id is no longer valid.
    Closed { id: ConnId, reason: CloseReason },
}

impl Event {
    pub fn id(&self) -> ConnId {
        match *self {
            Event::Accepted { id, .. }
            | Event::Connected { id }
            | Event::Readable { id }
            | Event::RemoteFin { id }
            | Event::Closed { id, .. } => id,
        }
    }
}

/// Connection statistics for status pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    pub id: ConnId,
    pub state: State,
    pub remote: Addr,
    pub remote_port: u16,
    pub local_port: u16,
    /// Smoothed round-trip time, once measured.
    pub srtt_ms: Option<u64>,
    pub rto_ms: u64,
    pub cwnd: u32,
    pub snd_wnd: u32,
    /// Bytes sent and not yet acknowledged.
    pub in_flight: u32,
    /// Bytes written by the application and not yet acknowledged.
    pub send_queued: usize,
    /// Bytes received and not yet read by the application.
    pub recv_queued: usize,
    pub retransmits: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}
fn seq_gt(a: u32, b: u32) -> bool {
    seq_lt(b, a)
}
fn seq_ge(a: u32, b: u32) -> bool {
    seq_le(b, a)
}

struct Tcb {
    remote: Addr,
    rport: u16,
    lport: u16,
    state: State,
    /// Opened with `connect` (reports `Connected`), as opposed to accepted.
    active: bool,

    // --- send side ---
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent (snd_nxt can move back after a timeout).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    max_snd_wnd: u32,
    /// Shift applied to the peer's window field.
    snd_shift: u8,
    /// Shift applied to the window field we send.
    rcv_shift: u8,
    /// The peer's SYN carried the window scale option.
    ws_peer: bool,
    /// Effective payload size per segment.
    mss: usize,
    /// Unacknowledged and unsent application data; `tx[0]` has sequence `tx_seq`.
    tx: VecDeque<u8>,
    tx_seq: u32,
    /// Sequence number of our FIN once the application closed.
    fin_seq: Option<u32>,

    // --- congestion control ---
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,
    in_recovery: bool,
    recover: u32,

    // --- RTT and timers ---
    srtt: Option<u64>,
    rttvar: u64,
    rto: u64,
    /// RTT measurement in progress: (sequence that must be acked, send time).
    rtt_probe: Option<(u32, u64)>,
    rexmt_at: Option<u64>,
    retries: u32,
    persist_at: Option<u64>,
    persist_backoff: u64,
    probes_unanswered: u32,
    keepalive_at: u64,
    keepalive_sent: u32,
    time_wait_until: u64,

    // --- receive side ---
    irs: u32,
    rcv_nxt: u32,
    rcv_buf: usize,
    rx: VecDeque<u8>,
    /// Out-of-order segments: (sequence, data).
    ooo: Vec<(u32, Vec<u8>)>,
    /// Sequence of the peer's FIN when it arrived out of order.
    fin_rcv_at: Option<u32>,
    fin_received: bool,
    fin_reported: bool,
    /// Right edge of the last window we advertised (never moves left).
    rcv_adv: u32,
    ack_pending: bool,
    segs_unacked: u32,
    delack_at: Option<u64>,

    closed_reported: bool,
    readable_reported: bool,

    retransmits: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

/// TCP for one overlay address. See the module docs.
pub struct TcpStack {
    our: Addr,
    cfg: TcpConfig,
    secret: [u8; 32],
    listening: Vec<u16>,
    conns: BTreeMap<ConnId, Tcb>,
    index: BTreeMap<(Addr, u16, u16), ConnId>,
    next_id: ConnId,
    next_port: u16,
    events: VecDeque<Event>,
    out: Vec<(Addr, Vec<u8>)>,
    now: u64,
}

impl TcpStack {
    /// `our` is the overlay address; `secret` keys the initial sequence numbers.
    pub fn new(our: Addr, secret: [u8; 32], cfg: TcpConfig) -> Self {
        let port_seed = u16::from_be_bytes([secret[0], secret[1]]);
        Self {
            our,
            cfg,
            secret,
            listening: Vec::new(),
            conns: BTreeMap::new(),
            index: BTreeMap::new(),
            next_id: 1,
            next_port: EPHEMERAL_FIRST + port_seed % (u16::MAX - EPHEMERAL_FIRST),
            events: VecDeque::new(),
            out: Vec::new(),
            now: 0,
        }
    }

    pub fn address(&self) -> Addr {
        self.our
    }

    /// Accept connections on `port`.
    pub fn listen(&mut self, port: u16) {
        if !self.listening.contains(&port) {
            self.listening.push(port);
        }
    }

    /// Stop accepting new connections on `port`. Open connections stay.
    pub fn unlisten(&mut self, port: u16) {
        self.listening.retain(|p| *p != port);
    }

    pub fn is_listening(&self, port: u16) -> bool {
        self.listening.contains(&port)
    }

    /// Connections the application can use (not TIME-WAIT or finished).
    pub fn connection_count(&self) -> usize {
        self.conns.values().filter(|t| !t.closed_reported).count()
    }

    /// Whether `seg` belongs to a connection the stack knows.
    pub fn has_connection(&self, seg: &Segment) -> bool {
        self.index.contains_key(&(seg.src, seg.sport, seg.dport))
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Packets to send: (destination address, IPv6 packet).
    pub fn drain_out(&mut self) -> Vec<(Addr, Vec<u8>)> {
        core::mem::take(&mut self.out)
    }

    /// Open a connection to `remote`:`port`. Returns `None` when the
    /// connection limit is reached or no local port is free.
    pub fn connect(&mut self, remote: Addr, port: u16, now: u64) -> Option<ConnId> {
        self.now = now;
        if self.open_count() >= self.cfg.max_conns && !self.evict_time_wait() {
            return None;
        }
        let lport = self.free_port(remote, port)?;
        let iss = self.isn(remote, port, lport);
        let mut t = Tcb::new(remote, port, lport, iss, true, &self.cfg, now);
        t.state = State::SynSent;
        let id = self.insert(t);
        self.send_syn(id);
        Some(id)
    }

    /// Copy received data into `buf`. Returns the number of bytes copied
    /// (0 when nothing is buffered or the id is unknown).
    pub fn read(&mut self, id: ConnId, buf: &mut [u8]) -> usize {
        let Some(t) = self.conns.get_mut(&id) else { return 0 };
        let n = buf.len().min(t.rx.len());
        for (dst, src) in buf.iter_mut().zip(t.rx.drain(..n)) {
            *dst = src;
        }
        if t.rx.is_empty() {
            t.readable_reported = false;
        }
        if n > 0 && t.window_update_due(self.cfg.mss as usize) {
            self.send_ack(id);
        }
        self.check_fin_and_close(id);
        n
    }

    /// Bytes waiting in the receive buffer.
    pub fn recv_queued(&self, id: ConnId) -> usize {
        self.conns.get(&id).map_or(0, |t| t.rx.len())
    }

    /// Queue `data` for sending. Returns how many bytes were accepted: fewer
    /// than `data.len()` when the send buffer is full, 0 when the connection
    /// cannot send (unknown, closed for writing, or reset).
    pub fn write(&mut self, id: ConnId, data: &[u8]) -> usize {
        let space = self.send_space(id);
        let n = space.min(data.len());
        if n == 0 {
            return 0;
        }
        let Some(t) = self.conns.get_mut(&id) else { return 0 };
        t.tx.extend(data[..n].iter().copied());
        self.output(id);
        n
    }

    /// Free space in the send buffer (0 if the connection cannot send).
    pub fn send_space(&self, id: ConnId) -> usize {
        match self.conns.get(&id) {
            Some(t)
                if t.fin_seq.is_none()
                    && matches!(t.state, State::SynSent | State::SynReceived | State::Established | State::CloseWait) =>
            {
                self.cfg.snd_buf.saturating_sub(t.tx.len())
            }
            _ => 0,
        }
    }

    /// Bytes written and not yet acknowledged by the peer.
    pub fn send_queued(&self, id: ConnId) -> usize {
        self.conns.get(&id).map_or(0, |t| t.tx.len())
    }

    /// Finish sending: a FIN follows the queued data. Reading continues until
    /// [`Event::RemoteFin`]; [`Event::Closed`] follows when both sides are done.
    pub fn close(&mut self, id: ConnId) {
        let Some(t) = self.conns.get_mut(&id) else { return };
        if t.fin_seq.is_some() {
            return;
        }
        match t.state {
            State::SynSent => {
                // Nothing was exchanged yet: just forget the connection.
                t.closed_reported = true;
                self.events.push_back(Event::Closed { id, reason: CloseReason::Normal });
                self.remove(id);
                return;
            }
            // The FIN waits for the handshake; the state moves on with the ACK.
            State::SynReceived => {}
            State::Established => t.state = State::FinWait1,
            State::CloseWait => t.state = State::LastAck,
            _ => return,
        }
        t.fin_seq = Some(t.tx_seq.wrapping_add(t.tx.len() as u32));
        self.output(id);
    }

    /// Reset the connection. No [`Event::Closed`] is reported for it.
    pub fn abort(&mut self, id: ConnId) {
        let Some(t) = self.conns.get(&id) else { return };
        if !matches!(t.state, State::SynSent | State::TimeWait | State::Closed) {
            let pkt = t.packet(self.our, t.snd_max, RST | ACK, &[], Options::default());
            self.out.push((t.remote, pkt));
        }
        self.remove(id);
    }

    /// Statistics for one connection.
    pub fn info(&self, id: ConnId) -> Option<ConnInfo> {
        self.conns.get(&id).map(|t| t.info(id))
    }

    /// Statistics for every connection the application can use.
    pub fn connections(&self) -> Vec<ConnInfo> {
        self.conns.iter().filter(|(_, t)| !t.closed_reported).map(|(id, t)| t.info(*id)).collect()
    }

    /// Remote address and port of a connection.
    pub fn remote(&self, id: ConnId) -> Option<(Addr, u16)> {
        self.conns.get(&id).map(|t| (t.remote, t.rport))
    }

    /// Local port of a connection.
    pub fn local_port(&self, id: ConnId) -> Option<u16> {
        self.conns.get(&id).map(|t| t.lport)
    }

    // -----------------------------------------------------------------------
    // Input
    // -----------------------------------------------------------------------

    /// Process one segment addressed to [`address`](Self::address).
    pub fn handle_segment(&mut self, seg: &Segment, now: u64) {
        self.now = now;
        if seg.dst != self.our {
            return;
        }
        let key = (seg.src, seg.sport, seg.dport);
        if let Some(&id) = self.index.get(&key) {
            let reuse = {
                let t = &self.conns[&id];
                // A new SYN on a TIME-WAIT tuple above the old sequence space opens a new connection.
                matches!(t.state, State::TimeWait | State::Closed)
                    && t.closed_reported
                    && seg.has(SYN)
                    && !seg.has(ACK)
                    && seq_gt(seg.seq, t.rcv_nxt)
            };
            if !reuse {
                self.input(id, seg);
                return;
            }
            self.remove(id);
        }
        if seg.has(RST) {
            return;
        }
        if seg.has(SYN) && !seg.has(ACK) && self.is_listening(seg.dport) {
            if self.open_count() >= self.cfg.max_conns && !self.evict_time_wait() {
                self.reject(seg);
                return;
            }
            self.accept(seg);
            return;
        }
        self.reject(seg);
    }

    fn accept(&mut self, seg: &Segment) {
        let iss = self.isn(seg.src, seg.sport, seg.dport);
        let mut t = Tcb::new(seg.src, seg.sport, seg.dport, iss, false, &self.cfg, self.now);
        t.state = State::SynReceived;
        t.irs = seg.seq;
        t.rcv_nxt = seg.seq.wrapping_add(1);
        t.apply_syn_options(seg, self.cfg.mss as usize);
        t.snd_wnd = seg.window as u32;
        t.max_snd_wnd = t.snd_wnd;
        t.snd_wl1 = seg.seq;
        let port = seg.dport;
        let id = self.insert(t);
        self.events.push_back(Event::Accepted { id, port });
        self.send_syn(id);
    }

    /// RST in reply to a segment for no connection (RFC 9293 3.10.7.1).
    fn reject(&mut self, seg: &Segment) {
        if seg.has(RST) {
            return;
        }
        let (seq, ack, flags) = if seg.has(ACK) {
            (seg.ack, 0, RST)
        } else {
            (0, seg.seq.wrapping_add(seg.seq_len()), RST | ACK)
        };
        let pkt = tcp::build(self.our, seg.src, seg.dport, seg.sport, seq, ack, flags, 0, Options::default(), &[]);
        self.out.push((seg.src, pkt));
    }

    fn input(&mut self, id: ConnId, seg: &Segment) {
        let state = self.conns[&id].state;
        match state {
            State::SynSent => self.input_syn_sent(id, seg),
            _ => self.input_synchronized(id, seg),
        }
    }

    fn input_syn_sent(&mut self, id: ConnId, seg: &Segment) {
        let our = self.our;
        let now = self.now;
        let mss = self.cfg.mss as usize;
        let t = self.conns.get_mut(&id).unwrap();
        let ack_ok = seg.has(ACK) && seg.ack == t.iss.wrapping_add(1);
        if seg.has(ACK) && !ack_ok {
            if !seg.has(RST) {
                let pkt = tcp::build(our, seg.src, seg.dport, seg.sport, seg.ack, 0, RST, 0, Options::default(), &[]);
                self.out.push((seg.src, pkt));
            }
            return;
        }
        if seg.has(RST) {
            if ack_ok {
                self.terminate(id, CloseReason::Refused);
            }
            return;
        }
        if !seg.has(SYN) {
            return;
        }
        t.irs = seg.seq;
        t.rcv_nxt = seg.seq.wrapping_add(1);
        t.apply_syn_options(seg, mss);
        t.snd_wl1 = seg.seq;
        t.snd_wl2 = seg.ack;
        t.snd_wnd = seg.window as u32; // never scaled in a SYN
        t.max_snd_wnd = t.snd_wnd;
        t.keepalive_at = now + KEEPALIVE_IDLE_MS;
        if ack_ok {
            t.on_syn_acked(now);
            t.state = State::Established;
            t.ack_pending = true;
            self.events.push_back(Event::Connected { id });
            self.output(id);
            self.flush_ack(id);
        } else {
            // Simultaneous open: answer with SYN-ACK.
            t.state = State::SynReceived;
            self.send_syn(id);
        }
    }

    fn input_synchronized(&mut self, id: ConnId, seg: &Segment) {
        let now = self.now;
        {
            let t = self.conns.get_mut(&id).unwrap();
            t.keepalive_at = now + KEEPALIVE_IDLE_MS;
            t.keepalive_sent = 0;
        }

        // A retransmitted SYN while we wait for the ACK of our SYN-ACK.
        {
            let t = &self.conns[&id];
            if t.state == State::SynReceived && seg.has(SYN) && !seg.has(ACK) && !seg.has(RST) {
                if seg.seq == t.irs {
                    self.send_syn(id);
                }
                return;
            }
        }

        // 1. Sequence number check.
        let acceptable = self.conns[&id].acceptable(seg);
        if !acceptable {
            if !seg.has(RST) {
                self.send_ack(id);
            }
            return;
        }

        // 2. RST: exact match closes, anything else in the window gets a challenge ACK.
        if seg.has(RST) {
            if seg.seq == self.conns[&id].rcv_nxt {
                let state = self.conns[&id].state;
                match state {
                    State::TimeWait | State::Closed => self.remove(id),
                    _ => self.terminate(id, CloseReason::Reset),
                }
            } else {
                self.send_ack(id);
            }
            return;
        }

        // 3. SYN in a synchronized state: challenge ACK (RFC 5961 4.2).
        if seg.has(SYN) {
            self.send_ack(id);
            return;
        }

        // 4. ACK.
        if !seg.has(ACK) {
            return;
        }
        if self.conns[&id].state == State::SynReceived {
            let t = self.conns.get_mut(&id).unwrap();
            if !(seq_lt(t.snd_una, seg.ack) && seq_le(seg.ack, t.snd_max)) {
                let pkt = tcp::build(self.our, seg.src, seg.dport, seg.sport, seg.ack, 0, RST, 0, Options::default(), &[]);
                self.out.push((seg.src, pkt));
                return;
            }
            t.on_syn_acked(now);
            t.state = if t.fin_seq.is_some() { State::FinWait1 } else { State::Established };
            t.snd_wnd = (seg.window as u32) << t.snd_shift;
            t.max_snd_wnd = t.max_snd_wnd.max(t.snd_wnd);
            t.snd_wl1 = seg.seq;
            t.snd_wl2 = seg.ack;
            if t.active {
                self.events.push_back(Event::Connected { id });
            }
        }
        if !self.process_ack(id, seg) {
            return;
        }

        // State changes caused by the ACK of our FIN.
        let fin_acked = self.conns[&id].fin_acked();
        match self.conns[&id].state {
            State::FinWait1 if fin_acked => self.conns.get_mut(&id).unwrap().state = State::FinWait2,
            State::Closing if fin_acked => self.enter_time_wait(id),
            State::LastAck if fin_acked => {
                self.conns.get_mut(&id).unwrap().state = State::Closed;
                self.check_fin_and_close(id);
                if !self.conns.contains_key(&id) {
                    return;
                }
            }
            State::TimeWait => {
                // Retransmitted FIN: acknowledge and restart the timer.
                if seg.has(FIN) {
                    self.conns.get_mut(&id).unwrap().time_wait_until = now + TIME_WAIT_MS;
                    self.send_ack(id);
                }
                return;
            }
            _ => {}
        }

        // 5–6. Data and FIN.
        let accepts_data = matches!(
            self.conns[&id].state,
            State::Established | State::FinWait1 | State::FinWait2
        );
        if accepts_data {
            self.process_data(id, seg);
        } else if !seg.payload.is_empty() || seg.has(FIN) {
            // Data after the peer's FIN: just acknowledge what we have.
            self.send_ack(id);
        }

        self.output(id);
        self.flush_ack(id);
    }

    /// Process the acknowledgment field. Returns `false` if the segment must be dropped.
    fn process_ack(&mut self, id: ConnId, seg: &Segment) -> bool {
        let now = self.now;
        let t = self.conns.get_mut(&id).unwrap();
        let ack = seg.ack;
        if seq_gt(ack, t.snd_max) {
            // Acknowledges something not yet sent.
            t.ack_pending = true;
            self.flush_ack(id);
            return false;
        }
        let wnd = (seg.window as u32) << t.snd_shift;
        let window_changed = wnd != t.snd_wnd;

        // Window update (RFC 9293 3.10.7.4).
        if seq_ge(ack, t.snd_una)
            && (seq_lt(t.snd_wl1, seg.seq) || (t.snd_wl1 == seg.seq && seq_le(t.snd_wl2, ack)))
        {
            t.snd_wnd = wnd;
            t.snd_wl1 = seg.seq;
            t.snd_wl2 = ack;
            t.max_snd_wnd = t.max_snd_wnd.max(wnd);
            if wnd > 0 {
                t.persist_at = None;
                t.persist_backoff = 0;
            }
        }
        if t.snd_wnd == 0 {
            // The peer answers our probes: it is alive, just not reading.
            t.probes_unanswered = 0;
        }

        if ack == t.snd_una {
            let flight = t.snd_max.wrapping_sub(t.snd_una);
            let dup = flight > 0 && seg.payload.is_empty() && !seg.has(FIN) && !window_changed;
            if dup {
                t.dupacks += 1;
                if t.dupacks == 3 && !t.in_recovery {
                    // Fast retransmit, enter NewReno recovery.
                    let mss = t.mss as u32;
                    t.ssthresh = (flight / 2).max(2 * mss);
                    t.recover = t.snd_max;
                    t.in_recovery = true;
                    t.rtt_probe = None;
                    t.cwnd = t.ssthresh + 3 * mss;
                    let una = t.snd_una;
                    self.retransmit_one(id, una);
                } else if t.dupacks > 3 && t.in_recovery {
                    t.cwnd = (t.cwnd + t.mss as u32).min(CWND_MAX);
                }
            }
            return true;
        }
        if seq_lt(ack, t.snd_una) {
            return true; // old duplicate
        }

        // New data acknowledged.
        let acked = ack.wrapping_sub(t.snd_una);
        // Grow the window only while it limits sending (RFC 7661).
        let cwnd_limited = t.snd_max.wrapping_sub(t.snd_una) + t.mss as u32 >= t.cwnd;
        if let Some((probe_seq, sent)) = t.rtt_probe {
            if seq_ge(ack, probe_seq) {
                t.rtt_sample(now.saturating_sub(sent));
                t.rtt_probe = None;
            }
        }
        if seq_gt(ack, t.tx_seq) {
            let n = (ack.wrapping_sub(t.tx_seq) as usize).min(t.tx.len());
            t.tx.drain(..n);
            t.tx_seq = t.tx_seq.wrapping_add(n as u32);
        }
        t.snd_una = ack;
        if seq_lt(t.snd_nxt, t.snd_una) {
            t.snd_nxt = t.snd_una;
        }
        t.retries = 0;
        t.probes_unanswered = 0;

        let mss = t.mss as u32;
        if t.in_recovery {
            if seq_ge(ack, t.recover) {
                // Full acknowledgment: leave recovery.
                let flight = t.snd_max.wrapping_sub(t.snd_una);
                t.cwnd = t.ssthresh.min(flight + mss).max(mss);
                t.in_recovery = false;
                t.dupacks = 0;
            } else {
                // Partial acknowledgment: retransmit the next hole.
                t.cwnd = t.cwnd.saturating_sub(acked).saturating_add(mss).max(mss);
                let una = t.snd_una;
                t.rexmt_at = Some(now + t.rto);
                self.retransmit_one(id, una);
            }
        } else {
            t.dupacks = 0;
            if !cwnd_limited {
                // Application-limited: keep the window.
            } else if t.cwnd < t.ssthresh {
                // Appropriate byte counting, L = 2 (RFC 3465).
                t.cwnd = t.cwnd.saturating_add(acked.min(2 * mss));
            } else {
                t.cwnd = t.cwnd.saturating_add((mss * mss / t.cwnd.max(1)).max(1));
            }
            t.cwnd = t.cwnd.min(CWND_MAX);
        }

        let t = self.conns.get_mut(&id).unwrap();
        t.rexmt_at = if t.snd_una == t.snd_max { None } else { Some(now + t.rto) };
        true
    }

    fn process_data(&mut self, id: ConnId, seg: &Segment) {
        let t = self.conns.get_mut(&id).unwrap();
        let mut seq = seg.seq;
        let mut data: &[u8] = &seg.payload;
        let mut fin = seg.has(FIN);

        // Trim what we already have.
        if seq_lt(seq, t.rcv_nxt) {
            let skip = t.rcv_nxt.wrapping_sub(seq) as usize;
            if skip > data.len() {
                // Everything, including any FIN, was received before.
                data = &[];
                fin = false;
            } else {
                data = &data[skip..];
            }
            seq = t.rcv_nxt;
            if data.is_empty() && !fin {
                // Duplicate: acknowledge at once so the sender learns where we are.
                t.ack_pending = true;
                t.segs_unacked = 2;
                return;
            }
        }
        // Trim what does not fit the window.
        let wnd = t.rcv_window() as usize;
        let offset = seq.wrapping_sub(t.rcv_nxt) as usize;
        let room = wnd.saturating_sub(offset);
        if data.len() > room {
            data = &data[..room];
            fin = false;
        }

        if !data.is_empty() {
            t.bytes_received += data.len() as u64;
            if seq == t.rcv_nxt {
                let was_empty = t.rx.is_empty();
                let filled_hole = !t.ooo.is_empty();
                t.rx.extend(data.iter().copied());
                t.rcv_nxt = t.rcv_nxt.wrapping_add(data.len() as u32);
                t.merge_ooo();
                t.ack_pending = true;
                t.segs_unacked += 1;
                if filled_hole {
                    t.segs_unacked = 2;
                }
                if t.delack_at.is_none() {
                    t.delack_at = Some(self.now + DELACK_MS);
                }
                if was_empty && !t.readable_reported {
                    t.readable_reported = true;
                    self.events.push_back(Event::Readable { id });
                }
            } else {
                t.store_ooo(seq, data);
                // Duplicate ACK right away so the sender can fast-retransmit.
                t.ack_pending = true;
                t.segs_unacked = 2;
            }
        }

        let t = self.conns.get_mut(&id).unwrap();
        if fin {
            t.fin_rcv_at = Some(seq.wrapping_add(data.len() as u32));
        }
        if !t.fin_received && t.fin_rcv_at == Some(t.rcv_nxt) {
            t.fin_received = true;
            t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
            t.ack_pending = true;
            t.segs_unacked = 2;
            match t.state {
                State::Established => t.state = State::CloseWait,
                State::FinWait1 => {
                    if t.fin_acked() {
                        self.enter_time_wait(id);
                    } else {
                        t.state = State::Closing;
                    }
                }
                State::FinWait2 => self.enter_time_wait(id),
                _ => {}
            }
            self.check_fin_and_close(id);
        }
    }

    // -----------------------------------------------------------------------
    // Output
    // -----------------------------------------------------------------------

    /// Send what the windows allow.
    fn output(&mut self, id: ConnId) {
        let now = self.now;
        loop {
            let Some(t) = self.conns.get_mut(&id) else { return };
            if !matches!(
                t.state,
                State::Established | State::CloseWait | State::FinWait1 | State::LastAck | State::Closing
            ) {
                return;
            }
            let flight = t.snd_nxt.wrapping_sub(t.snd_una);
            let off = t.snd_nxt.wrapping_sub(t.tx_seq) as usize;
            let avail = t.tx.len().saturating_sub(off);
            let fin_due = t.fin_seq.map_or(false, |f| seq_le(t.snd_nxt, f)) && off <= t.tx.len();
            if avail == 0 && !fin_due {
                return;
            }
            let wnd = t.cwnd.min(t.snd_wnd);
            let usable = wnd.saturating_sub(flight) as usize;
            let len = avail.min(usable).min(t.mss);
            if avail > 0 {
                // Sender silly-window avoidance (RFC 9293 3.8.6.2.1), no Nagle.
                let small = len < t.mss && len < avail && (len as u32) < t.max_snd_wnd / 2;
                if len == 0 || small {
                    // Nothing in flight will bring an ACK: the persist timer either
                    // probes a zero window or overrides the small-window hold.
                    if flight == 0 && t.persist_at.is_none() && t.rexmt_at.is_none() {
                        t.persist_backoff = t.rto;
                        t.persist_at = Some(now + t.persist_backoff);
                    }
                    return;
                }
            }
            let seq = t.snd_nxt;
            let span = self.send_data(id, seq, len);
            let t = self.conns.get_mut(&id).unwrap();
            if span == 0 {
                return;
            }
            if seq == t.snd_max && t.rtt_probe.is_none() {
                t.rtt_probe = Some((seq.wrapping_add(span), now));
            }
            t.snd_nxt = t.snd_nxt.wrapping_add(span);
            if seq_gt(t.snd_nxt, t.snd_max) {
                t.snd_max = t.snd_nxt;
            }
            if t.rexmt_at.is_none() {
                t.rexmt_at = Some(now + t.rto);
            }
        }
    }

    /// Send up to `len` bytes starting at `seq` (plus FIN if it follows).
    /// Returns the sequence space used.
    fn send_data(&mut self, id: ConnId, seq: u32, len: usize) -> u32 {
        let our = self.our;
        let t = self.conns.get_mut(&id).unwrap();
        let off = seq.wrapping_sub(t.tx_seq) as usize;
        let len = len.min(t.tx.len().saturating_sub(off));
        let end = seq.wrapping_add(len as u32);
        let fin = t.fin_seq == Some(end);
        if len == 0 && !fin {
            return 0;
        }
        let data: Vec<u8> = t.tx.range(off..off + len).copied().collect();
        let mut flags = ACK;
        if len > 0 && off + len == t.tx.len() {
            flags |= PSH;
        }
        if fin {
            flags |= FIN;
        }
        if seq_lt(seq, t.snd_max) {
            t.retransmits += 1;
        } else {
            t.bytes_sent += len as u64;
        }
        let pkt = t.packet(our, seq, flags, &data, Options::default());
        t.after_send_ack();
        let remote = t.remote;
        self.out.push((remote, pkt));
        len as u32 + fin as u32
    }

    fn retransmit_one(&mut self, id: ConnId, seq: u32) {
        let t = &self.conns[&id];
        let len = t.mss;
        self.send_data(id, seq, len);
    }

    fn send_syn(&mut self, id: ConnId) {
        let our = self.our;
        let mss = self.cfg.mss;
        let now = self.now;
        let t = self.conns.get_mut(&id).unwrap();
        let opts = Options {
            mss: Some(mss),
            wscale: if t.state == State::SynSent || t.ws_peer { Some(t.rcv_shift) } else { None },
        };
        let flags = if t.state == State::SynReceived { SYN | ACK } else { SYN };
        let iss = t.iss;
        // The window in a SYN is never scaled.
        let wnd = t.rcv_buf.min(u16::MAX as usize) as u16;
        let ack = if flags & ACK != 0 { t.rcv_nxt } else { 0 };
        let pkt = tcp::build(our, t.remote, t.lport, t.rport, iss, ack, flags, wnd, opts, &[]);
        t.snd_nxt = iss.wrapping_add(1);
        t.snd_max = t.snd_nxt;
        if t.rtt_probe.is_none() && t.retries == 0 {
            t.rtt_probe = Some((t.snd_nxt, now));
        }
        if t.rexmt_at.is_none() {
            t.rexmt_at = Some(now + t.rto);
        }
        t.rcv_adv = t.rcv_nxt.wrapping_add(wnd as u32);
        self.out.push((t.remote, pkt));
    }

    /// Send a pure ACK now.
    fn send_ack(&mut self, id: ConnId) {
        let our = self.our;
        let Some(t) = self.conns.get_mut(&id) else { return };
        if matches!(t.state, State::SynSent) {
            return;
        }
        // Pure ACKs carry the highest sequence sent: after a timeout snd_nxt
        // moves back, and the peer would find an older number unacceptable
        // and ignore the acknowledgment.
        let pkt = t.packet(our, t.snd_max, ACK, &[], Options::default());
        t.after_send_ack();
        self.out.push((t.remote, pkt));
    }

    /// Send the pending ACK if it cannot wait for the delayed-ACK timer.
    fn flush_ack(&mut self, id: ConnId) {
        let Some(t) = self.conns.get(&id) else { return };
        if t.ack_pending && t.segs_unacked >= 2 {
            self.send_ack(id);
        }
    }

    // -----------------------------------------------------------------------
    // Timers
    // -----------------------------------------------------------------------

    /// Run timers: retransmission, delayed ACK, zero-window probes,
    /// keepalive, TIME-WAIT. Call every 10–100 ms.
    pub fn poll(&mut self, now: u64) {
        self.now = now;
        let ids: Vec<ConnId> = self.conns.keys().copied().collect();
        for id in ids {
            let Some(t) = self.conns.get(&id) else { continue };

            if matches!(t.state, State::TimeWait) && now >= t.time_wait_until {
                self.remove(id);
                continue;
            }
            if t.rexmt_at.map_or(false, |at| now >= at) {
                self.on_rexmt_timeout(id);
                if !self.conns.contains_key(&id) {
                    continue;
                }
            }
            let t = &self.conns[&id];
            if t.persist_at.map_or(false, |at| now >= at) {
                self.on_persist_timeout(id);
                if !self.conns.contains_key(&id) {
                    continue;
                }
            }
            let t = &self.conns[&id];
            if t.ack_pending && t.delack_at.map_or(true, |at| now >= at) {
                self.send_ack(id);
            }
            let t = &self.conns[&id];
            let keepalive_state = matches!(t.state, State::Established | State::CloseWait | State::FinWait2);
            if keepalive_state && t.rexmt_at.is_none() && t.persist_at.is_none() && now >= t.keepalive_at {
                if t.keepalive_sent >= KEEPALIVE_PROBES {
                    self.abort_with(id, CloseReason::Timeout);
                    continue;
                }
                self.send_probe(id);
                let t = self.conns.get_mut(&id).unwrap();
                t.keepalive_sent += 1;
                t.keepalive_at = now + KEEPALIVE_INTERVAL_MS;
            }
            self.output(id);
        }
    }

    /// Earliest time (same clock as [`poll`](Self::poll)) at which a timer is due, or `None`
    /// with no connections. A value at or before `now` means `poll` has work right away.
    /// Lets the caller sleep until then instead of polling every few milliseconds; it must
    /// still call `poll` after any segment or application write, since those can make
    /// output ready without a timer.
    pub fn next_timer(&self) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut take = |at: u64| next = Some(next.map_or(at, |n| n.min(at)));
        for t in self.conns.values() {
            if matches!(t.state, State::TimeWait) {
                take(t.time_wait_until);
            }
            if let Some(at) = t.rexmt_at {
                take(at);
            }
            if let Some(at) = t.persist_at {
                take(at);
            }
            if t.ack_pending {
                // `poll` sends a pending ACK at once when no delay is armed.
                take(t.delack_at.unwrap_or(0));
            }
            let keepalive_state = matches!(t.state, State::Established | State::CloseWait | State::FinWait2);
            if keepalive_state && t.rexmt_at.is_none() && t.persist_at.is_none() {
                take(t.keepalive_at);
            }
        }
        next
    }

    fn on_rexmt_timeout(&mut self, id: ConnId) {
        let now = self.now;
        let t = self.conns.get_mut(&id).unwrap();
        t.retries += 1;
        let limit = if matches!(t.state, State::SynSent | State::SynReceived) { SYN_RETRIES } else { MAX_RETRIES };
        if t.retries > limit {
            self.abort_with(id, CloseReason::Timeout);
            return;
        }
        t.rto = (t.rto * 2).min(RTO_MAX_MS);
        t.rtt_probe = None;
        t.rexmt_at = None;
        match t.state {
            State::SynSent | State::SynReceived => {
                t.retransmits += 1;
                self.send_syn(id);
            }
            _ => {
                if t.snd_una == t.snd_max {
                    return;
                }
                let mss = t.mss as u32;
                let flight = t.snd_max.wrapping_sub(t.snd_una);
                t.ssthresh = (flight / 2).max(2 * mss);
                t.cwnd = mss;
                t.dupacks = 0;
                t.in_recovery = false;
                t.recover = t.snd_max;
                // Go back and resend from the first unacknowledged byte.
                t.snd_nxt = t.snd_una;
                t.rexmt_at = Some(now + t.rto);
                // With a closed window the probe timer takes over; send at least one segment.
                let una = t.snd_una;
                let span = self.send_data(id, una, mss as usize);
                let t = self.conns.get_mut(&id).unwrap();
                t.snd_nxt = t.snd_una.wrapping_add(span);
                self.output(id);
            }
        }
    }

    fn on_persist_timeout(&mut self, id: ConnId) {
        let now = self.now;
        let t = self.conns.get_mut(&id).unwrap();
        if t.snd_wnd > 0 {
            // Small window held back by silly-window avoidance: send what fits.
            t.persist_at = None;
            if t.snd_nxt == t.snd_una {
                let wnd = t.snd_wnd.min(t.cwnd) as usize;
                let seq = t.snd_nxt;
                let len = wnd.min(t.mss);
                let span = self.send_data(id, seq, len);
                let t = self.conns.get_mut(&id).unwrap();
                if span > 0 {
                    t.snd_nxt = t.snd_nxt.wrapping_add(span);
                    if seq_gt(t.snd_nxt, t.snd_max) {
                        t.snd_max = t.snd_nxt;
                    }
                    t.rexmt_at = Some(now + t.rto);
                }
            }
            return;
        }
        if t.probes_unanswered >= MAX_RETRIES {
            self.abort_with(id, CloseReason::Timeout);
            return;
        }
        t.probes_unanswered += 1;
        t.persist_backoff = (t.persist_backoff * 2).clamp(RTO_MIN_MS, RTO_MAX_MS);
        t.persist_at = Some(now + t.persist_backoff);
        self.send_probe(id);
    }

    /// Keepalive / zero-window probe: an ACK one byte below the window, which
    /// the peer must answer with an ACK carrying its current window.
    fn send_probe(&mut self, id: ConnId) {
        let our = self.our;
        let t = self.conns.get_mut(&id).unwrap();
        let pkt = t.packet(our, t.snd_una.wrapping_sub(1), ACK, &[], Options::default());
        t.after_send_ack();
        self.out.push((t.remote, pkt));
    }

    // -----------------------------------------------------------------------
    // Connection table
    // -----------------------------------------------------------------------

    fn open_count(&self) -> usize {
        self.conns.values().filter(|t| !matches!(t.state, State::TimeWait)).count()
    }

    fn evict_time_wait(&mut self) -> bool {
        let victim = self
            .conns
            .iter()
            .filter(|(_, t)| t.state == State::TimeWait)
            .min_by_key(|(_, t)| t.time_wait_until)
            .map(|(id, _)| *id);
        match victim {
            Some(id) => {
                self.remove(id);
                true
            }
            None => false,
        }
    }

    fn insert(&mut self, t: Tcb) -> ConnId {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.index.insert((t.remote, t.rport, t.lport), id);
        self.conns.insert(id, t);
        id
    }

    fn remove(&mut self, id: ConnId) {
        if let Some(t) = self.conns.remove(&id) {
            self.index.remove(&(t.remote, t.rport, t.lport));
        }
    }

    fn free_port(&mut self, remote: Addr, rport: u16) -> Option<u16> {
        let range = u16::MAX - EPHEMERAL_FIRST + 1;
        for _ in 0..range {
            let p = self.next_port;
            self.next_port = if p == u16::MAX { EPHEMERAL_FIRST } else { p + 1 };
            if !self.is_listening(p) && !self.index.contains_key(&(remote, rport, p)) {
                return Some(p);
            }
        }
        None
    }

    /// RFC 6528: a 4 µs clock plus a keyed hash of the connection tuple.
    fn isn(&self, remote: Addr, rport: u16, lport: u16) -> u32 {
        let mut h = Sha256::new();
        h.update(self.secret);
        h.update(self.our);
        h.update(remote);
        h.update(rport.to_be_bytes());
        h.update(lport.to_be_bytes());
        let d = h.finalize();
        let f = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        f.wrapping_add((self.now as u32).wrapping_mul(250))
    }

    fn enter_time_wait(&mut self, id: ConnId) {
        let now = self.now;
        let t = self.conns.get_mut(&id).unwrap();
        t.state = State::TimeWait;
        t.time_wait_until = now + TIME_WAIT_MS;
        t.rexmt_at = None;
        t.persist_at = None;
        self.check_fin_and_close(id);
    }

    /// Report `RemoteFin` once the data before it is read, and `Closed` once
    /// the connection is fully over and drained.
    fn check_fin_and_close(&mut self, id: ConnId) {
        let Some(t) = self.conns.get_mut(&id) else { return };
        if t.fin_received && !t.fin_reported && t.rx.is_empty() {
            t.fin_reported = true;
            self.events.push_back(Event::RemoteFin { id });
        }
        let t = self.conns.get_mut(&id).unwrap();
        let done = matches!(t.state, State::TimeWait | State::Closed) && t.fin_reported;
        if done && !t.closed_reported {
            t.closed_reported = true;
            self.events.push_back(Event::Closed { id, reason: CloseReason::Normal });
        }
        if t.closed_reported && t.state == State::Closed {
            self.remove(id);
        }
    }

    /// The connection ended abnormally: report it and forget it.
    fn terminate(&mut self, id: ConnId, reason: CloseReason) {
        if let Some(t) = self.conns.get(&id) {
            if !t.closed_reported {
                self.events.push_back(Event::Closed { id, reason });
            }
        }
        self.remove(id);
    }

    fn abort_with(&mut self, id: ConnId, reason: CloseReason) {
        let reported = self.conns.get(&id).map_or(true, |t| t.closed_reported);
        self.abort(id);
        if !reported {
            self.events.push_back(Event::Closed { id, reason });
        }
    }
}

impl Tcb {
    fn new(remote: Addr, rport: u16, lport: u16, iss: u32, active: bool, cfg: &TcpConfig, now: u64) -> Self {
        let mss = cfg.mss as usize;
        let mut rcv_shift = 0u8;
        while rcv_shift < 14 && (cfg.rcv_buf >> rcv_shift) > u16::MAX as usize {
            rcv_shift += 1;
        }
        Self {
            remote,
            rport,
            lport,
            state: State::Closed,
            active,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: iss,
            max_snd_wnd: 0,
            snd_shift: 0,
            rcv_shift,
            ws_peer: false,
            mss,
            tx: VecDeque::new(),
            tx_seq: iss.wrapping_add(1),
            fin_seq: None,
            cwnd: (10 * mss as u32).min((2 * mss as u32).max(14600)),
            ssthresh: CWND_MAX,
            dupacks: 0,
            in_recovery: false,
            recover: iss,
            srtt: None,
            rttvar: 0,
            rto: RTO_INIT_MS,
            rtt_probe: None,
            rexmt_at: None,
            retries: 0,
            persist_at: None,
            persist_backoff: 0,
            probes_unanswered: 0,
            keepalive_at: now + KEEPALIVE_IDLE_MS,
            keepalive_sent: 0,
            time_wait_until: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_buf: cfg.rcv_buf,
            rx: VecDeque::new(),
            ooo: Vec::new(),
            fin_rcv_at: None,
            fin_received: false,
            fin_reported: false,
            rcv_adv: 0,
            ack_pending: false,
            segs_unacked: 0,
            delack_at: None,
            closed_reported: false,
            readable_reported: false,
            retransmits: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Take MSS and window scale from the peer's SYN.
    fn apply_syn_options(&mut self, seg: &Segment, our_mss: usize) {
        let peer_mss = seg.opts.mss.map_or(1220, |m| m as usize);
        self.mss = our_mss.min(peer_mss).max(64);
        // Scaling is used only when both sides send the option.
        match seg.opts.wscale {
            Some(ws) => {
                self.ws_peer = true;
                self.snd_shift = ws.min(14);
            }
            None => {
                self.ws_peer = false;
                self.snd_shift = 0;
                self.rcv_shift = 0;
            }
        }
    }

    fn on_syn_acked(&mut self, now: u64) {
        if let Some((probe_seq, sent)) = self.rtt_probe {
            if seq_ge(self.iss.wrapping_add(1), probe_seq) && self.retries == 0 {
                self.rtt_sample(now.saturating_sub(sent));
            }
        }
        self.rtt_probe = None;
        self.snd_una = self.iss.wrapping_add(1);
        if seq_lt(self.snd_nxt, self.snd_una) {
            self.snd_nxt = self.snd_una;
        }
        self.rexmt_at = None;
        self.retries = 0;
        if !self.ws_peer {
            self.snd_shift = 0;
            self.rcv_shift = 0;
        }
        // RFC 6298 5.7: after a retransmitted SYN start data with a fresh RTO.
        if self.srtt.is_none() {
            self.rto = RTO_INIT_MS;
        }
    }

    fn rtt_sample(&mut self, r: u64) {
        let r = r.max(1);
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                let err = srtt.abs_diff(r);
                self.rttvar = (3 * self.rttvar + err) / 4;
                self.srtt = Some((7 * srtt + r) / 8);
            }
        }
        let srtt = self.srtt.unwrap();
        self.rto = (srtt + (4 * self.rttvar).max(DELACK_MS)).clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    fn fin_acked(&self) -> bool {
        self.fin_seq.map_or(false, |f| seq_gt(self.snd_una, f))
    }

    /// Receive window: free space in the receive buffer, never shrinking the
    /// right edge already advertised.
    fn rcv_window(&self) -> u32 {
        let free = self.rcv_buf.saturating_sub(self.rx.len()) as u32;
        let max = (u16::MAX as u32) << self.rcv_shift;
        let promised = self.rcv_adv.wrapping_sub(self.rcv_nxt);
        let promised = if (promised as i32) < 0 { 0 } else { promised };
        free.max(promised).min(max)
    }

    /// Window to advertise, with receiver silly-window avoidance: small
    /// openings are held back until they reach a full segment or half the buffer.
    fn adv_window(&self, mss: usize) -> u32 {
        let free = self.rcv_buf.saturating_sub(self.rx.len()) as u32;
        let promised = self.rcv_adv.wrapping_sub(self.rcv_nxt);
        let promised = if (promised as i32) < 0 { 0 } else { promised };
        let threshold = (mss as u32).min(self.rcv_buf as u32 / 2);
        let wnd = if free.saturating_sub(promised) < threshold { promised } else { free };
        wnd.min((u16::MAX as u32) << self.rcv_shift)
    }

    /// After the application read: is the window opened enough to tell the peer?
    fn window_update_due(&self, mss: usize) -> bool {
        if !matches!(self.state, State::Established | State::FinWait1 | State::FinWait2) || self.fin_received {
            return false;
        }
        let wnd = self.adv_window(mss);
        let advertised = self.rcv_adv.wrapping_sub(self.rcv_nxt);
        let advertised = if (advertised as i32) < 0 { 0 } else { advertised };
        let grow = wnd.saturating_sub(advertised);
        grow >= (2 * mss as u32).min(self.rcv_buf as u32 / 2)
    }

    fn packet(&self, our: Addr, seq: u32, flags: u8, data: &[u8], opts: Options) -> Vec<u8> {
        let wnd = self.adv_window(self.mss);
        let field = (wnd >> self.rcv_shift).min(u16::MAX as u32) as u16;
        let ack = if flags & ACK != 0 { self.rcv_nxt } else { 0 };
        tcp::build(our, self.remote, self.lport, self.rport, seq, ack, flags, field, opts, data)
    }

    /// Every segment we send carries an ACK: clear the delayed-ACK state and
    /// remember the window we advertised.
    fn after_send_ack(&mut self) {
        let wnd = self.adv_window(self.mss);
        let field = (wnd >> self.rcv_shift).min(u16::MAX as u32);
        let edge = self.rcv_nxt.wrapping_add(field << self.rcv_shift);
        if seq_gt(edge, self.rcv_adv) {
            self.rcv_adv = edge;
        }
        self.ack_pending = false;
        self.segs_unacked = 0;
        self.delack_at = None;
    }

    /// RFC 9293 3.10.7.4 segment acceptability.
    fn acceptable(&self, seg: &Segment) -> bool {
        let wnd = self.rcv_window();
        let len = seg.seq_len();
        let in_wnd = |s: u32| seq_le(self.rcv_nxt, s) && seq_lt(s, self.rcv_nxt.wrapping_add(wnd));
        match (len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => in_wnd(seg.seq),
            (_, 0) => false,
            _ => in_wnd(seg.seq) || in_wnd(seg.seq.wrapping_add(len - 1)),
        }
    }

    fn store_ooo(&mut self, seq: u32, data: &[u8]) {
        if self.ooo.iter().any(|(s, d)| *s == seq && d.len() >= data.len()) {
            return;
        }
        if self.ooo.len() >= OOO_MAX_SEGMENTS {
            return;
        }
        self.ooo.push((seq, data.to_vec()));
    }

    /// Move out-of-order segments that now continue the stream into `rx`.
    fn merge_ooo(&mut self) {
        loop {
            let mut progressed = false;
            let mut i = 0;
            while i < self.ooo.len() {
                let (s, ref d) = self.ooo[i];
                let end = s.wrapping_add(d.len() as u32);
                if seq_le(end, self.rcv_nxt) {
                    self.ooo.swap_remove(i);
                    continue;
                }
                if seq_le(s, self.rcv_nxt) {
                    let skip = self.rcv_nxt.wrapping_sub(s) as usize;
                    let (_, d) = self.ooo.swap_remove(i);
                    self.rx.extend(d[skip..].iter().copied());
                    self.rcv_nxt = end;
                    progressed = true;
                    continue;
                }
                i += 1;
            }
            if !progressed {
                break;
            }
        }
    }

    fn info(&self, id: ConnId) -> ConnInfo {
        ConnInfo {
            id,
            state: self.state,
            remote: self.remote,
            remote_port: self.rport,
            local_port: self.lport,
            srtt_ms: self.srtt,
            rto_ms: self.rto,
            cwnd: self.cwnd,
            snd_wnd: self.snd_wnd,
            in_flight: self.snd_max.wrapping_sub(self.snd_una),
            send_queued: self.tx.len(),
            recv_queued: self.rx.len(),
            retransmits: self.retransmits,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
        }
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;
    pub use alloc::vec;
    pub use alloc::vec::Vec;

    pub const A: Addr = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa];
    pub const B: Addr = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb];

    /// Two stacks joined by a link with delay, jitter, loss and duplication.
    pub struct Sim {
        pub a: TcpStack,
        pub b: TcpStack,
        pub now: u64,
        pub rng: u64,
        /// (deliver at, to A?, packet)
        pub wire: Vec<(u64, bool, Vec<u8>)>,
        pub delay: u64,
        pub jitter: u64,
        pub loss_pct: u64,
        pub dup_pct: u64,
        /// Drop everything (peer vanished).
        pub cut: bool,
        pub a_events: Vec<Event>,
        pub b_events: Vec<Event>,
        pub packets: u64,
    }

    impl Sim {
        pub fn new(cfg: TcpConfig) -> Self {
            Self {
                a: TcpStack::new(A, [1; 32], cfg),
                b: TcpStack::new(B, [2; 32], cfg),
                now: 10_000,
                rng: 0x1234_5678_9abc_def1,
                wire: Vec::new(),
                delay: 40,
                jitter: 0,
                loss_pct: 0,
                dup_pct: 0,
                cut: false,
                a_events: Vec::new(),
                b_events: Vec::new(),
                packets: 0,
            }
        }

        fn rand(&mut self, n: u64) -> u64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            if n == 0 { 0 } else { self.rng % n }
        }

        fn send(&mut self, to_a: bool, pkt: Vec<u8>) {
            self.packets += 1;
            if self.cut || self.rand(100) < self.loss_pct {
                return;
            }
            let copies = if self.rand(100) < self.dup_pct { 2 } else { 1 };
            for _ in 0..copies {
                let at = self.now + self.delay + self.rand(self.jitter + 1);
                self.wire.push((at, to_a, pkt.clone()));
            }
        }

        pub fn step(&mut self, ms: u64) {
            self.now += ms;
            let now = self.now;
            // Stable: packets due at the same time keep their sending order.
            let (mut due, rest): (Vec<_>, Vec<_>) = self.wire.drain(..).partition(|d| d.0 <= now);
            self.wire = rest;
            due.sort_by_key(|d| d.0);
            for (_, to_a, pkt) in due {
                let seg = tcp::parse(&pkt).expect("valid segment on the wire");
                if to_a { self.a.handle_segment(&seg, now) } else { self.b.handle_segment(&seg, now) }
            }
            self.a.poll(now);
            self.b.poll(now);
            self.flush();
        }

        pub fn flush(&mut self) {
            for (dst, pkt) in self.a.drain_out() {
                assert_eq!(dst, B);
                self.send(false, pkt);
            }
            for (dst, pkt) in self.b.drain_out() {
                assert_eq!(dst, A);
                self.send(true, pkt);
            }
            while let Some(e) = self.a.pop_event() {
                self.a_events.push(e);
            }
            while let Some(e) = self.b.pop_event() {
                self.b_events.push(e);
            }
        }

        /// Connect A to B:port and return (A id, B id).
        pub fn open(&mut self, port: u16) -> (ConnId, ConnId) {
            self.a_events.clear();
            self.b_events.clear();
            self.b.listen(port);
            let a = self.a.connect(B, port, self.now).unwrap();
            self.flush();
            for _ in 0..2_000 {
                self.step(5);
                let up = self.a_events.contains(&Event::Connected { id: a });
                let acc = self.b_events.iter().find_map(|e| match e {
                    Event::Accepted { id, port: p } if *p == port => Some(*id),
                    _ => None,
                });
                if let (true, Some(b)) = (up, acc) {
                    return (a, b);
                }
            }
            panic!("handshake did not complete");
        }

        pub fn closed(events: &[Event], id: ConnId) -> Option<CloseReason> {
            events.iter().find_map(|e| match e {
                Event::Closed { id: i, reason } if *i == id => Some(*reason),
                _ => None,
            })
        }
    }

    pub fn pattern(n: usize, salt: u32) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(salt) >> 13) as u8).collect()
    }

    /// Send `up` from A to B and `down` from B to A, then close both sides.
    /// Returns the simulated milliseconds the transfer took.
    pub fn transfer(sim: &mut Sim, a: ConnId, b: ConnId, up: &[u8], down: &[u8], max_ms: u64) -> u64 {
        let start = sim.now;
        let (mut us, mut ds) = (0, 0);
        let (mut got_b, mut got_a) = (Vec::new(), Vec::new());
        let mut buf = vec![0u8; 8192];
        let (mut a_closed, mut b_closed) = (false, false);
        while sim.now - start < max_ms {
            us += sim.a.write(a, &up[us..]);
            ds += sim.b.write(b, &down[ds..]);
            if us == up.len() && !a_closed {
                sim.a.close(a);
                a_closed = true;
            }
            if ds == down.len() && !b_closed {
                sim.b.close(b);
                b_closed = true;
            }
            loop {
                let n = sim.b.read(b, &mut buf);
                if n == 0 { break; }
                got_b.extend_from_slice(&buf[..n]);
            }
            loop {
                let n = sim.a.read(a, &mut buf);
                if n == 0 { break; }
                got_a.extend_from_slice(&buf[..n]);
            }
            sim.flush();
            if Sim::closed(&sim.a_events, a).is_some() && Sim::closed(&sim.b_events, b).is_some() {
                break;
            }
            sim.step(5);
        }
        assert_eq!(got_b.len(), up.len(), "A->B length");
        assert!(got_b == up, "A->B data intact");
        assert_eq!(got_a.len(), down.len(), "B->A length");
        assert!(got_a == down, "B->A data intact");
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Normal));
        assert_eq!(Sim::closed(&sim.b_events, b), Some(CloseReason::Normal));
        assert!(sim.a_events.contains(&Event::RemoteFin { id: a }));
        assert!(sim.b_events.contains(&Event::RemoteFin { id: b }));
        sim.now - start
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use super::tests_support::*;

    #[test]
    fn clean_link_bulk_transfer_uses_large_windows() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        let up = pattern(4_000_000, 1);
        // Measure mid-transfer that the window grew past 64 KiB.
        let mut sent = 0;
        let mut buf = vec![0u8; 65536];
        for _ in 0..400 {
            sent += sim.a.write(a, &up[sent..]);
            while sim.b.read(b, &mut buf) > 0 {}
            sim.step(5);
        }
        let info = sim.a.info(a).unwrap();
        assert!(info.snd_wnd > 65535, "window scaling in effect: {}", info.snd_wnd);
        assert!(info.cwnd > 65535, "congestion window grew: {}", info.cwnd);
        assert_eq!(info.retransmits, 0);
        assert!(info.srtt_ms.unwrap() >= 80 && info.srtt_ms.unwrap() < 200, "srtt {:?}", info.srtt_ms);
    }

    #[test]
    fn clean_link_throughput() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        let up = pattern(2_000_000, 1);
        let ms = transfer(&mut sim, a, b, &up, b"bye", 60_000);
        // 80 ms RTT, 256 KiB window: well above 1 MB/s once open.
        assert!(ms < 4_000, "2 MB took {ms} ms");
    }

    #[test]
    fn lossy_reordering_duplicating_link_delivers_everything() {
        for (loss, seed) in [(2, 7u64), (5, 11), (10, 13)] {
            let mut sim = Sim::new(TcpConfig::default());
            sim.rng ^= seed;
            sim.jitter = 30;
            sim.dup_pct = 3;
            let (a, b) = sim.open(22);
            sim.loss_pct = loss;
            let up = pattern(600_000, 3);
            let down = pattern(200_000, 5);
            transfer(&mut sim, a, b, &up, &down, 900_000);
        }
    }

    #[test]
    fn lossy_handshake_still_connects() {
        let mut sim = Sim::new(TcpConfig::default());
        sim.loss_pct = 40;
        sim.rng ^= 99;
        let (a, b) = sim.open(80);
        sim.loss_pct = 0;
        transfer(&mut sim, a, b, b"ping", b"pong", 120_000);
    }

    #[test]
    fn slow_reader_closes_window_and_resumes() {
        let cfg = TcpConfig { rcv_buf: 16 * 1024, ..TcpConfig::default() };
        let mut sim = Sim::new(cfg);
        let (a, b) = sim.open(22);
        let up = pattern(200_000, 9);
        let mut sent = 0;
        // B does not read for 20 s: A fills B's window and stops.
        for _ in 0..4_000 {
            sent += sim.a.write(a, &up[sent..]);
            sim.step(5);
        }
        // The persist timer squeezes the last bytes in: the buffer ends up full.
        assert_eq!(sim.b.recv_queued(b), 16 * 1024, "receive buffer full");
        assert_eq!(sim.a.info(a).unwrap().snd_wnd, 0, "zero window advertised");
        assert!(Sim::closed(&sim.a_events, a).is_none(), "no timeout while the peer is alive");
        // B reads again: everything arrives.
        let mut got = Vec::new();
        let mut buf = vec![0u8; 4096];
        for _ in 0..40_000 {
            sent += sim.a.write(a, &up[sent..]);
            loop {
                let n = sim.b.read(b, &mut buf);
                if n == 0 { break; }
                got.extend_from_slice(&buf[..n]);
            }
            if got.len() == up.len() { break; }
            sim.step(5);
        }
        assert!(got == up);
    }

    #[test]
    fn connect_to_closed_port_is_refused() {
        let mut sim = Sim::new(TcpConfig::default());
        let a = sim.a.connect(B, 9999, sim.now).unwrap();
        sim.flush();
        for _ in 0..100 {
            sim.step(5);
        }
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Refused));
        assert_eq!(sim.a.connection_count(), 0);
    }

    #[test]
    fn connect_to_silent_host_times_out() {
        let mut sim = Sim::new(TcpConfig::default());
        sim.cut = true;
        let a = sim.a.connect(B, 22, sim.now).unwrap();
        sim.flush();
        for _ in 0..1_000 {
            sim.step(100);
        }
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Timeout));
    }

    #[test]
    fn vanished_peer_with_data_in_flight_times_out() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, _b) = sim.open(22);
        sim.cut = true;
        sim.a.write(a, &pattern(10_000, 1));
        for _ in 0..20_000 {
            sim.step(100);
            if Sim::closed(&sim.a_events, a).is_some() { break; }
        }
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Timeout));
    }

    #[test]
    fn idle_connection_to_vanished_peer_is_detected_by_keepalive() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        // Idle but alive: keepalives are answered, nothing closes.
        for _ in 0..4_000 {
            sim.step(100);
        }
        assert!(Sim::closed(&sim.a_events, a).is_none());
        assert!(Sim::closed(&sim.b_events, b).is_none());
        sim.cut = true;
        for _ in 0..4_000 {
            sim.step(100);
        }
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Timeout));
        assert_eq!(Sim::closed(&sim.b_events, b), Some(CloseReason::Timeout));
    }

    #[test]
    fn abort_resets_the_peer() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        sim.a.abort(a);
        sim.flush();
        for _ in 0..50 {
            sim.step(5);
        }
        assert_eq!(Sim::closed(&sim.b_events, b), Some(CloseReason::Reset));
        assert!(Sim::closed(&sim.a_events, a).is_none(), "abort is silent locally");
    }

    #[test]
    fn time_wait_expires_and_port_can_be_reused() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        transfer(&mut sim, a, b, b"x", b"y", 10_000);
        // One side holds TIME-WAIT, then it is gone.
        for _ in 0..400 {
            sim.step(100);
        }
        assert!(sim.a.conns.is_empty() && sim.b.conns.is_empty(), "TIME-WAIT expired");
        let (a2, b2) = sim.open(22);
        transfer(&mut sim, a2, b2, b"again", b"ok", 10_000);
    }

    #[test]
    fn next_timer_tracks_the_earliest_timer() {
        let mut sim = Sim::new(TcpConfig::default());
        assert_eq!(sim.a.next_timer(), None, "no connections, no timers");
        let (a, b) = sim.open(22);
        for _ in 0..100 {
            sim.step(10);
        }
        // Idle established connection: only the keepalive is armed, far in the future.
        let at = sim.a.next_timer().expect("keepalive armed");
        assert!(at > sim.now + KEEPALIVE_IDLE_MS / 2 && at <= sim.now + KEEPALIVE_IDLE_MS, "at={at} now={}", sim.now);

        // Data in flight arms the retransmission timer well before the keepalive.
        sim.a.write(a, b"hello");
        sim.a.poll(sim.now);
        let at = sim.a.next_timer().expect("retransmission armed");
        assert!(at >= sim.now && at <= sim.now + RTO_INIT_MS.max(RTO_MIN_MS) * 2, "at={at} now={}", sim.now);

        // Receiving data arms the delayed ACK on B: due within DELACK_MS.
        sim.flush();
        sim.step(sim.delay);
        if let Some(at) = sim.b.next_timer() {
            assert!(at <= sim.now + DELACK_MS, "delayed ACK or earlier, at={at} now={}", sim.now);
        }
        let _ = b;

        // After the ACKs flow and the connection closes, TIME-WAIT is the last timer, then none.
        sim.a.close(a);
        for _ in 0..400 {
            sim.step(100);
        }
        let mut buf = [0u8; 8];
        sim.b.read(b, &mut buf);
        sim.b.close(b);
        for _ in 0..1_000 {
            sim.step(100);
        }
        assert!(sim.a.conns.is_empty() && sim.b.conns.is_empty());
        assert_eq!(sim.a.next_timer(), None);
        assert_eq!(sim.b.next_timer(), None);
    }

    #[test]
    fn half_close_keeps_the_other_direction_open() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        sim.a.write(a, b"request");
        sim.a.close(a);
        for _ in 0..50 {
            sim.step(5);
        }
        assert!(sim.b_events.contains(&Event::RemoteFin { id: b }) == false, "unread data comes first");
        let mut buf = [0u8; 64];
        let n = sim.b.read(b, &mut buf);
        assert_eq!(&buf[..n], b"request");
        sim.flush();
        assert!(sim.b_events.contains(&Event::RemoteFin { id: b }));
        // B still sends after A's FIN.
        let reply = pattern(100_000, 4);
        let mut sent = 0;
        let mut got = Vec::new();
        let mut rb = vec![0u8; 8192];
        for _ in 0..4_000 {
            sent += sim.b.write(b, &reply[sent..]);
            if sent == reply.len() {
                sim.b.close(b);
            }
            loop {
                let n = sim.a.read(a, &mut rb);
                if n == 0 { break; }
                got.extend_from_slice(&rb[..n]);
            }
            sim.step(5);
            if Sim::closed(&sim.a_events, a).is_some() { break; }
        }
        assert!(got == reply);
        assert_eq!(Sim::closed(&sim.a_events, a), Some(CloseReason::Normal));
    }

    #[test]
    fn out_of_window_rst_is_ignored() {
        let mut sim = Sim::new(TcpConfig::default());
        let (a, b) = sim.open(22);
        let t = &sim.b.conns[&b];
        let bogus = t.rcv_nxt.wrapping_add(10_000_000);
        let lport = sim.a.local_port(a).unwrap();
        let rst = tcp::build(A, B, lport, 22, bogus, 0, RST, 0, Options::default(), &[]);
        sim.b.handle_segment(&tcp::parse(&rst).unwrap(), sim.now);
        sim.flush();
        assert!(Sim::closed(&sim.b_events, b).is_none());
        transfer(&mut sim, a, b, b"still", b"alive", 10_000);
    }

    #[test]
    fn listener_limit_refuses_extra_connections() {
        let mut sim = Sim::new(TcpConfig::default());
        sim.b = TcpStack::new(B, [2; 32], TcpConfig { max_conns: 2, ..TcpConfig::default() });
        sim.b.listen(22);
        let ids: Vec<ConnId> = (0..3).map(|_| sim.a.connect(B, 22, sim.now).unwrap()).collect();
        sim.flush();
        for _ in 0..100 {
            sim.step(5);
        }
        let connected = ids.iter().filter(|id| sim.a_events.contains(&Event::Connected { id: **id })).count();
        assert_eq!(connected, 2);
        assert_eq!(Sim::closed(&sim.a_events, ids[2]), Some(CloseReason::Refused));
    }
}
