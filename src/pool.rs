//! Outbound peer pool with automatic candidate selection.
//!
//! The pool is pure bookkeeping: it decides *which* TCP candidate to dial next
//! and *when*, and tracks what each outbound slot is doing. It performs no I/O,
//! so the same logic runs on std and on `no_std` devices.
//!
//! Candidates come from any source (a static config list, a peer list the host
//! fetched, LAN discovery). The pool keeps `target` outbound slots filled and
//! prefers candidates with the lowest measured connect+handshake latency. A
//! failing candidate is put on exponential backoff; a connection that was up
//! and then closed gets a short cooldown instead of an immediate redial.

use alloc::vec::Vec;

use crate::crypto::PublicKey;
use crate::uri::TcpPeerUri;

/// Index of an outbound slot (`0..target`). Also used as the connection id.
pub type SlotId = usize;

/// How long a dial may take from TCP connect through metadata handshake.
pub const DIAL_TIMEOUT_MS: u64 = 10_000;
const BACKOFF_BASE_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 300_000;
const CLOSE_COOLDOWN_MS: u64 = 5_000;
/// Score assumed for a candidate whose latency is not measured yet.
const UNKNOWN_RTT_MS: u64 = 5_000;
/// Each failure adds this much to a candidate's score.
const FAILURE_PENALTY_MS: u64 = 1_000;

/// Where a candidate came from. Informational; the pool treats them alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    Config,
    Discovered,
}

#[derive(Debug, Clone)]
struct Candidate {
    uri: TcpPeerUri,
    source: CandidateSource,
    /// Last measured connect+handshake time.
    rtt_ms: Option<u64>,
    failures: u32,
    next_try_ms: u64,
}

impl Candidate {
    fn score(&self) -> u64 {
        self.rtt_ms.unwrap_or(UNKNOWN_RTT_MS) + self.failures as u64 * FAILURE_PENALTY_MS
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Idle,
    Dialing { cand: usize, since_ms: u64 },
    Up { cand: usize, key: PublicKey },
}

/// Snapshot of one candidate, for status output.
#[derive(Debug, Clone)]
pub struct CandidateInfo {
    pub uri: TcpPeerUri,
    pub source: CandidateSource,
    pub rtt_ms: Option<u64>,
    pub failures: u32,
}

/// Outbound peer pool. See the module docs.
#[derive(Debug)]
pub struct PeerPool {
    candidates: Vec<Candidate>,
    slots: Vec<SlotState>,
}

impl PeerPool {
    /// Create a pool that keeps up to `target_outbound` outbound connections.
    pub fn new(target_outbound: usize) -> Self {
        Self {
            candidates: Vec::new(),
            slots: alloc::vec![SlotState::Idle; target_outbound],
        }
    }

    pub fn target(&self) -> usize {
        self.slots.len()
    }

    /// Number of slots currently in the Up state.
    pub fn connected(&self) -> usize {
        self.slots.iter().filter(|s| matches!(s, SlotState::Up { .. })).count()
    }

    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Add a candidate. Returns `false` if the same host:port is already known
    /// (the first entry wins, including its expected key).
    pub fn add_candidate(&mut self, uri: TcpPeerUri, source: CandidateSource) -> bool {
        self.add_candidate_with_rtt(uri, source, None)
    }

    /// Add a candidate with an initial latency estimate (e.g. `response_ms`
    /// from a public peer list).
    pub fn add_candidate_with_rtt(
        &mut self,
        uri: TcpPeerUri,
        source: CandidateSource,
        rtt_hint_ms: Option<u64>,
    ) -> bool {
        let id = uri.host_port();
        if self.candidates.iter().any(|c| c.uri.host_port() == id) {
            return false;
        }
        self.candidates.push(Candidate {
            uri,
            source,
            rtt_ms: rtt_hint_ms,
            failures: 0,
            next_try_ms: 0,
        });
        true
    }

    /// Expected public key of the peer being dialed in `slot`, if known.
    pub fn expected_key(&self, slot: SlotId) -> Option<PublicKey> {
        match self.slots.get(slot) {
            Some(SlotState::Dialing { cand, .. }) => self.candidates[*cand].uri.expected_key(),
            _ => None,
        }
    }

    /// Fill idle slots with the best eligible candidates. Returns the dials to start.
    pub fn schedule(&mut self, now_ms: u64) -> Vec<(SlotId, TcpPeerUri)> {
        let mut dials = Vec::new();
        for slot in 0..self.slots.len() {
            if self.slots[slot] != SlotState::Idle {
                continue;
            }
            let Some(best) = self.best_candidate(now_ms) else { break };
            self.slots[slot] = SlotState::Dialing { cand: best, since_ms: now_ms };
            dials.push((slot, self.candidates[best].uri.clone()));
        }
        dials
    }

    /// Best candidate that is off backoff and not already in a slot.
    fn best_candidate(&self, now_ms: u64) -> Option<usize> {
        (0..self.candidates.len())
            .filter(|&i| self.candidates[i].next_try_ms <= now_ms)
            .filter(|&i| !self.slots.iter().any(|s| slot_uses(s, i)))
            .min_by_key(|&i| self.candidates[i].score())
    }

    /// TCP + metadata handshake finished for `slot`, peer key is `key`.
    /// Returns `false` (and leaves the slot as it was) if that key is already
    /// connected in another slot — the caller should close this connection.
    pub fn on_connected(&mut self, slot: SlotId, key: PublicKey, now_ms: u64) -> bool {
        if self.key_connected(&key, slot) {
            return false;
        }
        let SlotState::Dialing { cand, since_ms } = self.slots[slot] else {
            return false;
        };
        let c = &mut self.candidates[cand];
        c.rtt_ms = Some(now_ms.saturating_sub(since_ms));
        c.failures = 0;
        c.next_try_ms = 0;
        self.slots[slot] = SlotState::Up { cand, key };
        true
    }

    /// Dial failed or the handshake was rejected for `slot`.
    pub fn on_failed(&mut self, slot: SlotId, now_ms: u64) {
        if let SlotState::Dialing { cand, .. } = self.slots[slot] {
            let c = &mut self.candidates[cand];
            c.failures = c.failures.saturating_add(1);
            let shift = (c.failures - 1).min(20);
            let backoff = (BACKOFF_BASE_MS << shift).min(BACKOFF_MAX_MS);
            c.next_try_ms = now_ms + backoff;
        }
        self.slots[slot] = SlotState::Idle;
    }

    /// An established connection on `slot` closed. Short cooldown, no penalty.
    pub fn on_closed(&mut self, slot: SlotId, now_ms: u64) {
        match self.slots[slot] {
            SlotState::Up { cand, .. } => {
                self.candidates[cand].next_try_ms = now_ms + CLOSE_COOLDOWN_MS;
                self.slots[slot] = SlotState::Idle;
            }
            SlotState::Dialing { .. } => self.on_failed(slot, now_ms),
            SlotState::Idle => {}
        }
    }

    /// Fail every dial older than [`DIAL_TIMEOUT_MS`]. Returns the affected slots
    /// so the caller can close their sockets.
    pub fn expire(&mut self, now_ms: u64) -> Vec<SlotId> {
        let mut expired = Vec::new();
        for slot in 0..self.slots.len() {
            if let SlotState::Dialing { since_ms, .. } = self.slots[slot] {
                if now_ms.saturating_sub(since_ms) >= DIAL_TIMEOUT_MS {
                    self.on_failed(slot, now_ms);
                    expired.push(slot);
                }
            }
        }
        expired
    }

    /// Endpoint of the peer connected in `slot`, if the slot is Up.
    pub fn slot_uri(&self, slot: SlotId) -> Option<&TcpPeerUri> {
        match self.slots.get(slot)? {
            SlotState::Up { cand, .. } => Some(&self.candidates[*cand].uri),
            _ => None,
        }
    }

    /// Measured connect+handshake latency for the peer in `slot`, if Up.
    pub fn slot_rtt(&self, slot: SlotId) -> Option<u64> {
        match self.slots.get(slot)? {
            SlotState::Up { cand, .. } => self.candidates[*cand].rtt_ms,
            _ => None,
        }
    }

    /// Whether `key` is Up in any slot other than `except`.
    pub fn key_connected(&self, key: &PublicKey, except: SlotId) -> bool {
        self.slots.iter().enumerate().any(|(i, s)| {
            i != except && matches!(s, SlotState::Up { key: k, .. } if k == key)
        })
    }

    /// Keep the candidate for `uri` out of the schedule until `until_ms`.
    /// Used after a peer was dropped on purpose, so it is not redialed at once.
    pub fn cool_down_uri(&mut self, uri: &TcpPeerUri, until_ms: u64) {
        let id = uri.host_port();
        if let Some(c) = self.candidates.iter_mut().find(|c| c.uri.host_port() == id) {
            c.next_try_ms = c.next_try_ms.max(until_ms);
        }
    }

    pub fn candidates_info(&self) -> Vec<CandidateInfo> {
        self.candidates
            .iter()
            .map(|c| CandidateInfo {
                uri: c.uri.clone(),
                source: c.source,
                rtt_ms: c.rtt_ms,
                failures: c.failures,
            })
            .collect()
    }
}

fn slot_uses(state: &SlotState, cand: usize) -> bool {
    match state {
        SlotState::Idle => false,
        SlotState::Dialing { cand: c, .. } | SlotState::Up { cand: c, .. } => *c == cand,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> TcpPeerUri {
        TcpPeerUri::parse(s).unwrap()
    }

    #[test]
    fn dedupes_candidates() {
        let mut p = PeerPool::new(2);
        assert!(p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Config));
        assert!(!p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Discovered));
        assert_eq!(p.candidate_count(), 1);
    }

    #[test]
    fn fills_target_slots_with_distinct_candidates() {
        let mut p = PeerPool::new(2);
        p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Config);
        p.add_candidate(uri("tcp://b.example:1514"), CandidateSource::Config);
        p.add_candidate(uri("tcp://c.example:1514"), CandidateSource::Config);
        let dials = p.schedule(0);
        assert_eq!(dials.len(), 2);
        assert_ne!(dials[0].1, dials[1].1);
        assert!(p.schedule(0).is_empty(), "no idle slots left");
    }

    #[test]
    fn failed_candidate_backs_off() {
        let mut p = PeerPool::new(1);
        p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Config);
        let d = p.schedule(0);
        p.on_failed(d[0].0, 0);
        assert!(p.schedule(500).is_empty(), "still in backoff");
        assert_eq!(p.schedule(1_000).len(), 1, "backoff elapsed");
    }

    #[test]
    fn prefers_lowest_measured_latency() {
        let mut p = PeerPool::new(1);
        p.add_candidate(uri("tcp://flaky.example:1514"), CandidateSource::Config);
        p.add_candidate(uri("tcp://fast.example:1514"), CandidateSource::Config);
        // Tie at start: the first candidate is tried and fails.
        let d = p.schedule(0);
        assert_eq!(d[0].1.host(), "flaky.example");
        p.on_failed(d[0].0, 0);
        // fast.example is unmeasured (score 5000) and beats flaky (6000).
        let d = p.schedule(1_000);
        assert_eq!(d[0].1.host(), "fast.example");
        p.on_connected(d[0].0, [7; 32], 1_050); // measured: 50 ms
        p.on_closed(d[0].0, 1_050);
        // Once off cooldown, the measured 50 ms candidate wins over flaky (6000).
        let d = p.schedule(1_050 + CLOSE_COOLDOWN_MS);
        assert_eq!(d[0].1.host(), "fast.example");
    }

    #[test]
    fn rejects_duplicate_peer_key() {
        let mut p = PeerPool::new(2);
        p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Config);
        p.add_candidate(uri("tcp://b.example:1514"), CandidateSource::Config);
        let d = p.schedule(0);
        assert!(p.on_connected(d[0].0, [9; 32], 10));
        assert!(!p.on_connected(d[1].0, [9; 32], 10), "same key on two slots");
        p.on_failed(d[1].0, 10);
        assert_eq!(p.connected(), 1);
    }

    #[test]
    fn expires_stalled_dials() {
        let mut p = PeerPool::new(1);
        p.add_candidate(uri("tcp://a.example:1514"), CandidateSource::Config);
        p.schedule(0);
        assert!(p.expire(DIAL_TIMEOUT_MS - 1).is_empty());
        assert_eq!(p.expire(DIAL_TIMEOUT_MS), vec![0]);
        assert_eq!(p.connected(), 0);
    }
}
