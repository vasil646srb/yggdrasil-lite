//! Network quality: group peers by tree root, pick the global network, and rank
//! its peers by latency.
//!
//! A peer's root is the root of its tree branch as announced to us (see
//! [`Endpoint::peer_root`](crate::Endpoint::peer_root)). Peers that share a root
//! belong to the same network. The network with the most peers is the global
//! one. Ties go to our own root, then to the smaller key.
//!
//! Inside the global network, peers are ranked by their measured latency (a
//! moving average of echo round trips to the peer's address), then by hops from
//! the root. Peers on a different root are drop candidates. Peers whose root is
//! not known yet are kept: their announcements may not have arrived.
//!
//! The root is also probed with echo requests so its latency can be logged. A
//! request to the root follows the tree, so it is not a per-peer measurement;
//! peer ranking uses the direct latency to each peer.
//!
//! The caller decides when to evaluate. [`Quality::due`] says whether
//! `recheck_ms` has passed since the last evaluation (5 minutes by default).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::crypto::PublicKey;

/// How often the root is checked by default.
pub const DEFAULT_RECHECK_MS: u64 = 5 * 60 * 1000;

/// Moving average: `new = (old * (DIV - 1) + sample) / DIV`.
const EWMA_DIV: u64 = 4;

/// What the evaluation needs to know about one connected peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerView {
    pub key: PublicKey,
    /// Root of the peer's branch, if its announcements are known.
    pub root: Option<PublicKey>,
    /// Hops from that root (length of the peer's coordinates).
    pub hops: usize,
}

/// Result of one evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    /// Root of the global network, if any peer has a known root.
    pub global_root: Option<PublicKey>,
    /// Peers on the global root, best first (latency, then hops).
    pub global: Vec<PublicKey>,
    /// Peers whose known root differs from the global one: drop candidates.
    pub foreign: Vec<PublicKey>,
    /// Peers whose root is not known yet: kept.
    pub unknown: Vec<PublicKey>,
}

/// Quality state kept across evaluations.
#[derive(Debug)]
pub struct Quality {
    recheck_ms: u64,
    last_eval_ms: Option<u64>,
    /// Smoothed echo round-trip time per peer key, in ms.
    rtt: BTreeMap<PublicKey, u64>,
    /// Latest echo round-trip time to the global root, in ms.
    root_rtt: Option<u64>,
}

impl Quality {
    /// `recheck_ms` is the minimum time between evaluations.
    pub fn new(recheck_ms: u64) -> Self {
        Self { recheck_ms, last_eval_ms: None, rtt: BTreeMap::new(), root_rtt: None }
    }

    /// True if no evaluation has run yet or `recheck_ms` has passed since the last one.
    pub fn due(&self, now_ms: u64) -> bool {
        match self.last_eval_ms {
            None => true,
            Some(t) => now_ms.saturating_sub(t) >= self.recheck_ms,
        }
    }

    /// Feed one echo round trip to `key`.
    pub fn record_rtt(&mut self, key: &PublicKey, sample_ms: u64) {
        match self.rtt.get_mut(key) {
            Some(e) => *e = (*e * (EWMA_DIV - 1) + sample_ms) / EWMA_DIV,
            None => {
                self.rtt.insert(*key, sample_ms);
            }
        }
    }

    /// Smoothed RTT to `key`, if measured.
    pub fn rtt(&self, key: &PublicKey) -> Option<u64> {
        self.rtt.get(key).copied()
    }

    /// Record a round trip to the global root.
    pub fn record_root_rtt(&mut self, sample_ms: u64) {
        self.root_rtt = Some(sample_ms);
    }

    /// Latest measured round trip to the global root.
    pub fn root_rtt(&self) -> Option<u64> {
        self.root_rtt
    }

    /// Forget a peer's measurements (after it is dropped for good).
    pub fn forget(&mut self, key: &PublicKey) {
        self.rtt.remove(key);
    }

    /// Group `peers` by root and classify them. Records `now_ms` as the last evaluation.
    /// `own_root` is our tree root, used only to break ties between equal groups.
    pub fn evaluate(&mut self, peers: &[PeerView], own_root: &PublicKey, now_ms: u64) -> Verdict {
        self.last_eval_ms = Some(now_ms);

        let mut counts: BTreeMap<PublicKey, usize> = BTreeMap::new();
        for p in peers {
            if let Some(r) = p.root {
                *counts.entry(r).or_insert(0) += 1;
            }
        }
        // Most peers wins; then our own root; then the smaller key.
        let global_root = counts
            .iter()
            .max_by(|a, b| {
                a.1.cmp(b.1)
                    .then((a.0 == own_root).cmp(&(b.0 == own_root)))
                    .then(b.0.cmp(a.0))
            })
            .map(|(r, _)| *r);

        let mut verdict = Verdict { global_root, ..Verdict::default() };
        let mut ranked: Vec<(u64, usize, PublicKey)> = Vec::new();
        for p in peers {
            match (p.root, global_root) {
                (None, _) | (_, None) => verdict.unknown.push(p.key),
                (Some(r), Some(g)) if r == g => {
                    let rtt = self.rtt(&p.key).unwrap_or(u64::MAX);
                    ranked.push((rtt, p.hops, p.key));
                }
                (Some(_), Some(_)) => verdict.foreign.push(p.key),
            }
        }
        ranked.sort();
        verdict.global = ranked.into_iter().map(|(_, _, k)| k).collect();
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PublicKey {
        [b; 32]
    }

    fn view(k: u8, root: Option<u8>, hops: usize) -> PeerView {
        PeerView { key: key(k), root: root.map(key), hops }
    }

    #[test]
    fn majority_root_is_global_and_others_are_foreign() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        let peers = [view(1, Some(9), 2), view(2, Some(9), 3), view(3, Some(7), 1)];
        let v = q.evaluate(&peers, &key(0), 0);
        assert_eq!(v.global_root, Some(key(9)));
        assert_eq!(v.foreign, vec![key(3)]);
        assert_eq!(v.global.len(), 2);
        assert!(v.unknown.is_empty());
    }

    #[test]
    fn tie_goes_to_own_root_then_smaller_key() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        let tie = [view(1, Some(5), 1), view(2, Some(6), 1)];
        assert_eq!(q.evaluate(&tie, &key(6), 0).global_root, Some(key(6)), "own root wins");
        assert_eq!(q.evaluate(&tie, &key(0), 0).global_root, Some(key(5)), "then smaller key");
    }

    #[test]
    fn unknown_root_is_kept_not_dropped() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        let peers = [view(1, Some(9), 1), view(2, None, 0)];
        let v = q.evaluate(&peers, &key(0), 0);
        assert_eq!(v.unknown, vec![key(2)]);
        assert!(v.foreign.is_empty());
    }

    #[test]
    fn no_known_roots_means_no_global_network() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        let v = q.evaluate(&[view(1, None, 0)], &key(0), 0);
        assert_eq!(v.global_root, None);
        assert!(v.global.is_empty() && v.foreign.is_empty());
        assert_eq!(v.unknown, vec![key(1)]);
    }

    #[test]
    fn global_peers_ranked_by_latency_then_hops() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        q.record_rtt(&key(1), 300);
        q.record_rtt(&key(2), 100);
        // key(3) has no measurement yet: ranked last among equals.
        let peers = [view(1, Some(9), 1), view(2, Some(9), 4), view(3, Some(9), 1)];
        let v = q.evaluate(&peers, &key(0), 0);
        assert_eq!(v.global, vec![key(2), key(1), key(3)]);
    }

    #[test]
    fn due_after_recheck_interval() {
        let mut q = Quality::new(300_000);
        assert!(q.due(0), "never evaluated: due");
        q.evaluate(&[], &key(0), 0);
        assert!(!q.due(299_999));
        assert!(q.due(300_000));
    }

    #[test]
    fn rtt_is_smoothed() {
        let mut q = Quality::new(DEFAULT_RECHECK_MS);
        q.record_rtt(&key(1), 400);
        assert_eq!(q.rtt(&key(1)), Some(400));
        q.record_rtt(&key(1), 800);
        assert_eq!(q.rtt(&key(1)), Some(500)); // (400*3 + 800) / 4
        q.forget(&key(1));
        assert_eq!(q.rtt(&key(1)), None);
    }
}
