//! Peer search policy: when the outbound peer set is too slow, which peer to replace.
//!
//! Two latencies decide, in this order of priority:
//!
//! 1. **Allowed keys.** Round trip to the addresses of the keys given with `--allow`: these are
//!    the clients the node exists for. While at least one has a fresh measurement, the worst of
//!    them is the metric and the root is ignored.
//! 2. **Root.** Round trip to the global root, only when no allowed key has a fresh
//!    measurement (none configured, or all silent). A silent client is not treated as slow: it
//!    may simply be offline.
//!
//! The metric must exceed its limit before a peer is replaced, the first echo of a run is thrown
//! away (it pays for path discovery) and the rest are smoothed, so neither a cold start nor one
//! slow echo costs a peer. The peer to drop is the outbound one with the highest direct
//! latency; the caller leaves out peers it wants to keep (allowed keys connected directly, LAN
//! peers). Replacements are rate limited, and each one is judged afterwards: if the metric did
//! not improve, the next replacement waits twice as long (up to a maximum), so a client that is
//! simply far away does not make the node churn through every public peer.
//!
//! Pure logic on the caller's clock: no I/O and no allocation beyond small maps.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::crypto::PublicKey;

/// Latency to the root above this (ms) is slow.
pub const ROOT_LIMIT_MS: u64 = 200;
/// Latency to an allowed client above this (ms) is slow.
pub const CLIENT_LIMIT_MS: u64 = 150;

/// Smoothing: `new = (old * (DIV - 1) + sample) / DIV`.
const EWMA_DIV: u64 = 4;

/// Tunables; [`Default`] is what `tcp_node` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchConfig {
    pub root_limit_ms: u64,
    pub client_limit_ms: u64,
    /// A sample older than this no longer counts.
    pub sample_ttl_ms: u64,
    /// Samples needed before a latency counts.
    pub min_samples: u32,
    /// Leading samples of a run that are thrown away. The first echo to a node pays for path
    /// discovery and the session handshake (seconds, against a round trip of tens of
    /// milliseconds), so it says nothing about the path and would poison the average and the
    /// baseline the next replacement is judged against.
    pub warmup: u32,
    /// Minimum time between two replacements while replacements help.
    pub min_interval_ms: u64,
    /// Longest wait between replacements after unhelpful ones.
    pub max_interval_ms: u64,
    /// How long after a replacement to wait before judging it.
    pub settle_ms: u64,
    /// The metric must fall by at least this percentage for the replacement to count as helpful.
    pub improve_pct: u64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            root_limit_ms: ROOT_LIMIT_MS,
            client_limit_ms: CLIENT_LIMIT_MS,
            sample_ttl_ms: 45_000,
            min_samples: 2,
            warmup: 1,
            min_interval_ms: 30_000,
            max_interval_ms: 10 * 60_000,
            settle_ms: 60_000,
            improve_pct: 10,
        }
    }
}

/// The latency that currently decides, in ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// Worst smoothed round trip over the allowed keys with a fresh sample.
    Client(u64),
    /// Round trip to the global root.
    Root(u64),
}

impl Metric {
    pub fn rtt(self) -> u64 {
        match self {
            Metric::Client(r) | Metric::Root(r) => r,
        }
    }
}

/// A peer to replace and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub drop: PublicKey,
    pub metric: Metric,
}

/// Verdict on an earlier replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub before: Metric,
    pub after: u64,
    pub helped: bool,
    /// Wait before the next replacement.
    pub next_wait_ms: u64,
}

/// Smoothed latency, time of the last sample, number of samples in the current run.
type Entry = (u64, u64, u32);

#[derive(Debug, Clone, Copy)]
struct Trial {
    at: u64,
    baseline: Metric,
}

/// Search state kept across evaluations.
#[derive(Debug)]
pub struct PeerSearch {
    cfg: SearchConfig,
    /// Allowed key -> (smoothed rtt, time of the last sample, samples since it became fresh).
    clients: BTreeMap<PublicKey, Entry>,
    root: Option<Entry>,
    last_swap: Option<u64>,
    wait_ms: u64,
    trial: Option<Trial>,
    outcome: Option<Outcome>,
}

impl PeerSearch {
    pub fn new(cfg: SearchConfig) -> Self {
        Self {
            cfg,
            clients: BTreeMap::new(),
            root: None,
            last_swap: None,
            wait_ms: cfg.min_interval_ms,
            trial: None,
            outcome: None,
        }
    }

    fn smooth(old: Option<Entry>, sample: u64, now: u64, ttl: u64, warmup: u32) -> Entry {
        match old {
            // A stale average says nothing about the path now: start over.
            Some((avg, at, n)) if now.saturating_sub(at) <= ttl => {
                // While still in the warm-up the earlier samples are replaced, not averaged in.
                let avg = if n <= warmup { sample } else { (avg * (EWMA_DIV - 1) + sample) / EWMA_DIV };
                (avg, now, n.saturating_add(1))
            }
            _ => (sample, now, 1),
        }
    }

    fn counts(&self, e: &Entry, now: u64) -> bool {
        now.saturating_sub(e.1) <= self.cfg.sample_ttl_ms && e.2 >= self.cfg.min_samples.max(self.cfg.warmup + 1)
    }

    /// One echo round trip to the address of an allowed key.
    pub fn record_client(&mut self, key: &PublicKey, sample_ms: u64, now: u64) {
        let e = Self::smooth(self.clients.get(key).copied(), sample_ms, now, self.cfg.sample_ttl_ms, self.cfg.warmup);
        self.clients.insert(*key, e);
    }

    /// One echo round trip to the global root.
    pub fn record_root(&mut self, sample_ms: u64, now: u64) {
        self.root = Some(Self::smooth(self.root, sample_ms, now, self.cfg.sample_ttl_ms, self.cfg.warmup));
    }

    /// Worst smoothed round trip over the allowed keys with a fresh sample.
    pub fn client_rtt(&self, now: u64) -> Option<u64> {
        self.clients.values().filter(|e| self.counts(e, now)).map(|e| e.0).max()
    }

    /// Smoothed round trip to the root, if fresh.
    pub fn root_rtt(&self, now: u64) -> Option<u64> {
        self.root.filter(|e| self.counts(e, now)).map(|e| e.0)
    }

    /// The latency that decides now: allowed keys first, the root only without them.
    pub fn metric(&self, now: u64) -> Option<Metric> {
        self.client_rtt(now).map(Metric::Client).or_else(|| self.root_rtt(now).map(Metric::Root))
    }

    fn limit(&self, m: Metric) -> u64 {
        match m {
            Metric::Client(_) => self.cfg.client_limit_ms,
            Metric::Root(_) => self.cfg.root_limit_ms,
        }
    }

    /// The deciding metric if it is above its limit.
    pub fn slow(&self, now: u64) -> Option<Metric> {
        self.metric(now).filter(|m| m.rtt() > self.limit(*m))
    }

    /// True while the root decides and is slow: the caller should keep probing it.
    pub fn probing_root(&self, now: u64) -> bool {
        matches!(self.slow(now), Some(Metric::Root(_)))
    }

    /// Wait before the next replacement is allowed (ms).
    pub fn wait_ms(&self) -> u64 {
        self.wait_ms
    }

    /// Take the verdict on the last replacement, once it is in.
    pub fn take_outcome(&mut self) -> Option<Outcome> {
        self.outcome.take()
    }

    fn settle_trial(&mut self, now: u64) {
        let Some(t) = self.trial else { return };
        let age = now.saturating_sub(t.at);
        if age < self.cfg.settle_ms {
            return;
        }
        let current = match t.baseline {
            Metric::Client(_) => self.client_rtt(now),
            Metric::Root(_) => self.root_rtt(now),
        };
        let Some(after) = current else {
            // No fresh measurement yet. Give up after a long time rather than judge on nothing.
            if age > self.cfg.settle_ms * 4 {
                self.trial = None;
            }
            return;
        };
        let helped = after * 100 <= t.baseline.rtt() * (100 - self.cfg.improve_pct);
        self.wait_ms = if helped {
            self.cfg.min_interval_ms
        } else {
            (self.wait_ms * 2).min(self.cfg.max_interval_ms)
        };
        self.outcome = Some(Outcome { before: t.baseline, after, helped, next_wait_ms: self.wait_ms });
        self.trial = None;
        // The wait runs from the verdict: the verdict itself comes `settle_ms` after the swap,
        // which would otherwise eat the first doubling.
        self.last_swap = Some(now);
    }

    /// Pick the peer to replace, or `None`.
    ///
    /// `peers`: the outbound peers that may be dropped, with their direct latency if known.
    /// `spare`: a candidate is available to take the freed slot.
    pub fn decide(&mut self, now: u64, peers: &[(PublicKey, Option<u64>)], spare: bool) -> Option<Decision> {
        self.settle_trial(now);
        // A replacement is judged before the next one: otherwise a second peer goes while the
        // first is still settling, and the verdict (and the backoff) never gets a say.
        if self.trial.is_some() {
            return None;
        }
        let metric = self.slow(now)?;
        if self.last_swap.map_or(false, |t| now.saturating_sub(t) < self.wait_ms) || !spare {
            return None;
        }
        let drop = peers
            .iter()
            .filter_map(|(k, r)| r.map(|r| (r, *k)))
            .max_by_key(|(r, _)| *r)
            .map(|(_, k)| k)?;
        Some(Decision { drop, metric })
    }

    /// The caller dropped the peer. Starts the trial and forgets the measurements, which
    /// described the old peer set.
    pub fn swapped(&mut self, now: u64, d: &Decision) {
        self.last_swap = Some(now);
        self.trial = Some(Trial { at: now, baseline: d.metric });
        self.outcome = None;
        self.clients.clear();
        self.root = None;
    }

    /// A healthy path ends any backoff: the next problem is a new one.
    pub fn note_healthy(&mut self, now: u64) {
        if self.trial.is_none() && self.metric(now).is_some() && self.slow(now).is_none() {
            self.wait_ms = self.cfg.min_interval_ms;
        }
    }
}

/// Convenience for callers building the `peers` argument of [`PeerSearch::decide`].
pub fn droppable<'a>(
    outbound: impl Iterator<Item = (PublicKey, Option<u64>)> + 'a,
    keep: &'a [PublicKey],
) -> Vec<(PublicKey, Option<u64>)> {
    outbound.filter(|(k, _)| !keep.contains(k)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Config for tests that feed single samples.
    fn one_sample() -> SearchConfig {
        SearchConfig { min_samples: 1, warmup: 0, ..SearchConfig::default() }
    }

    fn key(n: u8) -> PublicKey {
        [n; 32]
    }

    fn peers() -> Vec<(PublicKey, Option<u64>)> {
        alloc::vec![(key(1), Some(40)), (key(2), Some(180)), (key(3), Some(90)), (key(4), None)]
    }

    #[test]
    fn slow_client_replaces_the_peer_with_the_highest_latency() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 220, 1_000);
        let d = s.decide(2_000, &peers(), true).expect("client is slow");
        assert_eq!(d.drop, key(2));
        assert_eq!(d.metric, Metric::Client(220));
    }

    #[test]
    fn allowed_keys_take_priority_over_the_root() {
        let mut s = PeerSearch::new(one_sample());
        // Root is terrible, the client is fine: the client decides, nothing is replaced.
        s.record_root(900, 1_000);
        s.record_client(&key(9), 60, 1_000);
        assert_eq!(s.metric(2_000), Some(Metric::Client(60)));
        assert!(s.decide(2_000, &peers(), true).is_none());
        assert!(!s.probing_root(2_000));
    }

    #[test]
    fn root_decides_only_without_a_fresh_client_measurement() {
        let mut s = PeerSearch::new(one_sample());
        s.record_root(350, 1_000);
        // No allowed key answered: the root is the fallback.
        let d = s.decide(2_000, &peers(), true).expect("root is slow");
        assert_eq!(d.metric, Metric::Root(350));
        assert!(s.probing_root(2_000));

        // A stale client sample does not count either.
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 40, 1_000);
        s.record_root(350, 60_000);
        assert_eq!(s.metric(60_000), Some(Metric::Root(350)));
    }

    #[test]
    fn worst_client_decides_and_a_single_spike_is_smoothed() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(8), 50, 1_000);
        s.record_client(&key(9), 60, 1_000);
        s.record_client(&key(9), 400, 11_000); // one slow echo: (60*3 + 400) / 4 = 145
        assert_eq!(s.client_rtt(12_000), Some(145));
        assert!(s.decide(12_000, &peers(), true).is_none(), "145 ms is under the limit");
        s.record_client(&key(9), 400, 21_000); // a second one: (145*3 + 400) / 4 = 208
        assert!(s.decide(22_000, &peers(), true).is_some());
    }

    #[test]
    fn nothing_to_do_when_healthy_without_spare_or_without_known_latency() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 80, 1_000);
        assert!(s.decide(2_000, &peers(), true).is_none());

        s.record_client(&key(9), 800, 3_000);
        s.record_client(&key(9), 800, 4_000);
        s.record_client(&key(9), 800, 5_000);
        assert!(s.decide(6_000, &peers(), false).is_none(), "no candidate to put in its place");
        assert!(s.decide(6_000, &[(key(4), None)], true).is_none(), "no peer with a measured latency");
    }

    #[test]
    fn replacements_are_rate_limited_and_judged() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 300, 0);
        let d = s.decide(1_000, &peers(), true).unwrap();
        s.swapped(1_000, &d);
        assert_eq!(s.metric(1_000), None, "old measurements are gone");

        // Fresh but still slow measurements right away: too soon for another replacement.
        s.record_client(&key(9), 300, 15_000);
        assert!(s.decide(16_000, &peers(), true).is_none());

        // After the settle time the replacement is judged: 300 -> 290 is no improvement, so
        // the wait doubles to 60 s, counted from the verdict.
        s.record_client(&key(9), 290, 61_000);
        assert!(s.decide(62_000, &peers(), true).is_none());
        let o = s.take_outcome().expect("verdict");
        assert!(!o.helped);
        assert_eq!(o.next_wait_ms, 60_000);
        assert_eq!(s.wait_ms(), 60_000);
        s.record_client(&key(9), 290, 100_000);
        assert!(s.decide(101_000, &peers(), true).is_none(), "39 s after the verdict");
        s.record_client(&key(9), 290, 121_000);
        assert!(s.decide(123_000, &peers(), true).is_some(), "61 s after the verdict");
    }

    #[test]
    fn no_second_replacement_while_the_first_is_unjudged() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 300, 0);
        let d = s.decide(1_000, &peers(), true).unwrap();
        s.swapped(1_000, &d);
        // Past the 30 s minimum interval but before the 60 s settle time, with fresh slow samples.
        s.record_client(&key(9), 300, 34_000);
        s.record_client(&key(9), 300, 44_000);
        assert!(s.decide(45_000, &peers(), true).is_none(), "the first replacement is still being judged");
        // Once judged (not helpful) the wait runs from the verdict.
        s.record_client(&key(9), 300, 61_000);
        assert!(s.decide(62_000, &peers(), true).is_none());
        assert!(s.take_outcome().is_some());
    }

    #[test]
    fn a_helpful_replacement_resets_the_wait() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 300, 0);
        let d = s.decide(1_000, &peers(), true).unwrap();
        s.swapped(1_000, &d);
        s.record_client(&key(9), 120, 62_000);
        assert!(s.decide(63_000, &peers(), true).is_none(), "120 ms is under the limit");
        let o = s.take_outcome().unwrap();
        assert!(o.helped);
        assert_eq!(s.wait_ms(), 30_000);
    }

    #[test]
    fn backoff_is_capped() {
        let cfg = SearchConfig { max_interval_ms: 100_000, ..one_sample() };
        let mut s = PeerSearch::new(cfg);
        let mut now = 0;
        for _ in 0..6 {
            s.record_client(&key(9), 300, now);
            let d = loop {
                now += 10_000;
                s.record_client(&key(9), 300, now);
                if let Some(d) = s.decide(now, &peers(), true) {
                    break d;
                }
            };
            s.swapped(now, &d);
            now += 61_000;
            s.record_client(&key(9), 300, now);
            let _ = s.decide(now, &peers(), true);
        }
        assert_eq!(s.wait_ms(), 100_000);
    }

    #[test]
    fn healthy_path_ends_the_backoff() {
        let mut s = PeerSearch::new(one_sample());
        s.record_client(&key(9), 300, 0);
        let d = s.decide(1_000, &peers(), true).unwrap();
        s.swapped(1_000, &d);
        s.record_client(&key(9), 300, 62_000);
        let _ = s.decide(63_000, &peers(), true);
        assert_eq!(s.wait_ms(), 60_000);
        // Later the client path is fine.
        s.record_client(&key(9), 50, 200_000);
        s.note_healthy(200_000);
        assert_eq!(s.wait_ms(), 30_000);
    }

    #[test]
    fn the_first_echo_is_thrown_away() {
        let mut s = PeerSearch::new(SearchConfig::default());
        // Path discovery and the handshake inflate the first echo to seconds.
        s.record_client(&key(9), 6_500, 1_000);
        assert_eq!(s.metric(2_000), None, "a single sample never counts");
        assert!(s.decide(2_000, &peers(), true).is_none());
        // The second echo is the first real one and replaces it: 80 ms, not an average with 6500.
        s.record_client(&key(9), 80, 11_000);
        assert_eq!(s.client_rtt(12_000), Some(80));
        assert!(s.decide(12_000, &peers(), true).is_none(), "80 ms is fine");
        // From then on samples are smoothed: (80*3 + 400) / 4 = 160.
        s.record_client(&key(9), 400, 21_000);
        assert_eq!(s.client_rtt(22_000), Some(160));
        // A run that went stale starts over, so an old spike cannot haunt the average.
        s.record_client(&key(9), 7_000, 100_000);
        assert_eq!(s.client_rtt(100_000), None, "fresh run, one sample");
        s.record_client(&key(9), 70, 110_000);
        assert_eq!(s.client_rtt(111_000), Some(70));
    }

    #[test]
    fn a_cold_start_does_not_fake_a_slow_path_or_a_baseline() {
        let mut s = PeerSearch::new(SearchConfig::default());
        // Real round trip 200 ms (over the 150 ms limit); the first echo took 6.5 s.
        s.record_client(&key(9), 6_500, 1_000);
        s.record_client(&key(9), 200, 11_000);
        let d = s.decide(12_000, &peers(), true).expect("200 ms is slow");
        assert_eq!(d.metric, Metric::Client(200), "baseline is the real round trip, not 6500");
        s.swapped(12_000, &d);
        // The new peer is just as slow: the verdict must say so.
        s.record_client(&key(9), 5_000, 20_000);
        s.record_client(&key(9), 200, 30_000);
        s.record_client(&key(9), 200, 70_000);
        assert!(s.decide(72_000, &peers(), true).is_none());
        let o = s.take_outcome().expect("verdict");
        assert!(!o.helped, "200 ms -> 200 ms did not help: {o:?}");
    }

    #[test]
    fn droppable_leaves_out_kept_keys() {
        let kept = [key(2)];
        let v = droppable(peers().into_iter(), &kept);
        assert!(v.iter().all(|(k, _)| *k != key(2)) && v.len() == 3);
    }
}
