//! Crypto-key routing (CKR), compatible with Yggdrasil-ng and yggdrasilckr: plain IPv4 and
//! internet IPv6 packets travel inside Yggdrasil traffic to a node's key (same `0x01` frame).
//!
//! Exit side (`--ckr-tun NAME`): packets from allowed keys go out of a TUN interface; the
//! system NATs them to the internet (the caller sets up forwarding and MASQUERADE). Clients
//! choose their own tunnel addresses (Yggdrasil-ng's `ip_addresses`), so the exit gives every
//! key its own address in [`POOL4`] / [`POOL6`] and rewrites the source on the way in and the
//! destination on the way back — the kernel never sees two clients with the same address.
//! IPv6 is accepted only from the key's own Yggdrasil address (like Yggdrasil-ng's
//! `yggdrasil_routing`), IPv4 from any address the client picked.
//!
//! TCP SYNs get their MSS clamped to [`MSS`] both ways: a Yggdrasil-ng client's TUN has a
//! 65535-byte MTU, the internet does not.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use yggdrasil_lite::address::addr_for_key;
use yggdrasil_lite::PublicKey;

/// The exit's client pool: 10.77.0.0/16 (the exit itself is 10.77.0.1).
pub const POOL4: [u8; 2] = [10, 77];
/// The exit's IPv6 pool: fd77:7967:6772::/64, a ULA (the exit itself is ::1).
pub const POOL6: [u8; 8] = [0xfd, 0x77, 0x79, 0x67, 0x67, 0x72, 0, 0];
/// TCP MSS for tunnelled connections (fits a 1500-byte internet path with room to spare).
pub const MSS: u16 = 1400;
/// A client's slot is reused after this long without packets (when the pool runs out).
const IDLE: Duration = Duration::from_secs(1800);
/// Slots 2..=65534 (10.77.0.2 .. 10.77.255.254).
const SLOTS: u32 = 65533;

struct Slot {
    idx: u16,
    /// The client's own tunnel IPv4 address (last seen), restored on replies.
    v4: [u8; 4],
    last: Instant,
}

/// What [`Exit::inbound`] did with a client's packet.
#[derive(Debug, PartialEq, Eq)]
pub enum In {
    Sent,
    NotAllowed,
    BadSource,
    Malformed,
    /// Internet IPv6 while the exit has none: answer with [`unreachable6`].
    NoIpv6,
}

pub struct Exit {
    allow_path: Option<String>,
    allow_any: bool,
    allow: HashSet<[u8; 16]>,
    allow_text: Option<String>,
    last_read: Option<Instant>,
    by_key: HashMap<PublicKey, Slot>,
    by_idx: HashMap<u16, PublicKey>,
    next: u32,
    /// The exit routes IPv6 to the internet (else IPv6 packets get an ICMPv6 error back).
    ipv6: bool,
}

impl Exit {
    /// `allow_path`: one entry per line, re-read every few seconds: `*` (anyone: a public
    /// exit) or Yggdrasil addresses of devices with access. No file: nobody.
    pub fn new(allow_path: Option<String>, ipv6: bool) -> Exit {
        Exit {
            allow_path,
            allow_any: false,
            allow: HashSet::new(),
            allow_text: None,
            last_read: None,
            by_key: HashMap::new(),
            by_idx: HashMap::new(),
            next: 0,
            ipv6,
        }
    }

    /// Re-read the allow list (at most every 3 s). Returns a line to log when it changed.
    pub fn reload(&mut self) -> Option<String> {
        if self.last_read.is_some_and(|t| t.elapsed() < Duration::from_secs(3)) {
            return None;
        }
        self.last_read = Some(Instant::now());
        let text = self.allow_path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
        if self.allow_text.as_deref() == Some(text.as_str()) {
            return None;
        }
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        self.allow_any = lines.contains(&"*");
        self.allow = lines.iter().filter_map(|l| l.parse::<Ipv6Addr>().ok()).map(|a| a.octets()).collect();
        self.allow_text = Some(text);
        Some(if self.allow_any { "ckr: exit open to everyone".into() } else { format!("ckr: exit open to {} device(s)", self.allow.len()) })
    }

    fn allowed(&self, key: &PublicKey) -> bool {
        self.allow_any || self.allow.contains(&addr_for_key(key).0)
    }

    fn slot(&mut self, key: &PublicKey, v4: Option<[u8; 4]>) -> u16 {
        let now = Instant::now();
        if let Some(s) = self.by_key.get_mut(key) {
            s.last = now;
            if let Some(a) = v4 {
                s.v4 = a;
            }
            return s.idx;
        }
        // A free slot, else the one idle the longest (beyond IDLE).
        let idx = if (self.by_idx.len() as u32) < SLOTS {
            loop {
                let i = (self.next % SLOTS + 2) as u16;
                self.next = self.next.wrapping_add(1);
                if !self.by_idx.contains_key(&i) {
                    break i;
                }
            }
        } else {
            let (old, idx) = self
                .by_key
                .iter()
                .filter(|(_, s)| now.duration_since(s.last) >= IDLE)
                .min_by_key(|(_, s)| s.last)
                .map(|(k, s)| (*k, s.idx))
                .unwrap_or_else(|| {
                    let (k, s) = self.by_key.iter().min_by_key(|(_, s)| s.last).unwrap();
                    (*k, s.idx)
                });
            self.by_key.remove(&old);
            idx
        };
        self.by_idx.insert(idx, *key);
        self.by_key.insert(*key, Slot { idx, v4: v4.unwrap_or([0; 4]), last: now });
        idx
    }

    /// A packet from `key` (unframed). On success `pkt` is rewritten for the TUN.
    pub fn inbound(&mut self, key: &PublicKey, pkt: &mut [u8]) -> In {
        if !self.allowed(key) {
            return In::NotAllowed;
        }
        match pkt.first().map(|b| b >> 4) {
            Some(4) => {
                let Some(ihl) = v4_header(pkt) else { return In::Malformed };
                let mut src = [0u8; 4];
                src.copy_from_slice(&pkt[12..16]);
                let idx = self.slot(key, Some(src));
                set_v4_addr(pkt, ihl, 12, &pool4(idx));
                clamp_mss(pkt, 4, ihl);
                In::Sent
            }
            Some(6) => {
                if pkt.len() < 40 {
                    return In::Malformed;
                }
                if pkt[8..24] != addr_for_key(key).0[..] {
                    return In::BadSource;
                }
                if !self.ipv6 {
                    return In::NoIpv6;
                }
                let idx = self.slot(key, None);
                set_v6_addr(pkt, 8, &pool6(idx));
                clamp_mss(pkt, 6, 40);
                In::Sent
            }
            _ => In::Malformed,
        }
    }

    /// A packet read from the TUN: the client it belongs to, with `pkt` rewritten for it.
    pub fn outbound(&mut self, pkt: &mut [u8]) -> Option<PublicKey> {
        match pkt.first().map(|b| b >> 4) {
            Some(4) => {
                let ihl = v4_header(pkt)?;
                if pkt[16..18] != POOL4 {
                    return None;
                }
                let idx = u16::from_be_bytes([pkt[18], pkt[19]]);
                let key = *self.by_idx.get(&idx)?;
                let s = self.by_key.get_mut(&key)?;
                s.last = Instant::now();
                let orig = s.v4;
                set_v4_addr(pkt, ihl, 16, &orig);
                clamp_mss(pkt, 4, ihl);
                icmp4_error_inner(pkt, ihl, &pool4(idx), &orig);
                Some(key)
            }
            Some(6) => {
                if pkt.len() < 40 || pkt[24..32] != POOL6 {
                    return None;
                }
                let idx = u16::from_be_bytes([pkt[38], pkt[39]]);
                if pkt[32..38] != [0; 6] {
                    return None;
                }
                let key = *self.by_idx.get(&idx)?;
                self.by_key.get_mut(&key)?.last = Instant::now();
                let ygg = addr_for_key(&key).0;
                set_v6_addr(pkt, 24, &ygg);
                clamp_mss(pkt, 6, 40);
                icmp6_error_inner(pkt, &pool6(idx), &ygg);
                Some(key)
            }
            _ => None,
        }
    }

    pub fn clients(&self) -> usize {
        self.by_key.len()
    }
}

/// Client side: may this packet read from our TUN go to the exit? IPv4 (any source: the
/// tunnel address is ours to pick) or IPv6 from our Yggdrasil address to the internet.
pub fn client_packet(pkt: &[u8], ours: &[u8; 16]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => v4_header(pkt).is_some(),
        Some(6) => pkt.len() >= 40 && pkt[8..24] == ours[..] && !matches!(pkt[24], 0x02 | 0x03),
        _ => false,
    }
}

fn pool4(idx: u16) -> [u8; 4] {
    let i = idx.to_be_bytes();
    [POOL4[0], POOL4[1], i[0], i[1]]
}

fn pool6(idx: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&POOL6);
    a[14..].copy_from_slice(&idx.to_be_bytes());
    a
}

/// Header length of a sane IPv4 packet.
fn v4_header(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    (ihl >= 20 && pkt.len() >= ihl).then_some(ihl)
}

/// Ones' complement sum of 16-bit words (odd tail padded), not folded.
fn sum16(data: &[u8]) -> u32 {
    let mut s = 0u32;
    let mut c = data.chunks_exact(2);
    for w in &mut c {
        s = s.wrapping_add(u16::from_be_bytes([w[0], w[1]]) as u32);
    }
    if let [b] = c.remainder() {
        s = s.wrapping_add((*b as u32) << 8);
    }
    s
}

fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

/// RFC 1624: update the checksum at `pkt[at..at+2]` for `old` bytes replaced by `new`.
fn adjust(pkt: &mut [u8], at: usize, old: &[u8], new: &[u8]) {
    if pkt.len() < at + 2 {
        return;
    }
    let hc = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
    let mut s = (!hc) as u32;
    for w in old.chunks(2) {
        s += (!u16::from_be_bytes([w[0], *w.get(1).unwrap_or(&0)])) as u32;
    }
    s += sum16(new);
    let v = !fold(s);
    pkt[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// Where the transport checksum of an unfragmented first piece lives: (offset, is UDP).
fn l4_checksum(pkt: &[u8], proto: u8, l4: usize) -> Option<(usize, bool)> {
    let (off, udp) = match proto {
        6 => (16, false),
        17 => (6, true),
        58 => (2, false), // ICMPv6 has a pseudo-header too
        _ => return None,
    };
    (pkt.len() >= l4 + off + 2).then_some((l4 + off, udp))
}

/// Replace the IPv4 source (`at` = 12) or destination (16) and fix the checksums.
fn set_v4_addr(pkt: &mut [u8], ihl: usize, at: usize, new: &[u8; 4]) {
    let old: [u8; 4] = pkt[at..at + 4].try_into().unwrap();
    if old == *new {
        return;
    }
    pkt[at..at + 4].copy_from_slice(new);
    adjust(pkt, 10, &old, new);
    let first = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff == 0;
    if first && pkt[9] != 58 {
        if let Some((c, udp)) = l4_checksum(pkt, pkt[9], ihl) {
            if !(udp && pkt[c] == 0 && pkt[c + 1] == 0) {
                adjust(pkt, c, &old, new);
            }
        }
    }
}

/// Replace the IPv6 source (`at` = 8) or destination (24) and fix the transport checksum.
fn set_v6_addr(pkt: &mut [u8], at: usize, new: &[u8; 16]) {
    let old: [u8; 16] = pkt[at..at + 16].try_into().unwrap();
    pkt[at..at + 16].copy_from_slice(new);
    if let Some((c, _)) = l4_checksum(pkt, pkt[6], 40) {
        adjust(pkt, c, &old, new);
    }
}

/// Clamp the MSS option of a TCP SYN starting at `l4`.
fn clamp_mss(pkt: &mut [u8], version: u8, l4: usize) {
    let proto = if version == 4 { pkt[9] } else { pkt[6] };
    if proto != 6 || pkt.len() < l4 + 20 {
        return;
    }
    if version == 4 && u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff != 0 {
        return;
    }
    if pkt[l4 + 13] & 0x02 == 0 {
        return;
    }
    let end = (l4 + (pkt[l4 + 12] >> 4) as usize * 4).min(pkt.len());
    let mut i = l4 + 20;
    while i < end {
        match pkt[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = pkt.get(i + 1) else { break };
                if len < 2 {
                    break;
                }
                if kind == 2 && len == 4 && i + 4 <= end {
                    let mss = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
                    if mss > MSS {
                        let old = [pkt[i + 2], pkt[i + 3]];
                        pkt[i + 2..i + 4].copy_from_slice(&MSS.to_be_bytes());
                        let new = MSS.to_be_bytes();
                        adjust(pkt, l4 + 16, &old, &new);
                    }
                    return;
                }
                i += len as usize;
            }
        }
    }
}

/// ICMPv4 errors carry the start of our packet: put the client's address back in it (so its
/// system matches "fragmentation needed" and the like), then recompute the ICMP checksum.
fn icmp4_error_inner(pkt: &mut [u8], ihl: usize, pool: &[u8; 4], orig: &[u8; 4]) {
    if pkt[9] != 1 || pkt.len() < ihl + 8 + 20 || !matches!(pkt[ihl], 3 | 11 | 12) {
        return;
    }
    let inner = ihl + 8;
    if pkt[inner] >> 4 != 4 || pkt[inner + 12..inner + 16] != pool[..] {
        return;
    }
    pkt[inner + 12..inner + 16].copy_from_slice(orig);
    adjust(pkt, inner + 10, pool, orig);
    pkt[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let c = !fold(sum16(&pkt[ihl..]));
    pkt[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
}

/// ICMPv6 "no route to destination" for a client's IPv6 packet, from its destination back to
/// it. An exit without IPv6 used to drop such packets silently: the client's TUN routes all
/// IPv6, Android then reports IPv6 as working, and apps that try it first (YouTube, Twitch)
/// waited for their timeouts while the browser fell back to IPv4 at once. The error makes
/// every client's connect fail right away, and the apps use IPv4.
pub fn unreachable6(pkt: &[u8]) -> Option<Vec<u8>> {
    // Never answer an ICMPv6 error (or a packet too short to be IPv6) with another.
    if pkt.len() < 40 || pkt[0] >> 4 != 6 || (pkt[6] == 58 && pkt.get(40).is_some_and(|t| *t < 128)) {
        return None;
    }
    let quote = &pkt[..pkt.len().min(1280 - 48)];
    let mut p = vec![0u8; 48 + quote.len()];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&((8 + quote.len()) as u16).to_be_bytes());
    p[6] = 58;
    p[7] = 64;
    p[8..24].copy_from_slice(&pkt[24..40]);
    p[24..40].copy_from_slice(&pkt[8..24]);
    p[40] = 1; // destination unreachable
    p[41] = 0; // no route to destination
    p[48..].copy_from_slice(quote);
    let c = icmp6_checksum(&p);
    p[42..44].copy_from_slice(&c.to_be_bytes());
    Some(p)
}

/// ICMPv6 errors: the same, with the pseudo-header checksum.
fn icmp6_error_inner(pkt: &mut [u8], pool: &[u8; 16], ygg: &[u8; 16]) {
    if pkt[6] != 58 || pkt.len() < 40 + 8 + 40 || !matches!(pkt[40], 1..=4) {
        return;
    }
    let inner = 48;
    if pkt[inner] >> 4 != 6 || pkt[inner + 8..inner + 24] != pool[..] {
        return;
    }
    pkt[inner + 8..inner + 24].copy_from_slice(ygg);
    pkt[42..44].copy_from_slice(&[0, 0]);
    let c = icmp6_checksum(pkt);
    pkt[42..44].copy_from_slice(&c.to_be_bytes());
}

fn icmp6_checksum(pkt: &[u8]) -> u16 {
    let body = &pkt[40..];
    let mut s = sum16(&pkt[8..40]);
    s = s.wrapping_add(body.len() as u32 >> 16).wrapping_add(body.len() as u32 & 0xffff);
    s = s.wrapping_add(58);
    s = s.wrapping_add(sum16(body));
    !fold(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> PublicKey {
        let mut k = [0u8; 32];
        k[0] = b;
        k[31] = 7;
        k
    }

    fn v4_checksum_ok(p: &[u8]) -> bool {
        let ihl = (p[0] & 0xf) as usize * 4;
        fold(sum16(&p[..ihl])) == 0xffff
    }

    /// TCP/UDP checksum over the IPv4 pseudo-header is valid.
    fn l4_ok_v4(p: &[u8]) -> bool {
        let ihl = (p[0] & 0xf) as usize * 4;
        let body = &p[ihl..];
        let mut s = sum16(&p[12..20]);
        s += p[9] as u32 + body.len() as u32;
        s += sum16(body);
        fold(s) == 0xffff
    }

    #[test]
    fn ipv6_without_ipv6_exit_gets_an_unreachable() {
        let k = key(9);
        let mut e = Exit::new(None, false);
        e.allow_any = true;
        let ygg = addr_for_key(&k).0;
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = 6;
        p[8..24].copy_from_slice(&ygg);
        p[24] = 0x2a;
        assert_eq!(e.inbound(&k, &mut p.clone()), In::NoIpv6);
        let r = unreachable6(&p).unwrap();
        assert!(l4_ok_v6(&r));
        assert_eq!(&r[24..40], &ygg[..]);
        assert_eq!(&r[8..24], &p[24..40]);
        assert_eq!((r[40], r[41]), (1, 0));
        assert_eq!(&r[48..], &p[..]);
        // No error about an error.
        assert!(unreachable6(&r).is_none());
    }

    fn l4_ok_v6(p: &[u8]) -> bool {
        let body = &p[40..];
        let mut s = sum16(&p[8..40]);
        s += p[6] as u32 + body.len() as u32;
        s += sum16(body);
        fold(s) == 0xffff
    }

    fn fix_v4(p: &mut [u8]) {
        let ihl = (p[0] & 0xf) as usize * 4;
        p[10..12].copy_from_slice(&[0, 0]);
        let c = !fold(sum16(&p[..ihl]));
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let c_at = ihl + if p[9] == 6 { 16 } else { 6 };
        p[c_at..c_at + 2].copy_from_slice(&[0, 0]);
        let body = &p[ihl..];
        let s = sum16(&p[12..20]) + p[9] as u32 + body.len() as u32 + sum16(body);
        let c = !fold(s);
        p[c_at..c_at + 2].copy_from_slice(&c.to_be_bytes());
    }

    /// IPv4 TCP SYN 10.99.0.2:40000 -> 93.184.216.34:80 with MSS 65495.
    fn syn4() -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 44, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 99, 0, 2, 93, 184, 216, 34];
        p.extend_from_slice(&[0x9c, 0x40, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(&[2, 4, 0xff, 0xd7]);
        fix_v4(&mut p);
        p
    }

    fn exit_any() -> Exit {
        let mut e = Exit::new(None, true);
        e.allow_any = true;
        e.last_read = Some(Instant::now());
        e
    }

    #[test]
    fn ipv4_round_trip_keeps_checksums_and_clamps_mss() {
        let mut e = exit_any();
        let k = key(1);
        let mut p = syn4();
        assert_eq!(e.inbound(&k, &mut p), In::Sent);
        assert_eq!(&p[12..16], &[10, 77, 0, 2]);
        assert_eq!(u16::from_be_bytes([p[42], p[43]]), MSS);
        assert!(v4_checksum_ok(&p) && l4_ok_v4(&p));
        // The reply: swap addresses and ports.
        let mut r = p.clone();
        r[12..16].copy_from_slice(&[93, 184, 216, 34]);
        r[16..20].copy_from_slice(&[10, 77, 0, 2]);
        r[20..22].copy_from_slice(&[0, 80]);
        r[22..24].copy_from_slice(&[0x9c, 0x40]);
        fix_v4(&mut r);
        assert_eq!(e.outbound(&mut r), Some(k));
        assert_eq!(&r[16..20], &[10, 99, 0, 2]);
        assert!(v4_checksum_ok(&r) && l4_ok_v4(&r));
    }

    #[test]
    fn two_clients_with_the_same_address_get_different_slots() {
        let mut e = exit_any();
        let (mut a, mut b) = (syn4(), syn4());
        e.inbound(&key(1), &mut a);
        e.inbound(&key(2), &mut b);
        assert_ne!(a[12..16], b[12..16]);
        assert_eq!(e.clients(), 2);
    }

    #[test]
    fn closed_exit_and_foreign_ipv6_sources_are_refused() {
        let mut e = Exit::new(None, true);
        e.last_read = Some(Instant::now());
        assert_eq!(e.inbound(&key(1), &mut syn4()), In::NotAllowed);
        e.allow.insert(addr_for_key(&key(1)).0);
        assert_eq!(e.inbound(&key(1), &mut syn4()), In::Sent);
        let mut p6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        p6.extend_from_slice(&addr_for_key(&key(2)).0); // not key 1's address
        p6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p6.extend_from_slice(&[0, 53, 0, 53, 0, 8, 0, 0]);
        assert_eq!(e.inbound(&key(1), &mut p6), In::BadSource);
    }

    #[test]
    fn ipv6_udp_round_trip() {
        let mut e = exit_any();
        let k = key(3);
        let ygg = addr_for_key(&k).0;
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut p = vec![0x60, 0, 0, 0, 0, 12, 17, 64];
        p.extend_from_slice(&ygg);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&[0x30, 0x39, 0, 53, 0, 12, 0, 0, 1, 2, 3, 4]);
        let c = {
            let body = &p[40..];
            !fold(sum16(&p[8..40]) + 17 + body.len() as u32 + sum16(body))
        };
        p[46..48].copy_from_slice(&c.to_be_bytes());
        assert!(l4_ok_v6(&p));
        assert_eq!(e.inbound(&k, &mut p), In::Sent);
        assert_eq!(&p[8..16], &POOL6);
        assert!(l4_ok_v6(&p));
        let mut r = p.clone();
        let pool = p[8..24].to_vec();
        r[8..24].copy_from_slice(&dst);
        r[24..40].copy_from_slice(&pool);
        assert_eq!(e.outbound(&mut r), Some(k));
        assert_eq!(&r[24..40], &ygg);
        assert!(l4_ok_v6(&r));
    }

    #[test]
    fn icmp_frag_needed_reaches_the_client_with_its_address() {
        let mut e = exit_any();
        let k = key(4);
        let mut p = syn4();
        e.inbound(&k, &mut p);
        // Router 198.51.100.1 -> 10.77.0.2: type 3 code 4, quoting the rewritten packet.
        let mut r = vec![0x45, 0, 0, 0, 0, 2, 0, 0, 64, 1, 0, 0, 198, 51, 100, 1, 10, 77, 0, 2];
        r.extend_from_slice(&[3, 4, 0, 0, 0, 0, 0x05, 0xdc]);
        r.extend_from_slice(&p[..28]);
        let len = r.len() as u16;
        r[2..4].copy_from_slice(&len.to_be_bytes());
        let c = !fold(sum16(&r[..20]));
        r[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(e.outbound(&mut r), Some(k));
        assert_eq!(&r[16..20], &[10, 99, 0, 2]);
        assert_eq!(&r[28 + 12..28 + 16], &[10, 99, 0, 2]);
        assert!(v4_checksum_ok(&r));
        assert_eq!(fold(sum16(&r[20..])), 0xffff);
        assert!(v4_checksum_ok(&r[28..]));
    }

    #[test]
    fn client_sends_ipv4_and_internet_ipv6_only() {
        let ours = addr_for_key(&key(5)).0;
        assert!(client_packet(&syn4(), &ours));
        let mut p6 = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
        p6.extend_from_slice(&ours);
        p6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(client_packet(&p6, &ours));
        p6[24] = 0x02; // a Yggdrasil address: the ordinary bridge, not the exit
        assert!(!client_packet(&p6, &ours));
    }
}
