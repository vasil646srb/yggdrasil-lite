//! TCP segment codec: parse and build IPv6 packets carrying TCP.
//!
//! Supports the options the stack in [`crate::tcp_stack`] negotiates: MSS
//! (kind 2) and window scale (kind 3, RFC 7323). Other options are skipped on
//! input and never sent.

use alloc::vec::Vec;

pub const PROTO_TCP: u8 = 6;
pub const HTTP_PORT: u16 = 80;
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
/// Default segment payload size over the overlay (IPv6 packet of 1260 bytes).
pub const MSS: usize = 1200;
const IPV6_HDR: usize = 40;
const TCP_HDR: usize = 20;

/// TCP options carried by a segment (only meaningful on SYN segments).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Maximum segment size the sender can receive.
    pub mss: Option<u16>,
    /// Window scale shift (0..=14).
    pub wscale: Option<u8>,
}

/// A parsed TCP segment inside an IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    /// Raw (unscaled) window field.
    pub window: u16,
    pub opts: Options,
    pub payload: Vec<u8>,
}

impl Segment {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Sequence space the segment occupies: payload plus one each for SYN and FIN.
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + self.has(SYN) as u32 + self.has(FIN) as u32
    }
}

/// Parse an IPv6 packet carrying TCP. Returns `None` if it is not TCP, is
/// truncated, or the checksum fails.
pub fn parse(pkt: &[u8]) -> Option<Segment> {
    if pkt.len() < IPV6_HDR + TCP_HDR || pkt[0] >> 4 != 6 || pkt[6] != PROTO_TCP {
        return None;
    }
    let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if plen < TCP_HDR || IPV6_HDR + plen > pkt.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    let seg = &pkt[IPV6_HDR..IPV6_HDR + plen];
    let doff = ((seg[12] >> 4) as usize) * 4;
    if doff < TCP_HDR || doff > plen || checksum(&src, &dst, seg) != 0 {
        return None;
    }
    Some(Segment {
        src,
        dst,
        sport: u16::from_be_bytes([seg[0], seg[1]]),
        dport: u16::from_be_bytes([seg[2], seg[3]]),
        seq: u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]),
        ack: u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]),
        flags: seg[13],
        window: u16::from_be_bytes([seg[14], seg[15]]),
        opts: parse_options(&seg[TCP_HDR..doff]),
        payload: seg[doff..].to_vec(),
    })
}

fn parse_options(mut b: &[u8]) -> Options {
    let mut o = Options::default();
    while let Some(&kind) = b.first() {
        match kind {
            0 => break,
            1 => b = &b[1..],
            _ => {
                let Some(&len) = b.get(1) else { break };
                let len = len as usize;
                if len < 2 || len > b.len() {
                    break;
                }
                match (kind, len) {
                    (2, 4) => o.mss = Some(u16::from_be_bytes([b[2], b[3]])),
                    (3, 3) => o.wscale = Some(b[2].min(14)),
                    _ => {}
                }
                b = &b[len..];
            }
        }
    }
    o
}

/// Build an IPv6 packet carrying one TCP segment.
#[allow(clippy::too_many_arguments)]
pub fn build(
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    opts: Options,
    payload: &[u8],
) -> Vec<u8> {
    let mut opt_bytes: Vec<u8> = Vec::new();
    if let Some(mss) = opts.mss {
        opt_bytes.extend_from_slice(&[2, 4]);
        opt_bytes.extend_from_slice(&mss.to_be_bytes());
    }
    if let Some(ws) = opts.wscale {
        opt_bytes.extend_from_slice(&[1, 3, 3, ws]);
    }
    let hdr_len = TCP_HDR + opt_bytes.len();
    let mut seg = Vec::with_capacity(hdr_len + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(((hdr_len / 4) as u8) << 4);
    seg.push(flags);
    seg.extend_from_slice(&window.to_be_bytes());
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(&opt_bytes);
    seg.extend_from_slice(payload);
    let sum = checksum(&src, &dst, &seg);
    seg[16..18].copy_from_slice(&sum.to_be_bytes());

    let mut pkt = Vec::with_capacity(IPV6_HDR + seg.len());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&(seg.len() as u16).to_be_bytes());
    pkt.push(PROTO_TCP);
    pkt.push(64);
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&seg);
    pkt
}

fn checksum(src: &[u8; 16], dst: &[u8; 16], seg: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for c in bytes.chunks(2) {
            let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { (c[0] as u16) << 8 };
            sum = sum.wrapping_add(w as u32);
        }
    };
    add(src);
    add(dst);
    add(&(seg.len() as u32).to_be_bytes());
    add(&[0, 0, 0, PROTO_TCP]);
    add(seg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const B: [u8; 16] = [0x02, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 1];

    #[test]
    fn build_then_parse_round_trips() {
        let pkt = build(A, B, 50000, 80, 7, 9, ACK | PSH, 1234, Options::default(), b"hi");
        let s = parse(&pkt).expect("valid tcp");
        assert_eq!((s.sport, s.dport, s.seq, s.ack, s.window), (50000, 80, 7, 9, 1234));
        assert!(s.has(ACK) && s.has(PSH));
        assert_eq!(s.payload, b"hi");
        assert_eq!(s.opts, Options::default());
    }

    #[test]
    fn options_round_trip() {
        let opts = Options { mss: Some(1200), wscale: Some(3) };
        let pkt = build(A, B, 1, 2, 0, 0, SYN, 65535, opts, &[]);
        let s = parse(&pkt).unwrap();
        assert_eq!(s.opts, opts);
        assert_eq!(s.seq_len(), 1);
    }

    #[test]
    fn corrupted_checksum_is_rejected() {
        let mut pkt = build(A, B, 1, 2, 0, 0, ACK, 100, Options::default(), b"data");
        let last = pkt.len() - 1;
        pkt[last] ^= 0xff;
        assert!(parse(&pkt).is_none());
    }
}
