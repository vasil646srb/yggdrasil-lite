//! UDP over IPv6 for overlay port forwarding: parse and build datagrams carried in
//! IPv6 packets. The checksum is mandatory for UDP over IPv6 and is always set.

use alloc::vec::Vec;

const IPV6_HDR: usize = 40;
const UDP_HDR: usize = 8;
pub const PROTO_UDP: u8 = 17;

/// A UDP datagram extracted from an IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv6 packet carrying UDP. Returns `None` for other protocols,
/// malformed lengths or a wrong checksum.
pub fn parse(pkt: &[u8]) -> Option<Datagram> {
    if pkt.len() < IPV6_HDR + UDP_HDR || pkt[0] >> 4 != 6 || pkt[6] != PROTO_UDP {
        return None;
    }
    let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if plen < UDP_HDR || IPV6_HDR + plen > pkt.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    let seg = &pkt[IPV6_HDR..IPV6_HDR + plen];
    let ulen = u16::from_be_bytes([seg[4], seg[5]]) as usize;
    // Checksum 0 is invalid over IPv6; a valid segment sums to zero including the field.
    if ulen != plen || u16::from_be_bytes([seg[6], seg[7]]) == 0 || checksum(&src, &dst, seg) != 0 {
        return None;
    }
    Some(Datagram {
        src,
        dst,
        sport: u16::from_be_bytes([seg[0], seg[1]]),
        dport: u16::from_be_bytes([seg[2], seg[3]]),
        payload: seg[UDP_HDR..].to_vec(),
    })
}

/// Build an IPv6 packet carrying one UDP datagram.
pub fn build(src: [u8; 16], dst: [u8; 16], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ulen = UDP_HDR + payload.len();
    let mut seg = Vec::with_capacity(ulen);
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&(ulen as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    let mut sum = checksum(&src, &dst, &seg);
    if sum == 0 {
        sum = 0xffff;
    }
    seg[6..8].copy_from_slice(&sum.to_be_bytes());

    let mut pkt = Vec::with_capacity(IPV6_HDR + ulen);
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&(ulen as u16).to_be_bytes());
    pkt.push(PROTO_UDP);
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
    add(&[0, 0, 0, PROTO_UDP]);
    add(seg);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];

    #[test]
    fn round_trip() {
        let pkt = build(A, B, 5000, 51820, b"hello");
        let dg = parse(&pkt).expect("valid datagram");
        assert_eq!(dg.src, A);
        assert_eq!(dg.dst, B);
        assert_eq!((dg.sport, dg.dport), (5000, 51820));
        assert_eq!(dg.payload, b"hello");
    }

    #[test]
    fn empty_payload_is_valid() {
        let pkt = build(A, B, 1, 2, &[]);
        assert_eq!(parse(&pkt).unwrap().payload, Vec::<u8>::new());
    }

    #[test]
    fn rejects_corruption_and_other_protocols() {
        let mut pkt = build(A, B, 5000, 51820, b"data");
        let last = pkt.len() - 1;
        pkt[last] ^= 0x01;
        assert!(parse(&pkt).is_none());

        let mut tcp_like = build(A, B, 5000, 51820, b"data");
        tcp_like[6] = 6;
        assert!(parse(&tcp_like).is_none());
    }
}
