//! Minimal IPv6 + ICMPv6 echo support for the lite node.
//!
//! Yggdrasil datagrams carry raw IPv6 packets. This module builds and parses
//! the echo request/reply pair so a device can answer pings and send its own.
//! Only the echo subset is handled; everything else is left to the application.

use alloc::vec::Vec;

pub const NEXT_HEADER_ICMPV6: u8 = 58;
pub const ECHO_REQUEST: u8 = 128;
pub const ECHO_REPLY: u8 = 129;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_HEADER_LEN: usize = 8;

/// A parsed ICMPv6 echo message inside an IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echo {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub kind: u8,
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// Parse an IPv6 packet carrying a valid ICMPv6 echo request or reply.
/// Returns `None` for anything else, including bad checksums.
pub fn parse_echo(pkt: &[u8]) -> Option<Echo> {
    if pkt.len() < IPV6_HEADER_LEN + ICMP_HEADER_LEN || pkt[0] >> 4 != 6 {
        return None;
    }
    if pkt[6] != NEXT_HEADER_ICMPV6 {
        return None;
    }
    let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if plen < ICMP_HEADER_LEN || IPV6_HEADER_LEN + plen > pkt.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    let icmp = &pkt[IPV6_HEADER_LEN..IPV6_HEADER_LEN + plen];
    let kind = icmp[0];
    if (kind != ECHO_REQUEST && kind != ECHO_REPLY) || icmp[1] != 0 {
        return None;
    }
    if checksum(&src, &dst, icmp) != 0 {
        return None;
    }
    Some(Echo {
        src,
        dst,
        kind,
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp[ICMP_HEADER_LEN..].to_vec(),
    })
}

/// Build an IPv6 packet with an ICMPv6 echo request or reply.
pub fn build_echo(src: [u8; 16], dst: [u8; 16], kind: u8, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let plen = ICMP_HEADER_LEN + payload.len();
    let mut icmp = Vec::with_capacity(plen);
    icmp.push(kind);
    icmp.push(0);
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let sum = checksum(&src, &dst, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut pkt = Vec::with_capacity(IPV6_HEADER_LEN + plen);
    pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, class 0, flow 0
    pkt.extend_from_slice(&(plen as u16).to_be_bytes());
    pkt.push(NEXT_HEADER_ICMPV6);
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// RFC 4443 checksum over the IPv6 pseudo-header and the ICMPv6 message.
/// For a message with its checksum field filled in, the result is 0 when valid.
fn checksum(src: &[u8; 16], dst: &[u8; 16], icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for c in bytes.chunks(2) {
            let w = if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) } else { (c[0] as u16) << 8 };
            sum = sum.wrapping_add(w as u32);
        }
    };
    add(src);
    add(dst);
    add(&(icmp.len() as u32).to_be_bytes());
    add(&[0, 0, 0, NEXT_HEADER_ICMPV6]);
    add(icmp);
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
    fn request_round_trips_and_checksum_valid() {
        let pkt = build_echo(A, B, ECHO_REQUEST, 0xbeef, 7, b"payload");
        let e = parse_echo(&pkt).expect("valid echo");
        assert_eq!(e.kind, ECHO_REQUEST);
        assert_eq!((e.src, e.dst), (A, B));
        assert_eq!((e.id, e.seq), (0xbeef, 7));
        assert_eq!(e.payload, b"payload");
    }

    #[test]
    fn corrupted_packet_is_rejected() {
        let mut pkt = build_echo(A, B, ECHO_REQUEST, 1, 1, b"x");
        let last = pkt.len() - 1;
        pkt[last] ^= 0xff;
        assert!(parse_echo(&pkt).is_none());
    }

    #[test]
    fn non_icmp_is_ignored() {
        let mut pkt = build_echo(A, B, ECHO_REQUEST, 1, 1, b"x");
        pkt[6] = 17; // UDP
        assert!(parse_echo(&pkt).is_none());
    }
}
