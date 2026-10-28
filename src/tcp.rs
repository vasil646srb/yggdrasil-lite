//! Minimal TCP server (port 80) that serves one static page over the overlay.
//!
//! Scope: passive open only, one request per connection, the response sent in
//! MSS-sized segments followed by FIN. There is no retransmission and no
//! congestion control, so keep the page small (one segment is 1200 bytes).
//! Traffic from non-allowed keys never reaches this module (the endpoint
//! filters first).

use alloc::format;
use alloc::vec::Vec;

pub const PROTO_TCP: u8 = 6;
pub const HTTP_PORT: u16 = 80;
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const MSS: usize = 1200;
const IPV6_HDR: usize = 40;
const TCP_HDR: usize = 20;
const MAX_CONNS: usize = 8;

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
    pub payload: Vec<u8>,
}

impl Segment {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Parse an IPv6 packet carrying TCP. Returns `None` if it is not TCP or the checksum fails.
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
        payload: seg[doff..].to_vec(),
    })
}

/// Build an IPv6 packet carrying one TCP segment. `mss` adds the MSS option (SYN only).
#[allow(clippy::too_many_arguments)]
pub fn build(
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    mss: bool,
) -> Vec<u8> {
    let opts: Vec<u8> = if mss {
        alloc::vec![2, 4, (MSS >> 8) as u8, MSS as u8]
    } else {
        Vec::new()
    };
    let hdr_len = TCP_HDR + opts.len();
    let mut seg = Vec::with_capacity(hdr_len + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&seq.to_be_bytes());
    seg.extend_from_slice(&ack.to_be_bytes());
    seg.push(((hdr_len / 4) as u8) << 4);
    seg.push(flags);
    seg.extend_from_slice(&65535u16.to_be_bytes()); // window
    seg.extend_from_slice(&[0, 0]); // checksum placeholder
    seg.extend_from_slice(&[0, 0]); // urgent pointer
    seg.extend_from_slice(&opts);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    SynRcvd,
    Established,
    LastAck,
}

struct Conn {
    peer: [u8; 16],
    pport: u16,
    state: State,
    iss: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    req: Vec<u8>,
    responded: bool,
}

/// HTTP server state for all connections on port 80.
pub struct HttpServer {
    page: Vec<u8>,
    conns: Vec<Conn>,
    next_iss: u32,
}

impl HttpServer {
    pub fn new(page: Vec<u8>) -> Self {
        Self { page, conns: Vec::new(), next_iss: 0x1000_0000 }
    }

    pub fn set_page(&mut self, page: Vec<u8>) {
        self.page = page;
    }

    /// Handle one inbound segment for `our`. Returns IPv6 packets to send to the peer.
    pub fn handle(&mut self, our: [u8; 16], seg: &Segment) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if seg.dst != our || seg.dport != HTTP_PORT {
            return out;
        }
        let idx = self.conns.iter().position(|c| c.peer == seg.src && c.pport == seg.sport);

        if seg.has(RST) {
            if let Some(i) = idx {
                self.conns.swap_remove(i);
            }
            return out;
        }

        if seg.has(SYN) && !seg.has(ACK) {
            match idx {
                None => {
                    if self.conns.len() >= MAX_CONNS {
                        return out;
                    }
                    let iss = self.next_iss;
                    self.next_iss = self.next_iss.wrapping_add(64_000);
                    let rcv = seg.seq.wrapping_add(1);
                    self.conns.push(Conn {
                        peer: seg.src,
                        pport: seg.sport,
                        state: State::SynRcvd,
                        iss,
                        snd_nxt: iss.wrapping_add(1),
                        rcv_nxt: rcv,
                        req: Vec::new(),
                        responded: false,
                    });
                    out.push(build(our, seg.src, HTTP_PORT, seg.sport, iss, rcv, SYN | ACK, &[], true));
                }
                Some(i) => {
                    // Retransmitted SYN: repeat the SYN-ACK.
                    let c = &self.conns[i];
                    out.push(build(our, seg.src, HTTP_PORT, seg.sport, c.iss, c.rcv_nxt, SYN | ACK, &[], true));
                }
            }
            return out;
        }

        let Some(i) = idx else { return out };
        let page = &self.page;
        let c = &mut self.conns[i];
        let mut done = false;

        if c.state == State::SynRcvd && seg.has(ACK) && seg.ack == c.snd_nxt {
            c.state = State::Established;
        }

        if c.state == State::LastAck {
            if seg.has(ACK) && seg.ack == c.snd_nxt {
                done = true;
            }
        } else {
            if c.state == State::Established && !seg.payload.is_empty() {
                if seg.seq == c.rcv_nxt {
                    c.req.extend_from_slice(&seg.payload);
                    c.rcv_nxt = c.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                }
                out.push(build(our, c.peer, HTTP_PORT, c.pport, c.snd_nxt, c.rcv_nxt, ACK, &[], false));

                if !c.responded && contains(&c.req, b"\r\n\r\n") {
                    c.responded = true;
                    let response = if c.req.starts_with(b"GET /speed") {
                        speed_response()
                    } else {
                        http_response(page)
                    };
                    for chunk in response.chunks(MSS) {
                        out.push(build(our, c.peer, HTTP_PORT, c.pport, c.snd_nxt, c.rcv_nxt, PSH | ACK, chunk, false));
                        c.snd_nxt = c.snd_nxt.wrapping_add(chunk.len() as u32);
                    }
                    out.push(build(our, c.peer, HTTP_PORT, c.pport, c.snd_nxt, c.rcv_nxt, FIN | ACK, &[], false));
                    c.snd_nxt = c.snd_nxt.wrapping_add(1);
                    c.state = State::LastAck;
                }
            }
            if seg.has(FIN) && c.state != State::LastAck {
                c.rcv_nxt = c.rcv_nxt.wrapping_add(1);
                out.push(build(our, c.peer, HTTP_PORT, c.pport, c.snd_nxt, c.rcv_nxt, ACK, &[], false));
                done = c.responded; // peer closed before we answered: drop the connection
            }
        }

        if done {
            self.conns.swap_remove(i);
        }
        out
    }
}

/// Speed-test body: `SPEED_BYTES` filler bytes, served for `GET /speed`.
const SPEED_BYTES: usize = 256 * 1024;

fn speed_response() -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {SPEED_BYTES}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    let mut out = head.into_bytes();
    out.resize(out.len() + SPEED_BYTES, 0x55);
    out
}

fn http_response(page: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        page.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(page);
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const B: [u8; 16] = [0x02, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 1];

    #[test]
    fn build_then_parse_round_trips() {
        let pkt = build(A, B, 50000, 80, 7, 9, ACK | PSH, b"hi", false);
        let s = parse(&pkt).expect("valid tcp");
        assert_eq!((s.sport, s.dport, s.seq, s.ack), (50000, 80, 7, 9));
        assert!(s.has(ACK) && s.has(PSH));
        assert_eq!(s.payload, b"hi");
    }

    #[test]
    fn handshake_request_and_response() {
        let mut srv = HttpServer::new(b"<html>ok</html>".to_vec());
        let syn = parse(&build(A, B, 50000, 80, 100, 0, SYN, &[], false)).unwrap();
        let synack = srv.handle(B, &syn);
        let sa = parse(&synack[0]).unwrap();
        assert!(sa.has(SYN) && sa.has(ACK));
        assert_eq!(sa.ack, 101);

        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let get = parse(&build(A, B, 50000, 80, 101, sa.seq.wrapping_add(1), ACK | PSH, req, false)).unwrap();
        let out: Vec<Segment> = srv.handle(B, &get).iter().filter_map(|p| parse(p)).collect();
        let body: Vec<u8> = out.iter().flat_map(|s| s.payload.clone()).collect();
        let text = core::str::from_utf8(&body).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.ends_with("<html>ok</html>"));
        assert!(out.iter().any(|s| s.has(FIN)));
    }

    #[test]
    fn speed_endpoint_serves_fixed_size_body() {
        let mut srv = HttpServer::new(b"page".to_vec());
        let syn = parse(&build(A, B, 50001, 80, 100, 0, SYN, &[], false)).unwrap();
        let sa = parse(&srv.handle(B, &syn)[0]).unwrap();
        let req = b"GET /speed?1 HTTP/1.1\r\nHost: x\r\n\r\n";
        let get = parse(&build(A, B, 50001, 80, 101, sa.seq.wrapping_add(1), ACK | PSH, req, false)).unwrap();
        let out: Vec<Segment> = srv.handle(B, &get).iter().filter_map(|p| parse(p)).collect();
        let body: Vec<u8> = out.iter().flat_map(|s| s.payload.clone()).collect();
        let head_end = body.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(body.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(body.len() - head_end, SPEED_BYTES);
        assert!(!body.windows(4).any(|w| w == b"page"));
    }

    #[test]
    fn ignores_other_ports_and_destinations() {
        let mut srv = HttpServer::new(b"x".to_vec());
        let other_port = parse(&build(A, B, 50000, 22, 1, 0, SYN, &[], false)).unwrap();
        assert!(srv.handle(B, &other_port).is_empty());
        let other_host = parse(&build(A, A, 50000, 80, 1, 0, SYN, &[], false)).unwrap();
        assert!(srv.handle(B, &other_host).is_empty());
    }
}
