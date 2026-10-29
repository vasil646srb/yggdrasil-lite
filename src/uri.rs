//! Peer URIs for the two stream transports the lite node speaks.
//!
//! `tcp://host:port` and `tls://host:port`, where `host` is an IPv4 address, a
//! bracketed IPv6 address (`tcp://[2001:db8::1]:1514`) or a DNS name. The scheme
//! only selects whether the connection is wrapped in TLS by the caller; the
//! handshake that follows is the same. Other schemes (`ws://`, `quic://`, …) are rejected.
//!
//! The only query option accepted is `?key=<64 hex chars>`: the peer's expected
//! Ed25519 public key (as published in public peer lists). When present, the
//! handshake must present exactly that key. Any other option (for example
//! `password=`) is rejected, since the lite node does not support it.

use alloc::string::{String, ToString};
use core::fmt;

/// A parsed `tcp://` or `tls://` peer endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpPeerUri {
    /// Host without brackets (IPv6 literal stored without `[`/`]`).
    host: String,
    port: u16,
    /// Expected peer public key, if known.
    key: Option<[u8; 32]>,
    /// `tls://` scheme: the caller wraps the stream in TLS before the handshake.
    tls: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    /// Scheme is not `tcp://`.
    UnsupportedScheme,
    /// No host part.
    EmptyHost,
    /// Missing or non-numeric port.
    BadPort,
    /// Path, fragment, or a query option the lite node does not support.
    UnsupportedOption,
    /// `key=` present but not 64 hex characters.
    BadKey,
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme => write!(f, "only tcp:// peers are supported"),
            Self::EmptyHost => write!(f, "empty host"),
            Self::BadPort => write!(f, "missing or invalid port"),
            Self::UnsupportedOption => write!(f, "unsupported path or query option"),
            Self::BadKey => write!(f, "key must be 64 hex characters"),
        }
    }
}

impl TcpPeerUri {
    /// Parse `tcp://host:port[?key=<hex>]` or `tls://...` (case-insensitive scheme, surrounding whitespace ignored).
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let s = input.trim();
        let (rest, tls) = if let Some(r) = strip_prefix_ci(s, "tcp://") {
            (r, false)
        } else if let Some(r) = strip_prefix_ci(s, "tls://") {
            (r, true)
        } else {
            return Err(UriError::UnsupportedScheme);
        };
        if rest.contains('/') || rest.contains('#') {
            return Err(UriError::UnsupportedOption);
        }

        let (addr, query) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };

        let (host, port_str) = if let Some(v6) = addr.strip_prefix('[') {
            let end = v6.find(']').ok_or(UriError::EmptyHost)?;
            let host = &v6[..end];
            let port = v6[end + 1..].strip_prefix(':').ok_or(UriError::BadPort)?;
            (host, port)
        } else {
            let idx = addr.rfind(':').ok_or(UriError::BadPort)?;
            (&addr[..idx], &addr[idx + 1..])
        };

        if host.is_empty() {
            return Err(UriError::EmptyHost);
        }
        let port: u16 = port_str.parse().map_err(|_| UriError::BadPort)?;
        if port == 0 {
            return Err(UriError::BadPort);
        }

        let mut key = None;
        if let Some(q) = query {
            for param in q.split('&').filter(|p| !p.is_empty()) {
                match param.split_once('=') {
                    Some(("key", v)) => key = Some(parse_hex32(v).ok_or(UriError::BadKey)?),
                    _ => return Err(UriError::UnsupportedOption),
                }
            }
        }

        Ok(Self {
            host: host.to_string(),
            port,
            key,
            tls,
        })
    }

    /// `tls://` endpoint: the caller must wrap the connection in TLS.
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Expected peer public key, if the URI or the peer list specified one.
    pub fn expected_key(&self) -> Option<[u8; 32]> {
        self.key
    }

    /// Same endpoint with an expected key attached.
    pub fn with_key(mut self, key: [u8; 32]) -> Self {
        self.key = Some(key);
        self
    }

    /// `host:port` (IPv6 wrapped in brackets), suitable for socket connect APIs.
    pub fn host_port(&self) -> String {
        if self.host.contains(':') {
            alloc::format!("[{}]:{}", self.host, self.port)
        } else {
            alloc::format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for TcpPeerUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", if self.tls { "tls" } else { "tcp" }, self.host_port())?;
        if let Some(k) = self.key {
            write!(f, "?key={}", hex32(&k))?;
        }
        Ok(())
    }
}

/// Parse exactly 64 hex characters into 32 bytes.
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in b.chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex32(k: &[u8; 32]) -> String {
    k.iter().map(|b| alloc::format!("{:02x}", b)).collect()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "2a038bfcc812ef82f0e4a936ccc065553b5beab0e566e2c48830eede873fdcc3";

    #[test]
    fn parses_ipv4_dns_and_ipv6() {
        let a = TcpPeerUri::parse("tcp://1.2.3.4:1514").unwrap();
        assert_eq!(a.host_port(), "1.2.3.4:1514");
        let b = TcpPeerUri::parse("TCP://peer.example.org:9001").unwrap();
        assert_eq!(b.host(), "peer.example.org");
        let c = TcpPeerUri::parse("tcp://[2001:db8::1]:1514").unwrap();
        assert_eq!(c.host(), "2001:db8::1");
        assert_eq!(c.to_string(), "tcp://[2001:db8::1]:1514");
    }

    #[test]
    fn parses_expected_key() {
        let u = TcpPeerUri::parse(&alloc::format!("tcp://1.2.3.4:1514?key={K}")).unwrap();
        assert_eq!(u.expected_key().unwrap()[0], 0x2a);
        assert_eq!(u.to_string(), alloc::format!("tcp://1.2.3.4:1514?key={K}"));
        assert_eq!(TcpPeerUri::parse("tcp://1.2.3.4:1514?key=zz"), Err(UriError::BadKey));
    }

    #[test]
    fn rejects_non_tcp_and_bad_forms() {
        assert_eq!(TcpPeerUri::parse("quic://1.2.3.4:443"), Err(UriError::UnsupportedScheme));
        assert!(TcpPeerUri::parse("tls://1.2.3.4:443").unwrap().is_tls());
        assert_eq!(TcpPeerUri::parse("ws://x:80"), Err(UriError::UnsupportedScheme));
        assert_eq!(TcpPeerUri::parse("tcp://1.2.3.4"), Err(UriError::BadPort));
        assert_eq!(TcpPeerUri::parse("tcp://1.2.3.4:0"), Err(UriError::BadPort));
        assert_eq!(TcpPeerUri::parse("tcp://:1514"), Err(UriError::EmptyHost));
        assert_eq!(TcpPeerUri::parse("tcp://1.2.3.4:1514?password=x"), Err(UriError::UnsupportedOption));
        assert_eq!(TcpPeerUri::parse("tcp://1.2.3.4:1514/x"), Err(UriError::UnsupportedOption));
        assert_eq!(TcpPeerUri::parse("tcp://[::1]1514"), Err(UriError::BadPort));
    }
}
