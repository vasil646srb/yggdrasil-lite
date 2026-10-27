//! Public peer lists (`publicnodes.json` format).
//!
//! Structure: top-level object → region files (`"armenia.md": {...}`) → peer
//! URIs as keys (`"tcp://host:port": {...}`) with metadata:
//! `up` (bool), `key` (hex public key), `response_ms` (number), plus fields the
//! lite node ignores. Some URIs carry `?key=` in the key string itself.
//!
//! Policy:
//! - only `tcp://` entries are imported;
//! - entries with `"up": false` are skipped;
//! - the peer's `key` pins the expected identity (the handshake must match);
//! - `response_ms` seeds the candidate's latency estimate.
//!
//! The platform downloads the list (see [`DEFAULT_PUBLIC_PEERS_URL`]) and calls
//! [`Endpoint::import_peer_list`](crate::Endpoint::import_peer_list). The
//! scanner tolerates malformed or truncated input: it never panics and skips
//! what it cannot parse.

use alloc::string::String;
use alloc::vec::Vec;

use crate::uri::{parse_hex32, TcpPeerUri};

/// Default public peer list.
pub const DEFAULT_PUBLIC_PEERS_URL: &str = "https://publicpeers.neilalexander.dev/publicnodes.json";

/// One importable peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    pub uri: TcpPeerUri,
    /// Expected public key: from the entry's `key` field, or the URI's `?key=`.
    pub key: Option<[u8; 32]>,
    /// Latency hint from the list, in milliseconds.
    pub response_ms: Option<u64>,
}

/// Extract the TCP peers that are up from a public peer list document.
pub fn tcp_peers_from_json(json: &[u8]) -> Vec<PeerEntry> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < json.len() {
        if json[i] != b'"' {
            i += 1;
            continue;
        }
        let (s, next) = read_string(json, i);
        i = next;
        let Some(s) = s else { continue };
        if !is_tcp_prefix(&s) {
            continue;
        }
        let Ok(uri) = TcpPeerUri::parse(&s) else { continue };

        // Metadata object directly after `"uri":`, if present.
        let mut fields = Fields::default();
        let after = skip_ws(json, i);
        if json.get(after) == Some(&b':') {
            let v = skip_ws(json, after + 1);
            if json.get(v) == Some(&b'{') {
                if let Some(end) = matching_brace(json, v) {
                    fields = parse_fields(&json[v..=end]);
                    i = end + 1;
                }
            }
        }

        if fields.up == Some(false) {
            continue;
        }
        let key = fields.key.or(uri.expected_key());
        out.push(PeerEntry {
            uri,
            key,
            response_ms: fields.response_ms,
        });
    }
    out
}

#[derive(Default)]
struct Fields {
    up: Option<bool>,
    key: Option<[u8; 32]>,
    response_ms: Option<u64>,
}

fn is_tcp_prefix(s: &str) -> bool {
    s.len() >= 6 && s.as_bytes()[..6].eq_ignore_ascii_case(b"tcp://")
}

/// Read a JSON string starting at `start` (which must be `"`). Returns the
/// decoded string (None if invalid UTF-8 or unterminated) and the index after
/// the closing quote. Escapes: `\/`, `\\`, `\"` and others keep the escaped
/// character; `\uXXXX` is not decoded (it does not occur in peer URIs).
fn read_string(json: &[u8], start: usize) -> (Option<String>, usize) {
    let mut buf: Vec<u8> = Vec::new();
    let mut i = start + 1;
    while i < json.len() {
        match json[i] {
            b'"' => {
                let s = core::str::from_utf8(&buf).ok().map(String::from);
                return (s, i + 1);
            }
            b'\\' if i + 1 < json.len() => {
                buf.push(json[i + 1]);
                i += 2;
            }
            c => {
                buf.push(c);
                i += 1;
            }
        }
    }
    (None, json.len())
}

fn skip_ws(json: &[u8], mut i: usize) -> usize {
    while i < json.len() && json[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Index of the `}` matching the `{` at `start`, skipping string contents.
fn matching_brace(json: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < json.len() {
        match json[i] {
            b'"' => i = read_string(json, i).1,
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Read `up`, `key` and `response_ms` from the top level of a metadata object.
fn parse_fields(obj: &[u8]) -> Fields {
    let mut f = Fields::default();
    let mut depth = 0usize;
    let mut i = 0;
    while i < obj.len() {
        match obj[i] {
            b'"' => {
                let (name, next) = read_string(obj, i);
                i = next;
                if depth != 1 {
                    continue;
                }
                let Some(name) = name else { continue };
                let colon = skip_ws(obj, i);
                if obj.get(colon) != Some(&b':') {
                    continue;
                }
                let v = skip_ws(obj, colon + 1);
                match name.as_str() {
                    "up" => {
                        if obj[v..].starts_with(b"true") {
                            f.up = Some(true);
                        } else if obj[v..].starts_with(b"false") {
                            f.up = Some(false);
                        }
                    }
                    "key" => {
                        if obj.get(v) == Some(&b'"') {
                            let (val, n) = read_string(obj, v);
                            f.key = val.as_deref().and_then(parse_hex32);
                            i = n;
                        }
                    }
                    "response_ms" => {
                        let digits: usize = obj[v..].iter().take_while(|c| c.is_ascii_digit()).count();
                        f.response_ms = core::str::from_utf8(&obj[v..v + digits])
                            .ok()
                            .and_then(|d| d.parse().ok());
                    }
                    _ => {}
                }
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    /// Excerpt in the real publicnodes.json shape.
    const SAMPLE: &[u8] = br#"{
  "armenia.md": {
    "quic://37.186.113.100:1515": {
      "up": true,
      "key": "2a038bfcc812ef82f0e4a936ccc065553b5beab0e566e2c48830eede873fdcc3",
      "response_ms": 127
    },
    "tcp://37.186.113.100:1514": {
      "up": true,
      "key": "2a038bfcc812ef82f0e4a936ccc065553b5beab0e566e2c48830eede873fdcc3",
      "imported": 1705748407,
      "response_ms": 124,
      "states": "*****"
    },
    "tls://ygg-evn-1tls.wgos.org:443": {
      "up": false,
      "imported": 1738868411
    },
    "ws://37.186.113.100:1516": {
      "up": true,
      "key": "2a038bfcc812ef82f0e4a936ccc065553b5beab0e566e2c48830eede873fdcc3"
    }
  },
  "other.md": {
    "tcp://down.example.net:1514": {
      "up": false,
      "imported": 1744707611
    },
    "tcp://ok.example.net:1514?key=0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9": {
      "up": true,
      "key": "0000000b0683e38d8cb3085cfbf217edf0f0b2de76bb5ac7f02a94cd42a3fed9",
      "response_ms": 334
    }
  }
}"#;

    #[test]
    fn imports_only_up_tcp_peers_with_keys_and_latency() {
        let peers = tcp_peers_from_json(SAMPLE);
        let uris: Vec<String> = peers.iter().map(|p| p.uri.host_port()).collect();
        assert_eq!(uris, vec!["37.186.113.100:1514", "ok.example.net:1514"]);

        let first = &peers[0];
        assert_eq!(first.response_ms, Some(124));
        assert_eq!(first.key.unwrap()[0], 0x2a);

        assert_eq!(peers[1].response_ms, Some(334));
        assert_eq!(peers[1].key.unwrap()[0], 0x00);
    }

    #[test]
    fn tolerates_truncated_and_garbage_input() {
        let _ = tcp_peers_from_json(b"{\"tcp://a.example:1514\": {\"up\": tr");
        let _ = tcp_peers_from_json(b"\"tcp://a.example:1514\"");
        let _ = tcp_peers_from_json(b"}}}]]]\"");
        assert!(tcp_peers_from_json(b"").is_empty());
    }

    #[test]
    fn plain_string_entries_are_accepted_without_metadata() {
        let peers = tcp_peers_from_json(br#"["tcp://a.example:1514", "tls://b.example:443"]"#);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].uri.to_string(), "tcp://a.example:1514");
        assert_eq!(peers[0].key, None);
        assert_eq!(peers[0].response_ms, None);
    }
}
