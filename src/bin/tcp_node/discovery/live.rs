//! The real LAN discovery (see the parent module).

use crate::*;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

/// Upstream LAN peers found by beacon: key -> scoped link-local address (with the interface id).
/// Shared between the probe threads and the dialer, which otherwise only see URIs without zone ids.
static LAN_SCOPED: Mutex<Vec<(PublicKey, SocketAddrV6)>> = Mutex::new(Vec::new());

fn lan_scoped_set(key: PublicKey, addr: SocketAddrV6) {
    if let Ok(mut v) = LAN_SCOPED.lock() {
        match v.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = addr,
            None => v.push((key, addr)),
        }
    }
}

pub(crate) fn lan_scoped_addr(key: &PublicKey) -> Option<SocketAddrV6> {
    LAN_SCOPED.lock().ok()?.iter().find(|(k, _)| k == key).map(|(_, a)| *a)
}

/// yggdrasil-go LAN discovery: IPv6 link-local multicast group and port.
const UPSTREAM_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0114);
const UPSTREAM_BEACON_PORT: u16 = 9001;

/// Parse a yggdrasil-go beacon (big endian): major u16 (0), minor u16 (5), public key (32),
/// listen port u16, hash length u16, hash. The hash is BLAKE2b-512 of the key with no password.
/// Anything else (other version, bad hash, wrong length) is ignored.
fn parse_upstream_beacon(b: &[u8]) -> Option<(PublicKey, u16)> {
    if b.len() < 40 {
        return None;
    }
    let major = u16::from_be_bytes([b[0], b[1]]);
    let minor = u16::from_be_bytes([b[2], b[3]]);
    if major != 0 || minor != 5 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&b[4..36]);
    let port = u16::from_be_bytes([b[36], b[37]]);
    let hash_len = u16::from_be_bytes([b[38], b[39]]) as usize;
    if port == 0 || hash_len != 64 || b.len() != 40 + hash_len {
        return None;
    }
    use blake2::{Blake2b512, Digest};
    let mut hasher = Blake2b512::new();
    hasher.update(key);
    let expected = hasher.finalize();
    if &b[40..] != expected.as_slice() {
        return None;
    }
    Some((key, port))
}

/// Interface indices to join the beacon group on. Android (Termux) denies apps read access to
/// `/sys/class/net`, so sysfs is only a first try; otherwise probe small indices, since joining
/// a non-existent index fails and a real one succeeds.
fn lan_ifindices() -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for entry in rd.flatten() {
            if entry.file_name().to_str() == Some("lo") {
                continue;
            }
            if let Ok(t) = std::fs::read_to_string(entry.path().join("ifindex")) {
                if let Ok(idx) = t.trim().parse::<u32>() {
                    out.push(idx);
                }
            }
        }
    }
    if out.is_empty() {
        out = (1..=64).collect();
    }
    out
}

/// Listen for yggdrasil-go beacons on every interface we can join the group on.
fn upstream_lan_socket() -> Result<UdpSocket, Box<dyn Error>> {
    let sock = bind_udp6_shared(UPSTREAM_BEACON_PORT)
        .map_err(|e| format!("bind [::]:{UPSTREAM_BEACON_PORT}: {e}"))?;
    let mut joined = Vec::new();
    for idx in lan_ifindices() {
        if sock.join_multicast_v6(&UPSTREAM_GROUP, idx).is_ok() {
            joined.push(idx);
        }
    }
    if joined.is_empty() {
        return Err(format!("could not join {UPSTREAM_GROUP} on any interface (tried sysfs and indices 1-64)").into());
    }
    println!("lan upstream:   joined {UPSTREAM_GROUP} on ifindex {joined:?}");
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Bind `[::]:port` with SO_REUSEADDR and SO_REUSEPORT. std cannot set them before `bind`,
/// and a yggdrasil-go on the same host (which sets both on its multicast socket) already
/// holds the beacon port; a plain bind fails with "address already in use" and discovery
/// would be off exactly where it is most likely wanted.
fn bind_udp6_shared(port: u16) -> std::io::Result<UdpSocket> {
    // SAFETY: plain socket calls; the descriptor is closed on every error path and otherwise
    // handed to `UdpSocket`, which owns it from then on. `sockaddr_in6` is zeroed first, so
    // platform-specific fields (such as `sin6_len`) are valid.
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ptr = &one as *const libc::c_int as *const libc::c_void;
        let mut ok = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, ptr, size) == 0;
        // Not every platform has SO_REUSEPORT; SO_REUSEADDR alone shares a multicast port on Linux.
        let _ = libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, ptr, size);
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_port = port.to_be();
        ok = ok
            && libc::bind(
                fd,
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ) == 0;
        if !ok {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

/// Join the beacon group when `--lan-upstream` is set.
pub(crate) fn open(enabled: bool) -> Option<UdpSocket> {
    if !enabled {
        return None;
    }
    match upstream_lan_socket() {
        Ok(s) => {
            println!("lan upstream:   [{}]:{} (listen only, TLS dial)", UPSTREAM_GROUP, UPSTREAM_BEACON_PORT);
            Some(s)
        }
        Err(e) => {
            eprintln!("lan upstream: disabled: {e}");
            None
        }
    }
}

/// Read every waiting beacon and add its sender as a candidate. Listen only, never send. Each
/// beacon's source is a link-local address whose scope id is the interface; keep it so the
/// dialer can use that exact address.
pub(crate) fn drain(sock: &UdpSocket, ep: &mut Endpoint) {
    let mut buf = [0u8; 128];
    while let Ok((n, src)) = sock.recv_from(&mut buf) {
        let Some((key, port)) = parse_upstream_beacon(&buf[..n]) else { continue };
        if key == *ep.public_key() {
            continue;
        }
        let SocketAddr::V6(v6) = src else { continue };
        if v6.ip().segments()[0] & 0xffc0 != 0xfe80 || v6.scope_id() == 0 {
            continue;
        }
        lan_scoped_set(key, SocketAddrV6::new(*v6.ip(), port, 0, v6.scope_id()));
        let uri = format!("tcp://[{}]:{}?key={}", v6.ip(), port, hex(&key));
        match ep.add_peer_uri(&uri, CandidateSource::Discovered) {
            Ok(true) => println!("lan: discovered upstream {} (scope {})", uri, v6.scope_id()),
            Ok(false) => {}
            Err(e) => println!("lan: bad upstream beacon from {src}: {e:?}"),
        }
    }
}

#[cfg(test)]
mod upstream_beacon_tests {
    use super::*;
    use blake2::{Blake2b512, Digest};

    fn beacon(key: &PublicKey, port: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&5u16.to_be_bytes());
        b.extend_from_slice(key);
        b.extend_from_slice(&port.to_be_bytes());
        let mut h = Blake2b512::new();
        h.update(key);
        let hash = h.finalize();
        b.extend_from_slice(&64u16.to_be_bytes());
        b.extend_from_slice(hash.as_slice());
        b
    }

    #[test]
    fn upstream_beacon_round_trip() {
        let key = [7u8; 32];
        assert_eq!(parse_upstream_beacon(&beacon(&key, 9001)), Some((key, 9001)));
    }

    #[test]
    fn upstream_beacon_rejects_bad_input() {
        let key = [7u8; 32];
        let mut wrong_version = beacon(&key, 9001);
        wrong_version[3] = 4;
        assert_eq!(parse_upstream_beacon(&wrong_version), None);
        let mut bad_hash = beacon(&key, 9001);
        let last = bad_hash.len() - 1;
        bad_hash[last] ^= 1;
        assert_eq!(parse_upstream_beacon(&bad_hash), None);
        assert_eq!(parse_upstream_beacon(&beacon(&key, 9001)[..50]), None);
        assert_eq!(parse_upstream_beacon(&beacon(&key, 0)), None);
    }
}
