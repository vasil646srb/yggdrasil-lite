//! Runnable yggdrasil-lite device for a Unix host (Termux, Linux, OpenWrt).
//!
//! Dials out to public TCP peers, keeps its identity in a key file, accepts
//! datagrams only from allowed keys, and can send a periodic test message.
//!
//! Usage:
//!   tcp_node                      # key ./ygg.key or ~/ygg.key, public peer list
//!   tcp_node --key ~/ygg.key --peers ~/peers.json --allow <hex-key> \
//!            [--target 3] [--ping <ipv6>] [--send <ipv6> <message>]
//!
//! Without `--peers` the public peer list is downloaded in the background
//! (curl, wget or uclient-fetch), cached next to the key file, refreshed every
//! 6 hours and retried every minute while it fails. The node starts dialing
//! as soon as it has candidates (the cache is used right away).
//!
//! `--forward PORT[:LOCAL]` (repeatable, comma-separated) lets allowed nodes reach
//! TCP ports on this host over Yggdrasil: `--forward 22` maps overlay port 22 to
//! 127.0.0.1:22, `--forward 2222:22` maps overlay port 2222 to 127.0.0.1:22.
//! Only keys given with `--allow` can connect, and only the listed ports are open;
//! `--open PORT` lets any Yggdrasil node use that forwarded port (a public service).
//!
//! `--connect LPORT:[ADDR]:PORT` (repeatable) is the reverse: local programs
//! connect to 127.0.0.1:LPORT and are carried to `[ADDR]:PORT` over Yggdrasil.
//!
//! `--quality-interval SECS` (default 300) sets how often the global network is
//! re-checked: peers are grouped by tree root, peers on another root are dropped,
//! and the rest are ranked by latency.
//!
//! `--target N` is the number of outbound peers to keep connected (1..=32,
//! default 3). The node dials the best candidates from `--peers` and replaces
//! any that fail; see `src/pool.rs` for the selection rules.
//!
//! The device answers ICMPv6 echo requests from allowed keys automatically.
//! `--ping` sends one echo request per second to an address and prints replies
//! with round-trip times.
//!
//! Optional parts are build features (see README, "Build variants"):
//!
//! * `html`: an HTML server on port 1080 (`--html-port`). The overlay TCP port serves a status
//!   page refreshed every second to allowed keys (`--html FILE` replaces it); open it from a
//!   yggstack/yggdrasil node with `curl -x socks5h://127.0.0.1:1080 http://[<device>]:1080/`.
//!   `127.0.0.1:1080` serves a dashboard (`GET /`) and the ESP32-compatible JSON
//!   (`GET /api/stats`); `--api ADDR` moves it (loopback only, no authentication), `--api off`
//!   disables it.
//! * `upstream-tls`: `tls://` peers and `--lan-upstream` discovery of yggdrasil-go peers.
//!
//! Without them the node only forwards TCP and UDP over TCP peers.
//!
//! The key file is created on first run (64 hex chars). Keep it private: it
//! determines the device's address.

use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::mpsc;
use std::time::{Duration, Instant};

extern crate alloc;

// The status API model is shared with the ESP32 firmware (pure Rust, no hardware deps). Only the
// `html` build uses it.
#[cfg(feature = "html")]
#[path = "../../examples/esp32/src/api_model.rs"]
#[allow(dead_code)]
mod api_model;

// Optional parts, each behind a feature and compiled to a stub without it:
//   html       local status dashboard + JSON API and the overlay status page (src/bin/tcp_node/html.rs)
//   upstream-tls  tls:// peers and yggdrasil-go LAN discovery (src/bin/tcp_node/discovery.rs)
#[path = "tcp_node/discovery.rs"]
mod discovery;
#[path = "tcp_node/html.rs"]
mod html;
#[path = "tcp_node/tun.rs"]
mod tun;

/// Protocol clock starts here (matches the library tests).
const CLOCK_BASE: u64 = 1_000;

/// Upper bound for `--target`: each outbound slot is a TCP connection and a TLS session.
const MAX_TARGET: usize = 32;

/// Default port of the HTML server: overlay port of the status page and local dashboard port.
const HTML_PORT: u16 = 1080;

/// Echo `id` used for quality probes (peer latency and root checks).
const QUALITY_ID: u16 = 0x5155;
/// Echo `seq` for a probe to a connected peer, and for a probe to the global root.
const PEER_PROBE_SEQ: u16 = 1;
const ROOT_PROBE_SEQ: u16 = 2;
/// Echo `seq` for a probe to an allowed client's overlay address.
const ALLOW_PROBE_SEQ: u16 = 3;
/// Echo `seq` for a probe to a `--connect` server's address.
const TARGET_PROBE_SEQ: u16 = 4;
/// Print the latency to each `--connect` server every this many probes.
const TARGET_REPORT_EVERY: u32 = 3;
/// How often each allowed client's address is pinged.
const ALLOW_PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// How often each connected peer is pinged for its latency.
const PEER_PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// Random payload carried by a quality probe; a reply counts only if it echoes it back.
type ProbeNonce = [u8; 8];

fn new_nonce(rng: &mut impl RngCore) -> ProbeNonce {
    let mut n = [0u8; 8];
    rng.fill_bytes(&mut n);
    n
}

/// Match a reply against the pending probe for `key` and consume it. Returns the send
/// time only when the echoed payload equals the nonce that was sent.
fn take_probe(map: &mut HashMap<PublicKey, (u64, ProbeNonce)>, key: &PublicKey, payload: &[u8]) -> Option<u64> {
    match map.get(key) {
        Some((sent, nonce)) if nonce.as_slice() == payload => {
            let sent = *sent;
            map.remove(key);
            Some(sent)
        }
        _ => None,
    }
}

/// A peer dropped for being on another root is not redialed for this long.
const FOREIGN_COOLDOWN_MS: u64 = 30 * 60 * 1000;
/// UDP forwarding: sessions per (client key, client port, overlay port), idle timeout,
/// and the largest payload carried (1280 minimum IPv6 MTU minus IPv6 and UDP headers).
const MAX_UDP_SESSIONS: usize = 64;
const UDP_IDLE: Duration = Duration::from_secs(60);
const MAX_UDP_PAYLOAD: usize = 1232;

/// A local UDP socket connected to a forwarded service, for one overlay client.
struct UdpSession {
    sock: UdpSocket,
    client: [u8; 16],
    client_port: u16,
    overlay_port: u16,
    last: Instant,
}

/// Stage 1 of peer selection: a plain TCP connect to every candidate, measured before any
/// overlay handshake. Candidates are probed in parallel, and the first round gates dialing.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_INTERVAL: Duration = Duration::from_secs(600);
const PROBE_WORKERS: usize = 8;
const FIRST_PROBE_MAX_WAIT: Duration = Duration::from_secs(60);

/// `--fwmark N` (Linux): SO_MARK for peer connections, so policy routing can keep them out of a
/// VPN that this node itself carries (0 = off).
static FWMARK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Connect to a peer, with `--fwmark` applied before the connect.
fn connect_peer(addr: &SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    let mark = FWMARK.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "linux")]
    if mark != 0 {
        use std::os::fd::FromRawFd;
        let family = if addr.is_ipv6() { libc::AF_INET6 } else { libc::AF_INET };
        // SAFETY: a fresh socket we own; on any error it is closed by the TcpStream drop below.
        let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let s = unsafe { TcpStream::from_raw_fd(fd) };
        let m = mark as libc::c_int;
        // SAFETY: setsockopt with a c_int value on our socket.
        if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &m as *const _ as *const libc::c_void, 4) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // connect with a timeout: non-blocking connect, then poll for writability.
        s.set_nonblocking(true)?;
        let (sa, len) = sockaddr(addr);
        // SAFETY: `sa` is a valid sockaddr of `len` bytes.
        let r = unsafe { libc::connect(fd, &sa as *const _ as *const libc::sockaddr, len) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(e);
            }
            let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            // SAFETY: one pollfd we own.
            let n = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
            if n == 0 {
                return Err(std::io::Error::new(ErrorKind::TimedOut, "connect timed out"));
            }
            if let Some(e) = s.take_error()? {
                return Err(e);
            }
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        s.set_nonblocking(false)?;
        return Ok(s);
    }
    let _ = mark;
    TcpStream::connect_timeout(addr, timeout)
}

#[cfg(target_os = "linux")]
fn sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: zeroed sockaddr_storage is a valid starting point for either family.
    let mut st: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.ip().octets()) },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage.
            unsafe { std::ptr::write(&mut st as *mut _ as *mut libc::sockaddr_in, sin) };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
                sin6_scope_id: a.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage.
            unsafe { std::ptr::write(&mut st as *mut _ as *mut libc::sockaddr_in6, sin6) };
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (st, len as libc::socklen_t)
}

/// TCP connect time to the candidate's address over the regular internet, or `None` on failure.
fn probe_tcp(uri: &TcpPeerUri) -> Option<u64> {
    let addr = match uri.expected_key().and_then(|k| discovery::lan_scoped_addr(&k)) {
        Some(sa) => SocketAddr::V6(sa),
        None => uri.host_port().to_socket_addrs().ok()?.next()?,
    };
    let t0 = Instant::now();
    let stream = connect_peer(&addr, PROBE_TIMEOUT).ok()?;
    let rtt = t0.elapsed().as_millis() as u64;
    drop(stream);
    Some(rtt)
}

/// Probe `uris` on `PROBE_WORKERS` threads; each result is sent on `tx`.
fn spawn_probe_round(uris: Vec<TcpPeerUri>, tx: &mpsc::Sender<(TcpPeerUri, Option<u64>)>) {
    let mut chunks: Vec<Vec<TcpPeerUri>> = (0..PROBE_WORKERS).map(|_| Vec::new()).collect();
    for (i, uri) in uris.into_iter().enumerate() {
        chunks[i % PROBE_WORKERS].push(uri);
    }
    for chunk in chunks.into_iter().filter(|c| !c.is_empty()) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for uri in chunk {
                let rtt = probe_tcp(&uri);
                let _ = tx.send((uri, rtt));
            }
        });
    }
}

/// LAN discovery: multicast group and UDP port for beacons.
/// yggdrasil-ng uses IPv6 link-local multicast; the URI parser has no zone-id support,
/// so this build uses IPv4 multicast and advertises plain IPv4 addresses.
/// Upper bound for accepted inbound connections (on top of `--target`).
const MAX_INBOUND: usize = 16;
/// Latency limits of the peer search (`yggdrasil_lite::search`). Allowed clients decide first;
/// the root decides only while no client has a fresh measurement.
const CLIENT_RTT_LIMIT_MS: u64 = search::CLIENT_LIMIT_MS;
const ROOT_RTT_LIMIT_MS: u64 = search::ROOT_LIMIT_MS;
/// While the root decides and is slow, it is probed this often, so peers are replaced one at a time on fresh results.
const SEARCH_PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// A peer replaced for a high root latency is not redialed for this long.
const SLOW_PEER_COOLDOWN_MS: u64 = 15 * 60 * 1000;

use rand::rngs::OsRng;
use rand::RngCore;
use yggdrasil_lite::icmp::{self, ECHO_REPLY};
use yggdrasil_lite::peerlist::DEFAULT_PUBLIC_PEERS_URL;
use yggdrasil_lite::uri::TcpPeerUri;
use yggdrasil_lite::{CloseReason, ConnId, TcpEvent};
use yggdrasil_lite::quality::{PeerView, Quality, Verdict, DEFAULT_RECHECK_MS};
use yggdrasil_lite::search::{self, droppable, Metric, PeerSearch, SearchConfig};
use yggdrasil_lite::address::addr_for_key;
use yggdrasil_lite::{frame_ipv6, unframe_ipv6, udp, Action, Address, CandidateSource, Direction, Endpoint, PublicKey};

struct Args {
    /// `--key FILE`; default: ./ygg.key if it exists, else ~/ygg.key.
    key: Option<String>,
    peers: Option<String>,
    allow: Vec<String>,
    target: usize,
    send: Option<(Ipv6Addr, String)>,
    ping: Option<Ipv6Addr>,
    /// `--html FILE`: page served on the overlay HTML port (html build).
    #[cfg_attr(not(feature = "html"), allow(dead_code))]
    html: Option<String>,
    /// `--api ADDR|off`: local dashboard address (html build).
    #[cfg_attr(not(feature = "html"), allow(dead_code))]
    api: Option<String>,
    /// `--html-port PORT`: overlay port of the page and default port of the local dashboard.
    #[cfg_attr(not(feature = "html"), allow(dead_code))]
    html_port: u16,
    quality_ms: u64,
    /// (overlay port, local port) pairs from `--forward`.
    forwards: Vec<(u16, u16)>,
    /// `--open PORT,..`: forwarded overlay ports that accept any key, not only `--allow`.
    open: Vec<u16>,
    /// `--proxy-protocol PORT,..`: forwarded overlay ports whose local side first gets a PROXY v1
    /// line with the caller's key-verified overlay address.
    proxy_ports: Vec<u16>,
    /// `--rtt-limit MS`: peer search replaces peers while the latency to the allowed keys or
    /// `--connect` servers is above this.
    rtt_limit: u64,
    /// `--fwmark N`: SO_MARK on peer connections (Linux).
    fwmark: u32,
    /// `--swap-interval SECS` / `--swap-settle SECS`: peer search timing (see SearchConfig).
    swap_interval: Option<u64>,
    swap_settle: Option<u64>,
    /// `--tun NAME` (Linux) / `--tun-ctl PATH` (fd over a unix socket): IPv6 packet bridge.
    tun: Option<String>,
    tun_ctl: Option<String>,
    /// `--tun-server ADDR`: its latency drives the peer search in TUN mode (like `--connect`).
    tun_server: Option<Ipv6Addr>,
    /// `--send-udp IPV6 PORT MSG`: send one UDP datagram over the overlay every 5 s (test aid).
    send_udp: Option<(Ipv6Addr, u16, String)>,
    /// `--forward-udp`: (overlay port, local port) pairs for UDP.
    forwards_udp: Vec<(u16, u16)>,
    /// `--lan-upstream`: discover yggdrasil-go peers via their IPv6 link-local beacons (dial over TLS).
    lan_upstream: bool,
    /// `--no-public`: do not download the public peer list; use only `--peers FILE` and LAN discovery.
    no_public: bool,
    /// `--lan-target`: outbound slots reserved for LAN peers (default: `--target`).
    lan_target: Option<usize>,
    /// `--listen PORT`: accept inbound TCP peers and advertise this port in beacons.
    listen: Option<u16>,
    /// `--connect LPORT:[ADDR]:PORT`: local listener carried to a remote overlay port.
    connects: Vec<(u16, Ipv6Addr, u16)>,
}

const USAGE: &str = "usage: tcp_node [options]

With no options the node creates or loads its key (./ygg.key, else ~/ygg.key),
downloads the public peer list and connects.

  --key FILE                identity file (created on first run)
  --peers FILE              local peer list instead of the public one
  --no-public               do not download the public peer list
  --target N                outbound peers to keep (1..=32, default 3)
  --allow HEXKEY            key allowed to use forwards, ping and the page (repeatable)
  --forward PORT[:LOCAL],.. expose local TCP ports over Yggdrasil
  --open PORT,..            let any Yggdrasil node use these forwarded ports and
                            ping us (no --allow needed; the page stays allowed-only)
  --tun NAME                IPv6 packet bridge on Linux TUN interface NAME: packets
                            to 200::/7 go over Yggdrasil (300::/8 = node subnets,
                            e.g. a ydn64 NAT64 pool); replies from nodes we wrote to
                            come back. Give the interface our address/7.
  --tun-ctl PATH            same, the interface fd arrives over unix socket PATH
                            (SCM_RIGHTS, e.g. from Android VpnService)
  --tun-server ADDR         in TUN mode, ping ADDR for the peer search (like --connect)
  --proxy-protocol PORT,..  for these forwarded overlay ports, first send the local program a
                            PROXY v1 line with the caller's (key-verified) overlay address
  --rtt-limit MS            replace peers while the latency to the allowed keys or
                            to the --connect servers is above this (default 150)
  --fwmark N                SO_MARK for peer connections (Linux, needs CAP_NET_ADMIN), so a VPN
                            routed through this node can route them around itself
  --swap-interval SECS      at least this long between two peer replacements
                            (default 30; doubles after a useless one, up to 10 min)
  --swap-settle SECS        how long a new peer is measured before the replacement is
                            judged helpful or not (default 60)
  --connect LPORT:[ADDR]:PORT
                            carry 127.0.0.1:LPORT to [ADDR]:PORT over Yggdrasil
  --forward-udp PORT[:LOCAL],..  expose local UDP ports
  --api ADDR|off            status dashboard and /api/stats, loopback only
                            (html build; default 127.0.0.1:<html-port>)
  --html FILE               page served on the overlay HTML port (html build)
  --html-port PORT          overlay port of the page and local dashboard port
                            (html build, default 1080)
  --ping IPV6               echo request every second
  --send IPV6 MESSAGE       datagram every 10 s (test aid)
  --send-udp IPV6 PORT MSG  UDP datagram every 5 s (test aid)
  --quality-interval SECS   network re-check interval (default 300)
  --listen PORT             accept plain TCP peers on this port
  --lan-upstream            dial yggdrasil-go LAN peers (upstream-tls build)
  --lan-target N            outbound slots for LAN peers (upstream-tls build)";

fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

/// `LPORT:[ADDR]:PORT`.
fn parse_connect(spec: &str) -> Result<(u16, Ipv6Addr, u16), String> {
    let bad = || format!("bad --connect '{spec}' (want LPORT:[IPV6]:PORT)");
    let (lport, rest) = spec.split_once(':').ok_or_else(bad)?;
    let rest = rest.strip_prefix('[').ok_or_else(bad)?;
    let (addr, rest) = rest.split_once(']').ok_or_else(bad)?;
    let port = rest.strip_prefix(':').ok_or_else(bad)?;
    let lport: u16 = lport.parse().ok().filter(|p| *p > 0).ok_or_else(bad)?;
    let port: u16 = port.parse().ok().filter(|p| *p > 0).ok_or_else(bad)?;
    let addr: Ipv6Addr = addr.parse().map_err(|_| bad())?;
    Ok((lport, addr, port))
}

fn parse_args() -> Args {
    let mut a = Args { key: None, connects: Vec::new(), peers: None, allow: Vec::new(), target: 3, send: None, ping: None, html: None, api: None, html_port: HTML_PORT, quality_ms: DEFAULT_RECHECK_MS, forwards: Vec::new(), open: Vec::new(), proxy_ports: Vec::new(), rtt_limit: CLIENT_RTT_LIMIT_MS, tun: None, tun_ctl: None, tun_server: None, swap_interval: None, swap_settle: None, fwmark: 0, forwards_udp: Vec::new(), send_udp: None, lan_upstream: false, no_public: false, listen: None, lan_target: None };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "--key" => a.key = Some(it.next().unwrap_or_else(|| usage())),
            "--connect" => {
                let spec = it.next().unwrap_or_else(|| usage());
                a.connects.push(parse_connect(&spec).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(2);
                }));
            }
            "--peers" => a.peers = Some(it.next().unwrap_or_else(|| usage())),
            "--allow" => a.allow.push(it.next().unwrap_or_else(|| usage())),
            "--target" => a.target = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--html" | "--api" | "--html-port" if !cfg!(feature = "html") => {
                eprintln!("{flag} needs a build with `--features html`");
                std::process::exit(2);
            }
            "--lan-upstream" | "--lan-target" if !cfg!(feature = "upstream-tls") => {
                eprintln!("{flag} needs a build with `--features upstream-tls`");
                std::process::exit(2);
            }
            "--html" => a.html = Some(it.next().unwrap_or_else(|| usage())),
            "--api" => a.api = Some(it.next().unwrap_or_else(|| usage())),
            "--html-port" => a.html_port = it.next().and_then(|v| v.parse().ok()).filter(|p| *p > 0).unwrap_or_else(|| usage()),
            "--forward" => {
                let spec = it.next().unwrap_or_else(|| usage());
                for part in spec.split(',') {
                    a.forwards.push(parse_forward(part.trim()).unwrap_or_else(|e| {
                        eprintln!("--forward: {e}");
                        std::process::exit(2);
                    }));
                }
            }
            "--open" => {
                let spec = it.next().unwrap_or_else(|| usage());
                for part in spec.split(',') {
                    match part.trim().parse::<u16>() {
                        Ok(p) if p > 0 => a.open.push(p),
                        _ => {
                            eprintln!("--open: bad port '{part}' (want 1..=65535)");
                            std::process::exit(2);
                        }
                    }
                }
            }
            "--tun" => a.tun = Some(it.next().unwrap_or_else(|| usage())),
            "--tun-ctl" => a.tun_ctl = Some(it.next().unwrap_or_else(|| usage())),
            "--tun-server" => a.tun_server = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--proxy-protocol" => {
                let spec = it.next().unwrap_or_else(|| usage());
                for part in spec.split(',') {
                    match part.trim().parse::<u16>() {
                        Ok(p) if p > 0 => a.proxy_ports.push(p),
                        _ => {
                            eprintln!("--proxy-protocol: bad port '{part}' (want 1..=65535)");
                            std::process::exit(2);
                        }
                    }
                }
            }
            "--fwmark" => a.fwmark = it.next().and_then(|v| v.strip_prefix("0x").map(|h| u32::from_str_radix(h, 16).ok()).unwrap_or_else(|| v.parse().ok())).unwrap_or_else(|| usage()),
            "--swap-interval" => a.swap_interval = Some(it.next().and_then(|v| v.parse().ok()).filter(|v: &u64| (5..=3600).contains(v)).unwrap_or_else(|| usage())),
            "--swap-settle" => a.swap_settle = Some(it.next().and_then(|v| v.parse().ok()).filter(|v: &u64| (10..=3600).contains(v)).unwrap_or_else(|| usage())),
            "--rtt-limit" => {
                a.rtt_limit = it.next().and_then(|v| v.parse().ok()).filter(|v: &u64| (10..=5000).contains(v)).unwrap_or_else(|| usage());
            }
            "--quality-interval" => {
                let secs: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                a.quality_ms = secs * 1000;
            }
            "--forward-udp" => {
                let spec = it.next().unwrap_or_else(|| usage());
                for part in spec.split(',') {
                    a.forwards_udp.push(parse_forward(part.trim()).unwrap_or_else(|e| {
                        eprintln!("--forward-udp: {e}");
                        std::process::exit(2);
                    }));
                }
            }
            "--send-udp" => {
                let addr = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                let port = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                let msg = it.next().unwrap_or_else(|| usage());
                a.send_udp = Some((addr, port, msg));
            }
            "--lan-upstream" => a.lan_upstream = true,
            "--no-public" => a.no_public = true,
            "--lan-target" => a.lan_target = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--listen" => a.listen = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--ping" => a.ping = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--send" => {
                let addr = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                let msg = it.next().unwrap_or_else(|| usage());
                a.send = Some((addr, msg));
            }
            _ => usage(),
        }
    }
    if a.forwards_udp.len() > 16 {
        eprintln!("at most 16 UDP forwarded ports");
        std::process::exit(2);
    }
    if a.forwards.len() > 16 {
        eprintln!("at most 16 forwarded ports");
        std::process::exit(2);
    }
    if a.quality_ms < 10_000 {
        eprintln!("--quality-interval must be at least 10 seconds");
        std::process::exit(2);
    }
    if !(1..=MAX_TARGET).contains(&a.target) {
        eprintln!("--target must be between 1 and {MAX_TARGET} (got {})", a.target);
        std::process::exit(2);
    }
    a
}

/// `PORT` (overlay port = local port) or `OVERLAY:LOCAL`.
fn parse_forward(spec: &str) -> Result<(u16, u16), String> {
    let port = |s: &str| -> Result<u16, String> {
        match s.parse::<u16>() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err(format!("bad port '{s}' (want 1..=65535)")),
        }
    };
    match spec.split_once(':') {
        Some((o, l)) => Ok((port(o)?, port(l)?)),
        None => {
            let p = port(spec)?;
            Ok((p, p))
        }
    }
}

/// Open the local socket for one forwarded session.
fn connect_local(port: u16) -> Option<TcpStream> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    let _ = s.set_nodelay(true);
    s.set_nonblocking(true).ok()?;
    Some(s)
}

/// An overlay TCP connection bridged to a local socket (both directions, non-blocking).
struct Bridge {
    sock: TcpStream,
    /// Bytes read from the overlay and not yet written to the local socket.
    to_local: Vec<u8>,
    to_local_off: usize,
    /// The local program finished sending; our FIN is queued.
    local_eof: bool,
    /// The overlay peer finished sending.
    remote_eof: bool,
    /// Local write side shut down after `remote_eof`.
    shut_wr: bool,
    label: String,
}

impl Bridge {
    fn new(sock: TcpStream, label: String) -> Self {
        Self { sock, to_local: Vec::new(), to_local_off: 0, local_eof: false, remote_eof: false, shut_wr: false, label }
    }
}

const BRIDGE_CHUNK: usize = 64 * 1024;

/// Longest wait in the main loop when nothing is ready and no timer is due earlier. The
/// library's slowest-moving timers are seconds long; this bounds how late the loop's own
/// periodic jobs and the worker-thread channels (peer list, probes) are noticed.
const IDLE_WAIT_MS: u64 = 100;
/// Wait cap while the candidate probe round runs: its workers report over a channel.
const PROBE_WAIT_MS: u64 = 20;
/// Wait cap while dials run on worker threads.
const DIAL_WAIT_MS: u64 = 20;

/// Move bytes both ways for one bridge. Returns `false` if the local socket failed.
fn pump_bridge(ep: &mut Endpoint, id: ConnId, b: &mut Bridge, buf: &mut [u8]) -> bool {
    // Overlay -> local.
    loop {
        if b.to_local_off == b.to_local.len() {
            b.to_local.clear();
            b.to_local_off = 0;
            let n = ep.tcp_read(id, buf);
            if n == 0 {
                break;
            }
            b.to_local.extend_from_slice(&buf[..n]);
        }
        match b.sock.write(&b.to_local[b.to_local_off..]) {
            Ok(0) => return false,
            Ok(n) => b.to_local_off += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => break,
            Err(_) => return false,
        }
    }
    if b.remote_eof && !b.shut_wr && b.to_local_off == b.to_local.len() {
        let _ = b.sock.shutdown(Shutdown::Write);
        b.shut_wr = true;
    }
    // Local -> overlay, only as much as the send buffer takes.
    while !b.local_eof {
        let space = ep.tcp_send_space(id).min(buf.len());
        if space == 0 {
            break;
        }
        match b.sock.read(&mut buf[..space]) {
            Ok(0) => {
                b.local_eof = true;
                ep.tcp_close(id);
            }
            Ok(n) => {
                ep.tcp_write(id, &buf[..n]);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => break,
            Err(_) => return false,
        }
    }
    true
}

/// `poll(2)` over a reusable descriptor set.
mod sys {
    use super::RawFd;
    use std::time::Duration;

    pub const IN: i16 = libc::POLLIN;
    pub const OUT: i16 = libc::POLLOUT;

    /// A reusable set of descriptors to wait on.
    #[derive(Default)]
    pub struct Poller {
        fds: Vec<libc::pollfd>,
    }

    impl Poller {
        pub fn clear(&mut self) {
            self.fds.clear();
        }

        /// Watch `fd` for `events` and return its index. With no events the entry is
        /// ignored by the kernel (fd -1), so a hung-up socket we do not care about
        /// right now cannot wake the loop.
        pub fn add(&mut self, fd: RawFd, events: i16) -> usize {
            let fd = if events == 0 { -1 } else { fd };
            self.fds.push(libc::pollfd { fd, events, revents: 0 });
            self.fds.len() - 1
        }

        /// Block for at most `timeout_ms` until a descriptor is ready.
        pub fn wait(&mut self, timeout_ms: u64) {
            for f in &mut self.fds {
                f.revents = 0;
            }
            let timeout = timeout_ms.min(libc::c_int::MAX as u64) as libc::c_int;
            // SAFETY: `fds` points at `len` initialized `pollfd` and stays borrowed for the call.
            let r = unsafe { libc::poll(self.fds.as_mut_ptr(), self.fds.len() as libc::nfds_t, timeout) };
            if r < 0 {
                for f in &mut self.fds {
                    f.revents = 0;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    // poll itself failed: sleep instead of spinning.
                    std::thread::sleep(Duration::from_millis(timeout_ms.clamp(1, 10)));
                }
            }
        }

        /// Readable, writable, hung up or failed: whatever the caller asked about needs a look.
        pub fn ready(&self, idx: usize) -> bool {
            self.fds[idx].revents != 0
        }

        pub fn any_ready(&self) -> bool {
            self.fds.iter().any(|f| f.revents != 0)
        }
    }

}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn parse_key(s: &str) -> Result<PublicKey, Box<dyn Error>> {
    let v = unhex(s)?;
    v.try_into().map_err(|_| "public key must be 32 bytes".into())
}

fn unhex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.into()))
        .collect()
}

/// Fetch the public peer list. HTTPS is not built into this binary, so an
/// external tool does it: curl, wget, or OpenWrt's uclient-fetch.
fn download_public_peers() -> Result<Vec<u8>, String> {
    let tools: [(&str, &[&str]); 3] = [
        ("curl", &["-fsSL", "--max-time", "30"]),
        ("wget", &["-q", "-T", "30", "-O", "-"]),
        ("uclient-fetch", &["-q", "-T", "30", "-O", "-"]),
    ];
    let mut errors = Vec::new();
    for (tool, args) in tools {
        match std::process::Command::new(tool).args(args).arg(DEFAULT_PUBLIC_PEERS_URL).output() {
            Ok(out) if out.status.success() && !out.stdout.is_empty() => return Ok(out.stdout),
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                errors.push(format!("{tool}: {} {err}", out.status));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => errors.push(format!("{tool}: not installed")),
            Err(e) => errors.push(format!("{tool}: {e}")),
        }
    }
    Err(errors.join("; "))
}

/// Peer list refresh after a successful download, and retry after a failure.
const PEER_LIST_REFRESH: Duration = Duration::from_secs(6 * 3600);
const PEER_LIST_RETRY: Duration = Duration::from_secs(60);

/// Download the public list in the background: now, then every 6 h, retrying every minute on failure.
fn spawn_peer_fetcher(tx: mpsc::Sender<Result<Vec<u8>, String>>) {
    std::thread::spawn(move || loop {
        let res = download_public_peers();
        let wait = if res.is_ok() { PEER_LIST_REFRESH } else { PEER_LIST_RETRY };
        if tx.send(res).is_err() {
            return;
        }
        std::thread::sleep(wait);
    });
}

/// Default key file: ./ygg.key if present, otherwise ~/ygg.key.
fn default_key_path() -> String {
    if std::path::Path::new("ygg.key").exists() {
        return "ygg.key".into();
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home).join("ygg.key").display().to_string(),
        _ => "ygg.key".into(),
    }
}

/// The downloaded peer list is cached next to the key file.
fn peer_cache_path(key_path: &str) -> std::path::PathBuf {
    std::path::Path::new(key_path).with_file_name("peers-cache.json")
}

fn save_peer_cache(path: &std::path::Path, json: &[u8]) {
    let tmp = path.with_extension("json.tmp");
    let res = std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = res {
        eprintln!("peers: cannot write cache {}: {e}", path.display());
    }
}

/// Read the 32-byte seed from `path`, creating it with fresh randomness if absent.
///
/// The file is created with mode 0600 and never overwritten. An existing file
/// readable by other users triggers a warning.
fn load_or_create_seed(path: &str) -> Result<[u8; 32], Box<dyn Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.permissions().mode() & 0o077 != 0 {
                    eprintln!("warning: {path} is accessible to other users, run: chmod 600 {path}");
                }
            }
            unhex(text.trim())?
                .try_into()
                .map_err(|_| "key file must hold 32 bytes (64 hex chars)".into())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(hex(&seed).as_bytes())?;
            Ok(seed)
        }
        Err(e) => Err(e.into()),
    }
}

/// Execute actions, feeding transport results back into the endpoint.
/// A peer connection: plain TCP, or TLS as a client (dialing upstream LAN peers).
enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "upstream-tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => s.flush(),
        }
    }
}

impl Stream {
    fn raw_fd(&self) -> RawFd {
        match self {
            Stream::Plain(s) => s.as_raw_fd(),
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => s.sock.as_raw_fd(),
        }
    }

    /// TLS keeps decrypted bytes in its own buffer, which the socket's readiness does not show
    /// (for example data that arrived together with the end of the handshake). Such a stream
    /// must be read even though poll reports nothing.
    fn has_buffered(&mut self) -> bool {
        match self {
            Stream::Plain(_) => false,
            // On an error, report data so the next read surfaces it.
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => s.conn.process_new_packets().map_or(true, |st| st.plaintext_bytes_to_read() > 0),
        }
    }

    fn shutdown(&mut self) {
        match self {
            Stream::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => {
                s.conn.send_close_notify();
                let _ = s.conn.complete_io(&mut s.sock);
                let _ = s.sock.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Open a connection for a candidate. Upstream LAN peers go over TLS to their scoped address;
/// everything else is a plain TCP connection as before.
fn dial_slot(uri: &TcpPeerUri) -> Option<Stream> {
    if let Some(key) = uri.expected_key() {
        if let Some(sa) = discovery::lan_scoped_addr(&key) {
            let s = dial_lan_tls(SocketAddr::V6(sa));
            if s.is_none() {
                eprintln!("lan: dial {sa} failed");
            }
            return s;
        }
    }
    if uri.is_tls() {
        return dial_public_tls(uri);
    }
    let addr = uri.host_port().to_socket_addrs().ok()?.next()?;
    let s = connect_peer(&addr, Duration::from_secs(5)).ok()?;
    let _ = s.set_nodelay(true);
    // Blocking writes with a timeout; reads poll with a short timeout.
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_read_timeout(Some(Duration::from_millis(1)));
    Some(Stream::Plain(s))
}

/// `tls://` peer from a public list: TLS to the resolved address, SNI and name from the URI.
#[cfg(feature = "upstream-tls")]
fn dial_public_tls(uri: &TcpPeerUri) -> Option<Stream> {
    let addr = uri.host_port().to_socket_addrs().ok()?.next()?;
    match upstream_tls::connect(addr, uri.host()) {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("tls: {uri}: {e}");
            None
        }
    }
}

#[cfg(not(feature = "upstream-tls"))]
fn dial_public_tls(uri: &TcpPeerUri) -> Option<Stream> {
    eprintln!("tls: {uri} skipped: build with `--features upstream-tls`");
    None
}

#[cfg(feature = "upstream-tls")]
fn dial_lan_tls(addr: SocketAddr) -> Option<Stream> {
    match upstream_tls::connect(addr, "localhost") {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("lan: TLS to {addr}: {e}");
            None
        }
    }
}

#[cfg(not(feature = "upstream-tls"))]
fn dial_lan_tls(_addr: SocketAddr) -> Option<Stream> {
    // Built without `upstream-tls`: upstream peers cannot be dialed, so the candidate fails.
    None
}

#[cfg(feature = "upstream-tls")]
mod upstream_tls {
    use super::Stream;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{ring, WebPkiSupportedAlgorithms};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    /// Accepts any certificate, as yggdrasil-go does (InsecureSkipVerify): peer identity comes from
    /// the signed meta-handshake that follows the TLS session, not from the certificate. The
    /// handshake signatures are still checked, so the session itself is sound.
    #[derive(Debug)]
    struct AcceptAnyCert(WebPkiSupportedAlgorithms);

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }

    /// One shared client configuration: building it per dial would redo the provider setup.
    fn client_config() -> Result<Arc<ClientConfig>, rustls::Error> {
        static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
        if let Some(c) = CONFIG.get() {
            return Ok(c.clone());
        }
        let provider = Arc::new(ring::default_provider());
        let algs = provider.signature_verification_algorithms;
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(algs)))
            .with_no_client_auth();
        Ok(CONFIG.get_or_init(|| Arc::new(cfg)).clone())
    }

    /// Dial over TLS (rustls). TLS 1.2 is the minimum and TLS 1.3 is used when both sides
    /// support it. Runs on a dial worker thread: the connect and the handshake may take seconds.
    pub fn connect(addr: SocketAddr, name: &str) -> Result<Stream, Box<dyn Error>> {
        let tcp = crate::connect_peer(&addr, Duration::from_secs(5))?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));

        // The name is used for SNI only (and not even sent for an IP address): the certificate
        // is not verified. A host name rustls rejects falls back to a fixed one.
        let server_name = ServerName::try_from(name.to_owned())
            .or_else(|_| ServerName::try_from("localhost".to_owned()))?;
        let conn = ClientConnection::new(client_config()?, server_name)?;
        let mut tls = StreamOwned::new(conn, tcp);
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|e| format!("TLS handshake: {e}"))?;
        }
        // Polled mode for the main loop: a read returns after 1 ms when there is no data.
        let _ = tls.sock.set_read_timeout(Some(Duration::from_millis(1)));
        Ok(Stream::Tls(Box::new(tls)))
    }
}

/// Outcome of a dial that ran on a worker thread.
struct DialDone {
    slot: usize,
    /// Generation of the dial, to tell it from a later dial of the same slot.
    gen: u64,
    stream: Option<Stream>,
}

/// Runs dials on worker threads. A refused or silent peer, or a slow TLS handshake, used to freeze
/// the whole node (every other peer and every forwarded connection) for up to ten seconds.
struct Dialer {
    tx: mpsc::Sender<DialDone>,
    rx: mpsc::Receiver<DialDone>,
    /// Slot -> generation of the dial in flight. A slot closed or re-dialed meanwhile drops the
    /// old result.
    inflight: HashMap<usize, u64>,
    next_gen: u64,
}

impl Dialer {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self { tx, rx, inflight: HashMap::new(), next_gen: 0 }
    }

    fn start(&mut self, slot: usize, uri: TcpPeerUri) {
        self.next_gen += 1;
        let gen = self.next_gen;
        self.inflight.insert(slot, gen);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let stream = dial_slot(&uri);
            let _ = tx.send(DialDone { slot, gen, stream });
        });
    }

    fn cancel(&mut self, slot: usize) {
        self.inflight.remove(&slot);
    }
}

fn run(actions: Vec<Action>, ep: &mut Endpoint, streams: &mut HashMap<usize, Stream>, dialer: &mut Dialer, now: u64) {
    let mut queue: VecDeque<Action> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            Action::Dial { slot, uri } => dialer.start(slot, uri),
            Action::Write { slot, data } => {
                if let Some(s) = streams.get_mut(&slot) {
                    PEER_TX.with(|m| *m.borrow_mut().entry(slot).or_default() += data.len() as u64);
                    if let Err(e) = s.write_all(&data) {
                        eprintln!("write to slot {slot} failed: {e} ({:?})", e.kind());
                        streams.remove(&slot);
                        ep.on_transport_closed(slot, now);
                    }
                }
            }
            Action::Close { slot } => {
                dialer.cancel(slot);
                if let Some(mut s) = streams.remove(&slot) {
                    s.shutdown();
                }
            }
        }
    }
}

/// Deliver one overlay UDP datagram to the local service mapped to its destination port.
fn udp_inbound(
    sessions: &mut HashMap<(PublicKey, u16, u16), UdpSession>,
    map: &HashMap<u16, u16>,
    key: &PublicKey,
    client: [u8; 16],
    dg: udp::Datagram,
) {
    let Some(&local) = map.get(&dg.dport) else { return };
    if dg.payload.len() > MAX_UDP_PAYLOAD {
        return;
    }
    let id = (*key, dg.sport, dg.dport);
    if !sessions.contains_key(&id) {
        if sessions.len() >= MAX_UDP_SESSIONS {
            return;
        }
        let sock = match UdpSocket::bind(("127.0.0.1", 0)).and_then(|s| {
            s.connect(("127.0.0.1", local))?;
            s.set_nonblocking(true)?;
            Ok(s)
        }) {
            Ok(s) => s,
            Err(e) => {
                println!("udp: cannot open session to 127.0.0.1:{local}: {e}");
                return;
            }
        };
        sessions.insert(
            id,
            UdpSession { sock, client, client_port: dg.sport, overlay_port: dg.dport, last: Instant::now() },
        );
    }
    if let Some(s) = sessions.get_mut(&id) {
        let _ = s.sock.send(&dg.payload);
        s.last = Instant::now();
    }
}

/// First 4 bytes of a key, as hex, for logs.
fn short_key(k: &PublicKey) -> String {
    k.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

/// Print the connected peers as a table: direction, endpoint, key, address, RTT, uptime.
fn print_peers(ep: &Endpoint, sockets: usize, now: u64) {
    let peers = ep.connected_peers();
    println!("peers: {}  sockets: {}  candidates: {}", peers.len(), sockets, ep.candidates().len());
    for c in ep.tcp_connections() {
        let srtt = c.srtt_ms.map(|r| format!("{r} ms")).unwrap_or_else(|| "?".into());
        println!(
            "  tcp {} {:?} [{}]:{} local {} rtt={srtt} cwnd={} sent={} recv={} rexmit={}",
            c.id, c.state, Ipv6Addr::from(c.remote), c.remote_port, c.local_port,
            c.cwnd, c.bytes_sent, c.bytes_received, c.retransmits
        );
    }
    for p in peers {
        let uptime = now.saturating_sub(p.up_ms) / 1000;
        let key: String = p.key.iter().take(4).map(|b| format!("{:02x}", b)).collect();
        let addr = Ipv6Addr::from(p.address.0);
        match p.direction {
            Direction::Outbound => {
                let uri = p.uri.map(|u| u.to_string()).unwrap_or_else(|| "?".into());
                let rtt = p.rtt_ms.map(|r| format!("{r} ms")).unwrap_or_else(|| "?".into());
                println!("  out {uri:<28} key={key}.. addr={addr} rtt={rtt} up={uptime}s");
            }
            Direction::Inbound => {
                println!("  in  {:<28} key={key}.. addr={addr} up={uptime}s", "(accepted)");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = parse_args();
    let key_path = args.key.clone().unwrap_or_else(default_key_path);
    let existed = std::path::Path::new(&key_path).exists();
    let seed = load_or_create_seed(&key_path).map_err(|e| format!("key file {key_path}: {e}"))?;
    println!("key:            {key_path}{}", if existed { "" } else { " (new)" });
    if let Some(n) = args.lan_target {
        if !(1..=MAX_TARGET).contains(&n) {
            eprintln!("--lan-target must be between 1 and {MAX_TARGET} (got {n})");
            std::process::exit(2);
        }
    }
    let lan_slots = if args.lan_upstream { args.lan_target.unwrap_or(args.target) } else { 0 };
    let mut ep = Endpoint::new_with_lan(seed, None, args.target, lan_slots);
    // tls:// peers only when this build can dial them.
    ep.set_tls_peers(cfg!(feature = "upstream-tls"));
    let cache_path = peer_cache_path(&key_path);
    let mut peer_rx: Option<mpsc::Receiver<Result<Vec<u8>, String>>> = None;

    match &args.peers {
        Some(path) => {
            let json = std::fs::read(path)?;
            let added = ep.import_peer_list(&json, CandidateSource::Config);
            println!("imported {added} TCP peers from {path}");
        }
        None if args.no_public => {
            println!("peers:          no public list (--no-public): LAN and --peers only");
        }
        None => {
            // No --peers: start with the cached list, download a fresh one in the background.
            if let Ok(json) = std::fs::read(&cache_path) {
                let added = ep.import_peer_list(&json, CandidateSource::Config);
                println!("peers:          {added} from cache {}", cache_path.display());
            }
            println!("peers:          downloading {DEFAULT_PUBLIC_PEERS_URL}");
            let (tx, rx) = mpsc::channel();
            spawn_peer_fetcher(tx);
            peer_rx = Some(rx);
        }
    }
    let allow_keys: Vec<PublicKey> = args.allow.iter().map(|k| parse_key(k)).collect::<Result<_, _>>()?;
    for k in &allow_keys {
        ep.allow_key(*k);
    }
    // Status pages (html build only): overlay page and local dashboard/API.
    let html = html::Html::start(&args, &mut ep)?;

    let forward_map: HashMap<u16, u16> = args.forwards.iter().copied().collect();
    for p in args.open.iter().chain(&args.proxy_ports) {
        if !forward_map.contains_key(p) {
            return Err(format!("--open/--proxy-protocol {p}: not a --forward overlay port").into());
        }
    }
    if !args.open.is_empty() {
        // Public service: clients measure their path to us with echo requests.
        ep.set_ping_any(true);
    }
    for (overlay, local) in &args.forwards {
        if args.open.contains(overlay) {
            ep.tcp_listen_open(*overlay);
            println!("forward:        overlay port {overlay} -> 127.0.0.1:{local} (open to all keys)");
        } else {
            ep.tcp_listen(*overlay);
            println!("forward:        overlay port {overlay} -> 127.0.0.1:{local}");
        }
    }
    let mut connect_listeners: Vec<(TcpListener, Ipv6Addr, u16)> = Vec::new();
    for (lport, addr, port) in &args.connects {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, *lport))
            .map_err(|e| format!("--connect: cannot listen on 127.0.0.1:{lport}: {e}"))?;
        l.set_nonblocking(true)?;
        println!("connect:        127.0.0.1:{lport} -> [{addr}]:{port}");
        connect_listeners.push((l, *addr, *port));
    }

    let addr = Address(ep.address().0);
    println!("device address: {}", Ipv6Addr::from(addr.0));
    println!("public key:     {}", hex(ep.public_key()));
    if lan_slots > 0 {
        println!("outbound peers: {} (--target) + {lan_slots} (LAN)", args.target);
    } else {
        println!("outbound peers: {} (--target)", args.target);
    }
    println!("allowed keys:   {}", args.allow.len());
    println!("web page:       http://[{}]/", Ipv6Addr::from(addr.0));

    let mut rng = OsRng;
    let mut streams: HashMap<usize, Stream> = HashMap::new();
    let mut dialer = Dialer::new();
    let start = Instant::now();
    // Start the protocol clock away from zero, as the library tests do.
    let clock = |start: Instant| CLOCK_BASE + start.elapsed().as_millis() as u64;
    let mut last_status = Instant::now() - Duration::from_secs(10);
    let mut last_snap = Instant::now() - Duration::from_secs(10);
    let mut quality = Quality::new(args.quality_ms);
    let mut overlay = OverlayInfo::default();
    let mut search_probe = Instant::now() - SEARCH_PROBE_INTERVAL;
    let (probe_tx, probe_rx) = mpsc::channel::<(TcpPeerUri, Option<u64>)>();
    let mut probe_pending: usize = 0;
    let mut probe_total: usize = 0;
    let mut probe_ok: usize = 0;
    let mut probe_next = Instant::now();
    let mut first_round = true;
    let probe_start = Instant::now();
    ep.set_dial_enabled(false);
    FWMARK.store(args.fwmark, std::sync::atomic::Ordering::Relaxed);
    let mut search_cfg = SearchConfig { client_limit_ms: args.rtt_limit, ..SearchConfig::default() };
    if let Some(s) = args.swap_interval {
        search_cfg.min_interval_ms = s * 1000;
        search_cfg.max_interval_ms = search_cfg.max_interval_ms.max(s * 1000);
    }
    if let Some(s) = args.swap_settle {
        search_cfg.settle_ms = s * 1000;
    }
    let mut finder = PeerSearch::new(search_cfg);
    // --connect servers: their latency drives the peer search like an allowed key's does.
    // Keyed by address (the key is learned from the first reply).
    let mut targets: Vec<[u8; 16]> = Vec::new();
    for a in args.connects.iter().map(|c| c.1).chain(args.tun_server) {
        if !targets.contains(&a.octets()) {
            targets.push(a.octets());
        }
    }
    let mut target_sent: HashMap<[u8; 16], (u64, ProbeNonce)> = HashMap::new();
    let mut target_keys: Vec<PublicKey> = Vec::new();
    let mut target_rounds: u32 = 0;
    let mut allow_sent: HashMap<PublicKey, (u64, ProbeNonce)> = HashMap::new();
    let mut last_allow_probe = Instant::now() - ALLOW_PROBE_INTERVAL;
    overlay.allow_keys = allow_keys.clone();
    let mut probe_sent: HashMap<PublicKey, (u64, ProbeNonce)> = HashMap::new();
    let mut root_probe: Option<(PublicKey, u64, ProbeNonce)> = None;
    let mut last_probe = Instant::now() - PEER_PROBE_INTERVAL;
    let mut bridges: HashMap<ConnId, Bridge> = HashMap::new();
    let mut bridge_buf = vec![0u8; BRIDGE_CHUNK];
    let mut peer_buf = vec![0u8; 64 * 1024];
    let mut last_send = Instant::now();
    let mut last_send_udp = Instant::now() - Duration::from_secs(5);
    let mut last_ping = Instant::now() - Duration::from_secs(1);
    let mut ping_seq: u16 = 0;
    let mut ping_sent: HashMap<u16, Instant> = HashMap::new();
    let udp_map: HashMap<u16, u16> = args.forwards_udp.iter().copied().collect();
    let mut udp_sessions: HashMap<(PublicKey, u16, u16), UdpSession> = HashMap::new();
    for (overlay, local) in &args.forwards_udp {
        println!("forward udp:    overlay port {overlay} -> 127.0.0.1:{local}");
    }
    let upstream_sock = discovery::open(args.lan_upstream);
    let mut tun_dev = match (&args.tun, &args.tun_ctl) {
        (Some(name), _) => Some(tun::Tun::open(name).map_err(|e| format!("--tun {name}: {e}"))?),
        (None, Some(path)) => Some(tun::Tun::from_ctl(path).map_err(|e| format!("--tun-ctl {path}: {e}"))?),
        _ => None,
    };
    if tun_dev.is_some() {
        ep.set_inbox_cap(4096);
        println!("tun:            bridge up, our address {}/7", Ipv6Addr::from(ep.address().0));
    }
    let mut traffic: HashMap<usize, PeerTraffic> = HashMap::new();
    let mut tun_buf = vec![0u8; 65536];
    let mut tun_dropped: u64 = 0;
    let listener = match args.listen {
        Some(port) => match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
            Ok(l) => {
                l.set_nonblocking(true)?;
                println!("listen:         tcp 0.0.0.0:{port} (inbound, max {MAX_INBOUND})");
                Some(l)
            }
            Err(e) => {
                eprintln!("listen: disabled, cannot bind TCP {port}: {e}");
                None
            }
        },
        None => None,
    };

    // The loop sleeps in poll(2) until a socket is ready or a timer is due. `prev_ready` means
    // the last wait ended because something was ready, so this pass handles input and the next
    // one (no waiting) must flush what that input queued (ACKs, echo replies, TCP output).
    let mut poller = sys::Poller::default();
    let mut ready_slots: HashSet<usize> = HashSet::new();
    let mut prev_ready = true;

    loop {
        // Work found by means other than socket readiness (worker threads, TLS buffers).
        let mut activity = false;
        let now = clock(start);
        let actions = ep.poll(now, &mut rng);
        run(actions, &mut ep, &mut streams, &mut dialer, now);

        // Dials that finished on their worker threads.
        while let Ok(done) = dialer.rx.try_recv() {
            if dialer.inflight.get(&done.slot) != Some(&done.gen) {
                continue; // the slot was closed or dialed again meanwhile: drop the stream
            }
            dialer.inflight.remove(&done.slot);
            activity = true;
            match done.stream {
                Some(stream) => {
                    streams.insert(done.slot, stream);
                    let acts = ep.on_transport_up(done.slot, now);
                    run(acts, &mut ep, &mut streams, &mut dialer, now);
                }
                None => ep.on_transport_failed(done.slot, now),
            }
        }

        // Public peer list from the background fetcher.
        if let Some(rx) = peer_rx.as_ref() {
            while let Ok(res) = rx.try_recv() {
                activity = true;
                match res {
                    Ok(json) => {
                        let added = ep.import_peer_list(&json, CandidateSource::Config);
                        println!(
                            "peers:          downloaded {} bytes, {added} new, {} candidates",
                            json.len(),
                            ep.candidates().len()
                        );
                        save_peer_cache(&cache_path, &json);
                        if added > 0 {
                            probe_next = Instant::now();
                        }
                    }
                    Err(e) => println!(
                        "peers:          download failed ({e}); retry in {} s",
                        PEER_LIST_RETRY.as_secs()
                    ),
                }
            }
        }

        // yggdrasil-go LAN beacons (upstream-tls build): listen only, never send.
        if let Some(sock) = upstream_sock.as_ref() {
            discovery::drain(sock, &mut ep);
        }

        // Inbound TCP peers (only when --listen is set).
        if let Some(l) = listener.as_ref() {
            while let Ok((stream, from)) = l.accept() {
                if streams.len() >= args.target + lan_slots + MAX_INBOUND {
                    drop(stream);
                    continue;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_read_timeout(Some(Duration::from_millis(1)));
                let (slot, acts) = ep.accept_transport(now);
                streams.insert(slot, Stream::Plain(stream));
                run(acts, &mut ep, &mut streams, &mut dialer, now);
                println!("inbound from {from}");
            }
        }

        // Stage 1: TCP-ping every candidate that is not connected yet.
        if probe_pending == 0 && Instant::now() >= probe_next {
            probe_next = Instant::now() + PROBE_INTERVAL;
            let connected: HashSet<String> = ep
                .connected_peers()
                .iter()
                .filter(|p| p.direction == Direction::Outbound)
                .filter_map(|p| p.uri.as_ref().map(|u| u.host_port()))
                .collect();
            let uris: Vec<TcpPeerUri> = ep
                .candidates()
                .into_iter()
                .map(|c| c.uri)
                .filter(|u| !connected.contains(&u.host_port()))
                .collect();
            probe_pending = uris.len();
            probe_total = uris.len();
            probe_ok = 0;
            if probe_pending == 0 {
                if first_round {
                    ep.set_dial_enabled(true);
                    first_round = false;
                }
            } else {
                println!("probe: checking {} candidates", probe_pending);
                spawn_probe_round(uris, &probe_tx);
            }
        }
        while let Ok((uri, rtt)) = probe_rx.try_recv() {
            activity = true;
            if rtt.is_some() {
                probe_ok += 1;
            }
            ep.record_candidate_probe(&uri, rtt);
            probe_pending = probe_pending.saturating_sub(1);
            if probe_pending == 0 {
                println!("probe: done, {probe_ok}/{probe_total} reachable");
            }
        }
        if first_round && (probe_pending == 0 || probe_start.elapsed() >= FIRST_PROBE_MAX_WAIT) {
            ep.set_dial_enabled(true);
            first_round = false;
            println!("probe: first round finished, dialing");
        }

        let slots: Vec<usize> = streams.keys().copied().collect();
        for slot in slots {
            // Only sockets poll reported (and TLS ones, see `buffers_reads`) are read, so idle
            // peers cost no system call and no 1 ms read timeout.
            if !ready_slots.contains(&slot) && !streams.get_mut(&slot).map_or(false, |s| s.has_buffered()) {
                continue;
            }
            // Keep reading while the buffer comes back full: a busy link would
            // otherwise be limited to one buffer per loop pass.
            for _ in 0..8 {
                let read = match streams.get_mut(&slot) {
                    Some(s) => s.read(&mut peer_buf),
                    None => break,
                };
                if matches!(read, Ok(n) if n > 0) {
                    activity = true;
                }
                match read {
                    Ok(0) => {
                        println!("peer slot {slot}: closed by remote (EOF) at {now} ms");
                        streams.remove(&slot);
                        ep.on_transport_closed(slot, now);
                        break;
                    }
                    Ok(n) => {
                        PEER_RX.with(|m| *m.borrow_mut().entry(slot).or_default() += n as u64);
                        let actions = ep.on_bytes(slot, &peer_buf[..n], now, &mut rng);
                        run(actions, &mut ep, &mut streams, &mut dialer, now);
                        if n < peer_buf.len() {
                            break;
                        }
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => break,
                    Err(e) => {
                        println!("peer slot {slot}: read error at {now} ms: {e} ({:?})", e.kind());
                        streams.remove(&slot);
                        ep.on_transport_closed(slot, now);
                        break;
                    }
                }
            }
        }

        while let Some(msg) = ep.recv() {
            // Round trips are measured with the clock read now, not the loop pass's `now`: a pass
            // can take tens of milliseconds on a slow CPU (signature checks), and `now` was read
            // before all of that.
            let rx = clock(start);
            let from = Ipv6Addr::from(msg.from.0);
            if let Some(echo) = icmp::parse_echo(unframe_ipv6(&msg.data)) {
                if echo.kind == ECHO_REPLY && echo.id == QUALITY_ID {
                    match echo.seq {
                        PEER_PROBE_SEQ => {
                            if let Some(sent) = take_probe(&mut probe_sent, &msg.from_key, &echo.payload) {
                                quality.record_rtt(&msg.from_key, rx.saturating_sub(sent));
                                if let Some(rtt) = quality.rtt(&msg.from_key) {
                                    ep.set_link_latency(msg.from_key, rtt);
                                }
                            }
                        }
                        ALLOW_PROBE_SEQ => {
                            if let Some(sent) = take_probe(&mut allow_sent, &msg.from_key, &echo.payload) {
                                let sample = rx.saturating_sub(sent);
                                overlay.allow_rtt.insert(msg.from_key, (sample, rx));
                                finder.record_client(&msg.from_key, sample, rx);
                            }
                        }
                        TARGET_PROBE_SEQ => {
                            let a = addr_for_key(&msg.from_key).0;
                            if let Some((sent, nonce)) = target_sent.get(&a).copied() {
                                if nonce.as_slice() == echo.payload.as_slice() {
                                    target_sent.remove(&a);
                                    let sample = rx.saturating_sub(sent);
                                    if !target_keys.contains(&msg.from_key) {
                                        target_keys.push(msg.from_key);
                                        overlay.allow_keys.push(msg.from_key);
                                    }
                                    overlay.allow_rtt.insert(msg.from_key, (sample, rx));
                                    finder.record_client(&msg.from_key, sample, rx);
                                    if target_rounds % TARGET_REPORT_EVERY == 1 {
                                        let avg = finder.client_rtt(rx).map(|v| format!("{v} ms")).unwrap_or("-".into());
                                        println!("server rtt:     [{}] {sample} ms (avg {avg}, limit {} ms)", Ipv6Addr::from(a), args.rtt_limit);
                                    }
                                }
                            }
                        }
                        ROOT_PROBE_SEQ => {
                            if let Some((root, sent, nonce)) = root_probe {
                                if root == msg.from_key && nonce.as_slice() == echo.payload.as_slice() {
                                    let sample = rx.saturating_sub(sent);
                                    quality.record_root_rtt(sample);
                                    finder.record_root(sample, rx);
                                    root_probe = None;
                                }
                            }
                        }
                        _ => {}
                    }
                    continue;
                }
            }
            if let Some(t) = tun_dev.as_mut() {
                let ip = unframe_ipv6(&msg.data);
                if ip.len() >= 40 && ip[24..40] == ep.address().0[..] && !udp::parse(ip).map_or(false, |d| udp_map.contains_key(&d.dport)) {
                    t.write(ip);
                    continue;
                }
            }
            if let Some(dg) = udp::parse(unframe_ipv6(&msg.data)) {
                if dg.dst == ep.address().0 && udp_map.contains_key(&dg.dport) {
                    udp_inbound(&mut udp_sessions, &udp_map, &msg.from_key, msg.from.0, dg);
                    continue;
                }
            }
            match icmp::parse_echo(unframe_ipv6(&msg.data)) {
                Some(echo) if echo.kind == ECHO_REPLY => {
                    let rtt = ping_sent
                        .remove(&echo.seq)
                        .map(|t| format!("{:.1} ms", t.elapsed().as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| "?".into());
                    println!("reply from {from}: seq={} time={rtt}", echo.seq);
                }
                _ => {
                    let d = &msg.data;
                    let hexs = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
                    let ip = unframe_ipv6(d);
                    if ip.len() >= 48 && ip[0] >> 4 == 6 {
                        println!(
                            "ipv6 from {from}: len={} next={} plen={} icmp_type={} icmp_code={}",
                            ip.len(), ip[6], u16::from_be_bytes([ip[4], ip[5]]), ip[40], ip[41]
                        );
                        println!("  hex: {}", hexs(&d[..d.len().min(160)]));
                    } else {
                        println!("recv from {from}: {} bytes  {}", d.len(), hexs(&d[..d.len().min(64)]));
                    }
                }
            }
        }

        if let Some(dest) = args.ping {
            if last_ping.elapsed() >= Duration::from_secs(1) {
                last_ping = Instant::now();
                ping_seq = ping_seq.wrapping_add(1);
                ping_sent.insert(ping_seq, Instant::now());
                let actions = ep.ping(&Address(dest.octets()), 0x7947, ping_seq, clock(start), &mut rng);
                run(actions, &mut ep, &mut streams, &mut dialer, clock(start));
            }
        }

        if let Some((dest, dport, text)) = &args.send_udp {
            if last_send_udp.elapsed() >= Duration::from_secs(5) {
                last_send_udp = Instant::now();
                let our = ep.address().0;
                let pkt = udp::build(our, dest.octets(), 40000, *dport, text.as_bytes());
                let acts = ep.send_to_address(&Address(dest.octets()), &frame_ipv6(&pkt), clock(start), &mut rng);
                run(acts, &mut ep, &mut streams, &mut dialer, clock(start));
            }
        }

        if let Some((dest, text)) = &args.send {
            if last_send.elapsed() >= Duration::from_secs(10) {
                last_send = Instant::now();
                let actions = ep.send_to_address(&Address(dest.octets()), text.as_bytes(), clock(start), &mut rng);
                run(actions, &mut ep, &mut streams, &mut dialer, clock(start));
            }
        }

        if last_snap.elapsed() >= Duration::from_secs(1) {
            last_snap = Instant::now();
            html.refresh(&mut ep, &quality, &overlay, args.target + lan_slots, clock(start));
            html.set_peers(peer_traffic_json(&ep, &quality, &mut traffic, clock(start)));
        }

        // TCP over the overlay: --forward (remote clients in) and --connect (local clients out).
        for (l, addr, port) in &connect_listeners {
            while let Ok((sock, from)) = l.accept() {
                let _ = sock.set_nodelay(true);
                if sock.set_nonblocking(true).is_err() {
                    continue;
                }
                match ep.tcp_connect(&Address(addr.octets()), *port) {
                    Some(id) => {
                        println!("tcp {id}: {from} -> [{addr}]:{port} connecting");
                        bridges.insert(id, Bridge::new(sock, format!("[{addr}]:{port}")));
                    }
                    None => println!("tcp: connection limit reached, dropping {from}"),
                }
            }
        }
        while let Some(ev) = ep.tcp_event() {
            match ev {
                TcpEvent::Accepted { id, port } => {
                    let local = forward_map.get(&port).copied().unwrap_or(port);
                    let remote = ep.tcp_remote(id);
                    let peer = remote.map(|(a, p)| format!("[{}]:{p}", Ipv6Addr::from(a.0))).unwrap_or_default();
                    match connect_local(local) {
                        Some(sock) => {
                            println!("tcp {id}: {peer} -> overlay port {port} -> 127.0.0.1:{local}");
                            let mut b = Bridge::new(sock, peer);
                            if let (true, Some((a, p))) = (args.proxy_ports.contains(&port), remote) {
                                b.to_local = proxy_v1(Ipv6Addr::from(a.0), Ipv6Addr::from(ep.address().0), p, port).into_bytes();
                            }
                            bridges.insert(id, b);
                        }
                        None => {
                            println!("tcp {id}: cannot connect to 127.0.0.1:{local}, resetting {peer}");
                            ep.tcp_abort(id);
                        }
                    }
                }
                TcpEvent::Connected { id } => {
                    if let Some(b) = bridges.get(&id) {
                        println!("tcp {id}: connected to {}", b.label);
                    }
                }
                TcpEvent::Readable { .. } => {}
                TcpEvent::RemoteFin { id } => {
                    if let Some(b) = bridges.get_mut(&id) {
                        b.remote_eof = true;
                    }
                }
                TcpEvent::Closed { id, reason } => {
                    if let Some(mut b) = bridges.remove(&id) {
                        // Deliver what is still buffered before closing the local side.
                        if reason == CloseReason::Normal {
                            let _ = b.sock.set_nonblocking(false);
                            let _ = b.sock.set_write_timeout(Some(Duration::from_secs(2)));
                            let _ = b.sock.write_all(&b.to_local[b.to_local_off..]);
                        }
                        let _ = b.sock.shutdown(Shutdown::Both);
                        println!("tcp {id}: {} closed ({reason:?})", b.label);
                    }
                }
            }
        }
        let ids: Vec<ConnId> = bridges.keys().copied().collect();
        for id in ids {
            let Some(b) = bridges.get_mut(&id) else { continue };
            if !pump_bridge(&mut ep, id, b, &mut bridge_buf) {
                println!("tcp {id}: local socket failed, resetting {}", b.label);
                bridges.remove(&id);
                ep.tcp_abort(id);
            }
        }

        // UDP forwarding: send local replies back over the overlay; drop idle sessions.
        if !udp_sessions.is_empty() {
            let our = ep.address().0;
            let mut replies: Vec<([u8; 16], u16, u16, Vec<u8>)> = Vec::new();
            let mut buf = [0u8; 2048];
            udp_sessions.retain(|_, s| s.last.elapsed() < UDP_IDLE);
            for s in udp_sessions.values_mut() {
                while let Ok(n) = s.sock.recv(&mut buf) {
                    s.last = Instant::now();
                    if n <= MAX_UDP_PAYLOAD {
                        replies.push((s.client, s.overlay_port, s.client_port, buf[..n].to_vec()));
                    }
                }
            }
            for (client, overlay, client_port, payload) in replies {
                let pkt = udp::build(our, client, overlay, client_port, &payload);
                let acts = ep.send_to_address(&Address(client), &frame_ipv6(&pkt), now, &mut rng);
                run(acts, &mut ep, &mut streams, &mut dialer, now);
            }
        }

        // TUN -> Yggdrasil. Bounded per pass so peers and timers keep their turn.
        if let Some(t) = tun_dev.as_mut() {
            let ours = ep.address().0;
            for _ in 0..512 {
                match t.read(&mut tun_buf) {
                    Ok(Some(n)) => match tun::route(&tun_buf[..n], &ours) {
                        Some(dst) => {
                            let acts = ep.send_packet(&dst, &frame_ipv6(&tun_buf[..n]), now, &mut rng);
                            run(acts, &mut ep, &mut streams, &mut dialer, now);
                        }
                        None => tun_dropped += 1,
                    },
                    Ok(None) => break,
                    Err(e) => return Err(format!("tun read: {e}").into()),
                }
            }
        }

        if last_probe.elapsed() >= PEER_PROBE_INTERVAL {
            last_probe = Instant::now();
            for p in ep.connected_peers().into_iter().filter(|p| p.direction == Direction::Outbound) {
                let nonce = new_nonce(&mut rng);
                let acts = ep.ping_key_payload(&p.key, QUALITY_ID, PEER_PROBE_SEQ, &nonce, now, &mut rng);
                probe_sent.insert(p.key, (clock(start), nonce)); // stamped right before the write
                run(acts, &mut ep, &mut streams, &mut dialer, now);
            }
        }

        if last_allow_probe.elapsed() >= ALLOW_PROBE_INTERVAL {
            last_allow_probe = Instant::now();
            let me = *ep.public_key();
            for k in allow_keys.iter().filter(|k| **k != me) {
                let nonce = new_nonce(&mut rng);
                let acts = ep.ping_payload(&addr_for_key(k), QUALITY_ID, ALLOW_PROBE_SEQ, &nonce, now, &mut rng);
                allow_sent.insert(*k, (clock(start), nonce)); // stamped right before the write
                run(acts, &mut ep, &mut streams, &mut dialer, now);
            }
            target_rounds = target_rounds.wrapping_add(1);
            for a in &targets {
                let nonce = new_nonce(&mut rng);
                let acts = ep.ping_payload(&Address(*a), QUALITY_ID, TARGET_PROBE_SEQ, &nonce, now, &mut rng);
                target_sent.insert(*a, (clock(start), nonce)); // stamped right before the write
                run(acts, &mut ep, &mut streams, &mut dialer, now);
            }
        }

        // Peer search: replace one slow outbound peer at a time (see `yggdrasil_lite::search`).
        // The latency to the allowed keys and --connect servers decides; the root decides only while none
        // answers, and is then re-probed every SEARCH_PROBE_INTERVAL while it is slow.
        {
            let me = *ep.public_key();
            if let Some(o) = finder.take_outcome() {
                let msg = if o.helped {
                    format!("замена помогла: {} -> {} ms", metric_text(o.before), o.after)
                } else {
                    format!(
                        "замена не помогла: {} -> {} ms, следующая не раньше чем через {} с",
                        metric_text(o.before),
                        o.after,
                        o.next_wait_ms / 1000
                    )
                };
                println!("{msg}");
                push_swap(&mut overlay, msg);
            }
            finder.note_healthy(now);
            overlay.searching = finder.probing_root(now);
            let outbound = ep.connected_peers().iter().filter(|p| p.direction == Direction::Outbound).count();
            // Peers that may be replaced: outbound, not found on the LAN, and not an allowed key
            // or a --connect server (connected directly, it is the shortest path there).
            let keep: Vec<PublicKey> = allow_keys.iter().chain(target_keys.iter()).copied().collect();
            let candidates_to_drop = droppable(
                ep.connected_peers()
                    .into_iter()
                    .filter(|p| p.direction == Direction::Outbound && !p.lan)
                    .map(|p| (p.key, quality.rtt(&p.key).or(p.rtt_ms))),
                &keep,
            );
            if let Some(d) = finder.decide(now, &candidates_to_drop, ep.candidates().len() > outbound) {
                let limit = match d.metric {
                    Metric::Client(_) => args.rtt_limit,
                    Metric::Root(_) => ROOT_RTT_LIMIT_MS,
                };
                let msg = format!("{} > {limit} ms: заменён пир {}", metric_text(d.metric), short_key(&d.drop));
                println!("{msg}");
                push_swap(&mut overlay, msg);
                let acts = ep.drop_peer(&d.drop, now, SLOW_PEER_COOLDOWN_MS);
                run(acts, &mut ep, &mut streams, &mut dialer, now);
                quality.forget(&d.drop);
                quality.clear_root_rtt();
                overlay.allow_rtt.clear();
                finder.swapped(now, &d);
            }
            if overlay.searching && root_probe.is_none() && search_probe.elapsed() >= SEARCH_PROBE_INTERVAL {
                if let Some(root) = overlay.root.filter(|r| *r != me) {
                    search_probe = Instant::now();
                    let nonce = new_nonce(&mut rng);
                    let acts = ep.ping_key_payload(&root, QUALITY_ID, ROOT_PROBE_SEQ, &nonce, now, &mut rng);
                    root_probe = Some((root, clock(start), nonce));
                    run(acts, &mut ep, &mut streams, &mut dialer, now);
                }
            }
        }

        if quality.due(now) {
            let peers: Vec<PeerView> = ep
                .connected_peers()
                .into_iter()
                .filter(|p| p.direction == Direction::Outbound)
                .map(|p| {
                    let (root, hops) = match ep.peer_root(&p.key) {
                        Some((r, h)) => (Some(r), h),
                        None => (None, 0),
                    };
                    PeerView { key: p.key, root, hops }
                })
                .collect();
            if !peers.is_empty() {
                let verdict = quality.evaluate(&peers, &ep.root(), now);
                overlay.verdict = Some(verdict.clone());
                overlay.eval_at = Some(now);
                overlay.root = verdict.global_root;
                let root_text = verdict.global_root.map(|r| short_key(&r)).unwrap_or_else(|| "none".into());
                let rtt_text = quality.root_rtt().map(|r| format!("{r} ms")).unwrap_or_else(|| "?".into());
                println!(
                    "quality: global root {root_text} | global {} | other root {} | unknown {} | root rtt {rtt_text}",
                    verdict.global.len(),
                    verdict.foreign.len(),
                    verdict.unknown.len(),
                );
                for k in &verdict.global {
                    let rtt = quality.rtt(k).map(|r| format!("{r} ms")).unwrap_or_else(|| "?".into());
                    println!("  best {} rtt={rtt}", short_key(k));
                }
                for k in &verdict.foreign {
                    println!("  drop {} (other root)", short_key(k));
                    let acts = ep.drop_peer(k, now, FOREIGN_COOLDOWN_MS);
                    run(acts, &mut ep, &mut streams, &mut dialer, now);
                    quality.forget(k);
                }
                if let Some(root) = verdict.global_root {
                    if root != *ep.public_key() {
                        let nonce = new_nonce(&mut rng);
                        let acts = ep.ping_key_payload(&root, QUALITY_ID, ROOT_PROBE_SEQ, &nonce, now, &mut rng);
                        root_probe = Some((root, clock(start), nonce));
                        run(acts, &mut ep, &mut streams, &mut dialer, now);
                    }
                }
            }
        }

        if last_status.elapsed() >= Duration::from_secs(10) {
            last_status = Instant::now();
            print_peers(&ep, streams.len(), clock(start));
            if tun_dropped > 0 {
                println!("tun:            {tun_dropped} packet(s) dropped (not to 200::/7, or not from our address)");
                tun_dropped = 0;
            }
        }

        // Wait for the next event instead of waking on a fixed period: a ready socket ends the
        // wait at once (so echo replies are timed when they arrive, not on the next tick), and
        // otherwise the earliest timer decides. The cap covers the periodic jobs above and the
        // worker threads, which report over channels that poll cannot see.
        // Decrypted TLS data that poll cannot see (it arrived with the end of the handshake, or
        // the read buffer filled up) is handled on the next pass.
        if streams.values_mut().any(|s| s.has_buffered()) {
            activity = true;
        }
        let wait_ms = if prev_ready || activity {
            0
        } else {
            let mut w = IDLE_WAIT_MS;
            if let Some(at) = ep.tcp_next_timer() {
                // `.max(1)`: a timer that stays due must never turn the loop into a spin.
                w = w.min(at.saturating_sub(clock(start)).max(1));
            }
            if first_round || probe_pending > 0 {
                w = w.min(PROBE_WAIT_MS);
            }
            if !dialer.inflight.is_empty() {
                w = w.min(DIAL_WAIT_MS); // dial workers report over a channel
            }
            w
        };
        poller.clear();
        let stream_idx: Vec<(usize, usize)> =
            streams.iter().map(|(slot, s)| (*slot, poller.add(s.raw_fd(), sys::IN))).collect();
        if let Some(l) = listener.as_ref() {
            poller.add(l.as_raw_fd(), sys::IN);
        }
        for (l, _, _) in &connect_listeners {
            poller.add(l.as_raw_fd(), sys::IN);
        }
        if let Some(s) = upstream_sock.as_ref() {
            poller.add(s.as_raw_fd(), sys::IN);
        }
        if let Some(t) = tun_dev.as_ref() {
            poller.add(t.raw_fd(), sys::IN);
        }
        for s in udp_sessions.values() {
            poller.add(s.sock.as_raw_fd(), sys::IN);
        }
        // A bridge wants input only while the overlay send buffer has room (otherwise a readable
        // socket would end every wait at once) and output only while bytes wait for the local side.
        for (id, b) in &bridges {
            let mut events = 0;
            if !b.local_eof && ep.tcp_send_space(*id) > 0 {
                events |= sys::IN;
            }
            if b.to_local_off < b.to_local.len() {
                events |= sys::OUT;
            }
            poller.add(b.sock.as_raw_fd(), events);
        }
        poller.wait(wait_ms);
        prev_ready = poller.any_ready();
        ready_slots.clear();
        ready_slots.extend(stream_idx.into_iter().filter(|(_, i)| poller.ready(*i)).map(|(slot, _)| slot));
    }
}


/// PROXY protocol v1 header. The source address is the one the endpoint checked against the
/// sender's key, so the local program can trust it.
fn proxy_v1(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> String {
    format!("PROXY TCP6 {src} {dst} {sport} {dport}\r\n")
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn proxy_v1_line() {
        let src: Ipv6Addr = "200:5d4:942c:661:7c2f:6725:af1c:eb0c".parse().unwrap();
        let dst: Ipv6Addr = "201::1".parse().unwrap();
        assert_eq!(proxy_v1(src, dst, 40000, 8787), "PROXY TCP6 200:5d4:942c:661:7c2f:6725:af1c:eb0c 201::1 40000 8787\r\n");
    }
}

thread_local! {
    /// Bytes read from / written to each peer transport slot (main loop thread only).
    static PEER_RX: std::cell::RefCell<HashMap<usize, u64>> = std::cell::RefCell::new(HashMap::new());
    static PEER_TX: std::cell::RefCell<HashMap<usize, u64>> = std::cell::RefCell::new(HashMap::new());
}

/// Per-peer traffic of the current session on a slot, for `/api/peers`.
#[derive(Default)]
#[cfg_attr(not(feature = "html"), allow(dead_code))]
struct PeerTraffic {
    /// Session this entry belongs to (`PeerInfo::up_ms`); a new session restarts the counts.
    up_ms: u64,
    rx_base: u64,
    tx_base: u64,
    last_rx: u64,
    last_tx: u64,
    last_at: u64,
    /// Smoothed rates, bytes per second.
    rx_bps: f64,
    tx_bps: f64,
}

/// `/api/peers`: connected peers with session traffic, current rates and their share of the
/// node's traffic right now (the peer carrying most of it is where the traffic goes).
#[cfg_attr(not(feature = "html"), allow(dead_code))]
fn peer_traffic_json(ep: &Endpoint, quality: &Quality, traffic: &mut HashMap<usize, PeerTraffic>, now: u64) -> String {
    let peers = ep.connected_peers();
    let (rx_all, tx_all) = (PEER_RX.with(|m| m.borrow().clone()), PEER_TX.with(|m| m.borrow().clone()));
    traffic.retain(|slot, _| peers.iter().any(|p| p.slot == *slot));
    let mut rows = Vec::new();
    for p in &peers {
        let (rx, tx) = (rx_all.get(&p.slot).copied().unwrap_or(0), tx_all.get(&p.slot).copied().unwrap_or(0));
        let t = traffic.entry(p.slot).or_default();
        if t.up_ms != p.up_ms || t.last_at == 0 {
            *t = PeerTraffic { up_ms: p.up_ms, rx_base: rx, tx_base: tx, last_rx: rx, last_tx: tx, last_at: now, ..Default::default() };
        } else if now > t.last_at {
            let dt = (now - t.last_at) as f64 / 1000.0;
            let (r, w) = ((rx - t.last_rx) as f64 / dt, (tx - t.last_tx) as f64 / dt);
            t.rx_bps = t.rx_bps * 0.5 + r * 0.5;
            t.tx_bps = t.tx_bps * 0.5 + w * 0.5;
            t.last_rx = rx;
            t.last_tx = tx;
            t.last_at = now;
        }
        rows.push((p, rx - t.rx_base, tx - t.tx_base, t.rx_bps, t.tx_bps));
    }
    let total: f64 = rows.iter().map(|r| r.3 + r.4).sum();
    let mut out = String::from("{\"peers\":[");
    for (i, (p, rx, tx, rbps, tbps)) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let uri = p.uri.as_ref().map(|u| u.to_string()).unwrap_or_default().replace('\\', "").replace('"', "");
        let rtt = quality.rtt(&p.key).or(p.rtt_ms).map(|v| v.to_string()).unwrap_or("null".into());
        let share = if total > 0.0 { ((rbps + tbps) / total * 100.0).round() } else { 0.0 };
        out.push_str(&format!(
            "{{\"key\":\"{}\",\"address\":\"{}\",\"uri\":\"{uri}\",\"dir\":\"{}\",\"lan\":{},\"rtt_ms\":{rtt},\"up_s\":{},\"rx\":{rx},\"tx\":{tx},\"rx_bps\":{},\"tx_bps\":{},\"share\":{share}}}",
            hex(&p.key),
            Ipv6Addr::from(p.address.0),
            if p.direction == Direction::Outbound { "out" } else { "in" },
            p.lan,
            now.saturating_sub(p.up_ms) / 1000,
            *rbps as u64,
            *tbps as u64,
        ));
    }
    out.push_str(&format!("],\"rx_bps\":{},\"tx_bps\":{}}}", rows.iter().map(|r| r.3).sum::<f64>() as u64, rows.iter().map(|r| r.4).sum::<f64>() as u64));
    out
}

/// Analysis state shown on the overlay status page (read only by the html build).
#[derive(Default)]
#[cfg_attr(not(feature = "html"), allow(dead_code))]
struct OverlayInfo {
    verdict: Option<Verdict>,
    /// Protocol time of the last evaluation.
    eval_at: Option<u64>,
    /// Recent peer replacements, newest last.
    swaps: Vec<String>,
    /// Allowed clients (from --allow), in the order given.
    allow_keys: Vec<PublicKey>,
    /// Latest echo round trip to each allowed client's address: (rtt ms, protocol time of sample).
    allow_rtt: HashMap<PublicKey, (u64, u64)>,
    /// Root of the global network from the last evaluation.
    root: Option<PublicKey>,
    /// True while the root decides the peer search and is above its limit: it is re-probed.
    searching: bool,
}

/// "клиент 220 ms" / "корень 350 ms": the latency that decided a peer replacement.
fn metric_text(m: Metric) -> String {
    match m {
        Metric::Client(r) => format!("до клиента/сервера {r} ms"),
        Metric::Root(r) => format!("корень {r} ms"),
    }
}

/// Keep the last few peer replacements for the status page.
fn push_swap(overlay: &mut OverlayInfo, msg: String) {
    overlay.swaps.push(msg);
    if overlay.swaps.len() > 5 {
        overlay.swaps.remove(0);
    }
}

#[cfg(test)]
mod probe_nonce_tests {
    use super::*;

    #[test]
    fn reply_counts_only_with_matching_nonce() {
        let key = [3u8; 32];
        let mut map: HashMap<PublicKey, (u64, ProbeNonce)> = HashMap::new();
        map.insert(key, (1_000, [1, 2, 3, 4, 5, 6, 7, 8]));

        // A reply that does not echo the nonce is ignored and leaves the probe pending.
        assert_eq!(take_probe(&mut map, &key, &[0u8; 8]), None);
        assert!(map.contains_key(&key));

        // The matching echo completes it once.
        assert_eq!(take_probe(&mut map, &key, &[1, 2, 3, 4, 5, 6, 7, 8]), Some(1_000));
        assert_eq!(take_probe(&mut map, &key, &[1, 2, 3, 4, 5, 6, 7, 8]), None);
    }
}
