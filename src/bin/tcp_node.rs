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
//! Only keys given with `--allow` can connect, and only the listed ports are open.
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
//! The device answers ICMPv6 echo requests from allowed keys automatically and
//! serves a small HTML page on TCP port 80 (`--html FILE` replaces the default).
//! Open it from a yggstack/yggdrasil node that is allowed: its SOCKS5 proxy at
//! 127.0.0.1:1080 with `curl -x socks5h://127.0.0.1:1080 http://[<device-address>]/`.
//! `--ping` sends one echo request per second to an address and prints replies
//! with round-trip times.
//!
//! The overlay page on port 80 shows the same stats, refreshed every second
//! (unless `--html FILE` replaces it).
//!
//! `--api ADDR` starts a status server (for example `--api 127.0.0.1:8080`):
//! `GET /` serves a dashboard, `GET /api/stats` returns the same JSON as the
//! ESP32 firmware. Bind to 127.0.0.1 unless you want the API on your network:
//! it has no authentication.
//!
//! The key file is created on first run (64 hex chars). Keep it private: it
//! determines the device's address.

use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

extern crate alloc;

// The status API model is shared with the ESP32 firmware (pure Rust, no hardware deps).
#[path = "../../examples/esp32/src/api_model.rs"]
#[allow(dead_code)]
mod api_model;
use api_model::{to_json, NetState, PeerState, PeerStat, DASHBOARD_HTML, MAX_PEERS};

/// Protocol clock starts here (matches the library tests).
const CLOCK_BASE: u64 = 1_000;

/// Upper bound for `--target`: each outbound slot is a TCP connection and a TLS session.
const MAX_TARGET: usize = 32;

/// Echo `id` used for quality probes (peer latency and root checks).
const QUALITY_ID: u16 = 0x5155;
/// Echo `seq` for a probe to a connected peer, and for a probe to the global root.
const PEER_PROBE_SEQ: u16 = 1;
const ROOT_PROBE_SEQ: u16 = 2;
/// Echo `seq` for a probe to an allowed client's overlay address.
const ALLOW_PROBE_SEQ: u16 = 3;
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

/// TCP connect time to the candidate's address over the regular internet, or `None` on failure.
fn probe_tcp(uri: &TcpPeerUri) -> Option<u64> {
    let addr = match uri.expected_key().and_then(|k| lan_scoped_addr(&k)) {
        Some(sa) => SocketAddr::V6(sa),
        None => uri.host_port().to_socket_addrs().ok()?.next()?,
    };
    let t0 = Instant::now();
    let stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
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
    html: Option<String>,
    api: Option<String>,
    quality_ms: u64,
    /// (overlay port, local port) pairs from `--forward`.
    forwards: Vec<(u16, u16)>,
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

const DEFAULT_PAGE: &str = "<!doctype html>
<html><head><meta charset=\"utf-8\"><title>yggdrasil-lite</title></head>
<body style=\"font-family:sans-serif\">
<h1>yggdrasil-lite device</h1>
<p>Этот узел работает через Yggdrasil.</p>
</body></html>
";

const USAGE: &str = "usage: tcp_node [options]

With no options the node creates or loads its key (./ygg.key, else ~/ygg.key),
downloads the public peer list and connects.

  --key FILE                identity file (created on first run)
  --peers FILE              local peer list instead of the public one
  --no-public               do not download the public peer list
  --target N                outbound peers to keep (1..=32, default 3)
  --allow HEXKEY            key allowed to use forwards, ping and the page (repeatable)
  --forward PORT[:LOCAL],.. expose local TCP ports over Yggdrasil
  --connect LPORT:[ADDR]:PORT
                            carry 127.0.0.1:LPORT to [ADDR]:PORT over Yggdrasil
  --forward-udp PORT[:LOCAL],..  expose local UDP ports
  --api ADDR                status dashboard and /api/stats (loopback only)
  --html FILE               page served on overlay port 80
  --ping IPV6               echo request every second
  --send IPV6 MESSAGE       datagram every 10 s (test aid)
  --send-udp IPV6 PORT MSG  UDP datagram every 5 s (test aid)
  --quality-interval SECS   network re-check interval (default 300)
  --listen PORT             accept plain TCP peers on this port
  --lan-upstream            dial yggdrasil-go LAN peers (needs upstream-tls build)
  --lan-target N            outbound slots for LAN peers";

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
    let mut a = Args { key: None, connects: Vec::new(), peers: None, allow: Vec::new(), target: 3, send: None, ping: None, html: None, api: None, quality_ms: DEFAULT_RECHECK_MS, forwards: Vec::new(), forwards_udp: Vec::new(), send_udp: None, lan_upstream: false, no_public: false, listen: None, lan_target: None };
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
            "--html" => a.html = Some(it.next().unwrap_or_else(|| usage())),
            "--api" => a.api = Some(it.next().unwrap_or_else(|| usage())),
            "--forward" => {
                let spec = it.next().unwrap_or_else(|| usage());
                for part in spec.split(',') {
                    a.forwards.push(parse_forward(part.trim()).unwrap_or_else(|e| {
                        eprintln!("--forward: {e}");
                        std::process::exit(2);
                    }));
                }
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
/// Wait cap with TLS peers, whose buffered bytes poll cannot see.
const TLS_WAIT_MS: u64 = 10;

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

/// Minimal `poll(2)` binding. std has no readiness API and libc is already linked by std,
/// so declaring the one function avoids a new dependency (the binary keeps `rand` + `heapless`).
mod sys {
    use super::RawFd;
    use std::os::raw::{c_int, c_ulong};
    use std::time::Duration;

    pub const IN: i16 = 0x001;
    pub const OUT: i16 = 0x004;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    extern "C" {
        fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
    }

    /// A reusable set of descriptors to wait on.
    #[derive(Default)]
    pub struct Poller {
        fds: Vec<PollFd>,
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
            self.fds.push(PollFd { fd, events, revents: 0 });
            self.fds.len() - 1
        }

        /// Block for at most `timeout_ms` until a descriptor is ready.
        pub fn wait(&mut self, timeout_ms: u64) {
            for f in &mut self.fds {
                f.revents = 0;
            }
            let timeout = timeout_ms.min(c_int::MAX as u64) as c_int;
            // SAFETY: `fds` points at `len` initialized `PollFd` (repr(C), the layout of
            // `struct pollfd`) and stays borrowed for the whole call.
            let r = unsafe { poll(self.fds.as_mut_ptr(), self.fds.len() as c_ulong, timeout) };
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
    Tls(Box<native_tls::TlsStream<TcpStream>>),
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
            Stream::Tls(s) => s.get_ref().as_raw_fd(),
        }
    }

    /// TLS keeps decrypted bytes in its own buffer, which the socket's readiness does not
    /// show, so such streams are read on every pass.
    fn buffers_reads(&self) -> bool {
        match self {
            Stream::Plain(_) => false,
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(_) => true,
        }
    }

    fn shutdown(&mut self) {
        match self {
            Stream::Plain(s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            #[cfg(feature = "upstream-tls")]
            Stream::Tls(s) => {
                let _ = s.shutdown();
                let _ = s.get_ref().shutdown(Shutdown::Both);
            }
        }
    }
}

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

fn lan_scoped_addr(key: &PublicKey) -> Option<SocketAddrV6> {
    LAN_SCOPED.lock().ok()?.iter().find(|(k, _)| k == key).map(|(_, a)| *a)
}

/// Open a connection for a candidate. Upstream LAN peers go over TLS to their scoped address;
/// everything else is a plain TCP connection as before.
fn dial_slot(uri: &TcpPeerUri) -> Option<Stream> {
    if let Some(key) = uri.expected_key() {
        if let Some(sa) = lan_scoped_addr(&key) {
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
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
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
    use std::error::Error;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    /// Dial over TLS (system OpenSSL via native-tls). The certificate and hostname are not
    /// checked, as yggdrasil-go does (InsecureSkipVerify); peer identity comes from the signed
    /// meta-handshake that follows. TLS 1.2 is the minimum, TLS 1.3 is used when both sides support it.
    pub fn connect(addr: SocketAddr, name: &str) -> Result<Stream, Box<dyn Error>> {
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        let _ = tcp.set_nodelay(true);
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));

        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
            .build()?;
        // The name is used for SNI only: the certificate is not verified.
        let tls = connector
            .connect(name, tcp)
            .map_err(|e| format!("TLS handshake: {e}"))?;
        // Polled mode for the main loop: reads return after 1 ms when there is no data.
        let _ = tls.get_ref().set_read_timeout(Some(Duration::from_millis(1)));
        Ok(Stream::Tls(Box::new(tls)))
    }
}

fn run(actions: Vec<Action>, ep: &mut Endpoint, streams: &mut HashMap<usize, Stream>, now: u64) {
    let mut queue: VecDeque<Action> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            Action::Dial { slot, uri } => match dial_slot(&uri) {
                Some(stream) => {
                    streams.insert(slot, stream);
                    queue.extend(ep.on_transport_up(slot, now));
                }
                None => ep.on_transport_failed(slot, now),
            },
            Action::Write { slot, data } => {
                if let Some(s) = streams.get_mut(&slot) {
                    if let Err(e) = s.write_all(&data) {
                        eprintln!("write to slot {slot} failed: {e} ({:?})", e.kind());
                        streams.remove(&slot);
                        ep.on_transport_closed(slot, now);
                    }
                }
            }
            Action::Close { slot } => {
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
    let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, UPSTREAM_BEACON_PORT))
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
    if args.lan_upstream && !cfg!(feature = "upstream-tls") {
        eprintln!("--lan-upstream needs a build with `--features upstream-tls`");
        std::process::exit(2);
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
    let page = match &args.html {
        Some(path) => std::fs::read(path)?,
        None => DEFAULT_PAGE.as_bytes().to_vec(),
    };
    ep.serve_http(page);

    let shared: Arc<Mutex<NetState>> = Arc::new(Mutex::new(NetState::new()));
    if let Some(addr) = &args.api {
        let sock: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| format!("--api: invalid address {addr}: {e}"))?;
        if !sock.ip().is_loopback() {
            return Err(format!("--api must bind to loopback (127.0.0.1 or [::1]), got {addr}").into());
        }
        let listener = TcpListener::bind(sock)?;
        println!("status API:     http://{addr}/  (JSON: /api/stats)");
        let shared = shared.clone();
        std::thread::spawn(move || serve_api(listener, shared));
    }

    let forward_map: HashMap<u16, u16> = args.forwards.iter().copied().collect();
    for (overlay, local) in &args.forwards {
        ep.tcp_listen(*overlay);
        println!("forward:        overlay port {overlay} -> 127.0.0.1:{local}");
    }
    let mut connect_listeners: Vec<(TcpListener, Ipv6Addr, u16)> = Vec::new();
    for (lport, addr, port) in &args.connects {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, *lport))
            .map_err(|e| format!("--connect: cannot listen on 127.0.0.1:{lport}: {e}"))?;
        l.set_nonblocking(true)?;
        println!("connect:        127.0.0.1:{lport} -> [{addr}]:{port}");
        connect_listeners.push((l, *addr, *port));
    }
    if forward_map.contains_key(&80) {
        println!("note: overlay port 80 is forwarded, so the overlay status page is not served");
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
    let mut finder = PeerSearch::new(SearchConfig::default());
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
    let upstream_sock = if args.lan_upstream {
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
    } else {
        None
    };
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
        run(actions, &mut ep, &mut streams, now);

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

        // yggdrasil-go LAN beacons: listen only, never send. Each beacon's source is a link-local
        // address whose scope id is the interface; keep it so we can dial that exact address.
        if let Some(sock) = upstream_sock.as_ref() {
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
                run(acts, &mut ep, &mut streams, now);
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
            if !ready_slots.contains(&slot) && !streams.get(&slot).map_or(false, Stream::buffers_reads) {
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
                        let actions = ep.on_bytes(slot, &peer_buf[..n], now, &mut rng);
                        run(actions, &mut ep, &mut streams, now);
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
            let from = Ipv6Addr::from(msg.from.0);
            if let Some(echo) = icmp::parse_echo(unframe_ipv6(&msg.data)) {
                if echo.kind == ECHO_REPLY && echo.id == QUALITY_ID {
                    match echo.seq {
                        PEER_PROBE_SEQ => {
                            if let Some(sent) = take_probe(&mut probe_sent, &msg.from_key, &echo.payload) {
                                quality.record_rtt(&msg.from_key, now.saturating_sub(sent));
                                if let Some(rtt) = quality.rtt(&msg.from_key) {
                                    ep.set_link_latency(msg.from_key, rtt);
                                }
                            }
                        }
                        ALLOW_PROBE_SEQ => {
                            if let Some(sent) = take_probe(&mut allow_sent, &msg.from_key, &echo.payload) {
                                let sample = now.saturating_sub(sent);
                                overlay.allow_rtt.insert(msg.from_key, (sample, now));
                                finder.record_client(&msg.from_key, sample, now);
                            }
                        }
                        ROOT_PROBE_SEQ => {
                            if let Some((root, sent, nonce)) = root_probe {
                                if root == msg.from_key && nonce.as_slice() == echo.payload.as_slice() {
                                    let sample = now.saturating_sub(sent);
                                    quality.record_root_rtt(sample);
                                    finder.record_root(sample, now);
                                    root_probe = None;
                                }
                            }
                        }
                        _ => {}
                    }
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
                run(actions, &mut ep, &mut streams, clock(start));
            }
        }

        if let Some((dest, dport, text)) = &args.send_udp {
            if last_send_udp.elapsed() >= Duration::from_secs(5) {
                last_send_udp = Instant::now();
                let our = ep.address().0;
                let pkt = udp::build(our, dest.octets(), 40000, *dport, text.as_bytes());
                let acts = ep.send_to_address(&Address(dest.octets()), &frame_ipv6(&pkt), clock(start), &mut rng);
                run(acts, &mut ep, &mut streams, clock(start));
            }
        }

        if let Some((dest, text)) = &args.send {
            if last_send.elapsed() >= Duration::from_secs(10) {
                last_send = Instant::now();
                let actions = ep.send_to_address(&Address(dest.octets()), text.as_bytes(), clock(start), &mut rng);
                run(actions, &mut ep, &mut streams, clock(start));
            }
        }

        if last_snap.elapsed() >= Duration::from_secs(1) {
            last_snap = Instant::now();
            let snap = snapshot(&ep, clock(start));
            // Overlay page (port 80 over Yggdrasil): the live stats, unless the user gave --html.
            if args.html.is_none() {
                ep.serve_http(status_page(&ep, &quality, &overlay, args.target + lan_slots, clock(start)).into_bytes());
            }
            if args.api.is_some() {
                *shared.lock().unwrap() = snap;
            }
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
                    let peer = ep.tcp_remote(id).map(|(a, p)| format!("[{}]:{p}", Ipv6Addr::from(a.0))).unwrap_or_default();
                    match connect_local(local) {
                        Some(sock) => {
                            println!("tcp {id}: {peer} -> overlay port {port} -> 127.0.0.1:{local}");
                            bridges.insert(id, Bridge::new(sock, peer));
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
                run(acts, &mut ep, &mut streams, now);
            }
        }

        if last_probe.elapsed() >= PEER_PROBE_INTERVAL {
            last_probe = Instant::now();
            for p in ep.connected_peers().into_iter().filter(|p| p.direction == Direction::Outbound) {
                let nonce = new_nonce(&mut rng);
                probe_sent.insert(p.key, (now, nonce));
                let acts = ep.ping_key_payload(&p.key, QUALITY_ID, PEER_PROBE_SEQ, &nonce, now, &mut rng);
                run(acts, &mut ep, &mut streams, now);
            }
        }

        if last_allow_probe.elapsed() >= ALLOW_PROBE_INTERVAL {
            last_allow_probe = Instant::now();
            let me = *ep.public_key();
            for k in allow_keys.iter().filter(|k| **k != me) {
                let nonce = new_nonce(&mut rng);
                allow_sent.insert(*k, (now, nonce));
                let acts = ep.ping_payload(&addr_for_key(k), QUALITY_ID, ALLOW_PROBE_SEQ, &nonce, now, &mut rng);
                run(acts, &mut ep, &mut streams, now);
            }
        }

        // Peer search: replace one slow outbound peer at a time (see `yggdrasil_lite::search`).
        // The latency to the allowed keys decides; the root decides only while no allowed key
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
            // (an allowed key connected directly is the shortest path to that client).
            let candidates_to_drop = droppable(
                ep.connected_peers()
                    .into_iter()
                    .filter(|p| p.direction == Direction::Outbound && !p.lan)
                    .map(|p| (p.key, quality.rtt(&p.key).or(p.rtt_ms))),
                &allow_keys,
            );
            if let Some(d) = finder.decide(now, &candidates_to_drop, ep.candidates().len() > outbound) {
                let limit = match d.metric {
                    Metric::Client(_) => CLIENT_RTT_LIMIT_MS,
                    Metric::Root(_) => ROOT_RTT_LIMIT_MS,
                };
                let msg = format!("{} > {limit} ms: заменён пир {}", metric_text(d.metric), short_key(&d.drop));
                println!("{msg}");
                push_swap(&mut overlay, msg);
                let acts = ep.drop_peer(&d.drop, now, SLOW_PEER_COOLDOWN_MS);
                run(acts, &mut ep, &mut streams, now);
                quality.forget(&d.drop);
                quality.clear_root_rtt();
                overlay.allow_rtt.clear();
                finder.swapped(now, &d);
            }
            if overlay.searching && root_probe.is_none() && search_probe.elapsed() >= SEARCH_PROBE_INTERVAL {
                if let Some(root) = overlay.root.filter(|r| *r != me) {
                    search_probe = Instant::now();
                    let nonce = new_nonce(&mut rng);
                    root_probe = Some((root, now, nonce));
                    let acts = ep.ping_key_payload(&root, QUALITY_ID, ROOT_PROBE_SEQ, &nonce, now, &mut rng);
                    run(acts, &mut ep, &mut streams, now);
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
                    run(acts, &mut ep, &mut streams, now);
                    quality.forget(k);
                }
                if let Some(root) = verdict.global_root {
                    if root != *ep.public_key() {
                        let nonce = new_nonce(&mut rng);
                        root_probe = Some((root, now, nonce));
                        let acts = ep.ping_key_payload(&root, QUALITY_ID, ROOT_PROBE_SEQ, &nonce, now, &mut rng);
                        run(acts, &mut ep, &mut streams, now);
                    }
                }
            }
        }

        if last_status.elapsed() >= Duration::from_secs(10) {
            last_status = Instant::now();
            print_peers(&ep, streams.len(), clock(start));
        }

        // Wait for the next event instead of waking on a fixed period: a ready socket ends the
        // wait at once (so echo replies are timed when they arrive, not on the next tick), and
        // otherwise the earliest timer decides. The cap covers the periodic jobs above and the
        // worker threads, which report over channels that poll cannot see.
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
            if streams.values().any(Stream::buffers_reads) {
                w = w.min(TLS_WAIT_MS);
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


/// Analysis state shown on the overlay status page.
#[derive(Default)]
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

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Slowest connected outbound peer by measured latency (falls back to the pool estimate).
/// "клиент 220 ms" / "корень 350 ms": the latency that decided a peer replacement.
fn metric_text(m: Metric) -> String {
    match m {
        Metric::Client(r) => format!("клиент {r} ms"),
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

/// Live update for the overlay status page: re-fetch the page every 2 s and swap the body in place.
/// The overlay server answers any request with the current page, so no extra endpoint is needed.
const STATUS_SCRIPT: &str = r#"<script>
(function () {
  var busy = false;
  function setUpd(text) {
    var el = document.getElementById('upd');
    if (el) { el.textContent = text; }
  }
  function tick() {
    if (busy) { return; }
    busy = true;
    fetch(location.href, { cache: 'no-store' })
      .then(function (r) { return r.text(); })
      .then(function (t) {
        var doc = new DOMParser().parseFromString(t, 'text/html');
        document.body.innerHTML = doc.body.innerHTML;
        renderSpeed();
        setUpd('обновлено ' + new Date().toLocaleTimeString());
      })
      .catch(function () { setUpd('нет связи, повтор...'); })
      .then(function () { busy = false; });
  }
  var speedText = 'не запускался';
  var speedBusy = false;
  function renderSpeed() {
    var el = document.getElementById('speed');
    if (el) { el.textContent = speedText; }
  }
  window.runSpeed = function () {
    if (speedBusy) { return; }
    speedBusy = true;
    speedText = 'измерение...';
    renderSpeed();
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 20000);
    var t0 = performance.now();
    fetch('/speed?' + Date.now(), { cache: 'no-store', signal: ctrl.signal })
      .then(function (r) { return r.arrayBuffer(); })
      .then(function (buf) {
        var sec = (performance.now() - t0) / 1000;
        var mbit = buf.byteLength * 8 / sec / 1e6;
        speedText = mbit.toFixed(2) + ' Мбит/с (' + buf.byteLength + ' байт за ' + sec.toFixed(1) + ' с)';
      })
      .catch(function () { speedText = 'не удалось: таймаут или обрыв канала'; })
      .then(function () { clearTimeout(timer); speedBusy = false; renderSpeed(); });
  };
  setInterval(tick, 2000);
})();
</script>"#;

/// HTML status page for the overlay port 80: every `--target` slot, root summary, replacement log.
fn status_page(ep: &Endpoint, quality: &Quality, info: &OverlayInfo, target: usize, now: u64) -> String {
    let outbound: Vec<_> = ep
        .connected_peers()
        .into_iter()
        .filter(|p| p.direction == Direction::Outbound)
        .collect();

    let root_line = match quality.root_rtt() {
        Some(r) if r > ROOT_RTT_LIMIT_MS => format!("<span class=\"bad\">{r} ms (больше {ROOT_RTT_LIMIT_MS} ms)</span>"),
        Some(r) => format!("<span class=\"ok\">{r} ms</span>"),
        None => "нет измерения".into(),
    };
    let (root_text, global_n, foreign_n, unknown_n, eval_text) = match &info.verdict {
        Some(v) => (
            v.global_root.map(|r| short_key(&r)).unwrap_or_else(|| "нет".into()),
            v.global.len(),
            v.foreign.len(),
            v.unknown.len(),
            info.eval_at
                .map(|t| format!("{} с назад", now.saturating_sub(t) / 1000))
                .unwrap_or_default(),
        ),
        None => ("ещё не оценено".into(), 0, 0, 0, String::new()),
    };

    let mut rows = String::new();
    for p in &outbound {
        let uri = p.uri.as_ref().map(|u| u.to_string()).unwrap_or_else(|| "?".into());
        let rtt = quality
            .rtt(&p.key)
            .or(p.rtt_ms)
            .map(|r| format!("{r} ms"))
            .unwrap_or_else(|| "?".into());
        let net = match info.verdict.as_ref() {
            Some(v) if v.global.contains(&p.key) => "главный корень",
            Some(v) if v.foreign.contains(&p.key) => "чужой корень",
            Some(_) => "ожидание",
            None => "—",
        };
        let up = now.saturating_sub(p.up_ms) / 1000;
        rows.push_str(&format!(
            "<tr><td>{}</td><td><code>{}…</code></td><td>{}</td><td>{}</td><td>{} с</td><td class=\"ok\">подключён</td></tr>\n",
            esc(&uri),
            short_key(&p.key),
            rtt,
            net,
            up
        ));
    }
    for _ in outbound.len()..target {
        rows.push_str("<tr><td colspan=\"6\" class=\"dim\">слот свободен: подбирается кандидат</td></tr>\n");
    }

    let mut allow_rows = String::new();
    for k in &info.allow_keys {
        let addr = Ipv6Addr::from(addr_for_key(k).0);
        let (rtt_cell, status) = match info.allow_rtt.get(k) {
            Some((r, at)) => {
                let age = now.saturating_sub(*at) / 1000;
                let cls = if *r > CLIENT_RTT_LIMIT_MS { "bad" } else { "ok" };
                let st = if *r > CLIENT_RTT_LIMIT_MS { "высокий" } else { "в норме" };
                (format!("<span class=\"{cls}\">{r} ms</span> ({age} с назад)"), st)
            }
            None => ("нет ответа".into(), "клиент не отвечает на echo"),
        };
        allow_rows.push_str(&format!(
            "<tr><td><code>{}…</code></td><td><code>{addr}</code></td><td>{rtt_cell}</td><td>{status}</td></tr>\n",
            short_key(k)
        ));
    }
    if allow_rows.is_empty() {
        allow_rows.push_str("<tr><td colspan=\"4\" class=\"dim\">разрешённых клиентов нет (--allow)</td></tr>\n");
    }

    let swaps: String = if info.swaps.is_empty() {
        "<p class=\"dim\">замен не было</p>".into()
    } else {
        let items: String = info.swaps.iter().rev().map(|s| format!("<li>{}</li>", esc(s))).collect();
        format!("<ul>{items}</ul>")
    };

    format!(
        "<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
{script}<title>yggdrasil-lite</title>\
<style>body{{font-family:sans-serif;margin:1.5em;color:#222}}table{{border-collapse:collapse;width:100%;font-size:14px}}\
td,th{{border:1px solid #ccc;padding:4px 6px;text-align:left}}.ok{{color:#080}}.bad{{color:#c00;font-weight:bold}}\
.dim{{color:#888}}code{{font-size:12px}}</style></head><body>\
<h1>yggdrasil-lite</h1>\
<p>адрес: <code>{addr}</code><br>ключ: <code>{pk}…</code></p>\
<p class=\"dim\" id=\"upd\">загрузка данных…</p>\
<h2>Сводка до корня</h2>\
<table>\
<tr><th>корень сети</th><td><code>{root_text}</code></td></tr>\
<tr><th>пинг до корня</th><td>{root_line}</td></tr>\
<tr><th>пиры на главном корне</th><td>{global_n}</td></tr>\
<tr><th>на чужом корне</th><td>{foreign_n}</td></tr>\
<tr><th>не определены</th><td>{unknown_n}</td></tr>\
<tr><th>порог замены</th><td>клиент {CLIENT_RTT_LIMIT_MS} ms (приоритет), корень {ROOT_RTT_LIMIT_MS} ms (если клиенты не отвечают)</td></tr>\
<tr><th>последняя оценка</th><td>{eval_text}</td></tr>\
</table>\
<h2>Пиры (--target {target})</h2>\
<table><tr><th>адрес</th><th>ключ</th><th>RTT</th><th>сеть</th><th>аптайм</th><th>статус</th></tr>\n{rows}</table>\
<h2>Разрешённые клиенты (адрес до клиента)</h2>\
<table><tr><th>ключ</th><th>адрес</th><th>RTT</th><th>статус</th></tr>\n{allow_rows}</table>\
<h2>Тест скорости (канал до узла)</h2>\
<p><button onclick=\"runSpeed()\">Тест скорости (256 КБ)</button> <span id=\"speed\">не запускался</span></p>\
<h2>Замены пиров</h2>{swaps}\
</body></html>",
        addr = Ipv6Addr::from(ep.address().0),
        pk = short_key(ep.public_key()),
        script = STATUS_SCRIPT,
    )
}

/// Build the status snapshot from the endpoint: node counters plus up to
/// `MAX_PEERS` peer slots (connected outbound peers first, then candidates).
fn snapshot(ep: &Endpoint, now: u64) -> NetState {
    let mut st = NetState::new();
    st.node.device = false;
    st.node.uptime_ms = now.saturating_sub(CLOCK_BASE);
    st.node.ipv6 = ep.address().0;
    st.node.listen_port = 80; // overlay HTTP page
    st.node.public_key = *ep.public_key();
    st.node.root = ep.root();
    st.node.coords = ep.coords();
    st.node.sessions = ep.session_count();
    st.node.paths = ep.path_count();

    let mut slot = 0;
    let mut shown: Vec<String> = Vec::new();
    for p in ep.connected_peers().into_iter().filter(|p| p.direction == Direction::Outbound) {
        if slot >= MAX_PEERS {
            break;
        }
        // host:port only: the key is shown in its own field and can exceed the address buffer.
        let uri = p.uri.map(|u| u.host_port()).unwrap_or_default();
        let ps = &mut st.peers[slot];
        let _ = ps.addr.push_str(&uri);
        ps.key = Some(p.key);
        ps.state = PeerState::Up;
        ps.rtt_ms = p.rtt_ms.map(|r| r as u32);
        ps.up_since_ms = Some(p.up_ms.saturating_sub(CLOCK_BASE));
        shown.push(uri);
        slot += 1;
    }
    for c in ep.candidates() {
        if slot >= MAX_PEERS {
            break;
        }
        let uri = c.uri.host_port();
        if shown.contains(&uri) {
            continue;
        }
        let ps: &mut PeerStat = &mut st.peers[slot];
        let _ = ps.addr.push_str(&uri);
        ps.state = if c.failures > 0 { PeerState::Failed } else { PeerState::Idle };
        ps.rtt_ms = c.rtt_ms.map(|r| r as u32);
        // Every failure was a failed attempt; the pool does not count attempts separately.
        ps.attempts = c.failures;
        ps.failures = c.failures;
        slot += 1;
    }
    st
}

/// Accept connections and answer each on its own thread.
fn serve_api(listener: TcpListener, shared: Arc<Mutex<NetState>>) {
    for conn in listener.incoming().flatten() {
        let shared = shared.clone();
        std::thread::spawn(move || handle_api_conn(conn, &shared));
    }
}

fn handle_api_conn(mut conn: TcpStream, shared: &Mutex<NetState>) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 1024];
    let n = conn.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    let (status, ctype, body): (&str, &str, String) = match (method, path) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.to_string()),
        ("GET", "/api/stats") => {
            let st = shared.lock().unwrap();
            ("200 OK", "application/json", to_json(&st))
        }
        ("GET", _) => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string()),
        _ => ("405 Method Not Allowed", "text/plain; charset=utf-8", "method not allowed\n".to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.write_all(resp.as_bytes());
}

#[cfg(test)]
mod status_page_tests {
    use super::*;

    #[test]
    fn renders_all_target_slots_and_root_summary() {
        let ep = Endpoint::new([7u8; 32], None, 3);
        let q = Quality::new(DEFAULT_RECHECK_MS);
        let mut info = OverlayInfo::default();
        info.swaps.push("корень 200 ms > 150 ms: заменён пир 0a0b0c0d".into());
        let html = status_page(&ep, &q, &info, 3, 5_000);
        assert_eq!(html.matches("слот свободен").count(), 3);
        assert!(html.contains("Сводка до корня"));
        assert!(html.contains("setInterval"));
        assert!(!html.contains("http-equiv"));
        assert!(html.contains("id=\"upd\""));
        assert!(html.contains("замены"), "{html}");
        assert!(html.contains("разрешённых клиентов нет"));

        let mut info2 = OverlayInfo::default();
        let client = [9u8; 32];
        info2.allow_keys.push(client);
        info2.allow_rtt.insert(client, (220, 4_000));
        let html2 = status_page(&ep, &q, &info2, 3, 5_000);
        assert!(html2.contains("220 ms"));
        assert!(html2.contains("высокий"));
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
