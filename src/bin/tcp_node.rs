//! Runnable yggdrasil-lite device for a Unix host (Termux, Linux, OpenWrt).
//!
//! Dials out to public TCP peers, keeps its identity in a key file, accepts
//! datagrams only from allowed keys, and can send a periodic test message.
//!
//! Usage:
//!   tcp_node --key ~/ygg.key --peers ~/peers.json --allow <hex-key> \
//!            [--target 3] [--ping <ipv6>] [--send <ipv6> <message>]
//!
//! `--forward PORT[:LOCAL]` (repeatable, comma-separated) lets allowed nodes reach
//! TCP ports on this host over Yggdrasil: `--forward 22` maps overlay port 22 to
//! 127.0.0.1:22, `--forward 2222:22` maps overlay port 2222 to 127.0.0.1:22.
//! Only keys given with `--allow` can connect, and only the listed ports are open.
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
use std::net::{Ipv6Addr, Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

extern crate alloc;

// The status API model is shared with the ESP32 firmware (pure Rust, no hardware deps).
#[path = "../../examples/esp32/src/api_model.rs"]
#[allow(dead_code)]
mod api_model;
use api_model::{overlay_page, to_json, NetState, PeerState, PeerStat, DASHBOARD_HTML, MAX_PEERS};

/// Protocol clock starts here (matches the library tests).
const CLOCK_BASE: u64 = 1_000;

/// Upper bound for `--target`: each outbound slot is a TCP connection and a TLS session.
const MAX_TARGET: usize = 32;

/// Echo `id` used for quality probes (peer latency and root checks).
const QUALITY_ID: u16 = 0x5155;
/// Echo `seq` for a probe to a connected peer, and for a probe to the global root.
const PEER_PROBE_SEQ: u16 = 1;
const ROOT_PROBE_SEQ: u16 = 2;
/// How often each connected peer is pinged for its latency.
const PEER_PROBE_INTERVAL: Duration = Duration::from_secs(10);
/// A peer dropped for being on another root is not redialed for this long.
const FOREIGN_COOLDOWN_MS: u64 = 30 * 60 * 1000;

use rand::rngs::OsRng;
use rand::RngCore;
use yggdrasil_lite::icmp::{self, ECHO_REPLY};
use yggdrasil_lite::forward::{self, Event as FwdEvent};
use yggdrasil_lite::quality::{PeerView, Quality, DEFAULT_RECHECK_MS};
use yggdrasil_lite::{unframe_ipv6, Action, Address, CandidateSource, Direction, Endpoint, PublicKey};

struct Args {
    key: String,
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
}

const DEFAULT_PAGE: &str = "<!doctype html>
<html><head><meta charset=\"utf-8\"><title>yggdrasil-lite</title></head>
<body style=\"font-family:sans-serif\">
<h1>yggdrasil-lite device</h1>
<p>Этот узел работает через Yggdrasil.</p>
</body></html>
";

fn usage() -> ! {
    eprintln!("usage: tcp_node --key FILE [--peers FILE] [--allow HEXKEY]... [--target N] [--ping IPV6] [--send IPV6 MESSAGE] [--html FILE] [--api ADDR] [--quality-interval SECS] [--forward PORT[:LOCAL],...]");
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut a = Args { key: String::new(), peers: None, allow: Vec::new(), target: 3, send: None, ping: None, html: None, api: None, quality_ms: DEFAULT_RECHECK_MS, forwards: Vec::new() };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--key" => a.key = it.next().unwrap_or_else(|| usage()),
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
            "--ping" => a.ping = Some(it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())),
            "--send" => {
                let addr = it.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
                let msg = it.next().unwrap_or_else(|| usage());
                a.send = Some((addr, msg));
            }
            _ => usage(),
        }
    }
    if a.key.is_empty() {
        usage();
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
    let _ = s.set_read_timeout(Some(Duration::from_millis(1)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    Some(s)
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

/// Read the 32-byte seed from `path`, creating it with fresh randomness if absent.
fn load_or_create_seed(path: &str) -> Result<[u8; 32], Box<dyn Error>> {
    match std::fs::read_to_string(path) {
        Ok(text) => unhex(text.trim())?
            .try_into()
            .map_err(|_| "key file must hold 32 bytes (64 hex chars)".into()),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            std::fs::write(path, hex(&seed))?;
            Ok(seed)
        }
        Err(e) => Err(e.into()),
    }
}

/// Execute actions, feeding transport results back into the endpoint.
fn run(actions: Vec<Action>, ep: &mut Endpoint, streams: &mut HashMap<usize, TcpStream>, now: u64) {
    let mut queue: VecDeque<Action> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            Action::Dial { slot, uri } => {
                let addr = uri.host_port().to_socket_addrs().ok().and_then(|mut it| it.next());
                let stream = addr.and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).ok());
                match stream {
                    Some(s) => {
                        let _ = s.set_nodelay(true);
                        // Blocking writes with a timeout; reads poll with a short timeout.
                        let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                        let _ = s.set_read_timeout(Some(Duration::from_millis(1)));
                        streams.insert(slot, s);
                        queue.extend(ep.on_transport_up(slot, now));
                    }
                    None => ep.on_transport_failed(slot, now),
                }
            }
            Action::Write { slot, data } => {
                if let Some(s) = streams.get_mut(&slot) {
                    if s.write_all(&data).is_err() {
                        streams.remove(&slot);
                        ep.on_transport_closed(slot, now);
                    }
                }
            }
            Action::Close { slot } => {
                if let Some(s) = streams.remove(&slot) {
                    let _ = s.shutdown(Shutdown::Both);
                }
            }
        }
    }
}

/// First 4 bytes of a key, as hex, for logs.
fn short_key(k: &PublicKey) -> String {
    k.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

/// Print the connected peers as a table: direction, endpoint, key, address, RTT, uptime.
fn print_peers(ep: &Endpoint, sockets: usize, now: u64) {
    let peers = ep.connected_peers();
    println!("peers: {}  sockets: {}", peers.len(), sockets);
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
    let seed = load_or_create_seed(&args.key)?;
    let mut ep = Endpoint::new(seed, None, args.target);

    if let Some(path) = &args.peers {
        let json = std::fs::read(path)?;
        let added = ep.import_peer_list(&json, CandidateSource::Config);
        println!("imported {added} TCP peers from {path}");
    }
    for k in &args.allow {
        ep.allow_key(parse_key(k)?);
    }
    let page = match &args.html {
        Some(path) => std::fs::read(path)?,
        None => DEFAULT_PAGE.as_bytes().to_vec(),
    };
    ep.serve_http(page);

    let shared: Arc<Mutex<NetState>> = Arc::new(Mutex::new(NetState::new()));
    if let Some(addr) = &args.api {
        let listener = TcpListener::bind(addr)?;
        println!("status API:     http://{addr}/  (JSON: /api/stats)");
        let shared = shared.clone();
        std::thread::spawn(move || serve_api(listener, shared));
    }

    let forward_map: HashMap<u16, u16> = args.forwards.iter().copied().collect();
    let forward_ports: Vec<u16> = args.forwards.iter().map(|(o, _)| *o).collect();
    ep.set_forward_ports(&forward_ports);
    for (overlay, local) in &args.forwards {
        println!("forward:        overlay port {overlay} -> 127.0.0.1:{local}");
    }
    if forward_ports.contains(&80) {
        println!("note: overlay port 80 is forwarded, so the overlay status page is not served");
    }

    let addr = Address(ep.address().0);
    println!("device address: {}", Ipv6Addr::from(addr.0));
    println!("public key:     {}", hex(ep.public_key()));
    println!("outbound peers: {} (--target)", args.target);
    println!("allowed keys:   {}", args.allow.len());
    println!("web page:       http://[{}]/", Ipv6Addr::from(addr.0));

    let mut rng = OsRng;
    let mut streams: HashMap<usize, TcpStream> = HashMap::new();
    let start = Instant::now();
    // Start the protocol clock away from zero, as the library tests do.
    let clock = |start: Instant| CLOCK_BASE + start.elapsed().as_millis() as u64;
    let mut last_status = Instant::now() - Duration::from_secs(10);
    let mut last_snap = Instant::now() - Duration::from_secs(10);
    let mut quality = Quality::new(args.quality_ms);
    let mut probe_sent: HashMap<PublicKey, u64> = HashMap::new();
    let mut root_probe: Option<(PublicKey, u64)> = None;
    let mut last_probe = Instant::now() - PEER_PROBE_INTERVAL;
    let mut fwd_streams: HashMap<u32, TcpStream> = HashMap::new();
    let mut fwd_eof: HashSet<u32> = HashSet::new();
    let mut last_send = Instant::now();
    let mut last_ping = Instant::now() - Duration::from_secs(1);
    let mut ping_seq: u16 = 0;
    let mut ping_sent: HashMap<u16, Instant> = HashMap::new();

    loop {
        let now = clock(start);
        let actions = ep.poll(now, &mut rng);
        run(actions, &mut ep, &mut streams, now);

        let slots: Vec<usize> = streams.keys().copied().collect();
        for slot in slots {
            let mut buf = [0u8; 4096];
            let read = match streams.get_mut(&slot) {
                Some(s) => s.read(&mut buf),
                None => continue,
            };
            match read {
                Ok(0) => {
                    streams.remove(&slot);
                    ep.on_transport_closed(slot, now);
                }
                Ok(n) => {
                    let actions = ep.on_bytes(slot, &buf[..n], now, &mut rng);
                    run(actions, &mut ep, &mut streams, now);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(_) => {
                    streams.remove(&slot);
                    ep.on_transport_closed(slot, now);
                }
            }
        }

        while let Some(msg) = ep.recv() {
            let from = Ipv6Addr::from(msg.from.0);
            if let Some(echo) = icmp::parse_echo(unframe_ipv6(&msg.data)) {
                if echo.kind == ECHO_REPLY && echo.id == QUALITY_ID {
                    match echo.seq {
                        PEER_PROBE_SEQ => {
                            if let Some(sent) = probe_sent.remove(&msg.from_key) {
                                quality.record_rtt(&msg.from_key, now.saturating_sub(sent));
                            }
                        }
                        ROOT_PROBE_SEQ => {
                            if let Some((root, sent)) = root_probe {
                                if root == msg.from_key {
                                    quality.record_root_rtt(now.saturating_sub(sent));
                                    root_probe = None;
                                }
                            }
                        }
                        _ => {}
                    }
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
                ep.serve_http(overlay_page(&to_json(&snap)).into_bytes());
            }
            if args.api.is_some() {
                *shared.lock().unwrap() = snap;
            }
        }

        // Port forwarding: open local sockets for remote clients and move bytes both ways.
        while let Some(ev) = ep.forward_event() {
            match ev {
                FwdEvent::Open { id, port } => {
                    let local = forward_map.get(&port).copied().unwrap_or(port);
                    match connect_local(local) {
                        Some(s) => {
                            fwd_streams.insert(id, s);
                        }
                        None => {
                            println!("forward: cannot connect to 127.0.0.1:{local}");
                            ep.forward_abort(id);
                        }
                    }
                }
                FwdEvent::Data { id, data } => {
                    let failed = match fwd_streams.get_mut(&id) {
                        Some(s) => s.write_all(&data).is_err(),
                        None => true,
                    };
                    if failed {
                        fwd_streams.remove(&id);
                        fwd_eof.remove(&id);
                        ep.forward_abort(id);
                    }
                }
                FwdEvent::RemoteFin { id } => {
                    if let Some(s) = fwd_streams.get(&id) {
                        let _ = s.shutdown(Shutdown::Write);
                    }
                }
                FwdEvent::Closed { id } => {
                    if let Some(s) = fwd_streams.remove(&id) {
                        let _ = s.shutdown(Shutdown::Both);
                    }
                    fwd_eof.remove(&id);
                }
            }
        }
        let ids: Vec<u32> = fwd_streams.keys().copied().collect();
        for id in ids {
            // Read only when the queue has room for a full chunk: nothing is dropped.
            if fwd_eof.contains(&id) || ep.forward_queued(id) > forward::SEND_QUEUE_MAX - forward::MAX_WRITE {
                continue;
            }
            let mut buf = [0u8; forward::MAX_WRITE];
            let read = match fwd_streams.get_mut(&id) {
                Some(s) => s.read(&mut buf),
                None => continue,
            };
            match read {
                Ok(0) => {
                    // Local side finished sending. Keep the socket for the reverse direction.
                    fwd_eof.insert(id);
                    ep.forward_close(id);
                }
                Ok(n) => {
                    ep.forward_write(id, &buf[..n]);
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                Err(_) => {
                    fwd_streams.remove(&id);
                    fwd_eof.remove(&id);
                    ep.forward_abort(id);
                }
            }
        }

        if last_probe.elapsed() >= PEER_PROBE_INTERVAL {
            last_probe = Instant::now();
            for p in ep.connected_peers().into_iter().filter(|p| p.direction == Direction::Outbound) {
                probe_sent.insert(p.key, now);
                let acts = ep.ping_key(&p.key, QUALITY_ID, PEER_PROBE_SEQ, now, &mut rng);
                run(acts, &mut ep, &mut streams, now);
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
                        root_probe = Some((root, now));
                        let acts = ep.ping_key(&root, QUALITY_ID, ROOT_PROBE_SEQ, now, &mut rng);
                        run(acts, &mut ep, &mut streams, now);
                    }
                }
            }
        }

        if last_status.elapsed() >= Duration::from_secs(10) {
            last_status = Instant::now();
            print_peers(&ep, streams.len(), clock(start));
        }

        // Shorter sleep while forwarded sessions are open, so bytes are not delayed.
        std::thread::sleep(Duration::from_millis(if fwd_streams.is_empty() { 100 } else { 5 }));
    }
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
