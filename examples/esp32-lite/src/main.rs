//! Light ESP32 Yggdrasil node.
//!
//! What it does:
//! - joins Wi-Fi (station) and opens its own AP "YggLite" (192.168.4.1);
//! - connects to up to 3 plain-TCP Yggdrasil peers (`tcp://`, IPv4 literals);
//! - serves a status page on the overlay (port 80, reachable over Yggdrasil);
//! - serves a status page, JSON and a send form on the local network (port 80);
//! - sends a text message to an IPv6 address (`/send`) and keeps the last
//!   received messages (`/inbox`).
//!
//! Compared with `examples/esp32`: no TLS, no UART bridge, no flash
//! configuration. Settings come from `.cargo/config.toml` at build time.
//!
//! Layout: one driver task owns the Yggdrasil endpoint and moves its actions
//! to the peer tasks. Each peer slot task owns one TCP socket. The local HTTP
//! server runs on both the AP and the station.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::fmt::Write as _;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_net::{IpListenEndpoint, Ipv4Cidr, Runner, StackResources, StaticConfigV4, tcp::TcpSocket};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, TrySendError};
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer};
use embedded_io_async::Write as AsyncWrite;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{clock::CpuClock, interrupt::software::SoftwareInterruptControl, rng::Rng, timer::timg::TimerGroup};
use esp_hal_dhcp_server::simple_leaser::SimpleDhcpLeaser;
use esp_hal_dhcp_server::structs::DhcpServerConfig;
use esp_println::println;
use esp_radio::wifi::{
    ModeConfig, WifiController, WifiDevice, WifiEvent, ap::AccessPointConfig, sta::StationConfig,
};
use heapless::Deque;
use rand_core::RngCore;

use yggdrasil_lite::address::Address;
use yggdrasil_lite::{Action, CandidateSource, Endpoint, Received, TcpPeerUri};

// The status JSON and page are shared with the full firmware and the Termux build.
#[path = "../../esp32/src/api_model.rs"]
#[allow(dead_code)]
mod api_model;
use api_model::{NetState, PeerState, PeerStat, DASHBOARD_HTML, MAX_PEERS, overlay_page, to_json};

esp_bootloader_esp_idf::esp_app_desc!();

// ============================================================================
// Configuration (from .cargo/config.toml [env])
// ============================================================================

const DEFAULT_WIFI_SSID: &str = env!("WIFI_SSID");
const DEFAULT_WIFI_PASSWORD: &str = env!("WIFI_PASSWORD");
const DEFAULT_YGG_PEER1: &str = env!("YGG_PEER1");
const DEFAULT_YGG_PEER2: &str = env!("YGG_PEER2");
const DEFAULT_YGG_PEER3: &str = env!("YGG_PEER3");
/// Optional fixed seed (64 hex chars). Without it the address changes on every boot.
const FIXED_YGG_SEED: Option<&str> = option_env!("YGG_SEED");

const AP_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const DHCP_POOL_START: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 10);
const DHCP_POOL_END: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 100);
const HTTP_PORT: u16 = 80;

/// Peer slots = concurrent outbound TCP connections.
const MAX_SLOTS: usize = 3;
/// Messages kept for `/inbox`.
const INBOX_CAP: usize = 8;
/// Bytes kept per inbox message.
const INBOX_MSG_MAX: usize = 120;

// ============================================================================
// Shared state
// ============================================================================

static WIFI_CONNECTED: AtomicBool = AtomicBool::new(false);
static STA_IP: Mutex<CriticalSectionRawMutex, Option<Ipv4Addr>> = Mutex::new(None);

/// The endpoint. Locked by the driver task and by the HTTP and peer tasks.
static EP: Mutex<CriticalSectionRawMutex, Option<Endpoint>> = Mutex::new(None);
/// Actions produced by peer tasks and HTTP handlers, waiting for the driver.
static QUEUE: Mutex<CriticalSectionRawMutex, Vec<Action>> = Mutex::new(Vec::new());
/// Last status snapshot, read by `/api/stats`.
static NET: Mutex<CriticalSectionRawMutex, NetState> = Mutex::new(NetState::new());
/// Received messages, read by `/inbox`.
static INBOX: Mutex<CriticalSectionRawMutex, Deque<InboxMsg, INBOX_CAP>> = Mutex::new(Deque::new());

/// Per slot: dial request (IPv4 address and port).
const SIG_DIAL: Signal<CriticalSectionRawMutex, (Ipv4Addr, u16)> = Signal::new();
static DIAL: [Signal<CriticalSectionRawMutex, (Ipv4Addr, u16)>; MAX_SLOTS] = [SIG_DIAL; MAX_SLOTS];
/// Per slot: close request.
const SIG_CLOSE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static CLOSE: [Signal<CriticalSectionRawMutex, ()>; MAX_SLOTS] = [SIG_CLOSE; MAX_SLOTS];
/// Per slot: bytes to write to the socket.
const CH_OUT: Channel<CriticalSectionRawMutex, Vec<u8>, 8> = Channel::new();
static OUT: [Channel<CriticalSectionRawMutex, Vec<u8>, 8>; MAX_SLOTS] = [CH_OUT; MAX_SLOTS];

#[derive(Clone, Copy)]
struct InboxMsg {
    from: [u8; 16],
    len: usize,
    data: [u8; INBOX_MSG_MAX],
}

fn uptime_ms() -> u64 {
    Instant::now().as_millis()
}

// ============================================================================
// RNG (hardware)
// ============================================================================

struct EspRng;

impl rand_core::RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        Rng::new().random()
    }

    fn next_u64(&mut self) -> u64 {
        let rng = Rng::new();
        (rng.random() as u64) << 32 | rng.random() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let rng = Rng::new();
        for chunk in dest.chunks_mut(4) {
            let random = rng.random().to_le_bytes();
            let len = chunk.len().min(4);
            chunk.copy_from_slice(&random[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EspRng {}

// ============================================================================
// Driver: endpoint polling and action dispatch
// ============================================================================

#[embassy_executor::task]
async fn driver() {
    let mut rng = EspRng;
    // Writes that did not fit into a slot channel yet, kept in order.
    let mut pending: [VecDeque<Vec<u8>>; MAX_SLOTS] = Default::default();
    let mut last_snapshot = 0u64;

    loop {
        Timer::after(Duration::from_millis(10)).await;
        let now = uptime_ms();

        let mut actions: Vec<Action> = core::mem::take(&mut *QUEUE.lock().await);
        let mut failed_dials: Vec<usize> = Vec::new();
        {
            let mut guard = EP.lock().await;
            if let Some(ep) = guard.as_mut() {
                actions.extend(ep.poll(now, &mut rng));
                while let Some(msg) = ep.recv() {
                    push_inbox(&msg).await;
                }
                if now.saturating_sub(last_snapshot) >= 1000 {
                    last_snapshot = now;
                    let snap = snapshot(ep, now).await;
                    let json = to_json(&snap);
                    *NET.lock().await = snap;
                    ep.serve_http(overlay_page(&json).into_bytes());
                }
            }
        }

        for action in actions {
            match action {
                Action::Dial { slot, uri } => match parse_dial(&uri) {
                    Some(addr) => DIAL[slot].signal(addr),
                    None => {
                        println!("peer {} skipped: IPv4 literal host:port required", uri.host_port());
                        failed_dials.push(slot);
                    }
                },
                Action::Write { slot, data } => {
                    let queue = &mut pending[slot];
                    queue.push_back(data);
                }
                Action::Close { slot } => CLOSE[slot].signal(()),
            }
        }

        if !failed_dials.is_empty() {
            let mut guard = EP.lock().await;
            if let Some(ep) = guard.as_mut() {
                for slot in failed_dials {
                    ep.on_transport_failed(slot, now);
                }
            }
        }

        // Deliver pending writes. A full channel keeps the rest for the next tick.
        for (slot, queue) in pending.iter_mut().enumerate() {
            while let Some(data) = queue.pop_front() {
                match OUT[slot].try_send(data) {
                    Ok(()) => {}
                    Err(TrySendError::Full(data)) => {
                        queue.push_front(data);
                        break;
                    }
                }
            }
        }
    }
}

/// Our address of a peer: IPv4 literal and port from `host:port`.
fn parse_dial(uri: &TcpPeerUri) -> Option<(Ipv4Addr, u16)> {
    let hp = uri.host_port();
    let (host, port) = hp.rsplit_once(':')?;
    Some((host.parse().ok()?, port.parse().ok()?))
}

/// Queue endpoint actions from a peer or HTTP task for the driver.
async fn queue_actions(actions: Vec<Action>) {
    if !actions.is_empty() {
        QUEUE.lock().await.extend(actions);
    }
}

async fn push_inbox(msg: &Received) {
    let mut m = InboxMsg { from: msg.from.0, len: 0, data: [0u8; INBOX_MSG_MAX] };
    let n = msg.data.len().min(INBOX_MSG_MAX);
    m.data[..n].copy_from_slice(&msg.data[..n]);
    m.len = n;
    let mut inbox = INBOX.lock().await;
    if inbox.is_full() {
        inbox.pop_front();
    }
    let _ = inbox.push_back(m);
}

/// Build the status snapshot from the endpoint.
async fn snapshot(ep: &Endpoint, now: u64) -> NetState {
    let mut st = NetState::new();
    st.node.device = true;
    st.node.uptime_ms = now;
    st.node.ipv6 = ep.address().0;
    st.node.listen_port = HTTP_PORT;
    st.node.public_key = *ep.public_key();
    st.node.root = ep.root();
    st.node.coords = ep.coords();
    st.node.sessions = ep.session_count();
    st.node.paths = ep.path_count();
    st.node.wifi_connected = WIFI_CONNECTED.load(Ordering::Relaxed);
    st.node.sta_ip = (*STA_IP.lock().await).map(|ip| ip.octets());
    st.node.uart_connected = false;
    st.node.heap_free = esp_alloc::HEAP.free();
    st.node.heap_used = esp_alloc::HEAP.used();

    let mut slot = 0;
    let mut shown: Vec<String> = Vec::new();
    for p in ep.connected_peers() {
        if slot >= MAX_PEERS || p.direction != yggdrasil_lite::Direction::Outbound {
            continue;
        }
        let uri = p.uri.map(|u| u.host_port()).unwrap_or_default();
        let ps: &mut PeerStat = &mut st.peers[slot];
        let _ = ps.addr.push_str(&uri);
        ps.key = Some(p.key);
        ps.state = PeerState::Up;
        ps.rtt_ms = p.rtt_ms.map(|r| r as u32);
        ps.up_since_ms = Some(p.up_ms);
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
        ps.attempts = c.failures;
        ps.failures = c.failures;
        slot += 1;
    }
    st
}

// ============================================================================
// Peer slot task: one TCP socket per outbound peer
// ============================================================================

#[embassy_executor::task(pool_size = MAX_SLOTS)]
async fn peer_slot(stack: embassy_net::Stack<'static>, slot: usize) {
    let mut rx = [0u8; 1536];
    let mut tx = [0u8; 1536];
    let mut buf = [0u8; 512];

    loop {
        let addr = DIAL[slot].wait().await;
        CLOSE[slot].reset();
        while OUT[slot].try_receive().is_ok() {}

        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(30)));
        if socket.connect(addr).await.is_err() {
            println!("peer {}:{} connect failed", addr.0, addr.1);
            let mut guard = EP.lock().await;
            if let Some(ep) = guard.as_mut() {
                ep.on_transport_failed(slot, uptime_ms());
            }
            continue;
        }

        let up = {
            let mut guard = EP.lock().await;
            match guard.as_mut() {
                Some(ep) => ep.on_transport_up(slot, uptime_ms()),
                None => Vec::new(),
            }
        };
        queue_actions(up).await;

        let mut rng = EspRng;
        loop {
            // Read from the peer, write what the driver sends, or stop on close.
            match select(socket.read(&mut buf), select(OUT[slot].receive(), CLOSE[slot].wait())).await {
                Either::First(Ok(0)) | Either::First(Err(_)) => break,
                Either::First(Ok(n)) => {
                    let actions = {
                        let mut guard = EP.lock().await;
                        match guard.as_mut() {
                            Some(ep) => ep.on_bytes(slot, &buf[..n], uptime_ms(), &mut rng),
                            None => Vec::new(),
                        }
                    };
                    queue_actions(actions).await;
                }
                Either::Second(Either::First(data)) => {
                    if socket.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Either::Second(Either::Second(())) => break,
            }
        }

        socket.abort();
        let _ = socket.flush().await;
        let mut guard = EP.lock().await;
        if let Some(ep) = guard.as_mut() {
            ep.on_transport_closed(slot, uptime_ms());
        }
    }
}

// ============================================================================
// Local HTTP server (AP and station): status page, JSON, send, inbox
// ============================================================================

#[embassy_executor::task(pool_size = 2)]
async fn http_server(stack: embassy_net::Stack<'static>, name: &'static str) {
    let mut rx_buffer = [0u8; 2048];
    let mut tx_buffer = [0u8; 2048];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(30)));

        if let Err(e) = socket
            .accept(IpListenEndpoint { addr: None, port: HTTP_PORT })
            .await
        {
            log::error!("[{}] HTTP accept error: {:?}", name, e);
            Timer::after(Duration::from_millis(1000)).await;
            continue;
        }

        let _ = handle_http(&mut socket).await;
        socket.close();
        Timer::after(Duration::from_millis(100)).await;
        socket.abort();
    }
}

async fn handle_http(socket: &mut TcpSocket<'_>) -> Result<(), embassy_net::tcp::Error> {
    let mut buffer = [0u8; 1024];
    let mut pos = 0;

    loop {
        match socket.read(&mut buffer[pos..]).await {
            Ok(0) => return Ok(()),
            Ok(len) => {
                pos += len;
                if buffer[..pos].windows(4).any(|w| w == b"\r\n\r\n") || pos >= buffer.len() {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }

    let request = core::str::from_utf8(&buffer[..pos]).unwrap_or("");
    let (method, target) = parse_request_line(request);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    let response = match (method, path) {
        ("GET", "/") => http_ok("text/html; charset=utf-8", &index_page()),
        ("GET", "/api/stats") => {
            let body = to_json(&NET.lock().await);
            http_ok("application/json", &body)
        }
        ("GET", "/inbox") => http_ok("application/json", &inbox_json().await),
        ("GET", "/send") => send_message(query).await,
        ("GET", _) => http_status("404 Not Found", "text/plain", "not found\n"),
        _ => http_status("405 Method Not Allowed", "text/plain", "method not allowed\n"),
    };
    socket.write_all(response.as_bytes()).await
}

fn http_ok(content_type: &str, body: &str) -> String {
    http_status_with("200 OK", content_type, body)
}

fn http_status(status: &str, content_type: &str, body: &str) -> String {
    http_status_with(status, content_type, body)
}

fn http_status_with(status: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// `GET /send?to=<ipv6>&msg=<text>`
async fn send_message(query: &str) -> String {
    let to = match find_form_value(query, "to").and_then(|v| url_decode(v).parse::<Ipv6Addr>().ok()) {
        Some(a) => a,
        None => return http_status("400 Bad Request", "text/plain", "need to=<yggdrasil IPv6>\n"),
    };
    let msg = find_form_value(query, "msg").map(url_decode).unwrap_or_default();
    if msg.is_empty() {
        return http_status("400 Bad Request", "text/plain", "need msg=<text>\n");
    }
    let actions = {
        let mut guard = EP.lock().await;
        match guard.as_mut() {
            Some(ep) => {
                let mut rng = EspRng;
                ep.send_to_address(&Address(to.octets()), msg.as_bytes(), uptime_ms(), &mut rng)
            }
            None => Vec::new(),
        }
    };
    queue_actions(actions).await;
    http_ok("text/plain", "queued\n")
}

async fn inbox_json() -> String {
    let inbox = INBOX.lock().await;
    let mut out = String::from("[");
    for (i, m) in inbox.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let from = Ipv6Addr::from(m.from);
        let _ = write!(out, "{{\"from\":\"{}\",\"text\":\"", from);
        push_json_escaped(&mut out, &m.data[..m.len]);
        out.push_str("\"}");
    }
    out.push(']');
    out
}

fn index_page() -> String {
    let mut s = String::from(concat!(
        "<html><head><meta charset=\"utf-8\"><title>YggLite</title>",
        "<style>body{font-family:monospace;margin:16px}input{margin:4px 0}</style>",
        "</head><body><h2>YggLite</h2>",
        "<h3>Send a message</h3>",
        "<form action=\"/send\" method=\"get\">",
        "<label>To (IPv6):</label><input name=\"to\" size=\"42\"><br>",
        "<label>Message:</label><input name=\"msg\" size=\"42\"><br>",
        "<button type=\"submit\">Send</button></form>",
        "<p><a href=\"/inbox\">Received messages (JSON)</a></p>",
    ));
    s.push_str(DASHBOARD_HTML);
    s
}

/// Value of `key` in an `a=1&b=2` query string.
fn find_form_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Decode `%XX` and `+` in a query value. Invalid escapes are kept as typed.
fn url_decode(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_request_line(request: &str) -> (&str, &str) {
    let first = request.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    (parts.next().unwrap_or(""), parts.next().unwrap_or("/"))
}

fn push_json_escaped(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push('.'),
        }
    }
}

// ============================================================================
// Wi-Fi, IP, DHCP
// ============================================================================

#[embassy_executor::task]
async fn connection_task(mut controller: WifiController<'static>) {
    loop {
        if matches!(controller.is_started(), Ok(true)) {
            log::info!("Connecting to WiFi '{}'...", DEFAULT_WIFI_SSID);
            match controller.connect_async().await {
                Ok(_) => {
                    WIFI_CONNECTED.store(true, Ordering::Relaxed);
                    log::info!("WiFi connected");
                    controller.wait_for_event(WifiEvent::StationDisconnected).await;
                    WIFI_CONNECTED.store(false, Ordering::Relaxed);
                    log::info!("WiFi disconnected");
                }
                Err(e) => {
                    log::error!("WiFi connection failed: {:?}", e);
                    Timer::after(Duration::from_millis(5000)).await;
                }
            }
        } else {
            return;
        }
    }
}

#[embassy_executor::task(pool_size = 2)]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

#[embassy_executor::task]
async fn sta_ip_monitor(stack: embassy_net::Stack<'static>) {
    loop {
        let ip = stack.config_v4().map(|c| c.address.address());
        let mut sta_ip = STA_IP.lock().await;
        if *sta_ip != ip {
            *sta_ip = ip;
            if let Some(ip) = ip {
                log::info!("Got STA IP: {}", ip);
            }
        }
        drop(sta_ip);
        Timer::after(Duration::from_millis(1000)).await;
    }
}

#[embassy_executor::task]
async fn dhcp_server(stack: embassy_net::Stack<'static>) {
    let config = DhcpServerConfig {
        ip: AP_IP,
        lease_time: Duration::from_secs(3600),
        gateways: &[AP_IP],
        subnet: None,
        dns: &[AP_IP],
        use_captive_portal: false,
    };
    let mut leaser = SimpleDhcpLeaser {
        start: DHCP_POOL_START,
        end: DHCP_POOL_END,
        leases: Default::default(),
    };
    if let Err(e) = esp_hal_dhcp_server::run_dhcp_server(stack, config, &mut leaser).await {
        log::error!("DHCP server error: {:?}", e);
    }
}

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.init($val)
    }};
}

// ============================================================================
// Startup
// ============================================================================

/// Seed from `YGG_SEED` (64 hex chars), or a random one (with a warning).
fn load_seed() -> [u8; 32] {
    if let Some(hex) = FIXED_YGG_SEED {
        if let Some(seed) = parse_seed(hex) {
            return seed;
        }
        log::error!("YGG_SEED must be 64 hex characters; using a random seed");
    } else {
        log::warn!("YGG_SEED not set: the address changes on every boot");
    }
    let mut seed = [0u8; 32];
    EspRng.fill_bytes(&mut seed);
    seed
}

fn parse_seed(hex: &str) -> Option<[u8; 32]> {
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut seed = [0u8; 32];
    for (i, out) in seed.iter_mut().enumerate() {
        *out = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Some(seed)
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    #[cfg(feature = "esp32c6")]
    esp_alloc::heap_allocator!(size: 120 * 1024);
    #[cfg(feature = "esp32")]
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 96 * 1024);

    let seed = load_seed();
    let mut ep = Endpoint::new(seed, None, MAX_SLOTS);
    let mut peers = 0;
    for spec in [DEFAULT_YGG_PEER1, DEFAULT_YGG_PEER2, DEFAULT_YGG_PEER3] {
        if spec.trim().is_empty() {
            continue;
        }
        let uri = format!("tcp://{}", spec.trim());
        match ep.add_peer_uri(&uri, CandidateSource::Config) {
            Ok(_) => peers += 1,
            Err(e) => println!("bad peer '{}': {:?}", spec, e),
        }
    }
    println!("YggLite");
    println!("  address: {}", Ipv6Addr::from(ep.address().0));
    println!("  peers:   {}", peers);
    *EP.lock().await = Some(ep);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let (mut controller, interfaces) = esp_radio::wifi::new(peripherals.WIFI, Default::default()).unwrap();
    let ap_device = interfaces.access_point;
    let sta_device = interfaces.station;

    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(AP_IP, 24),
        gateway: Some(AP_IP),
        dns_servers: Default::default(),
    });
    let sta_config = embassy_net::Config::dhcpv4(Default::default());

    let rng = Rng::new();
    let net_seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (ap_stack, ap_runner) = embassy_net::new(
        ap_device,
        ap_config,
        mk_static!(StackResources<4>, StackResources::<4>::new()),
        net_seed,
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        sta_device,
        sta_config,
        mk_static!(StackResources<10>, StackResources::<10>::new()),
        net_seed,
    );

    let station_config = ModeConfig::AccessPointStation(
        StationConfig::default()
            .with_ssid(DEFAULT_WIFI_SSID.into())
            .with_password(DEFAULT_WIFI_PASSWORD.into()),
        AccessPointConfig::default().with_ssid("YggLite".into()),
    );
    controller.set_config(&station_config).unwrap();
    controller.start_async().await.unwrap();
    log::info!("WiFi started");

    spawner.spawn(connection_task(controller)).ok();
    spawner.spawn(net_task(ap_runner)).ok();
    spawner.spawn(net_task(sta_runner)).ok();
    spawner.spawn(sta_ip_monitor(sta_stack)).ok();
    spawner.spawn(dhcp_server(ap_stack)).ok();
    spawner.spawn(http_server(ap_stack, "AP")).ok();
    spawner.spawn(http_server(sta_stack, "STA")).ok();
    spawner.spawn(driver()).ok();
    for slot in 0..MAX_SLOTS {
        spawner.spawn(peer_slot(sta_stack, slot)).ok();
    }

    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}
