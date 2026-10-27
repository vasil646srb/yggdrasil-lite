//! Status API for the web UI: shared snapshot of node and peer state, the
//! `/api/stats` JSON endpoint and the dashboard markup.
//!
//! The Yggdrasil node loop writes into [`NET`] (see [`sync_node`] and the
//! `peer_*` helpers); HTTP handlers read from it. The page polls
//! `/api/stats` every two seconds.

use core::fmt::Write;
use core::net::IpAddr;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use yggdrasil_lite::node::YggdrasilLite;

use crate::api_model::{to_json, NetState, PeerState, ADDR_LEN, MAX_PEERS};

/// Shared snapshot. Written by the node loop, read by HTTP handlers.
pub static NET: Mutex<CriticalSectionRawMutex, NetState> = Mutex::new(NetState::new());

/// Device uptime in ms (time since boot, from embassy).
pub fn uptime_ms() -> u64 {
    embassy_time::Instant::now().as_millis()
}

/// Copy node-level counters into the snapshot. Call on every poll tick
/// (the lock is held only for a few field writes).
pub async fn sync_node(node: &YggdrasilLite) {
    let uptime = uptime_ms();
    let wifi = crate::WIFI_CONNECTED.load(core::sync::atomic::Ordering::Relaxed);
    let uart = crate::UART_CONNECTED.load(core::sync::atomic::Ordering::Relaxed);
    let sta_ip = (*crate::STA_IP.lock().await).map(|ip| ip.octets());
    let ipv6 = *crate::YGG_IPV6.lock().await;
    let port = *crate::YGG_PORT.lock().await;

    let mut net = NET.lock().await;
    let n = &mut net.node;
    n.device = true;
    n.uptime_ms = uptime;
    n.ipv6 = ipv6;
    n.listen_port = port;
    n.public_key = *node.public_key();
    n.root = node.root();
    n.coords.clear();
    n.coords.extend(node.coords().into_iter());
    n.sessions = node.session_count();
    n.paths = node.path_count();
    n.wifi_connected = wifi;
    n.sta_ip = sta_ip;
    n.uart_connected = uart;
    n.heap_free = esp_alloc::HEAP.free();
    n.heap_used = esp_alloc::HEAP.used();
}

/// Record the configured address of peer slot `idx` (shown before first dial).
pub async fn set_peer_addr(idx: usize, ip: IpAddr, port: u16) {
    let mut s: heapless::String<ADDR_LEN> = heapless::String::new();
    let _ = write!(s, "{}:{}", ip, port);
    peer_update(idx, |p| p.addr = s).await;
}

/// Apply `f` to the stats of peer slot `idx`, if it exists.
pub async fn peer_update(idx: usize, f: impl FnOnce(&mut crate::api_model::PeerStat)) {
    if idx >= MAX_PEERS {
        return;
    }
    let mut net = NET.lock().await;
    f(&mut net.peers[idx]);
}

/// Dial attempt started for slot `idx`.
pub async fn peer_connecting(idx: usize) {
    peer_update(idx, |p| {
        p.state = PeerState::Connecting;
        p.attempts = p.attempts.saturating_add(1);
    })
    .await;
}

/// TCP/TLS/metadata failed for slot `idx`.
pub async fn peer_failed(idx: usize) {
    peer_update(idx, |p| {
        p.state = PeerState::Failed;
        p.failures = p.failures.saturating_add(1);
        p.up_since_ms = None;
    })
    .await;
}

/// Session with slot `idx` is up. `rtt_ms` is connect+TLS+metadata time.
pub async fn peer_up(idx: usize, key: [u8; 32], rtt_ms: u64) {
    let now = uptime_ms();
    peer_update(idx, |p| {
        p.state = PeerState::Up;
        p.key = Some(key);
        p.rtt_ms = Some(rtt_ms.min(u32::MAX as u64) as u32);
        p.up_since_ms = Some(now);
    })
    .await;
}

/// Mark the TCP+TLS stage done for slot `idx`.
pub async fn peer_handshake(idx: usize) {
    peer_update(idx, |p| p.state = PeerState::Handshake).await;
}

/// All sessions ended (before reconnect): keep counters, drop live state.
pub async fn peers_down() {
    let mut net = NET.lock().await;
    for p in net.peers.iter_mut() {
        if p.state != PeerState::Failed {
            p.state = PeerState::Idle;
        }
        p.up_since_ms = None;
    }
}

/// `GET /api/stats` response.
pub async fn stats_response() -> alloc::string::String {
    let body = {
        let net = NET.lock().await;
        to_json(&net)
    };
    let mut resp = alloc::string::String::new();
    let _ = write!(
        resp,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    resp
}

/// Dashboard markup lives in `api_model` so host builds share it.
pub use crate::api_model::DASHBOARD_HTML;
