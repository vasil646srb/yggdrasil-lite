//! Data model and JSON encoding for the device status API.
//!
//! Pure data: no I/O, no embassy, no esp-hal. Compiles on the device and on the
//! host, so the JSON format can be unit-tested without hardware.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// Number of outbound peer slots shown in the API (matches the web form).
pub const MAX_PEERS: usize = 3;
/// Max length of a peer address string, e.g. "192.168.1.100:12345".
pub const ADDR_LEN: usize = 48;

/// Connection state of one configured peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Configured, not dialed yet (or disconnected, waiting for reconnect).
    Idle,
    /// TCP connect in progress.
    Connecting,
    /// TCP and TLS are up, metadata exchange in progress.
    Handshake,
    /// Fully connected, traffic can flow.
    Up,
    /// Last attempt failed (TCP, TLS or metadata).
    Failed,
}

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerState::Idle => "idle",
            PeerState::Connecting => "connecting",
            PeerState::Handshake => "handshake",
            PeerState::Up => "up",
            PeerState::Failed => "failed",
        }
    }
}

/// Statistics for one configured peer.
#[derive(Clone, Debug)]
pub struct PeerStat {
    pub addr: heapless::String<ADDR_LEN>,
    pub key: Option<[u8; 32]>,
    pub state: PeerState,
    /// TCP connect + TLS + metadata time of the last successful session.
    pub rtt_ms: Option<u32>,
    /// Device uptime (ms) when the current session came up.
    pub up_since_ms: Option<u64>,
    pub attempts: u32,
    pub failures: u32,
}

impl PeerStat {
    pub const fn new() -> Self {
        Self {
            addr: heapless::String::new(),
            key: None,
            state: PeerState::Idle,
            rtt_ms: None,
            up_since_ms: None,
            attempts: 0,
            failures: 0,
        }
    }
}

/// Node-level statistics, refreshed from the Yggdrasil node loop.
#[derive(Clone, Debug)]
pub struct NodeStat {
    /// True on the ESP32 firmware (WiFi/UART/heap are meaningful).
    pub device: bool,
    pub uptime_ms: u64,
    pub ipv6: [u8; 16],
    pub listen_port: u16,
    pub public_key: [u8; 32],
    pub root: [u8; 32],
    pub coords: Vec<u64>,
    pub sessions: usize,
    pub paths: usize,
    pub wifi_connected: bool,
    pub sta_ip: Option<[u8; 4]>,
    pub uart_connected: bool,
    pub heap_free: usize,
    pub heap_used: usize,
}

impl NodeStat {
    pub const fn new() -> Self {
        Self {
            device: false,
            uptime_ms: 0,
            ipv6: [0; 16],
            listen_port: 0,
            public_key: [0; 32],
            root: [0; 32],
            coords: Vec::new(),
            sessions: 0,
            paths: 0,
            wifi_connected: false,
            sta_ip: None,
            uart_connected: false,
            heap_free: 0,
            heap_used: 0,
        }
    }
}

/// Everything the status API reports.
#[derive(Clone, Debug)]
pub struct NetState {
    pub node: NodeStat,
    pub peers: [PeerStat; MAX_PEERS],
}

const EMPTY_PEER: PeerStat = PeerStat::new();

impl NetState {
    pub const fn new() -> Self {
        Self {
            node: NodeStat::new(),
            peers: [EMPTY_PEER; MAX_PEERS],
        }
    }

    /// Number of peers currently in `Up` state.
    pub fn peers_up(&self) -> usize {
        self.peers.iter().filter(|p| p.state == PeerState::Up).count()
    }
}

/// Encode the state as compact JSON.
///
/// Shape:
/// ```text
/// {"uptime_s":N,
///  "node":{"device":bool,"address":"..","listen_port":N,"public_key":"hex","root":"hex",
///          "coords":[..],"sessions":N,"paths":N,"peers_up":N},
///  "link":{"wifi":bool,"sta_ip":"a.b.c.d"|null,"uart":bool},
///  "heap":{"free":N,"used":N},
///  "peers":[{"addr":"..","key":"hex"|null,"state":"up","rtt_ms":N|null,
///            "up_s":N|null,"attempts":N,"failures":N}]}
/// ```
pub fn to_json(s: &NetState) -> String {
    let n = &s.node;
    let mut out = String::with_capacity(768);

    let _ = write!(out, "{{\"uptime_s\":{},", n.uptime_ms / 1000);

    let _ = write!(out, "\"node\":{{\"device\":{},\"address\":\"", bool_str(n.device));
    let _ = write!(out, "{}", core::net::Ipv6Addr::from(n.ipv6));
    let _ = write!(out, "\",\"listen_port\":{},\"public_key\":\"", n.listen_port);
    push_hex(&mut out, &n.public_key);
    out.push_str("\",\"root\":\"");
    push_hex(&mut out, &n.root);
    out.push_str("\",\"coords\":[");
    for (i, c) in n.coords.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{}", c);
    }
    let _ = write!(
        out,
        "],\"sessions\":{},\"paths\":{},\"peers_up\":{}}},",
        n.sessions,
        n.paths,
        s.peers_up()
    );

    out.push_str("\"link\":{\"wifi\":");
    out.push_str(bool_str(n.wifi_connected));
    out.push_str(",\"sta_ip\":");
    match n.sta_ip {
        Some(ip) => {
            let _ = write!(out, "\"{}.{}.{}.{}\"", ip[0], ip[1], ip[2], ip[3]);
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"uart\":");
    out.push_str(bool_str(n.uart_connected));
    out.push_str("},");

    let _ = write!(
        out,
        "\"heap\":{{\"free\":{},\"used\":{}}},",
        n.heap_free, n.heap_used
    );

    out.push_str("\"peers\":[");
    for (i, p) in s.peers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"addr\":\"");
        push_escaped(&mut out, p.addr.as_str());
        out.push_str("\",\"key\":");
        match &p.key {
            Some(k) => {
                out.push('"');
                push_hex(&mut out, k);
                out.push('"');
            }
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"state\":\"{}\",\"rtt_ms\":", p.state.as_str());
        opt_num(&mut out, p.rtt_ms.map(u64::from));
        out.push_str(",\"up_s\":");
        opt_num(
            &mut out,
            p.up_since_ms
                .filter(|_| p.state == PeerState::Up)
                .map(|t| n.uptime_ms.saturating_sub(t) / 1000),
        );
        let _ = write!(out, ",\"attempts\":{},\"failures\":{}}}", p.attempts, p.failures);
    }
    out.push_str("]}");
    out
}

fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn opt_num(out: &mut String, v: Option<u64>) {
    match v {
        Some(x) => {
            let _ = write!(out, "{}", x);
        }
        None => out.push_str("null"),
    }
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
}

/// Escape the characters that would break a JSON string literal.
fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NetState {
        let mut s = NetState::new();
        s.node.uptime_ms = 125_000;
        s.node.ipv6[0] = 0x02;
        s.node.listen_port = 2000;
        s.node.public_key = [0xab; 32];
        s.node.root = [0x01; 32];
        s.node.coords = alloc::vec![1, 4, 9];
        s.node.sessions = 2;
        s.node.paths = 5;
        s.node.wifi_connected = true;
        s.node.sta_ip = Some([192, 168, 1, 50]);
        s.node.uart_connected = false;
        s.node.heap_free = 1000;
        s.node.heap_used = 2000;

        s.peers[0].addr.push_str("10.0.0.1:2020").unwrap();
        s.peers[0].key = Some([0xcd; 32]);
        s.peers[0].state = PeerState::Up;
        s.peers[0].rtt_ms = Some(340);
        s.peers[0].up_since_ms = Some(100_000);
        s.peers[0].attempts = 1;

        s.peers[1].addr.push_str("10.0.0.2:\"x\"").unwrap();
        s.peers[1].state = PeerState::Failed;
        s.peers[1].attempts = 3;
        s.peers[1].failures = 3;
        s
    }

    #[test]
    fn json_is_valid_and_has_expected_values() {
        let json = to_json(&sample());
        // Validity is checked by serde_json in the host test crate; here we
        // assert the key fragments the dashboard relies on.
        assert!(json.starts_with("{\"uptime_s\":125,"));
        assert!(json.contains("\"sta_ip\":\"192.168.1.50\""));
        assert!(json.contains("\"peers_up\":1"));
        assert!(json.contains("\"state\":\"up\",\"rtt_ms\":340,\"up_s\":25"));
        assert!(json.contains("\"addr\":\"10.0.0.2:\\\"x\\\"\""));
        assert!(json.contains("\"state\":\"failed\",\"rtt_ms\":null,\"up_s\":null"));
        assert!(json.contains("\"coords\":[1,4,9]"));
    }

    #[test]
    fn overlay_page_embeds_json_and_escapes_script_end() {
        let json = "{\"addr\":\"</script>\"}";
        let page = overlay_page(json);
        assert!(page.contains("var STATIC_STATS = {\"addr\":\"<\\/script>\"};"));
        assert!(page.contains("http-equiv=\"refresh\""));
        assert!(page.ends_with("</body></html>\n") || page.ends_with("</body></html>"));
        assert_eq!(page.matches("</script>").count(), 2); // our embed + dashboard script
    }

    #[test]
    fn disconnected_device_reports_nulls() {
        let json = to_json(&NetState::new());
        assert!(json.contains("\"sta_ip\":null"));
        assert!(json.contains("\"key\":null"));
        assert!(json.contains("\"peers_up\":0"));
    }
}

/// Dashboard section and script, appended to the `/` page.
/// Renders text with `textContent` only, so peer addresses cannot inject markup.
pub const DASHBOARD_HTML: &str = r#"
<h3>Network status</h3>
<div class="status" id="net" style="white-space:pre">loading...</div>
<h3>Peer connections</h3>
<table id="peers" border="1" cellpadding="4" style="border-collapse:collapse;font-size:12px">
<thead><tr><th>Peer</th><th>State</th><th>RTT, ms</th><th>Up, s</th><th>Key</th><th>Attempts / failures</th></tr></thead>
<tbody></tbody>
</table>
<script>
function cell(tr, text) {
  var td = document.createElement('td');
  td.textContent = text;
  tr.appendChild(td);
}
function render(s) {
  var n = s.node;
  var lines = [
    'Uptime:      ' + s.uptime_s + ' s',
    'Ygg IPv6:    ' + n.address + ' : ' + n.listen_port,
    'Root:        ' + n.root.slice(0, 16) + '...',
    'Coords:      [' + n.coords.join(' ') + ']',
    'Peers up:    ' + n.peers_up + ' / ' + s.peers.length,
    'Sessions:    ' + n.sessions + '   Paths: ' + n.paths
  ];
  if (n.device) {
    lines.push('WiFi STA:    ' + (s.link.wifi ? 'connected' : 'down') + (s.link.sta_ip ? ' (' + s.link.sta_ip + ')' : ''));
    lines.push('UART:        ' + (s.link.uart ? 'connected' : 'idle'));
    lines.push('Heap:        ' + s.heap.used + ' used / ' + (s.heap.used + s.heap.free) + ' total');
  }
  document.getElementById('net').textContent = lines.join('\n');

  var tbody = document.querySelector('#peers tbody');
  tbody.textContent = '';
  s.peers.forEach(function (p) {
    var tr = document.createElement('tr');
    cell(tr, p.addr || '-');
    cell(tr, p.state);
    cell(tr, p.rtt_ms === null ? '-' : p.rtt_ms);
    cell(tr, p.up_s === null ? '-' : p.up_s);
    cell(tr, p.key === null ? '-' : p.key.slice(0, 16) + '...');
    cell(tr, p.attempts + ' / ' + p.failures);
    tbody.appendChild(tr);
  });
}
function refresh() {
  if (typeof STATIC_STATS !== 'undefined') {
    render(STATIC_STATS);
    return;
  }
  fetch('/api/stats', { cache: 'no-store' })
    .then(function (r) { return r.json(); })
    .then(render)
    .catch(function () {
      document.getElementById('net').textContent = 'no response from device';
    });
}
refresh();
if (typeof STATIC_STATS === 'undefined') {
  setInterval(refresh, 2000);
}
</script>
</body></html>
"#;

/// Full HTML page with a snapshot embedded, for servers that answer every
/// request with the same body (the overlay HTTP server). The page reloads
/// itself every 2 seconds, so the device must refresh the snapshot in between.
pub fn overlay_page(json: &str) -> String {
    // A `</script>` inside the JSON would end the script element early.
    let safe = json.replace("</", "<\\/");
    let mut out = String::with_capacity(DASHBOARD_HTML.len() + safe.len() + 512);
    out.push_str(concat!(
        "<!doctype html><html><head><meta charset=\"utf-8\">",
        "<meta http-equiv=\"refresh\" content=\"2\">",
        "<title>yggdrasil-lite</title>",
        "<style>body{font-family:monospace;margin:16px}",
        ".status{background:#f0f0f0;padding:10px;margin:10px 0}",
        "h3{margin:14px 0 6px}</style></head><body>",
    ));
    out.push_str("<script>var STATIC_STATS = ");
    out.push_str(&safe);
    out.push_str(";</script>");
    out.push_str(DASHBOARD_HTML);
    out
}
