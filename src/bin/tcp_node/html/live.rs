//! The real status pages (see the parent module).

use crate::api_model::{to_json, NetState, PeerState, PeerStat, DASHBOARD_HTML, MAX_PEERS};
use crate::*;
use std::sync::{Arc, Mutex};

/// Handle to the running pages.
pub(crate) struct Html {
    shared: Arc<Mutex<NetState>>,
    /// `/api/peers` body, rebuilt by the main loop about once a second.
    peers: Arc<Mutex<String>>,
    /// The local dashboard is running.
    api: bool,
    /// The user gave `--html FILE`: the live overlay page is not generated.
    custom_page: bool,
    /// Overlay port of the status page.
    port: u16,
}

impl Html {
    /// Set up the overlay page and start the dashboard thread.
    pub(crate) fn start(args: &Args, ep: &mut Endpoint) -> Result<Html, Box<dyn Error>> {
        let page = match &args.html {
            Some(path) => std::fs::read(path)?,
            None => DEFAULT_PAGE.as_bytes().to_vec(),
        };
        ep.serve_http_on(args.html_port, page);
        if args.forwards.iter().any(|(overlay, _)| *overlay == args.html_port) {
            println!("note: overlay port {} is forwarded, so the overlay status page is not served", args.html_port);
        } else {
            println!("html page:      overlay port {}", args.html_port);
        }

        let shared: Arc<Mutex<NetState>> = Arc::new(Mutex::new(NetState::new()));
        let peers: Arc<Mutex<String>> = Arc::new(Mutex::new("{\"peers\":[]}".to_string()));
        // An explicit address must work; the default one may be taken (a SOCKS proxy on 1080).
        let (addr, explicit) = match args.api.as_deref() {
            Some("off") => return Ok(Html { shared, peers, api: false, custom_page: args.html.is_some(), port: args.html_port }),
            Some(a) => (a.to_string(), true),
            None => (format!("127.0.0.1:{}", args.html_port), false),
        };
        let sock: std::net::SocketAddr = addr.parse().map_err(|e| format!("--api: invalid address {addr}: {e}"))?;
        if !sock.ip().is_loopback() {
            return Err(format!("--api must bind to loopback (127.0.0.1 or [::1]), got {addr}").into());
        }
        let api = match TcpListener::bind(sock) {
            Ok(listener) => {
                println!("status API:     http://{addr}/  (JSON: /api/stats)");
                let (shared, peers) = (shared.clone(), peers.clone());
                std::thread::spawn(move || serve_api(listener, shared, peers));
                true
            }
            Err(e) if !explicit => {
                eprintln!("status API: disabled, cannot bind {addr}: {e}");
                false
            }
            Err(e) => return Err(format!("--api {addr}: {e}").into()),
        };
        Ok(Html { shared, peers, api, custom_page: args.html.is_some(), port: args.html_port })
    }

    /// New `/api/peers` body.
    pub(crate) fn set_peers(&self, json: String) {
        if self.api {
            *self.peers.lock().unwrap() = json;
        }
    }

    /// Refresh the overlay page and the dashboard's data (about once a second).
    pub(crate) fn refresh(&self, ep: &mut Endpoint, quality: &Quality, overlay: &OverlayInfo, slots: usize, now: u64) {
        if !self.custom_page {
            ep.serve_http_on(self.port, status_page(ep, quality, overlay, slots, now).into_bytes());
        }
        if self.api {
            *self.shared.lock().unwrap() = snapshot(ep, now);
        }
    }
}

const DEFAULT_PAGE: &str = "<!doctype html>
<html><head><meta charset=\"utf-8\"><title>yggdrasil-lite</title></head>
<body style=\"font-family:sans-serif\">
<h1>yggdrasil-lite device</h1>
<p>Этот узел работает через Yggdrasil.</p>
</body></html>
";

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
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
fn serve_api(listener: TcpListener, shared: Arc<Mutex<NetState>>, peers: Arc<Mutex<String>>) {
    for conn in listener.incoming().flatten() {
        let (shared, peers) = (shared.clone(), peers.clone());
        std::thread::spawn(move || handle_api_conn(conn, &shared, &peers));
    }
}

fn handle_api_conn(mut conn: TcpStream, shared: &Mutex<NetState>, peers: &Mutex<String>) {
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
        ("GET", "/api/peers") => ("200 OK", "application/json", peers.lock().unwrap().clone()),
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
