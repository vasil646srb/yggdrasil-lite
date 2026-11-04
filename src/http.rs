//! Small HTTP/1.1 server on overlay port 80, running on [`TcpStack`].
//!
//! Serves one page for any path and a speed-test body for `GET /speed`. One
//! request per connection (`Connection: close`). Responses are streamed as the
//! send buffer drains, so large bodies go through flow and congestion control
//! like any other TCP data. Only allowed keys reach it (the endpoint filters).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use crate::tcp_stack::{ConnId, Event, TcpStack};

/// Requests larger than this (headers included) are dropped.
const MAX_REQUEST: usize = 8 * 1024;
/// Speed-test body size for `GET /speed`.
pub const SPEED_BYTES: usize = 4 * 1024 * 1024;

enum Body {
    Bytes(Vec<u8>),
    Fill(usize),
}

impl Body {
    fn len(&self) -> usize {
        match self {
            Body::Bytes(b) => b.len(),
            Body::Fill(n) => *n,
        }
    }
}

struct Response {
    head: Vec<u8>,
    body: Body,
    /// Bytes of head + body already written.
    sent: usize,
}

#[derive(Default)]
struct Conn {
    request: Vec<u8>,
    response: Option<Response>,
    remote_done: bool,
}

/// HTTP state for connections on port 80.
pub struct HttpServer {
    page: Vec<u8>,
    conns: BTreeMap<ConnId, Conn>,
}

impl HttpServer {
    pub fn new(page: Vec<u8>) -> Self {
        Self { page, conns: BTreeMap::new() }
    }

    pub fn set_page(&mut self, page: Vec<u8>) {
        self.page = page;
    }

    /// Whether the connection belongs to this server.
    pub fn owns(&self, id: ConnId) -> bool {
        self.conns.contains_key(&id)
    }

    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// Take ownership of a newly accepted connection.
    pub fn accept(&mut self, id: ConnId) {
        self.conns.insert(id, Conn::default());
    }

    /// Handle an event for one of our connections.
    pub fn on_event(&mut self, ev: &Event) {
        match *ev {
            Event::RemoteFin { id } => {
                if let Some(c) = self.conns.get_mut(&id) {
                    c.remote_done = true;
                }
            }
            Event::Closed { id, .. } => {
                self.conns.remove(&id);
            }
            _ => {}
        }
    }

    /// Read requests and write responses. Call after any stack activity.
    pub fn pump(&mut self, stack: &mut TcpStack) {
        let mut buf = [0u8; 2048];
        let mut to_close = Vec::new();
        let mut to_abort = Vec::new();
        for (&id, c) in self.conns.iter_mut() {
            // Read the request; after the response is chosen, discard input.
            loop {
                let n = stack.read(id, &mut buf);
                if n == 0 {
                    break;
                }
                if c.response.is_none() {
                    c.request.extend_from_slice(&buf[..n]);
                }
            }
            if c.response.is_none() {
                if let Some(end) = find(&c.request, b"\r\n\r\n") {
                    c.response = Some(respond(&c.request[..end], &self.page));
                    c.request = Vec::new();
                } else if c.request.len() > MAX_REQUEST {
                    to_abort.push(id);
                    continue;
                } else if c.remote_done {
                    // The client closed without a complete request.
                    to_close.push(id);
                    continue;
                }
            }
            let Some(r) = c.response.as_mut() else { continue };
            let total = r.head.len() + r.body.len();
            while r.sent < total {
                let space = stack.send_space(id);
                if space == 0 {
                    break;
                }
                let n = if r.sent < r.head.len() {
                    let end = r.head.len().min(r.sent + space);
                    stack.write(id, &r.head[r.sent..end])
                } else {
                    let off = r.sent - r.head.len();
                    match &r.body {
                        Body::Bytes(b) => {
                            let end = b.len().min(off + space);
                            stack.write(id, &b[off..end])
                        }
                        Body::Fill(len) => {
                            let chunk = [0x55u8; 4096];
                            let k = (len - off).min(space).min(chunk.len());
                            stack.write(id, &chunk[..k])
                        }
                    }
                };
                if n == 0 {
                    break;
                }
                r.sent += n;
            }
            if r.sent >= total {
                to_close.push(id);
            }
        }
        for id in to_abort {
            stack.abort(id);
            self.conns.remove(&id);
        }
        for id in to_close {
            stack.close(id);
        }
    }
}

fn respond(request: &[u8], page: &[u8]) -> Response {
    let line_end = find(request, b"\r\n").unwrap_or(request.len());
    let line = &request[..line_end];
    let mut parts = line.split(|b| *b == b' ');
    let method = parts.next().unwrap_or(b"");
    let path = parts.next().unwrap_or(b"/");
    let head_only = method == b"HEAD";

    let (status, ctype, body) = if method != b"GET" && method != b"HEAD" {
        ("405 Method Not Allowed", "text/plain", Body::Bytes(b"method not allowed\n".to_vec()))
    } else if path == b"/speed" || path.starts_with(b"/speed?") {
        ("200 OK", "application/octet-stream", Body::Fill(SPEED_BYTES))
    } else {
        ("200 OK", "text/html; charset=utf-8", Body::Bytes(page.to_vec()))
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    Response {
        head: head.into_bytes(),
        body: if head_only { Body::Bytes(Vec::new()) } else { body },
        sent: 0,
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
