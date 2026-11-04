//! Status pages: the overlay HTML page and the local dashboard with its JSON API.
//!
//! Compiled with `--features html`; without it this module is a stub that does nothing, so a
//! plain build contains only the TCP/UDP forwarding node.
//!
//! The pages share one port number, `--html-port` (default 1080): the status page is served on
//! that overlay TCP port to allowed keys, and the dashboard (`GET /`, `GET /api/stats`) on
//! `127.0.0.1:<port>` unless `--api ADDR` says otherwise (`--api off` disables it). The
//! dashboard is loopback only and has no authentication.

#[cfg(feature = "html")]
#[path = "html/live.rs"]
mod live;
#[cfg(feature = "html")]
pub(crate) use live::Html;

#[cfg(not(feature = "html"))]
pub(crate) use stub::Html;

#[cfg(not(feature = "html"))]
mod stub {
    use crate::*;

    pub(crate) struct Html;

    impl Html {
        pub(crate) fn start(_args: &Args, _ep: &mut Endpoint) -> Result<Html, Box<dyn Error>> {
            Ok(Html)
        }

        pub(crate) fn refresh(&self, _ep: &mut Endpoint, _q: &Quality, _o: &OverlayInfo, _slots: usize, _now: u64) {}
    }
}
