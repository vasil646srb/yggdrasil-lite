// Host type-check harness for the device firmware's API code.
// api.rs and api_model.rs are compiled unchanged; the device-only
// dependencies (embassy, esp-alloc) are stubs, yggdrasil-lite is real.
extern crate alloc;

use core::net::Ipv4Addr;
use core::sync::atomic::AtomicBool;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;

// Statics that main.rs defines and api.rs reads via crate::.
pub static WIFI_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static UART_CONNECTED: AtomicBool = AtomicBool::new(false);
pub static STA_IP: Mutex<CriticalSectionRawMutex, Option<Ipv4Addr>> = Mutex::new(None);
pub static YGG_IPV6: Mutex<CriticalSectionRawMutex, [u8; 16]> = Mutex::new([0u8; 16]);
pub static YGG_PORT: Mutex<CriticalSectionRawMutex, u16> = Mutex::new(2000);

#[path = "../../src/api_model.rs"]
#[allow(dead_code)]
mod api_model;
#[path = "../../src/api.rs"]
#[allow(dead_code, unused_imports)]
mod api;

use yggdrasil_lite::node::{LiteConfig, YggdrasilLite};

// Exercise every hook the device code calls, with the device's argument types.
#[allow(dead_code)]
async fn exercise(node: &mut YggdrasilLite) -> alloc::string::String {
    use core::net::IpAddr;
    api::set_peer_addr(0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 2020).await;
    api::peer_connecting(0).await;
    let t0 = embassy_time::Instant::now();
    api::peer_handshake(0).await;
    api::peer_up(0, [7u8; 32], t0.elapsed().as_millis()).await;
    api::peer_failed(1).await;
    api::sync_node(node).await;
    api::peers_down().await;
    api::stats_response().await
}

fn main() {
    let mut node = YggdrasilLite::new(LiteConfig::new([1u8; 32]));
    let rt = tokio_free_block_on(exercise(&mut node));
    println!("{}", &rt[..120.min(rt.len())]);
}

// Minimal executor: the stubs never actually suspend.
fn tokio_free_block_on<F: core::future::Future>(f: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker { RawWaker::new(p, &VTABLE) }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = Box::pin(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
