//! yggdrasil-go LAN discovery (`--lan-upstream`): listen for their multicast beacons and dial the
//! senders over TLS.
//!
//! Compiled with `--features upstream-tls` (discovery is only useful with TLS, because
//! yggdrasil-go peers speak TLS); without it this module is a stub.

#[cfg(feature = "upstream-tls")]
#[path = "discovery/live.rs"]
mod live;
#[cfg(feature = "upstream-tls")]
pub(crate) use live::{drain, lan_scoped_addr, open};

#[cfg(not(feature = "upstream-tls"))]
pub(crate) use stub::{drain, lan_scoped_addr, open};

#[cfg(not(feature = "upstream-tls"))]
mod stub {
    use crate::*;

    /// Without TLS no LAN peer can be dialed, so there are no scoped addresses.
    pub(crate) fn lan_scoped_addr(_key: &PublicKey) -> Option<SocketAddrV6> {
        None
    }

    pub(crate) fn open(_enabled: bool) -> Option<UdpSocket> {
        None
    }

    pub(crate) fn drain(_sock: &UdpSocket, _ep: &mut Endpoint) {}
}
