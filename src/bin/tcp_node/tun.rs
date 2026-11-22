//! TUN bridge (`--tun NAME` on Linux, `--tun-ctl PATH` for an Android VpnService fd):
//! IPv6 packets read from the interface go to Yggdrasil node addresses (`200::/8`) and node
//! subnets (`300::/8`, e.g. a ydn64 NAT64 pool) with `Endpoint::send_packet`; replies from
//! the nodes we wrote to are written back. Everything else read from the interface is dropped.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

pub struct Tun {
    file: File,
    /// `--tun-ctl`: the control connection, kept open while the bridge runs.
    _ctl: Option<std::os::unix::net::UnixStream>,
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Packets the kernel holds for us on the interface (default 500). When the node falls behind
/// (a slow CPU), these wait first-in first-out and are dropped only when the ring is full:
/// 500 packets are 0.3 s of delay at 20 Mbit/s for everything in the tunnel; 128 drop sooner,
/// so TCP inside slows down instead.
#[cfg(target_os = "linux")]
const TUN_TXQUEUELEN: libc::c_int = 128;

/// `ip link set NAME txqueuelen N`, best effort.
#[cfg(target_os = "linux")]
fn set_txqueuelen(name: &str, len: libc::c_int) {
    const SIOCSIFTXQLEN: libc::c_ulong = 0x8943;
    #[repr(C)]
    struct IfReqQlen {
        name: [u8; 16],
        qlen: libc::c_int,
        _pad: [u8; 20],
    }
    let mut req = IfReqQlen { name: [0; 16], qlen: len, _pad: [0; 20] };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: a plain socket for the ioctl, closed right after; the ioctl reads an ifreq we own.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd >= 0 {
            libc::ioctl(fd, SIOCSIFTXQLEN as _, &mut req);
            libc::close(fd);
        }
    }
}

impl Tun {
    /// Create or attach Linux TUN interface `name` (IFF_TUN | IFF_NO_PI). Needs CAP_NET_ADMIN;
    /// the caller configures the address and routes (`ip -6 addr add <our address>/7 dev NAME`).
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> std::io::Result<Tun> {
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
        const IFF_TUN: libc::c_short = 0x0001;
        const IFF_NO_PI: libc::c_short = 0x1000;
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: libc::c_short,
            _pad: [u8; 22],
        }
        if name.is_empty() || name.len() > 15 {
            return Err(std::io::Error::other("interface name must be 1..15 bytes"));
        }
        let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
        let mut req = IfReq { name: [0; 16], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: TUNSETIFF reads and writes an ifreq-sized struct we own.
        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        set_nonblocking(file.as_raw_fd())?;
        set_txqueuelen(name, TUN_TXQUEUELEN);
        Ok(Tun { file, _ctl: None })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_name: &str) -> std::io::Result<Tun> {
        Err(std::io::Error::other("--tun NAME is Linux only; use --tun-ctl"))
    }

    /// Listen on unix socket `path`, accept one connection and receive the interface fd over
    /// it (SCM_RIGHTS), as Android's VpnService hands it out. Prints `tun ctl: PATH` when ready.
    pub fn from_ctl(path: &str) -> std::io::Result<Tun> {
        use std::os::unix::net::UnixListener;
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        println!("tun ctl:        {path}");
        let (stream, _) = listener.accept()?;
        let _ = std::fs::remove_file(path);
        let fd = recv_fd(stream.as_raw_fd())?;
        set_nonblocking(fd)?;
        // SAFETY: the fd was just received and is owned by nobody else in this process.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Tun { file, _ctl: Some(stream) })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// The control connection's fd (poll it: it turns readable when the other side closes).
    pub fn ctl_fd(&self) -> Option<RawFd> {
        self._ctl.as_ref().map(|c| c.as_raw_fd())
    }

    /// The control connection was closed by the side that handed us the interface.
    pub fn ctl_closed(&mut self) -> bool {
        let Some(c) = self._ctl.as_mut() else { return false };
        let mut b = [0u8; 64];
        match c.read(&mut b) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted),
        }
    }

    /// One packet, or `None` when nothing is waiting.
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        match self.file.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write one packet; a full interface queue drops it (like a router would).
    pub fn write(&mut self, pkt: &[u8]) {
        let _ = self.file.write(pkt);
    }
}

/// `--ckr-ctl PATH`: a unix socket the VPN side connects to, any time, to hand the node a TUN
/// fd (SCM_RIGHTS) for the crypto-key routing tunnel; closing that connection detaches it.
pub struct CtlListener {
    listener: std::os::unix::net::UnixListener,
}

impl CtlListener {
    pub fn bind(path: &str) -> std::io::Result<CtlListener> {
        let _ = std::fs::remove_file(path);
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        // The daemon (root) or the app's own uid connects; nobody else on the machine.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(CtlListener { listener })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// A newly handed interface, if a connection is waiting.
    pub fn accept(&self) -> std::io::Result<Option<Tun>> {
        let stream = match self.listener.accept() {
            Ok((s, _)) => s,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => return Ok(None),
            Err(e) => return Err(e),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let fd = recv_fd(stream.as_raw_fd())?;
        set_nonblocking(fd)?;
        stream.set_nonblocking(true)?;
        // SAFETY: the fd was just received and is owned by nobody else in this process.
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Some(Tun { file, _ctl: Some(stream) }))
    }
}

/// Receive one fd over a connected unix stream (SCM_RIGHTS).
fn recv_fd(sock: RawFd) -> std::io::Result<RawFd> {
    // SAFETY: plain recvmsg into buffers we own; the control buffer is large enough for
    // several fds and CMSG_* walk only inside it.
    unsafe {
        let mut data = [0u8; 16];
        let mut iov = libc::iovec { iov_base: data.as_mut_ptr() as *mut _, iov_len: data.len() };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut cbuf = vec![0u8; space * 4];
        loop {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut _;
            msg.msg_controllen = cbuf.len() as _;
            let n = libc::recvmsg(sock, &mut msg, 0);
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "control socket closed"));
            }
            let mut cm = libc::CMSG_FIRSTHDR(&msg);
            while !cm.is_null() {
                if (*cm).cmsg_level == libc::SOL_SOCKET && (*cm).cmsg_type == libc::SCM_RIGHTS {
                    return Ok(std::ptr::read_unaligned(libc::CMSG_DATA(cm) as *const RawFd));
                }
                cm = libc::CMSG_NXTHDR(&msg, cm);
            }
        }
    }
}

/// Destination of an IPv6 packet read from the interface, if Yggdrasil can carry it
/// (`200::/8` node address or `300::/8` node subnet) and it comes from `ours`.
pub fn route(pkt: &[u8], ours: &[u8; 16]) -> Option<[u8; 16]> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 || pkt[8..24] != ours[..] {
        return None;
    }
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    matches!(dst[0], 0x02 | 0x03).then_some(dst)
}
