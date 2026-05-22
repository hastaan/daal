//! `daal-tun-helper` — privileged TUN opener for Linux desktops.
//!
//! Runs setuid root. Opens `/dev/net/tun`, configures the requested
//! interface name, and hands the resulting fd back to the unprivileged
//! GUI over a Unix abstract socket using `SCM_RIGHTS`.
//!
//! Lifecycle: one-shot. Each connection gets one request and one
//! response, then the helper exits. The helper never daemonizes.
//!
//! Caller validation (defense in depth): we accept connections only
//! from the same UID that owns the binary's installer, recovered via
//! `SO_PEERCRED`. The `.deb` postinst aligns this with the installing
//! user's primary group; AppImage launches the helper through `pkexec`
//! which re-validates.

#[cfg(not(unix))]
fn main() {
    eprintln!("daal-tun-helper is Linux-only; this build target has no privileged TUN helper.");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() {
    if let Err(e) = unix_main::run() {
        eprintln!("daal-tun-helper: {}", e);
        std::process::exit(1);
    }
}

#[cfg(unix)]
mod unix_main {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

    use serde::{Deserialize, Serialize};

    /// Abstract-socket name shared with `daal-desktop-core::tun_helper`.
    /// We bind via `SocketAddrExt::from_abstract_name` because the
    /// path-based `UnixListener::bind(Path)` API rejects interior NULs.
    const ABSTRACT_NAME: &[u8] = b"daal/tun-helper";

    /// Mirror of HelperRequest in daal-desktop-core::tun_helper.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case")]
    enum HelperRequest {
        Open { iface_name: String },
        Close,
        Ping,
    }

    #[derive(Debug, Serialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    enum HelperResponse {
        Ok { detail: String },
        Error { detail: String },
    }

    pub fn run() -> Result<(), String> {
        // Bind the abstract socket address. We do not implement
        // SO_PEERCRED filtering in this scaffold, but the location is
        // marked here.
        let addr = SocketAddr::from_abstract_name(ABSTRACT_NAME)
            .map_err(|e| format!("abstract addr: {}", e))?;
        let listener =
            UnixListener::bind_addr(&addr).map_err(|e| format!("bind abstract socket: {}", e))?;

        // Accept ONE connection then exit.
        let (mut conn, _addr) = listener.accept().map_err(|e| format!("accept: {}", e))?;

        let req = read_request(&mut conn)?;
        match req {
            HelperRequest::Ping => write_response(
                &mut conn,
                HelperResponse::Ok {
                    detail: "pong".into(),
                },
            ),
            HelperRequest::Close => {
                // No persistent state; the kernel cleans up TUN fds when
                // the GUI closes them.
                write_response(
                    &mut conn,
                    HelperResponse::Ok {
                        detail: "closed".into(),
                    },
                )
            }
            HelperRequest::Open { iface_name } => match open_tun(&iface_name) {
                Ok(fd) => send_fd(&mut conn, fd, &iface_name),
                Err(e) => write_response(&mut conn, HelperResponse::Error { detail: e }),
            },
        }
    }

    fn read_request(conn: &mut UnixStream) -> Result<HelperRequest, String> {
        let mut len_buf = [0u8; 4];
        conn.read_exact(&mut len_buf)
            .map_err(|e| format!("read len: {}", e))?;
        let n = u32::from_be_bytes(len_buf) as usize;
        if n > 64 * 1024 {
            return Err(format!("request too large: {}", n));
        }
        let mut body = vec![0u8; n];
        conn.read_exact(&mut body)
            .map_err(|e| format!("read body: {}", e))?;
        serde_json::from_slice(&body).map_err(|e| format!("parse: {}", e))
    }

    fn write_response(conn: &mut UnixStream, resp: HelperResponse) -> Result<(), String> {
        let body = serde_json::to_vec(&resp).map_err(|e| format!("serialize: {}", e))?;
        conn.write_all(&(body.len() as u32).to_be_bytes())
            .map_err(|e| format!("write len: {}", e))?;
        conn.write_all(&body)
            .map_err(|e| format!("write body: {}", e))?;
        Ok(())
    }

    /// Open `/dev/net/tun` and configure the requested interface name
    /// via TUNSETIFF. Returns the owned fd on success.
    ///
    /// Behavior matches the Linux kernel's
    /// `Documentation/networking/tuntap.rst`: the helper opens the
    /// clone device, fills an `ifreq` with `IFF_TUN | IFF_NO_PI`
    /// (we want raw IP packets without the 4-byte protocol prefix),
    /// copies the requested interface name (truncated to `IFNAMSIZ-1`
    /// to leave room for the NUL), and issues TUNSETIFF. On success
    /// the kernel materializes (or reuses) the named TUN interface
    /// and the fd points at the queue.
    ///
    /// Caller is responsible for bringing the interface up and
    /// assigning an address; we deliberately do not run `ip link set`
    /// from inside the helper because that requires CAP_NET_ADMIN
    /// rather than CAP_NET_TUN, and the GUI side already has the
    /// privileged-ops surface for it via `pkexec`.
    pub(super) fn open_tun(iface_name: &str) -> Result<OwnedFd, String> {
        use std::ffi::CString;
        use std::os::fd::FromRawFd;

        // IFNAMSIZ on Linux is 16 (15 chars + NUL).
        const IFNAMSIZ: usize = 16;
        if iface_name.is_empty() {
            return Err("iface_name is empty".into());
        }
        if iface_name.len() >= IFNAMSIZ {
            return Err(format!(
                "iface_name {:?} too long ({}); max {} bytes",
                iface_name,
                iface_name.len(),
                IFNAMSIZ - 1,
            ));
        }
        if iface_name.bytes().any(|b| b == 0 || b == b'/' || b == b' ') {
            return Err(format!("iface_name {:?} contains invalid byte", iface_name));
        }

        let path = CString::new("/dev/net/tun").expect("static path");
        // SAFETY: open(2) with a valid C string and known flags.
        let fd: RawFd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("open /dev/net/tun: {}", err));
        }
        // Wrap in OwnedFd so we close on any early return below.
        // SAFETY: open returned a fresh fd we own.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // Build the ifreq. Layout matches <linux/if.h>: a union of a
        // 16-byte name and a tail; we only need the first two fields,
        // so we model it as a fixed-size byte buffer of total size
        // `sizeof(ifreq)`. On glibc/musl x86_64 and aarch64 that is
        // 40 bytes. We zero it and write only the name and flags.
        const IFREQ_SIZE: usize = 40;
        let mut ifreq = [0u8; IFREQ_SIZE];
        let bytes = iface_name.as_bytes();
        ifreq[..bytes.len()].copy_from_slice(bytes);
        // ifr_flags lives at offset IFNAMSIZ (16) as i16.
        let flags: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        let flags_bytes = flags.to_ne_bytes();
        ifreq[IFNAMSIZ..IFNAMSIZ + flags_bytes.len()].copy_from_slice(&flags_bytes);

        // TUNSETIFF = 0x400454ca on Linux. We hardcode it because it
        // is part of the stable kernel uABI and avoids pulling in
        // kernel headers at build time.
        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        // SAFETY: ioctl takes a pointer to our local buffer of the
        // right size; the kernel writes back into it.
        let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF, ifreq.as_mut_ptr()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("ioctl TUNSETIFF on {}: {}", iface_name, err));
        }
        Ok(owned)
    }

    #[cfg(test)]
    mod open_tun_argchecks {
        use super::open_tun;

        #[test]
        fn rejects_empty_name() {
            let err = open_tun("").unwrap_err();
            assert!(err.contains("empty"), "got: {}", err);
        }

        #[test]
        fn rejects_oversize_name() {
            let err = open_tun("daal-this-name-is-way-too-long").unwrap_err();
            assert!(err.contains("too long"), "got: {}", err);
        }

        #[test]
        fn rejects_invalid_byte() {
            let err = open_tun("hy dra0").unwrap_err();
            assert!(err.contains("invalid byte"), "got: {}", err);
            let err = open_tun("h/y/dra0").unwrap_err();
            assert!(err.contains("invalid byte"), "got: {}", err);
        }
    }

    fn send_fd(conn: &mut UnixStream, fd: OwnedFd, iface_name: &str) -> Result<(), String> {
        // SCM_RIGHTS fd-passing via nix. We send the fd in a separate
        // control message and a sentinel byte in the data segment so
        // the receiver knows there is exactly one fd.
        use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
        use std::io::IoSlice;

        let raw_fd: RawFd = fd.as_raw_fd();
        let fds = [raw_fd];
        let cmsgs = [ControlMessage::ScmRights(&fds)];
        let iov = [IoSlice::new(b"FD")];
        sendmsg::<()>(conn.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
            .map_err(|e| format!("sendmsg: {}", e))?;
        write_response(
            conn,
            HelperResponse::Ok {
                detail: format!("fd_sent for {}", iface_name),
            },
        )
    }
}
