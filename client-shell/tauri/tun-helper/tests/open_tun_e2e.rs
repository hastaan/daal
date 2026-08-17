//! End-to-end integration test for the privileged TUN helper.
//!
//! The test:
//!   1. Verifies the host can actually open `/dev/net/tun` (skips
//!      cleanly otherwise; this preserves CI portability).
//!   2. Spawns `daal-tun-helper` as a subprocess.
//!   3. Connects to the abstract socket the helper binds.
//!   4. Sends `{ "op": "open", "iface_name": "daaltest0" }`.
//!   5. Receives one fd over SCM_RIGHTS plus an `Ok` JSON response.
//!   6. Verifies the received fd is a TUN device by issuing TUNGETIFF
//!      and reading the iface name back.
//!
//! Helper lifecycle: one-shot per the Phase 1.5B contract — accept one
//! connection, serve one request, exit. We wait the child out at the
//! end of the test.
//!
//! Skip rules: this test is no-op when:
//!   - The build is not Linux (the helper is Linux-only).
//!   - `/dev/net/tun` is not openable by the current user.
//!   - The compiled `daal-tun-helper` binary cannot be located.

#![cfg(target_os = "linux")]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ABSTRACT_NAME: &[u8] = b"daal/tun-helper";
const IFNAMSIZ: usize = 16;
const TUNGETIFF: libc::c_ulong = 0x800454d2;
const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

/// True only if this process can actually *create* a TUN interface.
///
/// Opening `/dev/net/tun` is NOT sufficient evidence: the clone device is
/// mode 0666 on a normal distro, so `open` succeeds for any user. The
/// privilege check is `TUNSETIFF`, which needs CAP_NET_ADMIN and returns
/// EPERM without it. Probing with `open` alone made this guard always
/// return true, so the documented skip never fired and the test hard-failed
/// on every unprivileged machine — including every CI runner.
///
/// The probe interface is created without IFF_PERSIST, so closing the fd
/// tears it down immediately.
fn can_open_tun_clone() -> bool {
    let path = CString::new("/dev/net/tun").unwrap();
    // SAFETY: open(2) with a valid C string and valid flags.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return false;
    }

    // struct ifreq: 16-byte ifr_name, then a union whose first member
    // (ifr_flags) is a short. Zeroed name => kernel picks "tunN".
    let mut ifreq = [0u8; 40];
    let flags = IFF_TUN | IFF_NO_PI;
    ifreq[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());

    // SAFETY: fd is ours and ifreq is a correctly sized ifreq buffer.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifreq.as_mut_ptr()) };

    // SAFETY: fresh fd we own. Dropping it also destroys the probe iface.
    unsafe { libc::close(fd) };

    rc == 0
}

/// Locate the freshly-built helper binary. Cargo sets CARGO_BIN_EXE_<name>
/// for integration tests of bin crates.
fn helper_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_daal-tun-helper"))
}

/// Wait until the helper's abstract socket is reachable, with a timeout.
fn wait_for_helper(deadline: Instant) -> std::io::Result<UnixStream> {
    loop {
        let addr = SocketAddr::from_abstract_name(ABSTRACT_NAME)?;
        match UnixStream::connect_addr(&addr) {
            Ok(s) => return Ok(s),
            Err(e) => {
                if Instant::now() > deadline {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn write_request(conn: &mut UnixStream, json: &[u8]) {
    conn.write_all(&(json.len() as u32).to_be_bytes()).unwrap();
    conn.write_all(json).unwrap();
}

/// Read both an `Ok`/`Error` JSON response and one SCM_RIGHTS fd.
/// The helper sends the fd in a sendmsg with a 2-byte data segment
/// "FD" and the cmsg, then writes the JSON response with the
/// length-prefixed framing. We read both off the same connection.
fn read_response_and_fd(conn: &mut UnixStream) -> (String, Option<OwnedFd>) {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::IoSliceMut;

    // First, the FD-bearing sendmsg.
    let mut data = [0u8; 2];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(
        conn.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .expect("recvmsg fd-carrier");

    let mut got_fd: Option<OwnedFd> = None;
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            assert_eq!(fds.len(), 1, "expected exactly one fd, got {}", fds.len());
            // SAFETY: the kernel just installed this fd into our table.
            got_fd = Some(unsafe { OwnedFd::from_raw_fd(fds[0]) });
        }
    }
    assert_eq!(&data, b"FD", "fd-carrier sentinel must be 'FD'");

    // Then, the framed JSON response.
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).expect("read resp len");
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    conn.read_exact(&mut body).expect("read resp body");
    let s = String::from_utf8(body).expect("utf8");
    (s, got_fd)
}

fn assert_fd_is_tun(fd: &OwnedFd, expected_name: &str) {
    let mut ifreq = [0u8; 40];
    // SAFETY: ioctl writes back into our buffer of the right size.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNGETIFF, ifreq.as_mut_ptr()) };
    assert!(
        rc == 0,
        "TUNGETIFF on returned fd failed: {}",
        std::io::Error::last_os_error()
    );
    let nul = ifreq[..IFNAMSIZ]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(IFNAMSIZ);
    let got = std::str::from_utf8(&ifreq[..nul]).expect("iface name utf8");
    assert_eq!(
        got, expected_name,
        "TUNGETIFF returned iface name {:?}, expected {:?}",
        got, expected_name
    );
}

#[test]
fn helper_opens_tun_and_passes_fd_via_scm_rights() {
    if !can_open_tun_clone() {
        eprintln!(
            "skip: /dev/net/tun is not openable by the current user; \
             this test requires CAP_NET_ADMIN or root and a kernel with TUN built in"
        );
        return;
    }

    let mut child: Child = Command::new(helper_binary())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn daal-tun-helper");

    // The helper binds the socket then accepts one connection. Wait
    // for the bind to land. A bounded retry avoids a deterministic
    // race on slow CI.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut conn = match wait_for_helper(deadline) {
        Ok(c) => c,
        Err(e) => {
            let _ = child.kill();
            panic!(
                "could not connect to helper at abstract \"{}\": {}",
                String::from_utf8_lossy(ABSTRACT_NAME),
                e
            );
        }
    };

    let req = br#"{"op":"open","iface_name":"daaltest0"}"#;
    write_request(&mut conn, req);

    let (resp_json, fd) = read_response_and_fd(&mut conn);
    assert!(
        resp_json.contains("\"ok\""),
        "expected ok response, got {}",
        resp_json
    );
    let fd = fd.expect("expected fd via SCM_RIGHTS");
    assert_fd_is_tun(&fd, "daaltest0");

    // Reap the helper.
    let status = child.wait().expect("helper wait");
    assert!(status.success(), "helper exited non-zero: {:?}", status);
}
