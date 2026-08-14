//! SCM_RIGHTS fd-handoff round-trip for the TUN-helper client
//! (Phase 45 Part 4). A thread plays the privileged helper over a
//! socketpair, speaking the exact wire protocol of
//! `tun-helper/src/main.rs`: length-framed JSON requests, and for a
//! successful Open a 2-byte `FD` sentinel segment carrying the fd via
//! SCM_RIGHTS followed by a length-framed `Ok` response.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use daal_desktop_core::tun_helper::unix::open_fd_over;
use daal_desktop_core::tun_helper::{HelperRequest, HelperResponse};

fn read_request(conn: &mut UnixStream) -> HelperRequest {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).unwrap();
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    conn.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn write_response(conn: &mut UnixStream, resp: &HelperResponse) {
    let body = serde_json::to_vec(resp).unwrap();
    conn.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    conn.write_all(&body).unwrap();
}

fn send_fd(conn: &mut UnixStream, fd: RawFd) {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    use std::io::IoSlice;
    let fds = [fd];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(b"FD")];
    sendmsg::<()>(conn.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None).unwrap();
}

#[test]
fn open_fd_receives_working_fd() {
    let (mut client, mut helper) = UnixStream::pair().unwrap();

    let fake_helper = std::thread::spawn(move || {
        let req = read_request(&mut helper);
        let iface = match req {
            HelperRequest::Open { iface_name } => iface_name,
            other => panic!("expected Open, got {:?}", other),
        };
        assert_eq!(iface, "daal0");

        // Stand-in for the TUN fd: the read end of a pipe whose write
        // end the "helper" scribbles a sentinel into. If the client's
        // received fd reads that sentinel back, the descriptor really
        // crossed the socket.
        let (read_end, write_end) = nix::unistd::pipe().unwrap();
        send_fd(&mut helper, read_end);
        // Close the helper's copy — the client's dup must stay usable.
        nix::unistd::close(read_end).unwrap();
        write_response(
            &mut helper,
            &HelperResponse::Ok {
                detail: format!("fd_sent for {}", iface),
            },
        );
        nix::unistd::write(write_end, b"tun-bytes").unwrap();
        nix::unistd::close(write_end).unwrap();
    });

    let (fd, detail) = open_fd_over(&mut client, "daal0").expect("open_fd_over");
    fake_helper.join().unwrap();
    assert_eq!(detail, "fd_sent for daal0");

    let mut buf = [0u8; 16];
    let n = nix::unistd::read(fd, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"tun-bytes");
    nix::unistd::close(fd).unwrap();
}

#[test]
fn open_fd_surfaces_helper_error() {
    let (mut client, mut helper) = UnixStream::pair().unwrap();

    let fake_helper = std::thread::spawn(move || {
        let _req = read_request(&mut helper);
        write_response(
            &mut helper,
            &HelperResponse::Error {
                detail: "tun open: permission denied".into(),
            },
        );
    });

    let err = open_fd_over(&mut client, "daal0").expect_err("must fail");
    fake_helper.join().unwrap();
    assert!(
        err.to_string().contains("permission denied"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn open_fd_rejects_eof() {
    let (mut client, mut helper) = UnixStream::pair().unwrap();
    let fake_helper = std::thread::spawn(move || {
        let _req = read_request(&mut helper);
        // Hang up without an fd or a response.
    });
    let err = open_fd_over(&mut client, "daal0").expect_err("must fail");
    fake_helper.join().unwrap();
    assert!(
        err.to_string().contains("without an fd"),
        "unexpected error: {}",
        err
    );
}
