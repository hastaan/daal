//! IPC client for the privileged TUN helper.
//!
//! Linux: connects to a Unix abstract socket served by `daal-tun-helper`.
//! Windows: connects to a named pipe served by `daal-win-service`.
//!
//! Phase 1.5B carries only the protocol shape and a Linux-side
//! integration; Windows's named-pipe client is wired in 1.5B-Polish.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

// Imports below are only referenced by the platform-gated `unix` and
// `win` modules. On macOS neither module is included, so gate the use
// statement to keep the `unused_imports` lint quiet without losing
// resolution on Linux/Windows.
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::errors::{DesktopError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Open /dev/net/tun (Linux) or WinTUN (Windows). The helper hands
    /// the resulting fd / handle back over the IPC socket.
    Open { iface_name: String },
    /// Tear the interface down.
    Close,
    /// Helper version probe; no privileged action.
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperResponse {
    Ok { detail: String },
    Error { detail: String },
}

#[cfg(target_os = "linux")]
pub mod unix {
    use std::io::{Read, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::io::RawFd;
    use std::os::unix::net::{SocketAddr, UnixStream};
    use std::time::Duration;

    use super::*;

    /// The Phase 1.5B abstract-socket name. The helper binds to the
    /// Linux abstract address `\0daal/tun-helper`; Tauri connects via
    /// `SocketAddr::from_abstract_name(ABSTRACT_NAME)`. The path-based
    /// `UnixStream::connect(Path)` API rejects interior NULs, so we
    /// must go through `connect_addr`.
    pub const ABSTRACT_NAME: &[u8] = b"daal/tun-helper";

    pub fn ping(timeout: Duration) -> Result<HelperResponse> {
        send_request(HelperRequest::Ping, timeout)
    }

    pub fn open(iface_name: &str, timeout: Duration) -> Result<HelperResponse> {
        send_request(
            HelperRequest::Open {
                iface_name: iface_name.to_string(),
            },
            timeout,
        )
    }

    /// Open the TUN device via the helper and receive its fd over
    /// SCM_RIGHTS (the helper sends a 2-byte `FD` sentinel segment
    /// carrying the fd, then a length-framed `Ok` response).
    ///
    /// Ownership: the returned fd is raw on purpose — its intended
    /// consumer is `engine_set_tun_fd`, which takes ownership (Phase 45
    /// invariant 3: after a successful set the caller MUST NOT close).
    /// A caller that aborts before the handoff must close the fd
    /// itself (`nix::unistd::close`).
    pub fn open_fd(iface_name: &str, timeout: Duration) -> Result<(RawFd, String)> {
        let addr = SocketAddr::from_abstract_name(ABSTRACT_NAME)
            .map_err(|e| DesktopError::TunHelper(format!("abstract addr: {}", e)))?;
        let mut conn = UnixStream::connect_addr(&addr)
            .map_err(|e| DesktopError::TunHelper(format!("connect: {}", e)))?;
        conn.set_read_timeout(Some(timeout))?;
        conn.set_write_timeout(Some(timeout))?;
        open_fd_over(&mut conn, iface_name)
    }

    /// Protocol core of [`open_fd`], over an injected stream so tests
    /// can drive it through a socketpair.
    pub fn open_fd_over(conn: &mut UnixStream, iface_name: &str) -> Result<(RawFd, String)> {
        write_request(
            conn,
            &HelperRequest::Open {
                iface_name: iface_name.to_string(),
            },
        )?;
        recv_fd(conn)
    }

    pub fn close(timeout: Duration) -> Result<HelperResponse> {
        send_request(HelperRequest::Close, timeout)
    }

    fn send_request(req: HelperRequest, timeout: Duration) -> Result<HelperResponse> {
        let addr = SocketAddr::from_abstract_name(ABSTRACT_NAME)
            .map_err(|e| DesktopError::TunHelper(format!("abstract addr: {}", e)))?;
        let mut conn = UnixStream::connect_addr(&addr)
            .map_err(|e| DesktopError::TunHelper(format!("connect: {}", e)))?;
        conn.set_read_timeout(Some(timeout))?;
        conn.set_write_timeout(Some(timeout))?;
        write_request(&mut conn, &req)?;
        read_framed_response(&mut conn)
    }

    fn write_request(conn: &mut UnixStream, req: &HelperRequest) -> Result<()> {
        let body = serde_json::to_vec(req)?;
        conn.write_all(&(body.len() as u32).to_be_bytes())?;
        conn.write_all(&body)?;
        Ok(())
    }

    fn read_framed_response(conn: &mut UnixStream) -> Result<HelperResponse> {
        let mut len_buf = [0u8; 4];
        conn.read_exact(&mut len_buf)?;
        read_framed_response_after(conn, &len_buf, 4)
    }

    /// Finish reading a length-framed response when `got` bytes of the
    /// 4-byte length prefix already landed in `head` (recv_fd can eat
    /// the first bytes of an error response while probing for the fd
    /// segment).
    fn read_framed_response_after(
        conn: &mut UnixStream,
        head: &[u8],
        got: usize,
    ) -> Result<HelperResponse> {
        let mut len_buf = [0u8; 4];
        len_buf[..got].copy_from_slice(&head[..got]);
        conn.read_exact(&mut len_buf[got..])?;
        let n = u32::from_be_bytes(len_buf) as usize;
        if n > 64 * 1024 {
            return Err(DesktopError::TunHelper(format!(
                "response too large: {}",
                n
            )));
        }
        let mut body = vec![0u8; n];
        conn.read_exact(&mut body)?;
        let resp: HelperResponse = serde_json::from_slice(&body)?;
        Ok(resp)
    }

    /// Receive the helper's answer to `Open`: either the fd segment
    /// (`FD` sentinel + SCM_RIGHTS) followed by a framed `Ok`, or a
    /// plain framed `Error` when the privileged open failed.
    fn recv_fd(conn: &mut UnixStream) -> Result<(RawFd, String)> {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
        use std::io::IoSliceMut;
        use std::os::unix::io::AsRawFd;

        let mut data = [0u8; 4];
        let (nbytes, fds) = {
            let mut iov = [IoSliceMut::new(&mut data)];
            let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);
            let msg = recvmsg::<()>(
                conn.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::empty(),
            )
            .map_err(|e| DesktopError::TunHelper(format!("recvmsg: {}", e)))?;
            let fds: Vec<RawFd> = msg
                .cmsgs()
                .filter_map(|c| match c {
                    ControlMessageOwned::ScmRights(received) => Some(received),
                    _ => None,
                })
                .flatten()
                .collect();
            (msg.bytes, fds)
        };

        if fds.is_empty() {
            // No fd: this must be the length-framed error path.
            if nbytes == 0 {
                return Err(DesktopError::TunHelper(
                    "helper closed the connection without an fd or a response".into(),
                ));
            }
            return match read_framed_response_after(conn, &data, nbytes)? {
                HelperResponse::Error { detail } => Err(DesktopError::TunHelper(detail)),
                HelperResponse::Ok { detail } => Err(DesktopError::TunHelper(format!(
                    "helper replied Ok but sent no fd: {}",
                    detail
                ))),
            };
        }

        let fd = fds[0];
        // Defensive: a conforming helper sends exactly one fd.
        for extra in &fds[1..] {
            let _ = nix::unistd::close(*extra);
        }
        if &data[..nbytes] != b"FD" {
            let _ = nix::unistd::close(fd);
            return Err(DesktopError::TunHelper(format!(
                "fd segment carried unexpected sentinel {:?}",
                &data[..nbytes]
            )));
        }
        match read_framed_response(conn) {
            Ok(HelperResponse::Ok { detail }) => Ok((fd, detail)),
            Ok(HelperResponse::Error { detail }) => {
                let _ = nix::unistd::close(fd);
                Err(DesktopError::TunHelper(detail))
            }
            Err(e) => {
                let _ = nix::unistd::close(fd);
                Err(e)
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub mod win {
    use super::*;
    use std::time::Duration;

    pub const PIPE_NAME: &str = r"\\.\pipe\daal-engine";

    /// Stub for Windows; real implementation uses
    /// `windows-sys`'s named-pipe API and lands in 1.5B-Polish.
    pub fn ping(_timeout: Duration) -> Result<HelperResponse> {
        Err(DesktopError::TunHelper(
            "Windows TUN-helper IPC not implemented in 1.5B scaffold".into(),
        ))
    }
}
