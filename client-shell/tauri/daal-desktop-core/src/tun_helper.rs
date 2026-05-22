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
        let body = serde_json::to_vec(&req)?;
        conn.write_all(&(body.len() as u32).to_be_bytes())?;
        conn.write_all(&body)?;

        let mut len_buf = [0u8; 4];
        conn.read_exact(&mut len_buf)?;
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
