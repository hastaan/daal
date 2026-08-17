//! sing-box sidecar lifecycle and Clash REST control.
//!
//! Phase 1.5B model (per spec):
//!   * sing-box is a long-lived child of the desktop GUI.
//!   * On startup, the GUI generates a config with:
//!     - SOCKS5 inbound on 127.0.0.1:<random> (used for refresh + the
//!       optional "Set system proxy" toggle).
//!     - Clash REST API on 127.0.0.1:<random> with a random secret.
//!     - TUN inbound declared but idle (the helper later injects fd).
//!   * On Connect, we PUT a new outbound block via Clash REST.
//!   * On Disconnect, we PUT a "no-op" block.
//!
//! This module is intentionally NOT a full sing-box config builder; it
//! is the lifecycle wrapper. The route → outbound translation lives in
//! `commands::connect` because that's where the engine's selected route
//! lands.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::errors::{DesktopError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingboxConfig {
    /// Path to the sing-box binary. Resolved at GUI startup.
    pub binary: PathBuf,
    /// Path the sidecar will write its runtime config to.
    pub config_path: PathBuf,
    /// SOCKS5 inbound bound to 127.0.0.1; chosen by the GUI.
    pub socks_port: u16,
    /// Clash REST API port bound to 127.0.0.1.
    pub clash_port: u16,
    /// Random secret required to call the Clash REST API.
    pub clash_secret: String,
    /// RFC 1929 credential for the SOCKS5 inbound.
    ///
    /// An unauthenticated loopback SOCKS proxy is an open proxy for
    /// every other process on the machine — including a browser tab's
    /// helper, a packaged Electron app, or anything a user was tricked
    /// into running — and this one's `route.final` is `direct`, so it
    /// egresses from the user's real address. Requiring auth means an
    /// unauthenticated prober is answered METHOD=0xFF and cannot use
    /// it. Same reasoning, and the same shape, as the in-process
    /// Android inlet in core/engine/inlet.go.
    pub socks_user: String,
    pub socks_pass: String,
}

impl SingboxConfig {
    /// Generates a config blob suitable to pass via `-c` to sing-box.
    /// Outbounds are intentionally minimal — Connect rewrites them via
    /// the Clash REST endpoint.
    pub fn render_initial_json(&self) -> serde_json::Value {
        serde_json::json!({
            "log": { "level": "warn", "timestamp": false },
            "experimental": {
                "clash_api": {
                    "external_controller": format!("127.0.0.1:{}", self.clash_port),
                    "secret": self.clash_secret,
                }
            },
            "inbounds": [
                {
                    "type": "socks",
                    "tag": "socks-inlet",
                    "listen": "127.0.0.1",
                    "listen_port": self.socks_port,
                    "users": [
                        { "username": self.socks_user, "password": self.socks_pass }
                    ]
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": { "final": "direct" }
        })
    }
}

pub struct Singbox {
    cfg: SingboxConfig,
    child: Child,
}

impl Singbox {
    /// Spawns sing-box as a child process. Returns immediately; caller
    /// is responsible for keeping the `Singbox` alive in `AppState`.
    pub fn spawn(cfg: SingboxConfig) -> Result<Self> {
        let body = cfg.render_initial_json();
        std::fs::write(&cfg.config_path, serde_json::to_vec_pretty(&body)?)?;
        let child = Command::new(&cfg.binary)
            .arg("run")
            .arg("-c")
            .arg(&cfg.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| DesktopError::Singbox(format!("spawn: {}", e)))?;
        Ok(Self { cfg, child })
    }

    pub fn config(&self) -> &SingboxConfig {
        &self.cfg
    }

    /// `127.0.0.1:<socks_port>` — the sidecar's SOCKS5 inlet.
    ///
    /// NOT a tunnel endpoint. `render_initial_json` sets
    /// `route.final = "direct"` and `commands::connect` never rewrites
    /// the outbound set (the Clash REST translation was never
    /// implemented), so anything dialled here egresses from the user's
    /// real address. Handing this to `engine_set_tunnel_socks` would
    /// install a "tunnel" dialer that is not one, which both leaks and
    /// suppresses the fail-closed guard — see `commands::start_sidecar`.
    pub fn socks_endpoint(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.cfg.socks_port)
    }

    /// Stops the sidecar by killing the child. We deliberately do NOT
    /// pipe stdin / signals here; sing-box treats SIGKILL and SIGINT
    /// the same on shutdown (no on-disk state to flush) and the
    /// platform-portable Rust API for graceful termination is more
    /// complexity than this phase needs.
    pub fn stop(mut self) -> Result<()> {
        self.child.kill().ok();
        self.child.wait().ok();
        Ok(())
    }
}

/// Picks a random unprivileged port in the loopback range. We use the
/// kernel's "bind to port 0" trick rather than a userspace RNG so we
/// know the port is actually free.
pub fn pick_loopback_port() -> Result<u16> {
    use std::net::TcpListener;
    let l = TcpListener::bind("127.0.0.1:0")?;
    let p = l.local_addr()?.port();
    drop(l);
    Ok(p)
}

/// Generate a random secret for the Clash REST API. We avoid pulling
/// `rand` for one call and instead splice 32 bytes of os-randomness via
/// `getrandom` (re-export from `ed25519-dalek`'s rand_core dep would be
/// cleaner; for a single use we read /dev/urandom on Unix and CryptGen
/// on Windows via std::fs).
pub fn random_secret() -> Result<String> {
    let mut buf = [0u8; 16];
    fill_random(&mut buf)?;
    Ok(hex::encode(buf))
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    #[cfg(unix)]
    {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(buf)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        // On Windows we ship crypto via getrandom in production; for
        // this scaffold we error so the caller sees the missing piece.
        Err(DesktopError::Singbox(
            "random_secret: Windows getrandom not wired in scaffold".into(),
        ))
    }
}

/// Resolve the sing-box binary path at runtime. We look in:
///   1. $DAAL_SINGBOX_BIN
///   2. <state_dir>/bin/sing-box{,.exe}
///   3. PATH
pub fn resolve_singbox_binary(state_dir: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DAAL_SINGBOX_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let exe = if cfg!(windows) {
        "sing-box.exe"
    } else {
        "sing-box"
    };
    let bundled = state_dir.join("bin").join(exe);
    if bundled.exists() {
        return Some(bundled);
    }
    // PATH lookup.
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join(exe);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}
