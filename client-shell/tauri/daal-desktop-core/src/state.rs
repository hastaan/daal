//! Process-wide app state. Holds the loaded `Engine`, the sing-box
//! controller, and the optional TUN-helper IPC handle.
//!
//! `AppState` is `Send + Sync` and meant to be shared via `Arc` across
//! Tauri command handlers and background threads.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::engine::{Engine, HeartbeatSupervisor};
use crate::singbox::Singbox;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    pub singbox: Arc<RwLock<Option<Singbox>>>,
    pub heartbeat: Arc<HeartbeatSupervisor>,
    /// Per-process state directory; passed to engine_init.
    pub state_dir: PathBuf,
}

impl AppState {
    pub fn new(engine: Arc<Engine>, state_dir: PathBuf) -> Self {
        Self {
            engine,
            singbox: Arc::new(RwLock::new(None)),
            heartbeat: Arc::new(HeartbeatSupervisor::new()),
            state_dir,
        }
    }
}
