//! `daal-desktop-core` is the Tauri-agnostic Rust core for the
//! Daal desktop GUI. It owns:
//!
//! * `engine` — the dlopen wrapper around `libdaalcore.{so,dll,dylib}`
//!   and the typed Rust API over the engine_* C ABI.
//! * `singbox` — sing-box sidecar lifecycle (spawn, Clash REST control,
//!   shutdown) and the small SOCKS5 inlet the engine refresher targets.
//! * `tun_helper` — IPC with the privileged TUN helper (Linux) or
//!   Windows service.
//! * `commands` — the typed Tauri command surface (each command has a
//!   plain-Rust function plus an optional `#[tauri::command]` shim
//!   gated by the `tauri` feature flag in the GUI shell crate).
//! * `state` — `AppState` with a mutex-protected handle to the engine.
//!
//! Everything in this crate compiles without Node, Tauri, or any GUI
//! dependency, which keeps `cargo test` fast and CI simple.

#![deny(unsafe_code)]

pub mod commands;
pub mod engine;
pub mod errors;
pub mod singbox;
pub mod state;
pub mod tun_helper;

pub use crate::errors::DesktopError;
pub use crate::state::AppState;
