//! Command surface — the typed Rust functions the Tauri shell wraps
//! with `#[tauri::command]`. Each one returns `Result<T, String>` for
//! easy serialization to the JS side.
//!
//! The command set mirrors the Compose UI screens shipped in Phase
//! 1.5A so desktop UX parity is "same JSON in, same JSON out."

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::errors::{DesktopError, Result};
use crate::singbox::{self, Singbox, SingboxConfig};
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub engine_version: String,
    pub gui_version: &'static str,
}

pub const GUI_VERSION: &str = "0.2.0";

pub fn version_info(state: &AppState) -> VersionInfo {
    VersionInfo {
        engine_version: state.engine.version_str(),
        gui_version: GUI_VERSION,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewedBundle {
    pub fingerprint_hex: String,
    pub fingerprint_en: String,
    pub fingerprint_fa: String,
    pub fingerprint_visual_data_uri: String,
    pub publisher_name: String,
    pub bundle_id: String,
    pub spec_version: i32,
    pub route_count: usize,
}

/// Verify and preview an .sbp file using bundle-rs (no engine call).
/// The UI uses this to render the trust prompt BEFORE asking the user
/// to commit. The engine is only called once the user clicks Trust.
pub fn preview_bundle(path: PathBuf) -> Result<PreviewedBundle> {
    let bytes = std::fs::read(&path)?;
    let sbp = bundle_rs::parse_sbp(&bytes)?;
    bundle_rs::verify_bundle(&sbp)?;
    let fp = bundle_rs::publisher_fingerprint(&sbp.publisher_pub);
    // Phase 1.5B uses placeholder wordlists for the preview; the
    // authoritative wordlists live in publisher.DefaultWordlists() on
    // the Go side and the engine's import_sbp call returns the same
    // rendered fingerprint, so the UI can switch to those once
    // the trust prompt is committed.
    let en = ["alpha", "bravo", "charlie", "delta"];
    let fa = ["یک", "دو", "سه", "چهار"];
    let r = bundle_rs::render_fingerprint(&fp, &en, &fa);
    Ok(PreviewedBundle {
        fingerprint_hex: r.hex,
        fingerprint_en: r.en,
        fingerprint_fa: r.fa,
        fingerprint_visual_data_uri: r.visual_data_uri,
        publisher_name: sbp.manifest.publisher.name.clone(),
        bundle_id: sbp.manifest.bundle.id.clone(),
        spec_version: sbp.manifest.spec_version,
        route_count: sbp.manifest.routes.len(),
    })
}

/// Hand the .sbp to the engine for persistent import. Returns the
/// engine's verdict JSON unchanged so the UI can introspect it.
pub fn import_sbp(state: &AppState, path: PathBuf) -> Result<String> {
    state.engine.import_sbp(&path)
}

pub fn resolve_trust_prompt(state: &AppState, fingerprint: &str, decision: i32) -> Result<String> {
    state.engine.resolve_trust_prompt(fingerprint, decision)
}

pub fn fountain_feed_frame(state: &AppState, session_id: &str, frame_b64: &str) -> Result<String> {
    state.engine.fountain_feed_frame(session_id, frame_b64)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub route_id: String,
}

/// Connect: tell the engine which route to activate, then push the
/// resulting outbound to sing-box via Clash REST. (The route → outbound
/// translation will land alongside the sing-box Clash REST client; for
/// 1.5B the engine_set_route call is the contract that matters.)
pub fn connect(state: &AppState, req: ConnectRequest) -> Result<()> {
    state.engine.set_route(&req.route_id)?;
    Ok(())
}

pub fn disconnect(state: &AppState) -> Result<()> {
    state.engine.clear_route()?;
    Ok(())
}

pub fn diagnostics_explain(state: &AppState) -> Result<String> {
    state.engine.diagnostics_explain()
}

// -- D-2.1 -----------------------------------------------------------

pub fn route_summary(state: &AppState, route_id: &str) -> Result<String> {
    state.engine.route_summary(route_id)
}

pub fn available_routes(state: &AppState) -> Result<String> {
    state.engine.available_routes()
}

pub fn throughput_snapshot(state: &AppState) -> Result<String> {
    state.engine.throughput_snapshot()
}

pub fn panic_wipe(state: &AppState) -> Result<()> {
    state.engine.panic_wipe()
}

pub fn export_diagnostics(state: &AppState) -> Result<String> {
    state.engine.export_diagnostics()
}

/// Phase 2B: set the V2.2 budget mode dial. Mode is one of
/// `lifeline`, `normal`, `bulk`. The 2D mode `lifeline-strict` is NOT
/// accepted at the engine_set_mode boundary in 2B and will return an
/// error from the engine.
pub fn set_mode(state: &AppState, mode: &str) -> Result<()> {
    state.engine.set_mode(mode)
}

/// Phase 2C: notify the engine that the device's active network has
/// changed. The `(kind, carrier, ssid)` tuple is hashed inside the
/// engine before any persistence, logging, or diagnostics — the raw
/// strings never leave this function frame. Returns the engine's
/// JSON status blob (`{network_id, mode, restored_routes, fresh}`).
///
/// `kind` must be one of `wifi`, `cell`, `eth`, `unknown`. `carrier`
/// and `ssid` may be empty depending on the kind.
pub fn network_changed(state: &AppState, kind: &str, carrier: &str, ssid: &str) -> Result<String> {
    state.engine.network_changed(kind, carrier, ssid)
}

/// Phase 2D: unlock the routestore secrets via the Argon2id PIN-vault.
/// For high-risk-class devices only — the engine returns `-2` for
/// non-high-risk devices, which we translate to `Ok(())` because
/// "no unlock required" is a successful outcome at the desktop layer.
///
/// The PIN string is held in this function frame for the duration
/// of the call and never logged, never persisted, never returned.
pub fn unlock_secrets(state: &AppState, pin: &str) -> Result<UnlockOutcome> {
    match state.engine.unlock_secrets(pin) {
        Ok(()) => Ok(UnlockOutcome::Unlocked),
        Err(crate::errors::DesktopError::EngineReturn(-2)) => Ok(UnlockOutcome::NotRequired),
        Err(crate::errors::DesktopError::EngineReturn(-1)) => Ok(UnlockOutcome::WrongPin),
        Err(e) => Err(e),
    }
}

/// UnlockOutcome distinguishes "successfully unlocked" from "no PIN
/// gate required" from "wrong PIN" at the desktop layer. The wrong-PIN
/// case is intentionally NOT modeled as a Result::Err because the UI
/// re-prompts and a user-facing soft error is the right surface.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockOutcome {
    Unlocked,
    NotRequired,
    WrongPin,
}

/// Phase 2D: Toggle the engine's per-session bulk-capable opt-in
/// flag. Drives `engine_set_allow_bulk_capable` (NOT a release ABI
/// surface — the engine exposes a Go-level setter only). The flag
/// is cleared on engine_init and on session end; it survives
/// SetMode and engine_network_changed.
pub fn set_allow_bulk_capable(state: &AppState, allow: bool) -> Result<()> {
    state.engine.set_allow_bulk_capable(allow);
    Ok(())
}

pub fn pointer_rotation_status(state: &AppState) -> Result<String> {
    state.engine.pointer_rotation_status()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSubscriptionRequest {
    pub publisher_fingerprint: String,
    pub url: String,
    pub display_name: String,
}

pub fn subscription_add(state: &AppState, req: AddSubscriptionRequest) -> Result<String> {
    state
        .engine
        .subscription_add(&req.publisher_fingerprint, &req.url, &req.display_name)
}

pub fn subscription_refresh(
    state: &AppState,
    subscription_id: &str,
    timeout_ms: i32,
) -> Result<String> {
    state
        .engine
        .subscription_refresh(subscription_id, timeout_ms)
}

pub fn subscription_remove(state: &AppState, subscription_id: &str) -> Result<()> {
    state.engine.subscription_remove(subscription_id)
}

/// Snapshot of every subscription known to the engine. Used by the
/// desktop Subscriptions screen on mount; without this the screen only
/// renders rows the user added this session, which the 1.5B handover
/// flagged as a known limitation.
pub fn subscription_list(state: &AppState) -> Result<String> {
    state.engine.subscription_list()
}

pub fn revocation_refresh_all(state: &AppState, timeout_ms: i32) -> Result<String> {
    state.engine.revocation_refresh_all(timeout_ms)
}

/// Spawn sing-box (if not yet running) and call engine_set_tunnel_socks
/// so the Go-side refresher routes through the local SOCKS5 inlet.
pub fn start_sidecar(state: &AppState) -> Result<()> {
    let mut guard = state.singbox.write().expect("singbox poisoned");
    if guard.is_some() {
        return Ok(());
    }
    let bin = singbox::resolve_singbox_binary(&state.state_dir)
        .ok_or_else(|| DesktopError::Singbox("sing-box binary not found".into()))?;
    let socks_port = singbox::pick_loopback_port()?;
    let clash_port = singbox::pick_loopback_port()?;
    let secret = singbox::random_secret()?;
    let cfg = SingboxConfig {
        binary: bin,
        config_path: state.state_dir.join("singbox.json"),
        socks_port,
        clash_port,
        clash_secret: secret,
    };
    let sb = Singbox::spawn(cfg)?;
    let endpoint = sb.socks_endpoint();
    *guard = Some(sb);
    drop(guard);
    // Hand the SOCKS5 endpoint to the Go core's refresher.
    let _ = state
        .engine
        .set_tunnel_socks(&endpoint.ip().to_string(), endpoint.port(), "", "")?;
    Ok(())
}

pub fn stop_sidecar(state: &AppState) -> Result<()> {
    // Clear the tunnel dialer FIRST so a parallel refresh doesn't try
    // to dial through a dead SOCKS port.
    let _ = state.engine.set_tunnel_socks("", 0, "", "");
    let mut guard = state.singbox.write().expect("singbox poisoned");
    if let Some(sb) = guard.take() {
        sb.stop()?;
    }
    Ok(())
}

/// 2-second-tick heartbeat the GUI calls from a background timer.
/// Returns the current healthy flag.
pub fn heartbeat_tick(state: &AppState) -> bool {
    state.heartbeat.check_once(&state.engine);
    state.heartbeat.is_healthy()
}

// ---- v0.2.x — full plumbing wrappers ------------------------------

pub fn apply_cooldown(state: &AppState, route_id: &str, seconds: i32) -> Result<()> {
    state.engine.apply_cooldown(route_id, seconds)
}

pub fn lifecycle_event(state: &AppState, token: &str) -> Result<()> {
    state.engine.lifecycle_event(token)
}

pub fn probe_udp(state: &AppState, timeout_ms: i32) -> i32 {
    state.engine.probe_udp(timeout_ms)
}
pub fn probe_dns(state: &AppState, timeout_ms: i32) -> i32 {
    state.engine.probe_dns(timeout_ms)
}
pub fn probe_tcp443(state: &AppState, timeout_ms: i32) -> i32 {
    state.engine.probe_tcp443(timeout_ms)
}

pub fn scheduler_status(state: &AppState) -> Result<String> {
    state.engine.scheduler_status()
}
pub fn stats_redacted(state: &AppState) -> Result<String> {
    state.engine.stats_redacted()
}

pub fn redistribute_route(state: &AppState, route_id: &str, recipient_fp: &str) -> Result<String> {
    state.engine.redistribute_route(route_id, recipient_fp)
}

pub fn set_route_budget(state: &AppState, route_id: &str, budget_tag: &str) -> Result<String> {
    state.engine.set_route_budget(route_id, budget_tag)
}

pub fn set_rendezvous_priority(state: &AppState, priority_json: &str) -> Result<()> {
    state.engine.set_rendezvous_priority(priority_json)
}
pub fn set_push_rendezvous_enabled(state: &AppState, enabled: bool) -> Result<()> {
    state.engine.set_push_rendezvous_enabled(enabled)
}
pub fn set_auto_promotion(state: &AppState, enabled: bool) {
    state.engine.set_auto_promotion(enabled);
}
pub fn set_masque_submode_override(state: &AppState, submode: &str) -> Result<()> {
    state.engine.set_masque_submode_override(submode)
}
pub fn set_experimental_families_enabled(state: &AppState, enabled: bool) -> Result<()> {
    state.engine.set_experimental_families_enabled(enabled)
}

pub fn bootstrap_install_seeds(state: &AppState) -> Result<String> {
    state.engine.bootstrap_install_seeds()
}
pub fn bootstrap_refresh(state: &AppState, timeout_ms: i32) -> Result<String> {
    state.engine.bootstrap_refresh(timeout_ms)
}
pub fn bootstrap_status(state: &AppState) -> Result<String> {
    state.engine.bootstrap_status()
}

pub fn uri_detect(state: &AppState, text: &str) -> Result<String> {
    state.engine.uri_detect(text)
}
pub fn uri_import(state: &AppState, raw_uri: &str) -> Result<String> {
    state.engine.uri_import(raw_uri)
}

pub fn loaded_wasm_modules(state: &AppState) -> Result<String> {
    state.engine.loaded_wasm_modules()
}
pub fn wasm_kill_switch_pubkey(state: &AppState) -> Result<String> {
    state.engine.wasm_kill_switch_pubkey()
}

/// Shorter alias for tests.
pub(crate) fn _heartbeat_unused(_d: Duration) {}

/// Re-export so tests can construct an Engine in isolation.
pub use crate::engine::Engine as RawEngine;
