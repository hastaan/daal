//! Tauri 2 GUI shell — wraps every command in `daal-desktop-core`
//! with a `#[tauri::command]` annotation and exposes them to the React
//! webview.
//!
//! The `Engine` is loaded on app startup. Path resolution (in order):
//!
//!   1. `$DAAL_ENGINE_LIB` env var (developer convenience).
//!   2. `<exe_dir>/libdaalcore.{so,dll,dylib}` (shipped alongside the
//!      bundled .deb / .AppImage / NSIS installer).
//!   3. `<state_dir>/lib/libdaalcore.{so,dll,dylib}` (sideloaded by
//!      packagers).
//!
//! ABI mismatch fails fast with a UI banner.

// FRP-5 wizard backend (key custody, OperatorRecord persistence,
// CLI bridge, Tauri command surface). The wizard logic itself lives
// in the workspace crate `daal-wizard` (so cargo tests don't need
// the GTK/webkit toolchain). The Tauri command bindings are wired
// in by FRP-5 commit 3/5.

pub mod recipient;

#[cfg(any(desktop, test))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use daal_desktop_core::{
    commands::{self as cmd, AddSubscriptionRequest, ConnectRequest, PreviewedBundle, VersionInfo},
    engine::Engine,
    state::AppState,
};
use daal_wizard::cli_bridge::{
    BindResult as WizardBindResult, FountainFrame, ProgressEvent,
    RotateContext as WizardRotateContext, RotationRecommendation as WizardRotationRecommendation,
    SubprocessRunner,
};
use daal_wizard::commands as wcmd;
use daal_wizard::commands::{
    RotateExecuteInput, RotateExecuteOutput, RotateRecommendInput, SubkeyRotateResult,
};
use daal_wizard::keystore::Keystore;
use daal_wizard::operator_db::OperatorDb;
use daal_wizard::operator_db::{CdnFrontRow, SignedSbpRow, SubkeyRow};
use daal_wizard::publisher_key::Fingerprint;
use daal_wizard::staging::default_staging_dir;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

/// `WizardState` is the Tauri-managed state holding the
/// `WizardCtx` the wizard commands operate against. We keep it
/// separate from `AppState` so the rest of the desktop client
/// is unchanged when the wizard isn't in use.
pub struct WizardStateMgr(pub wcmd::WizardCtx);

fn lib_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "libdaalcore.dll"
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        "libdaalcore.dylib"
    } else {
        "libdaalcore.so"
    }
}

#[cfg(desktop)]
fn locate_engine_lib(state_dir: &PathBuf) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DAAL_ENGINE_LIB") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(p) = locate_engine_lib_in(parent, state_dir, lib_filename()) {
                return Some(p);
            }
        }
    }
    let p = state_dir.join("lib").join(lib_filename());
    if p.exists() {
        return Some(p);
    }
    None
}

// Mobile platforms package the engine lib inside the app bundle and the
// system linker resolves it by short name. Android places .so files
// under <apk>/lib/<abi>/libdaalcore.so (auto-extracted to the app's
// nativeLibraryDir); iOS embeds .dylibs in @executable_path/Frameworks.
// In both cases dlopen(short_name) works without an explicit path.
#[cfg(target_os = "android")]
fn locate_engine_lib(_state_dir: &PathBuf) -> Option<PathBuf> {
    Some(PathBuf::from(lib_filename()))
}

#[cfg(target_os = "ios")]
fn locate_engine_lib(_state_dir: &PathBuf) -> Option<PathBuf> {
    Some(PathBuf::from(lib_filename()))
}

/// Pure search routine factored out of `locate_engine_lib` so unit
/// tests can exercise each candidate without mocking `current_exe`.
/// Search order, returning the first existing match:
///
///   1. `<exe_dir>/resources/<lib>`                              — Windows NSIS
///   2. `<exe_dir>/../Resources/<lib>`                           — macOS .app bundle
///   3. `<exe_dir>/../lib/Daal Desktop/resources/<lib>`         — Linux .deb / .AppImage (current productName)
///   4. `<exe_dir>/../lib/daal-desktop/resources/<lib>`         — Linux .deb (sanitised variant)
///   5. `<exe_dir>/../lib/Daal/resources/<lib>`                 — legacy productName layout
///   6. `<exe_dir>/<lib>`                                        — raw dev / sideload
///
/// The Linux candidates cover both possible sanitisation outputs of
/// `productName = "Daal Desktop"` (the literal name with a space, and
/// the lowercased-hyphenated variant) plus the legacy "Daal" layout
/// for users who never reinstalled. The smoke test in desktop.yml
/// exercises whichever path the current tauri-bundler chooses.
#[cfg(desktop)]
fn locate_engine_lib_in(exe_dir: &Path, _state_dir: &PathBuf, lib: &str) -> Option<PathBuf> {
    let candidates = [
        exe_dir.join("resources").join(lib),
        exe_dir.join("../Resources").join(lib),
        exe_dir.join("../lib").join("Daal Desktop").join("resources").join(lib),
        exe_dir.join("../lib").join("daal-desktop").join("resources").join(lib),
        exe_dir.join("../lib").join("Daal").join("resources").join(lib),
        exe_dir.join(lib),
    ];
    for p in candidates {
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod locate_tests {
    use super::*;
    use std::fs;

    fn touch(p: &Path) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, b"").unwrap();
    }

    #[test]
    fn locate_finds_in_resources_subdir() {
        // Tauri's NSIS / .deb / .AppImage install layout.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().to_path_buf();
        let state_dir = tmp.path().join("state");
        let dll = exe_dir.join("resources").join("libdaalcore.dll");
        touch(&dll);
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.dll")
            .expect("should find DLL in resources/");
        assert_eq!(found.canonicalize().unwrap(), dll.canonicalize().unwrap());
    }

    #[test]
    fn locate_finds_in_app_resources_dir() {
        // macOS .app bundle layout: exe lives in <App>/Contents/MacOS/,
        // resources live in <App>/Contents/Resources/.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().join("Contents").join("MacOS");
        fs::create_dir_all(&exe_dir).unwrap();
        let dylib = tmp.path().join("Contents").join("Resources").join("libdaalcore.dylib");
        touch(&dylib);
        let state_dir = tmp.path().join("state");
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.dylib")
            .expect("should find dylib in ../Resources/");
        assert_eq!(found.canonicalize().unwrap(), dylib.canonicalize().unwrap());
    }

    #[test]
    fn locate_finds_in_linux_lib_subdir_legacy_daal() {
        // Legacy productName "Daal" layout (alpha.1 builds before
        // the rename): /usr/lib/Daal/resources/libdaalcore.so
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().join("usr").join("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let so = tmp.path().join("usr").join("lib").join("Daal").join("resources").join("libdaalcore.so");
        touch(&so);
        let state_dir = tmp.path().join("state");
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.so")
            .expect("should find .so via legacy Daal/ path");
        assert_eq!(found.canonicalize().unwrap(), so.canonicalize().unwrap());
    }

    #[test]
    fn locate_finds_in_linux_lib_subdir_with_space() {
        // Current productName "Daal Desktop" → tauri-bundler may emit
        // /usr/lib/Daal Desktop/resources/libdaalcore.so verbatim.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().join("usr").join("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let so = tmp.path().join("usr").join("lib").join("Daal Desktop").join("resources").join("libdaalcore.so");
        touch(&so);
        let state_dir = tmp.path().join("state");
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.so")
            .expect("should find .so in 'Daal Desktop' resources path");
        assert_eq!(found.canonicalize().unwrap(), so.canonicalize().unwrap());
    }

    #[test]
    fn locate_finds_in_linux_lib_subdir_lowercased() {
        // Or tauri-bundler may emit the sanitised form
        // /usr/lib/daal-desktop/resources/libdaalcore.so.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().join("usr").join("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let so = tmp.path().join("usr").join("lib").join("daal-desktop").join("resources").join("libdaalcore.so");
        touch(&so);
        let state_dir = tmp.path().join("state");
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.so")
            .expect("should find .so in daal-desktop/ resources path");
        assert_eq!(found.canonicalize().unwrap(), so.canonicalize().unwrap());
    }

    #[test]
    fn locate_falls_back_to_exe_adjacent() {
        // Raw `cargo build` / sideload layout — DLL right next to exe.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().to_path_buf();
        let state_dir = tmp.path().join("state");
        let so = exe_dir.join("libdaalcore.so");
        touch(&so);
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.so")
            .expect("should find adjacent to exe");
        assert_eq!(found.canonicalize().unwrap(), so.canonicalize().unwrap());
    }

    #[test]
    fn locate_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("state");
        let result = locate_engine_lib_in(tmp.path(), &state_dir, "libdaalcore.so");
        assert!(result.is_none());
    }

    #[test]
    fn locate_prefers_resources_over_exe_adjacent() {
        // Both exist — `resources/` MUST win (it's the canonical
        // installed-bundle location). This guards against a future
        // refactor accidentally reordering the candidate list.
        let tmp = tempfile::tempdir().unwrap();
        let exe_dir = tmp.path().to_path_buf();
        let state_dir = tmp.path().join("state");
        let adjacent = exe_dir.join("libdaalcore.dll");
        touch(&adjacent);
        let bundled = exe_dir.join("resources").join("libdaalcore.dll");
        touch(&bundled);
        let found = locate_engine_lib_in(&exe_dir, &state_dir, "libdaalcore.dll").unwrap();
        assert_eq!(
            found.canonicalize().unwrap(),
            bundled.canonicalize().unwrap(),
            "must prefer resources/ subdir over exe-adjacent"
        );
    }
}

fn default_state_dir() -> PathBuf {
    // On Android, dirs_next::data_dir() returns None. Use the
    // sandboxed app-files directory exposed by the env, which Tauri
    // sets before our entry point runs. On iOS the home dir is the
    // app sandbox; <home>/Library/Application Support is the
    // standard data location.
    #[cfg(target_os = "android")]
    {
        if let Ok(p) = std::env::var("HOME") {
            return PathBuf::from(p).join("files").join("daal");
        }
    }
    #[cfg(target_os = "ios")]
    {
        if let Ok(p) = std::env::var("HOME") {
            return PathBuf::from(p)
                .join("Library")
                .join("Application Support")
                .join("daal");
        }
    }
    if let Some(d) = dirs_next::data_dir() {
        return d.join("daal");
    }
    std::env::temp_dir().join("daal")
}

#[tauri::command]
fn version_info(state: State<'_, AppState>) -> VersionInfo {
    cmd::version_info(&state)
}

#[tauri::command]
fn preview_bundle(path: String) -> Result<PreviewedBundle, String> {
    cmd::preview_bundle(PathBuf::from(path)).map_err(|e| e.to_string())
}

#[tauri::command]
fn import_sbp(state: State<'_, AppState>, path: String) -> Result<String, String> {
    cmd::import_sbp(&state, PathBuf::from(path)).map_err(|e| e.to_string())
}

#[tauri::command]
fn resolve_trust_prompt(
    state: State<'_, AppState>,
    fingerprint: String,
    decision: i32,
) -> Result<String, String> {
    cmd::resolve_trust_prompt(&state, &fingerprint, decision).map_err(|e| e.to_string())
}

#[tauri::command]
fn connect(state: State<'_, AppState>, route_id: String) -> Result<(), String> {
    cmd::connect(&state, ConnectRequest { route_id }).map_err(|e| e.to_string())
}

#[tauri::command]
fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    cmd::disconnect(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn diagnostics_explain(state: State<'_, AppState>) -> Result<String, String> {
    cmd::diagnostics_explain(&state).map_err(|e| e.to_string())
}

// -- D-2.1 — display-summary surface ---------------------------------

#[tauri::command]
fn route_summary(state: State<'_, AppState>, route_id: String) -> Result<String, String> {
    cmd::route_summary(&state, &route_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn available_routes(state: State<'_, AppState>) -> Result<String, String> {
    cmd::available_routes(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn throughput_snapshot(state: State<'_, AppState>) -> Result<String, String> {
    cmd::throughput_snapshot(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn panic_wipe(state: State<'_, AppState>) -> Result<(), String> {
    cmd::panic_wipe(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_diagnostics(state: State<'_, AppState>) -> Result<String, String> {
    cmd::export_diagnostics(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
    cmd::set_mode(&state, &mode).map_err(|e| e.to_string())
}

#[tauri::command]
fn network_changed(
    state: State<'_, AppState>,
    kind: String,
    carrier: String,
    ssid: String,
) -> Result<String, String> {
    cmd::network_changed(&state, &kind, &carrier, &ssid).map_err(|e| e.to_string())
}

#[tauri::command]
fn unlock_secrets(state: State<'_, AppState>, pin: String) -> Result<cmd::UnlockOutcome, String> {
    cmd::unlock_secrets(&state, &pin).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_allow_bulk_capable(state: State<'_, AppState>, allow: bool) -> Result<(), String> {
    cmd::set_allow_bulk_capable(&state, allow).map_err(|e| e.to_string())
}

#[tauri::command]
fn pointer_rotation_status(state: State<'_, AppState>) -> Result<String, String> {
    cmd::pointer_rotation_status(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn subscription_add(
    state: State<'_, AppState>,
    req: AddSubscriptionRequest,
) -> Result<String, String> {
    cmd::subscription_add(&state, req).map_err(|e| e.to_string())
}

#[tauri::command]
fn subscription_refresh(
    state: State<'_, AppState>,
    subscription_id: String,
    timeout_ms: i32,
) -> Result<String, String> {
    cmd::subscription_refresh(&state, &subscription_id, timeout_ms).map_err(|e| e.to_string())
}

#[tauri::command]
fn subscription_remove(state: State<'_, AppState>, subscription_id: String) -> Result<(), String> {
    cmd::subscription_remove(&state, &subscription_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn subscription_list(state: State<'_, AppState>) -> Result<String, String> {
    cmd::subscription_list(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn revocation_refresh_all(state: State<'_, AppState>, timeout_ms: i32) -> Result<String, String> {
    cmd::revocation_refresh_all(&state, timeout_ms).map_err(|e| e.to_string())
}

#[tauri::command]
fn start_sidecar(state: State<'_, AppState>) -> Result<(), String> {
    cmd::start_sidecar(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn stop_sidecar(state: State<'_, AppState>) -> Result<(), String> {
    cmd::stop_sidecar(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn heartbeat_tick(state: State<'_, AppState>) -> bool {
    cmd::heartbeat_tick(&state)
}

// ---- v0.2.x — full plumbing pass ----------------------------------

#[tauri::command]
fn apply_cooldown(
    state: State<'_, AppState>,
    route_id: String,
    seconds: i32,
) -> Result<(), String> {
    cmd::apply_cooldown(&state, &route_id, seconds).map_err(|e| e.to_string())
}

#[tauri::command]
fn lifecycle_event(state: State<'_, AppState>, token: String) -> Result<(), String> {
    cmd::lifecycle_event(&state, &token).map_err(|e| e.to_string())
}

#[tauri::command]
fn probe_udp(state: State<'_, AppState>, timeout_ms: i32) -> i32 {
    cmd::probe_udp(&state, timeout_ms)
}
#[tauri::command]
fn probe_dns(state: State<'_, AppState>, timeout_ms: i32) -> i32 {
    cmd::probe_dns(&state, timeout_ms)
}
#[tauri::command]
fn probe_tcp443(state: State<'_, AppState>, timeout_ms: i32) -> i32 {
    cmd::probe_tcp443(&state, timeout_ms)
}

#[tauri::command]
fn scheduler_status(state: State<'_, AppState>) -> Result<String, String> {
    cmd::scheduler_status(&state).map_err(|e| e.to_string())
}
#[tauri::command]
fn stats_redacted(state: State<'_, AppState>) -> Result<String, String> {
    cmd::stats_redacted(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn redistribute_route(
    state: State<'_, AppState>,
    route_id: String,
    recipient_fp: String,
) -> Result<String, String> {
    cmd::redistribute_route(&state, &route_id, &recipient_fp).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_route_budget(
    state: State<'_, AppState>,
    route_id: String,
    budget_tag: String,
) -> Result<String, String> {
    cmd::set_route_budget(&state, &route_id, &budget_tag).map_err(|e| e.to_string())
}

#[tauri::command]
fn set_rendezvous_priority(
    state: State<'_, AppState>,
    priority_json: String,
) -> Result<(), String> {
    cmd::set_rendezvous_priority(&state, &priority_json).map_err(|e| e.to_string())
}
#[tauri::command]
fn set_push_rendezvous_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    cmd::set_push_rendezvous_enabled(&state, enabled).map_err(|e| e.to_string())
}
#[tauri::command]
fn set_auto_promotion(state: State<'_, AppState>, enabled: bool) {
    cmd::set_auto_promotion(&state, enabled)
}
#[tauri::command]
fn set_masque_submode_override(
    state: State<'_, AppState>,
    submode: String,
) -> Result<(), String> {
    cmd::set_masque_submode_override(&state, &submode).map_err(|e| e.to_string())
}
#[tauri::command]
fn set_experimental_families_enabled(
    state: State<'_, AppState>,
    enabled: bool,
) -> Result<(), String> {
    cmd::set_experimental_families_enabled(&state, enabled).map_err(|e| e.to_string())
}

#[tauri::command]
fn bootstrap_install_seeds(state: State<'_, AppState>) -> Result<String, String> {
    cmd::bootstrap_install_seeds(&state).map_err(|e| e.to_string())
}
#[tauri::command]
fn bootstrap_refresh(state: State<'_, AppState>, timeout_ms: i32) -> Result<String, String> {
    cmd::bootstrap_refresh(&state, timeout_ms).map_err(|e| e.to_string())
}
#[tauri::command]
fn bootstrap_status(state: State<'_, AppState>) -> Result<String, String> {
    cmd::bootstrap_status(&state).map_err(|e| e.to_string())
}

#[tauri::command]
fn uri_detect(state: State<'_, AppState>, text: String) -> Result<String, String> {
    cmd::uri_detect(&state, &text).map_err(|e| e.to_string())
}
#[tauri::command]
fn uri_import(state: State<'_, AppState>, raw_uri: String) -> Result<String, String> {
    cmd::uri_import(&state, &raw_uri).map_err(|e| e.to_string())
}

#[tauri::command]
fn loaded_wasm_modules(state: State<'_, AppState>) -> Result<String, String> {
    cmd::loaded_wasm_modules(&state).map_err(|e| e.to_string())
}
#[tauri::command]
fn wasm_kill_switch_pubkey(state: State<'_, AppState>) -> Result<String, String> {
    cmd::wasm_kill_switch_pubkey(&state).map_err(|e| e.to_string())
}

// ---- FRP-5 wizard command shims ------------------------------------

#[tauri::command]
fn wizard_store_cloud_token(
    wstate: State<'_, WizardStateMgr>,
    provider: String,
    token: String,
    pin: String,
) -> Result<i64, String> {
    wcmd::store_cloud_token(&wstate.0, &provider, &token, &pin).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_pricing_lookup(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    region: String,
    server_type: String,
    pin: String,
) -> Result<daal_wizard::cli_bridge::Pricing, String> {
    wcmd::pricing_lookup(&wstate.0, operator_id, &region, &server_type, &pin)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_select_profile(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    region: String,
    server_type: String,
    toolbox_profile: String,
    enabled_families: Vec<String>,
) -> Result<(), String> {
    wcmd::select_profile(
        &wstate.0,
        operator_id,
        &region,
        &server_type,
        &toolbox_profile,
        enabled_families,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_publisher_keygen(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
) -> Result<Fingerprint, String> {
    wcmd::publisher_keygen(&wstate.0, operator_id, &pin).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_publisher_keyimport(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
    priv_bytes_b64: String,
) -> Result<Fingerprint, String> {
    wcmd::publisher_keyimport(&wstate.0, operator_id, &pin, &priv_bytes_b64)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_finalize_pre_provision(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<String, String> {
    wcmd::finalize_pre_provision(&wstate.0, operator_id)
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_list_operators(
    wstate: State<'_, WizardStateMgr>,
) -> Result<Vec<wcmd::OperatorSummary>, String> {
    wcmd::list_operators(&wstate.0).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_cancel_and_cleanup(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<(), String> {
    wcmd::cancel_and_cleanup(&wstate.0, operator_id).map_err(|e| e.to_string())
}

// ---- FRP-4b live operations ----------------------------------------

/// `wizard_provision_run`: blocking call that drives `daal-deploy
/// provision` for the given operator. Progress events stream back
/// to the wizard frontend via `app.emit("wizard://provision-event", …)`.
#[tauri::command]
fn wizard_provision_run(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
    helper_ip: String,
) -> Result<(), String> {
    let app_clone = app.clone();
    let mut on_progress = move |ev: ProgressEvent| {
        let _ = app_clone.emit("wizard://provision-event", ev);
    };
    wcmd::provision_run(&wstate.0, operator_id, &pin, &helper_ip, &mut on_progress)
        .map_err(|e| e.to_string())
}

/// `wizard_sign_relaypack`: blocking call that drives `daal-deploy
/// bind-and-sign`. Progress events stream via
/// `app.emit("wizard://sign-event", …)`. Returns the final
/// BindResult to the caller (so Screen 6 can render the
/// fingerprint immediately on success).
#[tauri::command]
fn wizard_sign_relaypack(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
    phase: String,
    output_dir: String,
    publisher_name: String,
) -> Result<WizardBindResult, String> {
    let app_clone = app.clone();
    let mut on_progress = move |ev: ProgressEvent| {
        let _ = app_clone.emit("wizard://sign-event", ev);
    };
    let path = std::path::PathBuf::from(output_dir);
    wcmd::sign_relaypack(
        &wstate.0,
        operator_id,
        &pin,
        &phase,
        &path,
        &publisher_name,
        &mut on_progress,
    )
    .map_err(|e| e.to_string())
}

/// `wizard_qr_render`: streams animated-QR fountain frames to the
/// frontend via `app.emit("wizard://qr-frame", FountainFrame)`.
/// The frontend's QR canvas reads `frame_b64` (base64url), decodes,
/// and renders via a JS QR encoder at the user-selected FPS.
///
/// `max_frames` 0 is supported by the CLI for direct operator use,
/// but the Tauri frontend deliberately requests finite batches so
/// screen navigation cannot leave an unbounded QR subprocess alive.
#[tauri::command]
fn wizard_qr_render(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    block_size: u32,
    max_frames: u32,
    seed: i64,
) -> Result<(), String> {
    let app_clone = app.clone();
    let mut on_frame = move |frame: FountainFrame| -> bool {
        let _ = app_clone.emit("wizard://qr-frame", frame);
        true
    };
    wcmd::qr_render(
        &wstate.0,
        operator_id,
        block_size,
        max_frames,
        seed,
        &mut on_frame,
    )
    .map_err(|e| e.to_string())
}

// ---- FRP-8 CDN-front command shims --------------------------------

#[tauri::command]
fn wizard_store_cloudflare_token(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    token: String,
    pin: String,
) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("Cloudflare token must not be empty".into());
    }
    let op = wstate.0.db.get(operator_id).map_err(|e| e.to_string())?;
    let _ = wstate
        .0
        .keystore
        .open(&op.cloud_token_keystore_alias, &pin)
        .map_err(|e| e.to_string())?;
    let alias = format!("daal.cloudflare.{operator_id}.token");
    wstate
        .0
        .keystore
        .seal(&alias, &pin, token.as_bytes())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_provision_cdn_front(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    hostname: String,
    origin_ip: String,
    origin_ipv6: String,
    origin_path: String,
    public_path: String,
    pin: String,
) -> Result<i64, String> {
    let input = wcmd::ProvisionCdnFrontInput {
        operator_id,
        hostname,
        origin_ip,
        origin_ipv6,
        origin_path,
        public_path,
    };
    wcmd::provision_cdn_front(&wstate.0, &input, &pin).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_list_cdn_fronts(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<CdnFrontRow>, String> {
    wcmd::list_cdn_fronts(&wstate.0, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_verify_cdn_posture(
    wstate: State<'_, WizardStateMgr>,
    front_id: i64,
    pin: String,
) -> Result<(), String> {
    wcmd::verify_cdn_posture(&wstate.0, front_id, &pin).map_err(|e| e.to_string())
}

// ---- FRP-7 rotation command shims ---------------------------------

#[derive(serde::Deserialize)]
pub struct RotateRecommendArgs {
    /// Either "explanation" or "context".
    pub mode: String,
    /// Required when mode == "explanation". A JSON-encoded
    /// selection.Explanation.
    pub explanation_json: Option<String>,
    /// Required when mode == "context".
    #[serde(default)]
    pub failure_classifications: Vec<String>,
    #[serde(default)]
    pub network_signals: Vec<String>,
    #[serde(default)]
    pub exposure_mode: String,
    #[serde(default)]
    pub credential_leak_suspected: bool,
}

/// `wizard_rotate_recommend`: ask the Go rotation recommender for
/// a level + confidence + reason. Synchronous — the recommender is
/// fast (the Go function is pure; the CLI cost is process start).
#[tauri::command]
fn wizard_rotate_recommend(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    args: RotateRecommendArgs,
) -> Result<WizardRotationRecommendation, String> {
    let input = if args.mode == "explanation" {
        let json = args
            .explanation_json
            .ok_or_else(|| "explanation_json required for mode=explanation".to_string())?;
        RotateRecommendInput::Explanation(json)
    } else {
        RotateRecommendInput::Context(WizardRotateContext {
            failure_classifications: args.failure_classifications,
            network_signals: args.network_signals,
            exposure_mode: if args.exposure_mode.is_empty() {
                "direct_vps".into()
            } else {
                args.exposure_mode
            },
            credential_leak_suspected: args.credential_leak_suspected,
        })
    };
    wcmd::rotate_recommend(&wstate.0, operator_id, input).map_err(|e| e.to_string())
}

/// `wizard_rotate_execute`: run the chosen rotation. Streams
/// progress events on `wizard://rotate-event` and returns the
/// success summary on completion.
#[tauri::command]
fn wizard_rotate_execute(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
    level: String,
    reason: String,
    helper_ip: Option<String>,
    new_floating_ip_id: Option<String>,
    regen_credentials: Option<bool>,
    new_sni: Option<String>,
    new_ws_path: Option<String>,
    new_toolbox_profile: Option<String>,
    cdn_front_id: Option<i64>,
    cdn_account_id: Option<String>,
    cdn_new_public_path: Option<String>,
    cdn_new_hostname: Option<String>,
    cdn_new_origin_ipv4: Option<String>,
    cdn_new_origin_ipv6: Option<String>,
    freshness_signed_sbp_url: Option<String>,
) -> Result<RotateExecuteOutput, String> {
    let app_clone = app.clone();
    let mut on_progress = move |ev: ProgressEvent| {
        let _ = app_clone.emit("wizard://rotate-event", ev);
    };
    let input = RotateExecuteInput {
        level,
        reason,
        helper_ip,
        new_floating_ip_id,
        regen_credentials: regen_credentials.unwrap_or(false),
        new_sni,
        new_ws_path,
        new_toolbox_profile,
        cdn_front_id,
        cdn_account_id,
        cdn_new_public_path,
        cdn_new_hostname,
        cdn_new_origin_ipv4,
        cdn_new_origin_ipv6,
        freshness_signed_sbp_url,
    };
    wcmd::rotate_execute(&wstate.0, operator_id, &pin, input, &mut on_progress)
        .map_err(|e| e.to_string())
}

/// `wizard_rotate_revert`: flip the most-recent inactive history
/// row back to active. Returns the restored row.
#[tauri::command]
fn wizard_rotate_revert(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<SignedSbpRow, String> {
    wcmd::rotate_revert(&wstate.0, operator_id).map_err(|e| e.to_string())
}

/// `wizard_rotate_history`: list the rotation history rows for a
/// given operator (most-recent first). The wizard's "rotation log"
/// view binds to this.
#[tauri::command]
fn wizard_rotate_history(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<SignedSbpRow>, String> {
    wcmd::list_rotation_history(&wstate.0, operator_id).map_err(|e| e.to_string())
}

// ---- FRP-7.5 sub-key rotation command shims ------------------------

/// `wizard_subkey_rotate`: mint a fresh sub-key + cert under the
/// supplied root publisher key (PIN-gated). Returns the keystore
/// paths and validity window. Runs `daal-publish subkey rotate
/// --json` under the hood; opens NO sockets.
#[tauri::command]
fn wizard_subkey_rotate(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    pin: String,
    validity: Option<String>,
    label: Option<String>,
) -> Result<SubkeyRotateResult, String> {
    let validity = validity.unwrap_or_else(|| "90d".to_string());
    let label = label.unwrap_or_else(|| "rotated-subkey".to_string());
    wcmd::subkey_rotate(&wstate.0, operator_id, &pin, &validity, &label).map_err(|e| e.to_string())
}

/// `wizard_subkey_active`: return the currently-active sub-key
/// row for the operator, or `null` if none has been rotated yet.
/// The wizard's lifetime banner (75%/95%) reads valid_until_unix
/// from this row to compute its threshold.
#[tauri::command]
fn wizard_subkey_active(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Option<SubkeyRow>, String> {
    wcmd::active_subkey(&wstate.0, operator_id).map_err(|e| e.to_string())
}

/// `wizard_subkey_history`: list the sub-key rotation history,
/// most recent first. The Settings → Rotate sub-key screen binds
/// the past-rotations table to this.
#[tauri::command]
fn wizard_subkey_history(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<SubkeyRow>, String> {
    wcmd::list_subkey_history(&wstate.0, operator_id).map_err(|e| e.to_string())
}

// ---- FRP-6 recipient command shims ---------------------------------

/// Wraps `recipient::SessionRegistry` for Tauri-managed state.
pub struct RecipientStateMgr(pub recipient::SessionRegistry);

#[tauri::command]
fn recipient_qr_session_new(rstate: State<'_, RecipientStateMgr>) -> String {
    rstate.0.new_session()
}

#[tauri::command]
fn recipient_qr_feed_frame(
    state: State<'_, AppState>,
    rstate: State<'_, RecipientStateMgr>,
    session_id: String,
    index: u32,
    total_frames: u32,
    data_b64: String,
) -> Result<recipient::SessionStatus, String> {
    let _ = (index, total_frames);
    rstate.0.ensure(&session_id)?;
    let body =
        cmd::fountain_feed_frame(&state, &session_id, &data_b64).map_err(|e| e.to_string())?;
    rstate.0.record_engine_response(&session_id, &body)
}

#[tauri::command]
fn recipient_qr_status(
    rstate: State<'_, RecipientStateMgr>,
    session_id: String,
) -> Result<recipient::SessionStatus, String> {
    rstate.0.status(&session_id)
}

#[tauri::command]
fn recipient_qr_cancel(
    rstate: State<'_, RecipientStateMgr>,
    session_id: String,
) -> Result<(), String> {
    rstate.0.cancel(&session_id);
    Ok(())
}

/// `recipient_qr_finalize` returns the importer verdict produced by
/// the core fountain decoder when it completed. Failure leaves the
/// session in the registry so the caller can retry after more frames.
#[tauri::command]
fn recipient_qr_finalize(
    rstate: State<'_, RecipientStateMgr>,
    session_id: String,
) -> Result<String, String> {
    rstate.0.finish(&session_id)
}

fn build_wizard_ctx(state_dir: &PathBuf) -> Result<wcmd::WizardCtx, String> {
    let db_path = state_dir.join("wizard.db");
    let db = Arc::new(OperatorDb::open_at(&db_path).map_err(|e| e.to_string())?);
    #[cfg(feature = "dev-no-keystore")]
    let keystore = Arc::new(Keystore::new_in_memory(state_dir));
    #[cfg(not(feature = "dev-no-keystore"))]
    let keystore = Arc::new(Keystore::new_os(state_dir));
    let staging_dir = default_staging_dir();
    let cli = Arc::new(SubprocessRunner::new(None));
    let clock: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    Ok(wcmd::WizardCtx {
        db,
        keystore,
        staging_dir,
        cli,
        clock,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default().with_max_level(log::LevelFilter::Info),
        );
    }
    let state_dir = default_state_dir();
    std::fs::create_dir_all(&state_dir).ok();

    let lib_path = locate_engine_lib(&state_dir).expect(
        "could not find libdaalcore — set $DAAL_ENGINE_LIB or install the engine library",
    );
    let engine = Engine::load(&lib_path).expect("engine load");
    engine.init(&state_dir, "warn").expect("engine init");

    let app_state = AppState::new(engine, state_dir.clone());
    let wizard_ctx = build_wizard_ctx(&state_dir).expect("wizard context init (DB + keystore)");
    let recipient_registry = recipient::SessionRegistry::default();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .manage(WizardStateMgr(wizard_ctx))
        .manage(RecipientStateMgr(recipient_registry))
        .invoke_handler(tauri::generate_handler![
            version_info,
            preview_bundle,
            import_sbp,
            resolve_trust_prompt,
            connect,
            disconnect,
            diagnostics_explain,
            export_diagnostics,
            set_mode,
            network_changed,
            unlock_secrets,
            set_allow_bulk_capable,
            pointer_rotation_status,
            subscription_add,
            subscription_refresh,
            subscription_remove,
            subscription_list,
            revocation_refresh_all,
            start_sidecar,
            stop_sidecar,
            heartbeat_tick,
            wizard_store_cloud_token,
            wizard_pricing_lookup,
            wizard_select_profile,
            wizard_publisher_keygen,
            wizard_publisher_keyimport,
            wizard_finalize_pre_provision,
            wizard_list_operators,
            wizard_cancel_and_cleanup,
            wizard_provision_run,
            wizard_sign_relaypack,
            wizard_qr_render,
            // FRP-8 CDN-front surface
            wizard_store_cloudflare_token,
            wizard_provision_cdn_front,
            wizard_list_cdn_fronts,
            wizard_verify_cdn_posture,
            // FRP-7 rotation surface
            wizard_rotate_recommend,
            wizard_rotate_execute,
            wizard_rotate_revert,
            wizard_rotate_history,
            // FRP-7.5 sub-key rotation surface
            wizard_subkey_rotate,
            wizard_subkey_active,
            wizard_subkey_history,
            // FRP-6 recipient surface
            recipient_qr_session_new,
            recipient_qr_feed_frame,
            recipient_qr_status,
            recipient_qr_cancel,
            recipient_qr_finalize,
            // D-2.1 display-summary surface
            route_summary,
            available_routes,
            throughput_snapshot,
            panic_wipe,
            // v0.2.x — full plumbing pass
            apply_cooldown,
            lifecycle_event,
            probe_udp,
            probe_dns,
            probe_tcp443,
            scheduler_status,
            stats_redacted,
            redistribute_route,
            set_route_budget,
            set_rendezvous_priority,
            set_push_rendezvous_enabled,
            set_auto_promotion,
            set_masque_submode_override,
            set_experimental_families_enabled,
            bootstrap_install_seeds,
            bootstrap_refresh,
            bootstrap_status,
            uri_detect,
            uri_import,
            loaded_wasm_modules,
            wasm_kill_switch_pubkey,
        ])
        .setup(|app| {
            // Best-effort: spawn sing-box on launch so the SOCKS5 inlet
            // is up by the time the user clicks Connect. Errors are
            // swallowed; the user can retry from Subscriptions.
            let state: State<AppState> = app.state();
            let _ = cmd::start_sidecar(&state);

            // D-2.1: install a system-tray icon with a context menu
            // (Connect / Disconnect / Open / Quit). On Linux this is
            // best-effort — some desktop environments don't expose a
            // tray; failure is silently ignored.
            #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
            {
                use tauri::tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent};
                use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};

                let app_handle = app.handle().clone();
                let connect_item = MenuItem::with_id(
                    &app_handle, "tray.connect", "Connect", true, None::<&str>,
                )?;
                let disconnect_item = MenuItem::with_id(
                    &app_handle, "tray.disconnect", "Disconnect", true, None::<&str>,
                )?;
                let open_item = MenuItem::with_id(
                    &app_handle, "tray.open", "Open Daal", true, None::<&str>,
                )?;
                let quit_item = MenuItem::with_id(
                    &app_handle, "tray.quit", "Quit Daal", true, None::<&str>,
                )?;
                let separator = PredefinedMenuItem::separator(&app_handle)?;
                let menu = Menu::with_items(
                    &app_handle,
                    &[&connect_item, &disconnect_item, &separator, &open_item, &quit_item],
                )?;

                let _ = TrayIconBuilder::new()
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .icon(app.default_window_icon().cloned().unwrap_or_else(|| {
                        tauri::image::Image::new_owned(vec![0u8; 16 * 16 * 4], 16, 16)
                    }))
                    .on_menu_event(move |handle, event| {
                        let state: State<AppState> = handle.state();
                        match event.id.as_ref() {
                            "tray.connect" => { /* picks default route via UI */ }
                            "tray.disconnect" => { let _ = cmd::disconnect(&state); }
                            "tray.open" => {
                                if let Some(w) = handle.get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                            "tray.quit" => { handle.exit(0); }
                            _ => {}
                        }
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                    })
                    .build(app);
            }

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
