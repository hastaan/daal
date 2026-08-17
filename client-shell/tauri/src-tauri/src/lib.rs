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
mod custody;

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
use tauri_plugin_opener::OpenerExt;

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
        exe_dir
            .join("../lib")
            .join("Daal Desktop")
            .join("resources")
            .join(lib),
        exe_dir
            .join("../lib")
            .join("daal-desktop")
            .join("resources")
            .join(lib),
        exe_dir
            .join("../lib")
            .join("Daal")
            .join("resources")
            .join(lib),
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
        let dylib = tmp
            .path()
            .join("Contents")
            .join("Resources")
            .join("libdaalcore.dylib");
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
        let so = tmp
            .path()
            .join("usr")
            .join("lib")
            .join("Daal")
            .join("resources")
            .join("libdaalcore.so");
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
        let so = tmp
            .path()
            .join("usr")
            .join("lib")
            .join("Daal Desktop")
            .join("resources")
            .join("libdaalcore.so");
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
        let so = tmp
            .path()
            .join("usr")
            .join("lib")
            .join("daal-desktop")
            .join("resources")
            .join("libdaalcore.so");
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

/// Render a `DesktopError` for the React layer. When the error is a
/// `bundle_rs::Error` we prepend its stable `code()` so the UI can
/// look up friendly i18n copy (e.g. `ErrInvalidSignature` ->
/// "This bundle's signature doesn't match its publisher key — the
///  file is corrupt or was tampered with."). Other errors fall back
/// to the plain Display form, which is already user-facing in
/// existing toasts.
fn render_bundle_err(e: &daal_desktop_core::DesktopError) -> String {
    if let daal_desktop_core::DesktopError::Bundle(inner) = e {
        return format!("{}: {}", inner.code(), inner);
    }
    e.to_string()
}

#[tauri::command]
fn preview_bundle(path: String) -> Result<PreviewedBundle, String> {
    cmd::preview_bundle(PathBuf::from(path)).map_err(|e| render_bundle_err(&e))
}

#[tauri::command]
fn import_sbp(state: State<'_, AppState>, path: String) -> Result<String, String> {
    cmd::import_sbp(&state, PathBuf::from(path)).map_err(|e| render_bundle_err(&e))
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

/// Device Custody B5: full multiplatform panic-wipe.
///
/// Steps, ordered so a power-loss mid-wipe still leaves a
/// recoverable state (the engine-side `RemoveAll(state_dir)` is
/// the last thing we do):
///
///   1. Snapshot every keystore alias known to the wizard DB
///      (publisher Ed25519 priv, cloud-provider token, cell admin
///      / signer privs).
///   2. Append the audit event NOW so it's visible if the wipe
///      is interrupted before the DB is removed.
///   3. `Keystore::forget(alias)` for each → wipes desktop OS
///      keyring entries (libsecret / Keychain / Credential
///      Manager). On Android this hits `<state>/keyblobs/`,
///      which step 7 also nukes via `RemoveAll`.
///   4. `custody.forget_prefix("")` → wipes every custody blob
///      under `<state>/custody/aliases/` (current + history
///      privs, anything else).
///   5. `custody.lock()` → drops the in-memory DWK so a
///      crashed-mid-wipe process can't be ptrace-scraped.
///   6. Best-effort `RemoveAll(staging_dir)` (separate from
///      `state_dir` on desktop) — drops `.sbp`/`.sbpx`
///      stagings, pre-provision JSON, picked-file scratch.
///   7. `engine.panic_wipe()` → shuts the engine down and
///      removes `state_dir` (wizard.db, custody/, keyblobs/,
///      engine routestore, vault, logs).
///
/// On any step's failure we still proceed to subsequent steps —
/// panic-wipe must be best-effort once initiated.
#[tauri::command]
fn panic_wipe(
    state: State<'_, AppState>,
    wstate: State<'_, WizardStateMgr>,
) -> Result<(), String> {
    let now = (wstate.0.clock)();
    let level = wstate.0.custody.level().as_str().to_string();

    // 1. Snapshot aliases.
    let aliases = wstate.0.db.list_all_keystore_aliases().unwrap_or_default();
    let alias_count = aliases.len();
    let custody_history_count = wstate
        .0
        .db
        .list_recipient_identity_history()
        .map(|h| h.len())
        .unwrap_or(0);

    // 2. Audit event before destructive steps.
    let detail = serde_json::json!({
        "alias_count": alias_count,
        "custody_history_count": custody_history_count,
    });
    let _ = wstate
        .0
        .db
        .insert_custody_event(now, "panic_wipe", &level, &detail.to_string());

    // 3. Wipe keystore aliases.
    for a in aliases {
        let _ = wstate.0.keystore.forget(&a);
    }

    // 4. Wipe every custody blob.
    let _ = wstate.0.custody.forget_prefix("");
    // 5. Drop in-memory DWK.
    wstate.0.custody.lock();

    // 6. Staging dir (may be under config_dir, distinct from state_dir).
    let staging = wstate.0.staging_dir.clone();
    if staging.exists() {
        let _ = std::fs::remove_dir_all(&staging);
    }

    // 7. Engine-owned nuke — last because it removes wizard.db
    //    so step 2's audit event is gone after this.
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
fn route_delete(state: State<'_, AppState>, route_id: String) -> Result<(), String> {
    cmd::route_delete(&state, &route_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn publisher_delete(state: State<'_, AppState>, publisher_id: String) -> Result<i32, String> {
    cmd::publisher_delete(&state, &publisher_id).map_err(|e| e.to_string())
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
fn scheduler_tick(state: State<'_, AppState>) -> Result<(), String> {
    cmd::scheduler_tick(&state).map_err(|e| e.to_string())
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
fn set_push_rendezvous_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    cmd::set_push_rendezvous_enabled(&state, enabled).map_err(|e| e.to_string())
}
#[tauri::command]
fn set_auto_promotion(state: State<'_, AppState>, enabled: bool) {
    cmd::set_auto_promotion(&state, enabled)
}
#[tauri::command]
fn set_masque_submode_override(state: State<'_, AppState>, submode: String) -> Result<(), String> {
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

/// `operator_id`: `Some(id)` updates that relay's token in place;
/// `None` creates a new relay. Passing the known id is what stops
/// Back→Next on the first wizard screen from minting duplicate
/// operator rows, each with its own custody aliases.
#[tauri::command]
fn wizard_store_cloud_token(
    wstate: State<'_, WizardStateMgr>,
    provider: String,
    token: String,
    operator_id: Option<i64>,
) -> Result<i64, String> {
    wcmd::store_cloud_token(&wstate.0, &provider, &token, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_list_existing_servers(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<daal_wizard::cli_bridge::ExistingServer>, String> {
    wcmd::list_existing_servers(&wstate.0, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_list_server_types(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    region: String,
) -> Result<Vec<daal_wizard::cli_bridge::ServerTypeOption>, String> {
    wcmd::list_server_types(&wstate.0, operator_id, &region).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_pricing_lookup(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    region: String,
    server_type: String,
) -> Result<daal_wizard::cli_bridge::Pricing, String> {
    wcmd::pricing_lookup(&wstate.0, operator_id, &region, &server_type).map_err(|e| e.to_string())
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
) -> Result<Fingerprint, String> {
    wcmd::publisher_keygen(&wstate.0, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_publisher_keyimport(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    priv_bytes_b64: String,
) -> Result<Fingerprint, String> {
    wcmd::publisher_keyimport(&wstate.0, operator_id, &priv_bytes_b64).map_err(|e| e.to_string())
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
fn wizard_get_operator_state(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<wcmd::OperatorState, String> {
    wcmd::get_operator_state(&wstate.0, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_cancel_and_cleanup(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<(), String> {
    wcmd::cancel_and_cleanup(&wstate.0, operator_id).map_err(|e| e.to_string())
}

/// `wizard_relay_destroy`: remove a relay, and — when the user asked
/// for it — destroy the cloud server, ephemeral SSH key and firewall
/// behind it first.
///
/// `delete_server: false` is exactly [`wizard_cancel_and_cleanup`].
/// `delete_server: true` reaches the provider API, so it blocks for as
/// long as that takes; an `Err` here means the cloud side refused and
/// the relay is still fully intact locally, ready to retry.
#[tauri::command]
fn wizard_relay_destroy(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    delete_server: bool,
) -> Result<wcmd::DestroyReport, String> {
    wcmd::relay_destroy(&wstate.0, operator_id, delete_server).map_err(|e| e.to_string())
}

// ---- FRP-4b live operations ----------------------------------------

/// `wizard_provision_run`: runs `daal-deploy provision` on a
/// background thread so the UI stays responsive. Progress events
/// stream back via `app.emit("wizard://provision-event", …)`.
#[tauri::command]
async fn wizard_provision_run(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    existing_server_id: Option<String>,
) -> Result<(), String> {
    // Extract Arc fields so we can move them into spawn_blocking
    // (State<> borrows the managed value and can't cross await).
    let db = wstate.0.db.clone();
    let keystore = wstate.0.keystore.clone();
    let staging_dir = wstate.0.staging_dir.clone();
    let cli = wstate.0.cli.clone();
    let clock = wstate.0.clock.clone();
    let custody = wstate.0.custody.clone();
    let app_clone = app.clone();
    let esid = existing_server_id.unwrap_or_default();
    // The helper IP is no longer a parameter — provision_run reads it
    // from operators.helper_ip and fails fast with E_HELPER_IP_MISSING
    // if it was never detected.
    eprintln!("[provision] start op={} esid={:?}", operator_id, esid);
    let result = tauri::async_runtime::spawn_blocking(move || {
        eprintln!("[provision] spawn_blocking entered");
        let ctx = wcmd::WizardCtx { db, keystore, staging_dir, cli, clock, custody };
        let mut event_count = 0u32;
        let mut on_progress = |ev: ProgressEvent| {
            event_count += 1;
            eprintln!("[provision] event #{} step={} msg={}", event_count, ev.step, ev.message);
            // Primary: emit via Tauri event system
            match app_clone.emit("wizard-provision-event", &ev) {
                Ok(()) => eprintln!("[provision] emit ok"),
                Err(e) => eprintln!("[provision] emit FAILED: {e}"),
            }
            // Fallback: inject JS directly into WebView
            if let Some(w) = app_clone.get_webview_window("main") {
                match serde_json::to_string(&ev) {
                    Ok(payload) => {
                        let js = format!(
                            "(() => {{ \
                               const ev = {payload}; \
                               window.__daal_provision_events = window.__daal_provision_events || []; \
                               window.__daal_provision_events.push(ev); \
                               window.dispatchEvent(new CustomEvent('daal-provision-event', {{ detail: ev }})); \
                             }})()"
                        );
                        match w.eval(&js) {
                            Ok(()) => eprintln!("[provision] eval injected"),
                            Err(e) => eprintln!("[provision] eval FAILED: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[provision] eval payload encode FAILED: {e}"),
                }
            }
        };
        let r = wcmd::provision_run(&ctx, operator_id, &esid, &mut on_progress);
        eprintln!("[provision] provision_run returned ok={}", r.is_ok());
        r.map_err(|e| {
            let msg = e.to_string();
            eprintln!("[provision] error: {msg}");
            msg
        })
    })
    .await
    .map_err(|e| format!("join: {e}"))?;
    eprintln!("[provision] done ok={}", result.is_ok());
    result
}

/// `wizard_sign_relaypack`: runs `daal-deploy bind-and-sign` on a
/// background thread. Progress events stream via
/// `app.emit("wizard://sign-event", …)`.
#[tauri::command]
async fn wizard_sign_relaypack(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    phase: String,
    output_dir: String,
    publisher_name: String,
) -> Result<WizardBindResult, String> {
    let db = wstate.0.db.clone();
    let keystore = wstate.0.keystore.clone();
    let staging_dir = wstate.0.staging_dir.clone();
    let cli = wstate.0.cli.clone();
    let clock = wstate.0.clock.clone();
    let custody = wstate.0.custody.clone();
    let app_clone = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let ctx = wcmd::WizardCtx {
            db,
            keystore,
            staging_dir,
            cli,
            clock,
            custody,
        };
        let mut on_progress = move |ev: ProgressEvent| {
            let _ = app_clone.emit("wizard://sign-event", ev);
        };
        let path = if output_dir.trim().is_empty() {
            ctx.staging_dir.clone()
        } else {
            std::path::PathBuf::from(output_dir)
        };
        wcmd::sign_relaypack(
            &ctx,
            operator_id,
            &phase,
            &path,
            &publisher_name,
            &mut on_progress,
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("join: {e}"))?
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
async fn wizard_qr_render(
    app: AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    block_size: u32,
    max_frames: u32,
    seed: i64,
) -> Result<(), String> {
    let db = wstate.0.db.clone();
    let keystore = wstate.0.keystore.clone();
    let staging_dir = wstate.0.staging_dir.clone();
    let cli = wstate.0.cli.clone();
    let clock = wstate.0.clock.clone();
    let custody = wstate.0.custody.clone();
    let app_clone = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let ctx = wcmd::WizardCtx {
            db,
            keystore,
            staging_dir,
            cli,
            clock,
            custody,
        };
        let mut on_frame = move |frame: FountainFrame| -> bool {
            let _ = app_clone.emit("wizard://qr-frame", frame);
            true
        };
        wcmd::qr_render(
            &ctx,
            operator_id,
            block_size,
            max_frames,
            seed,
            &mut on_frame,
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

// ---- FRP-8 CDN-front command shims --------------------------------

#[tauri::command]
fn wizard_store_cloudflare_token(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    token: String,
) -> Result<(), String> {
    // Delegated to daal-wizard so the write goes through `custody_put`
    // and the failure carries the same stable `E_CUSTODY_*` prefix as
    // every other secret-touching command. (The old code also opened
    // the cloud token to "verify the PIN"; with no PIN there is nothing
    // to verify, and reading a secret only to discard it was never a
    // check of anything.)
    wcmd::store_cloudflare_token(&wstate.0, operator_id, &token).map_err(|e| e.to_string())
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
) -> Result<i64, String> {
    let input = wcmd::ProvisionCdnFrontInput {
        operator_id,
        hostname,
        origin_ip,
        origin_ipv6,
        origin_path,
        public_path,
    };
    wcmd::provision_cdn_front(&wstate.0, &input).map_err(|e| e.to_string())
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
) -> Result<(), String> {
    wcmd::verify_cdn_posture(&wstate.0, front_id).map_err(|e| e.to_string())
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
    wcmd::rotate_execute(&wstate.0, operator_id, input, &mut on_progress)
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
/// operator's root publisher key, which is read from device custody.
/// Returns the artefact paths and validity window. Runs
/// `daal-publish subkey rotate --json` under the hood; opens NO
/// sockets.
///
/// Note the sub-key priv it produces is written to the staging dir in
/// plaintext (0o600) and only its path is recorded — see the
/// `TODO(custody)` in `commands::subkey_rotate`. The PIN never
/// protected that file either; it gated the command that made it.
#[tauri::command]
fn wizard_subkey_rotate(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    validity: Option<String>,
    label: Option<String>,
) -> Result<SubkeyRotateResult, String> {
    let validity = validity.unwrap_or_else(|| "90d".to_string());
    let label = label.unwrap_or_else(|| "rotated-subkey".to_string());
    wcmd::subkey_rotate(&wstate.0, operator_id, &validity, &label).map_err(|e| e.to_string())
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

// ---- FRP-14 per-recipient surface ----------------------------------

#[tauri::command]
fn wizard_recipient_provision(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    address: String,
    display_name: String,
) -> Result<daal_wizard::recipient_book::RecipientSummary, String> {
    // Logcat trace so the *actual* stderr from the daal-deploy
    // subprocess surfaces on the device when provisioning fails.
    // The UI only shows the short wrapped error; the full stderr
    // is invaluable when debugging on-box auth/firewall/route
    // mismatches.
    eprintln!(
        "[recipient_provision] op={} addr_prefix={} display_name={:?}",
        operator_id,
        address.chars().take(12).collect::<String>(),
        display_name,
    );
    let r = daal_wizard::recipient_book::recipient_provision(
        &wstate.0,
        operator_id,
        &address,
        &display_name,
    );
    match &r {
        Ok(s) => eprintln!("[recipient_provision] ok id={} name={}", s.id, s.name),
        Err(e) => eprintln!("[recipient_provision] err: {}", e),
    }
    r.map_err(|e| e.to_string())
}

/// Produce the shareable shared `.sbp` (default distribution artifact):
/// mints the shared `r0` box user and rewrites the signed `.sbp` with its
/// creds so any phone can import + connect it — no per-recipient sealing.
#[tauri::command]
fn wizard_produce_shared_sbp(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<daal_wizard::recipient_book::SharedSbpSummary, String> {
    eprintln!("[produce_shared_sbp] op={}", operator_id);
    let r = daal_wizard::recipient_book::produce_shared_sbp(&wstate.0, operator_id);
    match &r {
        Ok(s) => eprintln!("[produce_shared_sbp] ok -> {}", s.sbp_path),
        Err(e) => eprintln!("[produce_shared_sbp] err: {}", e),
    }
    r.map_err(|e| e.to_string())
}

/// Rebuild the `.sbpx` for a recipient already on the roster.
///
/// The repair for a recipient whose envelope was never written (the
/// Tier-2 rewrite fails closed on a pre-Tier-2 box). Re-mints that
/// recipient's existing box user rather than adding a second one —
/// see `recipient_book::recipient_repack_sbpx` for why calling
/// `wizard_recipient_provision` again is not an option.
#[tauri::command]
fn wizard_recipient_repack_sbpx(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    recipient_id: i64,
) -> Result<daal_wizard::recipient_book::RecipientSummary, String> {
    eprintln!("[recipient_repack_sbpx] op={operator_id} rid={recipient_id}");
    let r =
        daal_wizard::recipient_book::recipient_repack_sbpx(&wstate.0, operator_id, recipient_id);
    match &r {
        Ok(s) => eprintln!("[recipient_repack_sbpx] ok -> {}", s.sbpx_path),
        Err(e) => eprintln!("[recipient_repack_sbpx] err: {e}"),
    }
    r.map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_recipient_revoke(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    recipient_id: i64,
) -> Result<daal_wizard::recipient_book::RecipientSummary, String> {
    daal_wizard::recipient_book::recipient_revoke(&wstate.0, operator_id, recipient_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_recipient_list(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<daal_wizard::recipient_book::RecipientSummary>, String> {
    daal_wizard::recipient_book::recipient_list(&wstate.0, operator_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn wizard_recipient_list_remote(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<String>, String> {
    daal_wizard::recipient_book::recipient_list_remote(&wstate.0, operator_id)
        .map_err(|e| e.to_string())
}

/// Hard-removes an already-revoked recipient from the local roster.
/// No box round-trip: [`wizard_recipient_revoke`] does the on-box
/// teardown; this just purges the greyed-out row + its `.sbpx`.
#[tauri::command]
fn wizard_recipient_delete(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    recipient_id: i64,
) -> Result<(), String> {
    daal_wizard::recipient_book::recipient_delete(&wstate.0, operator_id, recipient_id)
        .map_err(|e| e.to_string())
}

// ---- Publisher custody: status, migration, recovery ----------------

/// Honest custody report for the publisher surface. The UI renders a
/// passive label from `level` when everything is fine, a blocking
/// migration card when `legacy_pending`, and a non-dismissable error
/// card when `ok == false`.
#[tauri::command]
fn publisher_custody_status(
    wstate: State<'_, WizardStateMgr>,
) -> Result<wcmd::PublisherCustodyStatus, String> {
    wcmd::custody_status(&wstate.0).map_err(|e| e.to_string())
}

/// One-time upgrade from the PIN-sealed store to device custody.
///
/// Safety property: a legacy blob is deleted only after the same
/// plaintext has been written under custody AND read back
/// byte-identical. Callers must keep the gate open until the returned
/// `signing_keys_safe` is true — a publisher signing key that fails to
/// migrate is unrecoverable, and the relay it signs for can never gain
/// or drop another recipient.
#[tauri::command]
fn publisher_migrate_from_pin(
    wstate: State<'_, WizardStateMgr>,
    pin: String,
) -> Result<wcmd::CustodyMigrationReport, String> {
    wcmd::migrate_from_pin(&wstate.0, &pin).map_err(|e| e.to_string())
}

/// Unlock session-passphrase custody.
///
/// A publisher-flavoured wrapper over `device_custody_unlock` that
/// additionally probes with a real round-trip, so a wrong passphrase
/// is reported *here* as `E_CUSTODY_WRONG_PASS` instead of surfacing
/// minutes later as an opaque decrypt failure in the middle of signing.
#[tauri::command]
fn publisher_custody_unlock(
    wstate: State<'_, WizardStateMgr>,
    passphrase: String,
) -> Result<wcmd::PublisherCustodyStatus, String> {
    wcmd::custody_unlock(&wstate.0, &passphrase).map_err(|e| e.to_string())
}

/// Write a recovery copy of a relay's publisher signing key into the
/// platform Downloads directory. Returns the file name written; the
/// key bytes never cross the IPC boundary.
///
/// This is the only mitigation for the one thing device custody is
/// worse at than a PIN: the Device Wrap Key lives in the OS/hardware
/// keystore and cannot be exported, so a factory reset or a keystore
/// invalidation destroys every relay this device publishes. There is
/// no escrow. `wizard_publisher_keyimport` is the restore path.
#[tauri::command]
fn publisher_save_recovery_key(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    file_name: String,
) -> Result<String, String> {
    let staged = wcmd::export_recovery_key(&wstate.0, operator_id).map_err(|e| e.to_string())?;
    let name = sanitize_filename(&file_name);
    let name = if name.is_empty() {
        format!("daal-relay-{operator_id}-recovery.daalkey")
    } else if name.ends_with(".daalkey") {
        name
    } else {
        format!("{name}.daalkey")
    };
    let res = save_path_to_downloads(&staged.to_string_lossy(), &name);
    // The staged copy is a plaintext signing key; unlink it whether or
    // not the Downloads write succeeded.
    let _ = std::fs::remove_file(&staged);
    res?;
    Ok(name)
}

// ---- Relay identity, artifacts, helper IP --------------------------

/// Set (or clear, with "") the human nickname for a relay.
#[tauri::command]
fn wizard_set_operator_nickname(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    nickname: String,
) -> Result<(), String> {
    wcmd::set_operator_nickname(&wstate.0, operator_id, &nickname).map_err(|e| e.to_string())
}

/// List a relay's distributable files. Read-only; safe to call on
/// every render. Index 0 is the shared `.sbp`, index 1 the raw signed
/// bundle, then one entry per recipient by ascending id. Missing files
/// come back with `exists: false` rather than being omitted.
#[tauri::command]
fn wizard_list_artifacts(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<Vec<wcmd::ArtifactInfo>, String> {
    wcmd::list_artifacts(&wstate.0, operator_id).map_err(|e| e.to_string())
}

/// The persisted helper IP for a relay, or "" if never detected.
#[tauri::command]
fn wizard_get_helper_ip(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<String, String> {
    wcmd::get_helper_ip(&wstate.0, operator_id).map_err(|e| e.to_string())
}

/// Persist the helper IP. `source` is "auto" | "manual" | "whoami"
/// and is recorded for diagnosis only. Rejects anything that is not a
/// textual IPv4/IPv6 address, which is what stops a captive-portal
/// login page from being stored as an address.
#[tauri::command]
fn wizard_set_helper_ip(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    helper_ip: String,
    source: String,
) -> Result<(), String> {
    wcmd::set_helper_ip(&wstate.0, operator_id, &helper_ip, &source).map_err(|e| e.to_string())
}

// ---- FRP-14 Layer 3c: recipient-side identity ----------------------

/// First call: generate keypair + seal priv + persist row.
/// Subsequent calls: return cached summary (no keystore I/O on
/// the read path, but a round-trip check on the PIN — see
/// `specs/recipient-identity-v1.md` §5).
#[tauri::command]
fn recipient_identity_get_or_create(
    wstate: State<'_, WizardStateMgr>,
) -> Result<daal_wizard::recipient_identity::RecipientIdentitySummary, String> {
    daal_wizard::recipient_identity::get_or_create(&wstate.0).map_err(|e| e.to_string())
}

// ---- Device Custody v1: level + session unlock/lock ----------------

/// Returns the honest custody level for this device:
/// `"hardware" | "os_keystore" | "session_passphrase"`.
#[tauri::command]
fn device_custody_level(wstate: State<'_, WizardStateMgr>) -> Result<String, String> {
    Ok(wstate.0.custody.level().as_str().to_string())
}

/// Returns true when custody is currently usable without a
/// passphrase prompt (always true for hardware/os_keystore; for
/// session-passphrase, true only after a successful unlock).
#[tauri::command]
fn device_custody_is_unlocked(wstate: State<'_, WizardStateMgr>) -> Result<bool, String> {
    Ok(wstate.0.custody.is_unlocked())
}

/// Session-passphrase devices: derive the in-memory wrap key from
/// `passphrase`. Hardware/os_keystore: `passphrase` is ignored and
/// this simply forces the DWK to load (surfacing keystore errors).
///
/// On success, append an `unlocked` audit event so the history
/// view reflects the session.
#[tauri::command]
fn device_custody_unlock(
    wstate: State<'_, WizardStateMgr>,
    passphrase: Option<String>,
) -> Result<(), String> {
    wstate
        .0
        .custody
        .unlock(passphrase.as_deref())
        .map_err(|e| e.to_string())?;
    let level = wstate.0.custody.level().as_str().to_string();
    let now = (wstate.0.clock)();
    let _ = wstate
        .0
        .db
        .insert_custody_event(now, "unlocked", &level, "{}");
    Ok(())
}

/// Drop in-memory key material. No-op for hardware/os_keystore.
/// Also emits a `locked` event into custody_events if an identity
/// row exists, so the Settings → Custody → History view shows the
/// action. Errors from event logging are swallowed — locking must
/// always succeed.
#[tauri::command]
fn device_custody_lock(wstate: State<'_, WizardStateMgr>) -> Result<(), String> {
    wstate.0.custody.lock();
    let level = wstate.0.custody.level().as_str().to_string();
    let now = (wstate.0.clock)();
    let _ = wstate.0.db.insert_custody_event(now, "locked", &level, "{}");
    Ok(())
}

/// Device Custody B4: rotate the recipient identity. Mints a new
/// X25519 keypair, demotes the current keypair into history (so
/// existing `.sbpx` packs still open), and writes a `rotated`
/// audit event. Returns the new identity summary.
#[tauri::command]
fn device_custody_rotate(
    wstate: State<'_, WizardStateMgr>,
) -> Result<daal_wizard::recipient_identity::RecipientIdentitySummary, String> {
    daal_wizard::recipient_identity::rotate(&wstate.0).map_err(|e| e.to_string())
}

/// Device Custody B4: list the rotation history (newest retirement
/// first). Empty list = no rotations have happened.
#[tauri::command]
fn device_custody_history(
    wstate: State<'_, WizardStateMgr>,
) -> Result<Vec<daal_wizard::operator_db::RecipientIdentityHistoryRow>, String> {
    wstate
        .0
        .db
        .list_recipient_identity_history()
        .map_err(|e| e.to_string())
}

/// Device Custody B4: read the audit-event log (newest first).
/// `limit` caps the row count; 200 is a reasonable UI default.
#[tauri::command]
fn device_custody_events(
    wstate: State<'_, WizardStateMgr>,
    limit: Option<i64>,
) -> Result<Vec<daal_wizard::operator_db::CustodyEventRow>, String> {
    wstate
        .0
        .db
        .list_custody_events(limit.unwrap_or(200))
        .map_err(|e| e.to_string())
}

/// Read-only: returns `null` when no identity exists yet so the
/// React layer can render a "Create my Daal address" CTA. No
/// keystore I/O.
#[tauri::command]
fn recipient_identity_get(
    wstate: State<'_, WizardStateMgr>,
) -> Result<Option<daal_wizard::recipient_identity::RecipientIdentitySummary>, String> {
    daal_wizard::recipient_identity::get_summary(&wstate.0).map_err(|e| e.to_string())
}

// ---- FRP-14 Layer 3d: recipient-side `.sbpx` import ----------------

/// Sniff a file's leading bytes for the `.sbpx` magic.
/// Returns `true` for `.sbpx`, `false` for plain `.sbp` or
/// anything else. The React import flow uses this to decide
/// whether to call `recipient_import_sbpx` (encrypted lane) or
/// fall through to the existing `importSbp` lane (plain).
#[tauri::command]
fn recipient_sbpx_sniff(path: String) -> Result<bool, String> {
    daal_wizard::recipient_sbpx::sniff_file(std::path::Path::new(&path))
        .map_err(|e| e.to_string())
}

/// Stage a user-picked file under the wizard's private staging dir.
///
/// On Android the system file picker hands us a `content://` SAF URI
/// that std::fs cannot open. We resolve it through the JVM's
/// ContentResolver, copy the bytes to `<staging>/picked/<rand>.bin`,
/// and return that real path. On desktop the input is already a real
/// path and is returned verbatim (the dialog plugin only emits real
/// paths there).
#[tauri::command]
fn stage_picked_file(
    wstate: State<'_, WizardStateMgr>,
    path: String,
) -> Result<String, String> {
    // Plain filesystem path? Pass through unchanged.
    if !path.starts_with("content://") {
        return Ok(path);
    }

    #[cfg(target_os = "android")]
    {
        use jni::objects::JValue;
        use rand::RngCore;

        let picked_dir = wstate.0.staging_dir.join("picked");
        std::fs::create_dir_all(&picked_dir).map_err(|e| format!("mkdir picked: {e}"))?;
        let mut tag = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        let dest = picked_dir.join(format!("{}.bin", hex::encode(tag)));
        let dest_str = dest.to_string_lossy().to_string();

        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach thread: {e}"))?;
        let class = env
            .find_class("org/daal/desktop/MainActivity")
            .map_err(|e| format!("find_class: {e}"))?;
        let j_uri = env.new_string(&path).map_err(|e| format!("j_uri: {e}"))?;
        let j_dest = env
            .new_string(&dest_str)
            .map_err(|e| format!("j_dest: {e}"))?;
        let ok = env
            .call_static_method(
                &class,
                "copyContentUriToFile",
                "(Ljava/lang/String;Ljava/lang/String;)Z",
                &[JValue::Object(&j_uri), JValue::Object(&j_dest)],
            )
            .and_then(|v| v.z())
            .map_err(|e| format!("call copyContentUriToFile: {e}"))?;
        drop(env);
        std::mem::forget(vm);
        if !ok {
            return Err(format!("could not read picked file at {path}"));
        }
        return Ok(dest_str);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = wstate;
        Err(format!("content:// URIs not supported on this platform"))
    }
}

/// Decrypt a `.sbpx` envelope using the recipient's identity.
/// Returns the absolute path of a plaintext `.sbp` tempfile under
/// the wizard staging dir. The caller (UI) hands this path to the
/// existing `importSbp` contract.
#[tauri::command]
fn recipient_import_sbpx(
    wstate: State<'_, WizardStateMgr>,
    path: String,
) -> Result<String, String> {
    let p = std::path::PathBuf::from(&path);
    daal_wizard::recipient_sbpx::import_sbpx(&wstate.0, &p)
        .map(|out| out.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
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

/// Resolve the `daal-deploy` binary path. On Android, it's bundled as
/// `libdaal_deploy.so` in the native library directory (extracted from
/// jniLibs/ at install time). On desktop, it's on PATH or next to the
/// exe. Returns `None` to let SubprocessRunner fall back to PATH lookup.
fn resolve_deploy_binary() -> Option<PathBuf> {
    // Android: the binary sits next to libdaalcore.so in the
    // nativeLibraryDir. We find it by looking for the engine lib
    // (already resolved at startup) and checking its sibling.
    #[cfg(target_os = "android")]
    {
        // The native lib dir on Android is e.g.
        // /data/app/<hash>/org.daal.desktop-<hash>/lib/arm64/
        // We can find it by reading /proc/self/maps for libdaalcore.so.
        if let Some(dir) = find_native_lib_dir() {
            let deploy = dir.join("libdaal_deploy.so");
            if deploy.exists() {
                log::info!("resolved daal-deploy at {:?}", deploy);
                return Some(deploy);
            }
        }
    }
    // Desktop: try next to the current exe first.
    #[cfg(not(target_os = "android"))]
    {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let deploy = dir.join("daal-deploy");
                if deploy.exists() {
                    return Some(deploy);
                }
            }
        }
    }
    None // SubprocessRunner falls back to PATH lookup
}

/// On Android, find the directory containing our native libraries by
/// scanning /proc/self/maps for libdaalcore.so.
#[cfg(target_os = "android")]
fn find_native_lib_dir() -> Option<PathBuf> {
    use std::io::{BufRead, BufReader};
    if let Ok(f) = std::fs::File::open("/proc/self/maps") {
        for line in BufReader::new(f).lines().flatten() {
            if line.contains("libdaalcore.so") {
                // Line format: "addr-addr perms offset dev inode   /path/to/lib"
                if let Some(path) = line.rsplit_once(' ').map(|(_, p)| p) {
                    if let Some(dir) = std::path::Path::new(path).parent() {
                        return Some(dir.to_path_buf());
                    }
                }
            }
        }
    }
    None
}

fn build_wizard_ctx(state_dir: &PathBuf) -> Result<wcmd::WizardCtx, String> {
    let db_path = state_dir.join("wizard.db");
    let db = Arc::new(OperatorDb::open_at(&db_path).map_err(|e| e.to_string())?);
    #[cfg(feature = "dev-no-keystore")]
    let keystore = Arc::new(Keystore::new_in_memory(state_dir));
    #[cfg(not(feature = "dev-no-keystore"))]
    let keystore = Arc::new(Keystore::new_os(state_dir));
    let staging_dir = default_staging_dir();

    // On Android, daal-deploy is bundled as libdaal_deploy.so in the
    // same native-library directory as libdaalcore.so. The system
    // extracts all jniLibs at install time; we resolve via the engine
    // lib path that was already located at startup.
    let deploy_bin = resolve_deploy_binary();
    let cli = Arc::new(SubprocessRunner::new(deploy_bin));
    let clock: Arc<dyn Fn() -> i64 + Send + Sync> = Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    let custody = custody::build_device_custody(state_dir);
    Ok(wcmd::WizardCtx {
        db,
        keystore,
        staging_dir,
        cli,
        clock,
        custody,
    })
}

/// `wizard_get_sbp_path`: returns the absolute path of the signed
/// `.sbp` invite package for an operator. Used by the Publisher
/// wizard's Step 7 + Step 1 to display the path and share the file.
///
/// Convention (see `sign_relaypack` in daal-wizard): the .sbp is
/// written to `<staging_dir>/<operator_id>.sbp`.
#[tauri::command]
fn wizard_get_sbp_path(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
) -> Result<String, String> {
    let path = wstate
        .0
        .staging_dir
        .join(format!("{operator_id}.sbp"));
    if !path.exists() {
        return Err(format!("no signed invite package for operator {operator_id}"));
    }
    Ok(path.to_string_lossy().to_string())
}

/// Convert an arbitrary user-supplied label into a safe file stem.
/// Strips path separators, control chars, and trims; collapses
/// whitespace runs to `_`. Returns "" if the input has no usable
/// chars left.
fn sanitize_filename(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for c in s.chars() {
        let keep = match c {
            // Reject path/control/reserved chars across OSes.
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => false,
            c if c.is_control() => false,
            _ => true,
        };
        if !keep {
            continue;
        }
        if c.is_whitespace() {
            if !last_was_space && !out.is_empty() {
                out.push('_');
                last_was_space = true;
            }
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// `share_invite`: copy an operator's signed `.sbp` into a cache dir
/// under a user-friendly name, then open the system share-sheet on
/// platforms that support it. Returns the path of the staged file
/// so the UI can show the user where it lives.
///
/// Behaviour by platform:
/// - Android: FileProvider + `ACTION_SEND` chooser (Telegram, Gmail, …).
/// - macOS:   `open -R` reveals the file in Finder; the user can
///            right-click → Share from there. A native picker can be
///            wired later via `NSSharingServicePicker`.
/// - Windows: `explorer /select,<path>` reveals in Explorer.
/// - Linux:   `xdg-open <parent dir>`.
/// - iOS:     placeholder — wire `UIActivityViewController` later.
#[tauri::command]
fn share_invite(
    _app: tauri::AppHandle,
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    friendly_name: String,
) -> Result<String, String> {
    // Prefer the shared .sbp (rewritten with the r0 shared user's working
    // outbounds by wizard_produce_shared_sbp) — that's the one any phone
    // can actually connect. Fall back to the raw Step-6 .sbp only if the
    // shared one hasn't been produced yet.
    let shared = wstate
        .0
        .staging_dir
        .join(format!("{operator_id}.shared.sbp"));
    let raw = wstate
        .0
        .staging_dir
        .join(format!("{operator_id}.sbp"));
    let canonical = if shared.exists() { shared } else { raw };
    if !canonical.exists() {
        return Err(format!(
            "no relay pack on this device for server #{operator_id}"
        ));
    }
    let safe = sanitize_filename(&friendly_name);
    let stem = if safe.is_empty() {
        format!("relaypack-{operator_id}")
    } else {
        safe
    };
    // Stage the copy under <staging>/share/ so we never expose the
    // canonical (potentially numbered) name to the share-sheet.
    let share_dir = wstate.0.staging_dir.join("share");
    std::fs::create_dir_all(&share_dir).map_err(|e| format!("mkdir share: {e}"))?;
    let dest = share_dir.join(format!("{stem}.sbp"));
    std::fs::copy(&canonical, &dest).map_err(|e| format!("copy: {e}"))?;
    let path = dest.to_string_lossy().to_string();
    let chooser_title = "Send Daal relay pack".to_string();
    let mime = "application/octet-stream".to_string();

    #[cfg(target_os = "android")]
    {
        use jni::objects::JValue;
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach thread: {e}"))?;
        let class = env
            .find_class("org/daal/desktop/MainActivity")
            .map_err(|e| format!("find_class: {e}"))?;
        let j_path = env.new_string(&path).map_err(|e| format!("j_path: {e}"))?;
        let j_mime = env.new_string(&mime).map_err(|e| format!("j_mime: {e}"))?;
        let j_title = env
            .new_string(&chooser_title)
            .map_err(|e| format!("j_title: {e}"))?;
        let call_res: std::result::Result<(), String> = env
            .call_static_method(
                &class,
                "shareFile",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&j_path),
                    JValue::Object(&j_mime),
                    JValue::Object(&j_title),
                ],
            )
            .map(|_| ())
            .map_err(|e| format!("call shareFile: {e}"));
        drop(env);
        std::mem::forget(vm);
        call_res?;
        return Ok(path);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = (mime, chooser_title);
        // Desktop fallback: reveal the file in the system file
        // manager so the user can share it from there.
        let p = std::path::PathBuf::from(&path);
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg("-R").arg(&p).spawn();
        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("explorer")
            .arg(format!("/select,{}", p.display()))
            .spawn();
        #[cfg(all(unix, not(target_os = "macos")))]
        let _ = std::process::Command::new("xdg-open")
            .arg(p.parent().unwrap_or_else(|| std::path::Path::new(".")))
            .spawn();
        Ok(path)
    }
}

/// Copy a staged file into the phone's public Downloads via the Kotlin
/// MainActivity.saveToDownloads (MediaStore). Lets the user keep/manage
/// the connection file and re-import it later. Desktop: copies next to the
/// user's home Downloads dir.
fn save_path_to_downloads(src: &str, display_name: &str) -> Result<(), String> {
    if !std::path::Path::new(src).exists() {
        return Err(format!("file not found: {src}"));
    }
    #[cfg(target_os = "android")]
    {
        use jni::objects::JValue;
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach thread: {e}"))?;
        let class = env
            .find_class("org/daal/desktop/MainActivity")
            .map_err(|e| format!("find_class: {e}"))?;
        let j_src = env.new_string(src).map_err(|e| format!("j_src: {e}"))?;
        let j_name = env
            .new_string(display_name)
            .map_err(|e| format!("j_name: {e}"))?;
        let ok: bool = env
            .call_static_method(
                &class,
                "saveToDownloads",
                "(Ljava/lang/String;Ljava/lang/String;)Z",
                &[JValue::Object(&j_src), JValue::Object(&j_name)],
            )
            .and_then(|v| v.z())
            .map_err(|e| format!("call saveToDownloads: {e}"))?;
        drop(env);
        std::mem::forget(vm);
        if !ok {
            return Err("could not write to Downloads".into());
        }
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    {
        let dl = dirs_downloads();
        std::fs::create_dir_all(&dl).map_err(|e| format!("mkdir downloads: {e}"))?;
        std::fs::copy(src, dl.join(display_name)).map_err(|e| format!("copy: {e}"))?;
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
fn dirs_downloads() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join("Downloads"))
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Save the operator's shared `.sbp` (produced by wizard_produce_shared_sbp)
/// into the phone's Downloads folder under a friendly name.
#[tauri::command]
fn save_shared_sbp_to_downloads(
    wstate: State<'_, WizardStateMgr>,
    operator_id: i64,
    file_name: String,
) -> Result<(), String> {
    let shared = wstate
        .0
        .staging_dir
        .join(format!("{operator_id}.shared.sbp"));
    let name = sanitize_filename(&file_name);
    let name = if name.is_empty() {
        format!("daal-connection-{operator_id}.sbp")
    } else if name.ends_with(".sbp") {
        name
    } else {
        format!("{name}.sbp")
    };
    save_path_to_downloads(&shared.to_string_lossy(), &name)
}

/// Save a per-recipient `.sbpx` (from a recipient row's sbpx_path) into the
/// phone's Downloads folder.
#[tauri::command]
fn save_sbpx_to_downloads(sbpx_path: String, file_name: String) -> Result<(), String> {
    let name = sanitize_filename(&file_name);
    let name = if name.is_empty() {
        "daal-connection.sbpx".to_string()
    } else if name.ends_with(".sbpx") {
        name
    } else {
        format!("{name}.sbpx")
    };
    save_path_to_downloads(&sbpx_path, &name)
}

/// FRP-14 Layer 3b.5: `share_invite_sbpx` — same shape as
/// `share_invite` but for the per-recipient `.sbpx` envelope.
/// Path is supplied directly from the recipient row's `sbpx_path`
/// field; this command stages a friendly-named copy and opens the
/// OS share-sheet (Android) / file manager (desktop).
#[tauri::command]
fn share_invite_sbpx(
    _app: tauri::AppHandle,
    wstate: State<'_, WizardStateMgr>,
    sbpx_path: String,
    friendly_name: String,
) -> Result<String, String> {
    let canonical = std::path::PathBuf::from(&sbpx_path);
    if !canonical.exists() {
        return Err(format!("no .sbpx at {sbpx_path}"));
    }
    let safe = sanitize_filename(&friendly_name);
    let stem = if safe.is_empty() {
        "relaypack".to_string()
    } else {
        safe
    };
    let share_dir = wstate.0.staging_dir.join("share");
    std::fs::create_dir_all(&share_dir).map_err(|e| format!("mkdir share: {e}"))?;
    let dest = share_dir.join(format!("{stem}.sbpx"));
    std::fs::copy(&canonical, &dest).map_err(|e| format!("copy: {e}"))?;
    let path = dest.to_string_lossy().to_string();
    let chooser_title = "Send Daal relay pack".to_string();
    let mime = "application/octet-stream".to_string();

    #[cfg(target_os = "android")]
    {
        use jni::objects::JValue;
        let ctx = ndk_context::android_context();
        let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }
            .map_err(|e| format!("attach JavaVM: {e}"))?;
        let mut env = vm
            .attach_current_thread()
            .map_err(|e| format!("attach thread: {e}"))?;
        let class = env
            .find_class("org/daal/desktop/MainActivity")
            .map_err(|e| format!("find_class: {e}"))?;
        let j_path = env.new_string(&path).map_err(|e| format!("j_path: {e}"))?;
        let j_mime = env.new_string(&mime).map_err(|e| format!("j_mime: {e}"))?;
        let j_title = env
            .new_string(&chooser_title)
            .map_err(|e| format!("j_title: {e}"))?;
        let call_res: std::result::Result<(), String> = env
            .call_static_method(
                &class,
                "shareFile",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(&j_path),
                    JValue::Object(&j_mime),
                    JValue::Object(&j_title),
                ],
            )
            .map(|_| ())
            .map_err(|e| format!("call shareFile: {e}"));
        drop(env);
        std::mem::forget(vm);
        call_res?;
        return Ok(path);
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = (mime, chooser_title);
        let p = std::path::PathBuf::from(&path);
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg("-R").arg(&p).spawn();
        #[cfg(target_os = "windows")]
        let _ = std::process::Command::new("explorer")
            .arg(format!("/select,{}", p.display()))
            .spawn();
        #[cfg(all(unix, not(target_os = "macos")))]
        let _ = std::process::Command::new("xdg-open")
            .arg(p.parent().unwrap_or_else(|| std::path::Path::new(".")))
            .spawn();
        Ok(path)
    }
}

/// Open a URL in the system's default browser as a separate app.
/// On Android this calls MainActivity.openInBrowser() via JNI.
/// On desktop it uses xdg-open / open / start.
#[tauri::command]
fn open_external_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri::Url;
    let _parsed = Url::parse(&url).map_err(|e| format!("invalid URL: {e}"))?;

    #[cfg(target_os = "android")]
    {
        use tauri::Emitter;
        // We can't do JNI from here easily, so emit an event that
        // the webview JS picks up and calls window.open(). Actually,
        // let's use the opener plugin — it does work, Custom Tab is fine.
        app.opener()
            .open_url(&url, None::<&str>)
            .map_err(|e| format!("opener: {e}"))?;
        return Ok(());
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        std::process::Command::new(if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(target_os = "windows") {
            "cmd"
        } else {
            "xdg-open"
        })
        .args(if cfg!(target_os = "windows") {
            vec!["/c", "start", url.as_str()]
        } else {
            vec![url.as_str()]
        })
        .spawn()
        .map_err(|e| format!("open failed: {e}"))?;
        Ok(())
    }
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

    let lib_path = locate_engine_lib(&state_dir)
        .expect("could not find libdaalcore — set $DAAL_ENGINE_LIB or install the engine library");
    // `Engine::load` resolves ~50 symbols up front, so the usual way it
    // fails is not "no library" but "library older than this shell" —
    // `libdaalcore` is a build artifact and the one under `resources/`
    // is only as fresh as whoever last built it. A bare `.expect` turned
    // that into a black window and an unattributable panic, so name the
    // path and the missing symbol: the fix is always to rebuild the
    // engine (`go build -buildmode=c-shared -tags cshared
    // ./cmd/libdaalcore` from `core/`) into that directory.
    let engine = Engine::load(&lib_path).unwrap_or_else(|e| {
        panic!(
            "engine load failed for {}: {e}\n\
             the engine library is out of date or corrupt — rebuild it into that path with:\n\
             (cd core && CGO_ENABLED=1 go build -buildmode=c-shared -tags cshared -o <path> ./cmd/libdaalcore)",
            lib_path.display()
        )
    });
    engine.init(&state_dir, "warn").expect("engine init");

    // Phase 45 — publish a global Arc<Engine> so the Android JNI bridge
    // (Java_org_daal_desktop_platform_DaalCoreBridge_*) can reach the
    // engine symbols without piping through AppState (no AppHandle in a
    // JNI extern "system" function).
    #[cfg(target_os = "android")]
    {
        let _ = ENGINE_FOR_JNI.set(engine.clone());
    }

    let app_state = AppState::new(engine, state_dir.clone());
    let wizard_ctx = build_wizard_ctx(&state_dir).expect("wizard context init (DB + keystore)");
    let recipient_registry = recipient::SessionRegistry::default();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_daal_platform::init())
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
            route_delete,
            publisher_delete,
            subscription_list,
            revocation_refresh_all,
            start_sidecar,
            stop_sidecar,
            heartbeat_tick,
            wizard_store_cloud_token,
            wizard_list_existing_servers,
            wizard_list_server_types,
            wizard_pricing_lookup,
            wizard_select_profile,
            wizard_publisher_keygen,
            wizard_publisher_keyimport,
            wizard_finalize_pre_provision,
            wizard_list_operators,
            wizard_get_operator_state,
            wizard_cancel_and_cleanup,
            wizard_relay_destroy,
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
            // FRP-14 per-recipient surface
            wizard_recipient_provision,
            wizard_recipient_repack_sbpx,
            wizard_recipient_revoke,
            wizard_recipient_list,
            wizard_recipient_list_remote,
            wizard_recipient_delete,
            wizard_produce_shared_sbp,
            // Publisher custody: status, one-time PIN migration, recovery
            publisher_custody_status,
            publisher_migrate_from_pin,
            publisher_custody_unlock,
            publisher_save_recovery_key,
            // Relay identity, artifacts, helper IP
            wizard_set_operator_nickname,
            wizard_list_artifacts,
            wizard_get_helper_ip,
            wizard_set_helper_ip,
            // FRP-14 Layer 3c: recipient-side identity
            recipient_identity_get_or_create,
            recipient_identity_get,
            // Device Custody v1 status + session unlock/lock
            device_custody_level,
            device_custody_is_unlocked,
            device_custody_unlock,
            device_custody_lock,
            // Device Custody B4: rotate + history + events
            device_custody_rotate,
            device_custody_history,
            device_custody_events,
            // FRP-14 Layer 3d: recipient-side .sbpx import
            recipient_sbpx_sniff,
            stage_picked_file,
            recipient_import_sbpx,
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
            scheduler_tick,
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
            open_external_url,
            share_invite,
            share_invite_sbpx,
            save_shared_sbp_to_downloads,
            save_sbpx_to_downloads,
            wizard_get_sbp_path,
        ])
        .setup(|app| {
            // Best-effort: spawn sing-box on launch so the SOCKS5 inlet
            // is up by the time the user clicks Connect. Errors are
            // swallowed; the user can retry from Subscriptions.
            let state: State<AppState> = app.state();
            let _ = cmd::start_sidecar(&state);

            // Gap 4-recipient: drive scheduler.Tick on a ~60 s
            // background timer so per-row ProfileUpdateMin cadence
            // actually fires while the GUI is running. The engine's
            // scheduler.Plan respects the persisted "last good
            // refresh" stamps, so this is safe to call frequently —
            // most ticks will be no-ops. Errors are swallowed; the
            // UI's manual ↻ on the Subscriptions panel is the
            // fallback.
            {
                let app_handle = app.handle().clone();
                std::thread::spawn(move || {
                    // Small initial delay so the GUI has time to call
                    // engine_init before our first tick.
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    loop {
                        let state: State<AppState> = app_handle.state();
                        let _ = cmd::scheduler_tick(&state);
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                });
            }

            // D-2.1: install a system-tray icon with a context menu
            // (Connect / Disconnect / Open / Quit). On Linux this is
            // best-effort — some desktop environments don't expose a
            // tray; failure is silently ignored.
            #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
            {
                use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
                use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

                let app_handle = app.handle().clone();
                let connect_item =
                    MenuItem::with_id(&app_handle, "tray.connect", "Connect", true, None::<&str>)?;
                let disconnect_item = MenuItem::with_id(
                    &app_handle,
                    "tray.disconnect",
                    "Disconnect",
                    true,
                    None::<&str>,
                )?;
                let open_item =
                    MenuItem::with_id(&app_handle, "tray.open", "Open Daal", true, None::<&str>)?;
                let quit_item =
                    MenuItem::with_id(&app_handle, "tray.quit", "Quit Daal", true, None::<&str>)?;
                let separator = PredefinedMenuItem::separator(&app_handle)?;
                let menu = Menu::with_items(
                    &app_handle,
                    &[
                        &connect_item,
                        &disconnect_item,
                        &separator,
                        &open_item,
                        &quit_item,
                    ],
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
                            "tray.disconnect" => {
                                let _ = cmd::disconnect(&state);
                            }
                            "tray.open" => {
                                if let Some(w) = handle.get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                            "tray.quit" => {
                                handle.exit(0);
                            }
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

// ----------------------------------------------------------------------
// Phase 45 — Android JNI bridge.
//
// The Kotlin object `org.daal.desktop.platform.DaalCoreBridge` declares
// five `external` methods that the in-process engine ABI surfaces
// through libdaalcore.so:
//
//   setTunFd(fd: Int): Int
//   clearTunFd(): Int
//   registerProtectCallback(): Int
//   setRoute(routeId: String): Int
//   clearRoute(): Int
//
// We implement each as `Java_org_daal_desktop_platform_DaalCoreBridge_<name>`
// (Kotlin's class-mangling rule for object companions), reach the
// engine through ENGINE_FOR_JNI (a OnceLock populated during Tauri
// app startup), and translate the result into a JNI-friendly jint.
//
// The protect callback installs a C trampoline that, when called by
// the engine driver, takes the fd, locates the active JavaVM via
// ndk_context, and calls `DaalCoreBridge.invokeProtect(fd: Int): Boolean`
// — which routes to `VpnService.protect()` because DaalVpnService set
// `DaalCoreBridge.protectImpl = { fd -> protect(fd) }` before any
// upstream socket existed.

#[cfg(target_os = "android")]
static ENGINE_FOR_JNI: std::sync::OnceLock<Arc<Engine>> = std::sync::OnceLock::new();

#[cfg(target_os = "android")]
mod jni_bridge {
    use std::ffi::c_int;
    use std::sync::Arc;

    use jni::objects::{JClass, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    use daal_desktop_core::engine::Engine;

    fn engine() -> Option<Arc<Engine>> {
        super::ENGINE_FOR_JNI.get().cloned()
    }

    /// Engine driver's protect trampoline. The signature matches the
    /// `int (*)(int fd)` contract documented on
    /// engine_register_protect_callback: returns non-zero on success,
    /// zero on failure.
    extern "C" fn protect_trampoline(fd: c_int) -> c_int {
        use jni::objects::JValue;
        let raw_vm = ndk_context::android_context().vm();
        if raw_vm.is_null() {
            return 0;
        }
        let vm = match unsafe { jni::JavaVM::from_raw(raw_vm.cast()) } {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let result = (|| -> Result<bool, jni::errors::Error> {
            let mut env = vm.attach_current_thread()?;
            let class = env.find_class("org/daal/desktop/platform/DaalCoreBridge")?;
            let v = env.call_static_method(
                &class,
                "invokeProtect",
                "(I)Z",
                &[JValue::Int(fd)],
            )?;
            v.z()
        })();
        // The JavaVM came from a raw pointer we do not own (ndk_context
        // holds the lifetime); avoid running the destructor.
        std::mem::forget(vm);
        if result.unwrap_or(false) {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_DaalCoreBridge_setTunFd<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
        fd: jint,
    ) -> jint {
        let Some(eng) = engine() else { return -1 };
        match eng.set_tun_fd(fd as c_int) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_DaalCoreBridge_clearTunFd<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jint {
        let Some(eng) = engine() else { return -1 };
        match eng.clear_tun_fd() {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_DaalCoreBridge_registerProtectCallback<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jint {
        let Some(eng) = engine() else { return -1 };
        let ptr = protect_trampoline as *const () as usize;
        match eng.register_protect_callback(ptr) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_DaalCoreBridge_setRoute<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        route_id: JString<'local>,
    ) -> jint {
        let Some(eng) = engine() else { return -1 };
        let s: String = match env.get_string(&route_id) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        match eng.set_route(&s) {
            Ok(_) => 0,
            Err(e) => {
                // Surface the engine's reason — DaalVpnService otherwise
                // only sees the -1 and logs a bare "tearing down".
                log::error!("DaalCoreBridge.setRoute({s}) failed: {e}");
                -1
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_org_daal_desktop_platform_DaalCoreBridge_clearRoute<'local>(
        _env: JNIEnv<'local>,
        _class: JClass<'local>,
    ) -> jint {
        let Some(eng) = engine() else { return -1 };
        match eng.clear_route() {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}
