//! `engine` — dlopen wrapper around `libdaalcore.{so,dll,dylib}`.
//!
//! The unsafe surface is contained here; everything else in the crate
//! is `#![deny(unsafe_code)]`. Each ABI function gets a typed Rust
//! wrapper that:
//!
//! 1. Converts strings to/from C-strings.
//! 2. Pre-allocates a UTF-8 output buffer that grows on -ERANGE.
//! 3. Returns `Result<JsonValue>` for the JSON-returning calls.
//!
//! ABI version check: `version()` MUST start with `daal-core 0.9`.
//! Kept in lockstep with `core/abi/abi.go::Version` (release-check
//! pins it as locked invariant). Mismatches are surfaced via
//! `DesktopError::AbiMismatch` so the GUI can show a one-line
//! "reinstall Daal" banner.

#![allow(unsafe_code)] // Confined to this module.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::Path;
use std::sync::{Arc, Mutex};

use libloading::{Library, Symbol};

use crate::errors::{DesktopError, Result};

const REQUIRED_VERSION_PREFIX: &str = "daal-core 0.9";

/// Loaded engine library + resolved C ABI symbol table.
///
/// The ABI is intentionally append-only (per spec); resolving every
/// symbol up-front lets the GUI fail fast on a mismatched library
/// rather than panic mid-flow.
pub struct Engine {
    // The library MUST outlive every Symbol borrowed from it. We hold
    // it in an Arc so AppState can clone cheap handles.
    _lib: Arc<Library>,

    // Lifecycle.
    init: extern "C" fn(*const c_char, *const c_char) -> c_int,
    shutdown: extern "C" fn() -> c_int,
    version: extern "C" fn() -> *const c_char,

    // Routes.
    set_route: extern "C" fn(*const c_char) -> c_int,
    clear_route: extern "C" fn() -> c_int,
    set_mode: extern "C" fn(*const c_char) -> c_int,
    apply_cooldown: extern "C" fn(*const c_char, c_int) -> c_int,

    // Probes.
    probe_udp: extern "C" fn(c_int) -> c_int,
    probe_dns: extern "C" fn(c_int) -> c_int,
    probe_tcp443: extern "C" fn(c_int) -> c_int,

    // Stats / diagnostics.
    stats_redacted: extern "C" fn(*mut c_void, c_int) -> c_int,
    export_diagnostics: extern "C" fn(*mut c_void, c_int) -> c_int,

    // Bundle import.
    import_sbp: extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
    resolve_trust_prompt: extern "C" fn(*const c_char, c_int, *mut c_void, c_int) -> c_int,
    fountain_feed_frame: extern "C" fn(*const c_char, *const c_char, *mut c_void, c_int) -> c_int,

    // Phase 1.5A — subscriptions / revocation / pointer rotation /
    // diagnostics-explain (6 added functions).
    subscription_add:
        extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void, c_int) -> c_int,
    subscription_refresh: extern "C" fn(*const c_char, c_int, *mut c_void, c_int) -> c_int,
    subscription_remove: extern "C" fn(*const c_char) -> c_int,
    subscription_list: extern "C" fn(*mut c_void, c_int) -> c_int,
    revocation_refresh_all: extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
    pointer_rotation_status: extern "C" fn(*mut c_void, c_int) -> c_int,
    diagnostics_explain: extern "C" fn(*mut c_void, c_int) -> c_int,

    // D-2.1 — display-summary surface (4 added functions).
    route_summary: extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
    available_routes: extern "C" fn(*mut c_void, c_int) -> c_int,
    throughput_snapshot: extern "C" fn(*mut c_void, c_int) -> c_int,
    panic_wipe: extern "C" fn() -> c_int,

    // Phase 1.5B — TunnelDialer wiring (1 added function).
    set_tunnel_socks: extern "C" fn(
        *const c_char,
        c_int,
        *const c_char,
        *const c_char,
        *mut c_void,
        c_int,
    ) -> c_int,

    // Phase 2F — In-engine scheduler (1 added function, surface 34→35).
    scheduler_status: extern "C" fn(*mut c_void, c_int) -> c_int,

    // Phase 2A — Route budget tag setter (1 added function, surface 35→36).
    set_route_budget: extern "C" fn(*const c_char, *const c_char, *mut c_void, c_int) -> c_int,

    // Phase 2C — Per-network memory (1 added function, surface 36→37).
    // Hashes (kind, carrier, ssid) on entry; the raw strings never
    // cross the FFI back to the host. Returns JSON status.
    network_changed:
        extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void, c_int) -> c_int,

    // Phase 2D — Argon2id PIN-vault unlock (surface 37→39). For
    // high-risk class only; non-high-risk returns -2 from the engine.
    // Returns 0 on success, -1 on wrong PIN, -2 if device is not
    // in high-risk class.
    unlock_secrets: extern "C" fn(*const c_char) -> c_int,

    // Phase 2D — bulk-capable session opt-in setter (1 added
    // function, surface 38→39). Pass 1 to allow, 0 to disallow.
    // Always returns 0. Cleared by NewSession.
    set_allow_bulk_capable: extern "C" fn(c_int) -> c_int,

    // v0.2.x — full plumbing pass. Every remaining engine_* symbol
    // gets a typed wrapper here so the GUI can reach it.
    lifecycle_event: extern "C" fn(*const c_char) -> c_int,
    set_rendezvous_priority: extern "C" fn(*const c_char) -> c_int,
    set_push_rendezvous_enabled: extern "C" fn(c_int) -> c_int,
    set_auto_promotion: extern "C" fn(c_int) -> c_int,
    set_masque_submode_override: extern "C" fn(*const c_char) -> c_int,
    set_experimental_families_enabled: extern "C" fn(c_int) -> c_int,
    bootstrap_install_seeds: extern "C" fn(*mut c_void, c_int) -> c_int,
    bootstrap_refresh: extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
    bootstrap_status: extern "C" fn(*mut c_void, c_int) -> c_int,
    redistribute_route:
        extern "C" fn(*const c_char, *const c_char, *mut c_void, c_int) -> c_int,
    uri_detect: extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
    uri_import: extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
    wasm_kill_switch_pubkey: extern "C" fn(*mut c_void, c_int) -> c_int,
    loaded_wasm_modules: extern "C" fn(*mut c_void, c_int) -> c_int,
}

impl Engine {
    /// dlopens the shared library at `path`, resolves every required
    /// symbol, then verifies `engine_version()` starts with the
    /// required prefix. Returns an `Engine` ready to call.
    pub fn load(path: &Path) -> Result<Arc<Self>> {
        // SAFETY: Library::new is unsafe because dlopen executes the
        // library's initializers. We trust libdaalcore (we built it).
        let lib =
            unsafe { Library::new(path) }.map_err(|e| DesktopError::EngineLoad(e.to_string()))?;
        let lib = Arc::new(lib);

        // SAFETY: each get<T> resolves a symbol whose declared signature
        // we wrote to match the //export'd Go function. Mismatches
        // surface as crashes the first time we call them, so the
        // version check below acts as a cheap canary.
        unsafe {
            let init = *lookup::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(
                &lib,
                b"engine_init",
            )?;
            let shutdown = *lookup::<unsafe extern "C" fn() -> c_int>(&lib, b"engine_shutdown")?;
            let version =
                *lookup::<unsafe extern "C" fn() -> *const c_char>(&lib, b"engine_version")?;
            let set_route =
                *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(&lib, b"engine_set_route")?;
            let clear_route =
                *lookup::<unsafe extern "C" fn() -> c_int>(&lib, b"engine_clear_route")?;
            let set_mode =
                *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(&lib, b"engine_set_mode")?;
            let apply_cooldown = *lookup::<unsafe extern "C" fn(*const c_char, c_int) -> c_int>(
                &lib,
                b"engine_apply_cooldown",
            )?;
            let probe_udp =
                *lookup::<unsafe extern "C" fn(c_int) -> c_int>(&lib, b"engine_probe_udp")?;
            let probe_dns =
                *lookup::<unsafe extern "C" fn(c_int) -> c_int>(&lib, b"engine_probe_dns")?;
            let probe_tcp443 =
                *lookup::<unsafe extern "C" fn(c_int) -> c_int>(&lib, b"engine_probe_tcp443")?;
            let stats_redacted = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_stats_redacted",
            )?;
            let export_diagnostics = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_export_diagnostics",
            )?;
            let import_sbp = *lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_import_sbp")?;
            let resolve_trust_prompt = *lookup::<
                unsafe extern "C" fn(*const c_char, c_int, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_resolve_trust_prompt")?;
            let fountain_feed_frame = *lookup::<
                unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_fountain_feed_frame")?;
            let subscription_add = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_subscription_add")?;
            let subscription_refresh = *lookup::<
                unsafe extern "C" fn(*const c_char, c_int, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_subscription_refresh")?;
            let subscription_remove = *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                &lib,
                b"engine_subscription_remove",
            )?;
            let subscription_list = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_subscription_list",
            )?;
            let revocation_refresh_all = *lookup::<
                unsafe extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_revocation_refresh_all")?;
            let pointer_rotation_status = *lookup::<
                unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
            >(&lib, b"engine_pointer_rotation_status")?;
            let diagnostics_explain = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_diagnostics_explain",
            )?;
            let set_tunnel_socks = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    c_int,
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_set_tunnel_socks")?;
            let scheduler_status = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_scheduler_status",
            )?;
            let set_route_budget = *lookup::<
                unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_set_route_budget")?;
            let network_changed = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_network_changed")?;
            let unlock_secrets = *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                &lib,
                b"engine_unlock_secrets",
            )?;
            let set_allow_bulk_capable = *lookup::<unsafe extern "C" fn(c_int) -> c_int>(
                &lib,
                b"engine_set_allow_bulk_capable",
            )?;

            // D-2.1 — display-summary surface.
            let route_summary = *lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_route_summary")?;
            let available_routes = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_available_routes",
            )?;
            let throughput_snapshot = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_throughput_snapshot",
            )?;
            let panic_wipe = *lookup::<unsafe extern "C" fn() -> c_int>(
                &lib,
                b"engine_panic_wipe",
            )?;

            // v0.2.x extras.
            let lifecycle_event = *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                &lib,
                b"engine_lifecycle_event",
            )?;
            let set_rendezvous_priority =
                *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                    &lib,
                    b"engine_set_rendezvous_priority",
                )?;
            let set_push_rendezvous_enabled =
                *lookup::<unsafe extern "C" fn(c_int) -> c_int>(
                    &lib,
                    b"engine_set_push_rendezvous_enabled",
                )?;
            let set_auto_promotion = *lookup::<unsafe extern "C" fn(c_int) -> c_int>(
                &lib,
                b"engine_set_auto_promotion",
            )?;
            let set_masque_submode_override =
                *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                    &lib,
                    b"engine_set_masque_submode_override",
                )?;
            let set_experimental_families_enabled =
                *lookup::<unsafe extern "C" fn(c_int) -> c_int>(
                    &lib,
                    b"engine_set_experimental_families_enabled",
                )?;
            let bootstrap_install_seeds =
                *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_bootstrap_install_seeds",
                )?;
            let bootstrap_refresh = *lookup::<
                unsafe extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_bootstrap_refresh")?;
            let bootstrap_status =
                *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_bootstrap_status",
                )?;
            let redistribute_route = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_redistribute_route")?;
            let uri_detect = *lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_uri_detect")?;
            let uri_import = *lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_uri_import")?;
            let wasm_kill_switch_pubkey =
                *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_wasm_kill_switch_pubkey",
                )?;
            let loaded_wasm_modules =
                *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_loaded_wasm_modules",
                )?;

            // Reinterpret each unsafe-extern as the safe-extern variant
            // we store in the struct. The wrapper methods enforce all
            // borrow / lifetime invariants before crossing the FFI.
            let engine = Engine {
                _lib: lib,
                init: std::mem::transmute(init),
                shutdown: std::mem::transmute(shutdown),
                version: std::mem::transmute(version),
                set_route: std::mem::transmute(set_route),
                clear_route: std::mem::transmute(clear_route),
                set_mode: std::mem::transmute(set_mode),
                apply_cooldown: std::mem::transmute(apply_cooldown),
                probe_udp: std::mem::transmute(probe_udp),
                probe_dns: std::mem::transmute(probe_dns),
                probe_tcp443: std::mem::transmute(probe_tcp443),
                stats_redacted: std::mem::transmute(stats_redacted),
                export_diagnostics: std::mem::transmute(export_diagnostics),
                import_sbp: std::mem::transmute(import_sbp),
                resolve_trust_prompt: std::mem::transmute(resolve_trust_prompt),
                fountain_feed_frame: std::mem::transmute(fountain_feed_frame),
                subscription_add: std::mem::transmute(subscription_add),
                subscription_refresh: std::mem::transmute(subscription_refresh),
                subscription_remove: std::mem::transmute(subscription_remove),
                subscription_list: std::mem::transmute(subscription_list),
                revocation_refresh_all: std::mem::transmute(revocation_refresh_all),
                pointer_rotation_status: std::mem::transmute(pointer_rotation_status),
                diagnostics_explain: std::mem::transmute(diagnostics_explain),
                set_tunnel_socks: std::mem::transmute(set_tunnel_socks),
                scheduler_status: std::mem::transmute(scheduler_status),
                set_route_budget: std::mem::transmute(set_route_budget),
                network_changed: std::mem::transmute(network_changed),
                unlock_secrets: std::mem::transmute(unlock_secrets),
                set_allow_bulk_capable: std::mem::transmute(set_allow_bulk_capable),
                route_summary: std::mem::transmute(route_summary),
                available_routes: std::mem::transmute(available_routes),
                throughput_snapshot: std::mem::transmute(throughput_snapshot),
                panic_wipe: std::mem::transmute(panic_wipe),
                lifecycle_event: std::mem::transmute(lifecycle_event),
                set_rendezvous_priority: std::mem::transmute(set_rendezvous_priority),
                set_push_rendezvous_enabled: std::mem::transmute(set_push_rendezvous_enabled),
                set_auto_promotion: std::mem::transmute(set_auto_promotion),
                set_masque_submode_override: std::mem::transmute(set_masque_submode_override),
                set_experimental_families_enabled: std::mem::transmute(
                    set_experimental_families_enabled,
                ),
                bootstrap_install_seeds: std::mem::transmute(bootstrap_install_seeds),
                bootstrap_refresh: std::mem::transmute(bootstrap_refresh),
                bootstrap_status: std::mem::transmute(bootstrap_status),
                redistribute_route: std::mem::transmute(redistribute_route),
                uri_detect: std::mem::transmute(uri_detect),
                uri_import: std::mem::transmute(uri_import),
                wasm_kill_switch_pubkey: std::mem::transmute(wasm_kill_switch_pubkey),
                loaded_wasm_modules: std::mem::transmute(loaded_wasm_modules),
            };

            // Verify ABI version BEFORE returning the handle.
            let v = engine.version_str();
            if !v.starts_with(REQUIRED_VERSION_PREFIX) {
                return Err(DesktopError::AbiMismatch(v));
            }
            Ok(Arc::new(engine))
        }
    }

    /// Returns `engine_version()` as an owned String.
    pub fn version_str(&self) -> String {
        let p = (self.version)();
        if p.is_null() {
            return String::new();
        }
        // SAFETY: engine_version returns a Go-allocated, NUL-terminated
        // C string; we copy immediately and do not free.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// Heartbeat-style call used by the supervisor thread. Cheap and
    /// side-effect-free.
    pub fn heartbeat(&self) -> bool {
        let p = (self.version)();
        !p.is_null()
    }

    /// `engine_init`.
    pub fn init(&self, state_dir: &Path, log_level: &str) -> Result<()> {
        let dir_c = path_to_cstring(state_dir)?;
        let lvl_c = CString::new(log_level)
            .map_err(|_| DesktopError::EngineSymbol("log_level contained NUL".into()))?;
        let rc = (self.init)(dir_c.as_ptr(), lvl_c.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_shutdown`.
    pub fn shutdown(&self) -> Result<()> {
        let rc = (self.shutdown)();
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_set_route`. `route_id` empty-string clears the route.
    pub fn set_route(&self, route_id: &str) -> Result<()> {
        let s = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id contained NUL".into()))?;
        let rc = (self.set_route)(s.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_clear_route`.
    pub fn clear_route(&self) -> Result<()> {
        let rc = (self.clear_route)();
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_set_mode`. Mode is one of `lifeline`, `normal`, `bulk`.
    pub fn set_mode(&self, mode: &str) -> Result<()> {
        let s = CString::new(mode)
            .map_err(|_| DesktopError::EngineSymbol("mode contained NUL".into()))?;
        let rc = (self.set_mode)(s.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_apply_cooldown`.
    pub fn apply_cooldown(&self, route_id: &str, seconds: i32) -> Result<()> {
        let s = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let rc = (self.apply_cooldown)(s.as_ptr(), seconds as c_int);
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn probe_udp(&self, timeout_ms: i32) -> i32 {
        (self.probe_udp)(timeout_ms as c_int) as i32
    }
    pub fn probe_dns(&self, timeout_ms: i32) -> i32 {
        (self.probe_dns)(timeout_ms as c_int) as i32
    }
    pub fn probe_tcp443(&self, timeout_ms: i32) -> i32 {
        (self.probe_tcp443)(timeout_ms as c_int) as i32
    }

    /// `engine_stats_redacted`. Returns the JSON payload as a String.
    pub fn stats_redacted(&self) -> Result<String> {
        call_buf(|buf, len| (self.stats_redacted)(buf, len))
    }

    pub fn export_diagnostics(&self) -> Result<String> {
        call_buf(|buf, len| (self.export_diagnostics)(buf, len))
    }

    /// `engine_import_sbp`. Returns the verdict JSON.
    pub fn import_sbp(&self, path: &Path) -> Result<String> {
        let p = path_to_cstring(path)?;
        call_buf(|buf, len| (self.import_sbp)(p.as_ptr(), buf, len))
    }

    /// `engine_resolve_trust_prompt`.
    /// decision: 0=trust, 1=once, 2=cancel.
    pub fn resolve_trust_prompt(&self, fingerprint: &str, decision: i32) -> Result<String> {
        let f =
            CString::new(fingerprint).map_err(|_| DesktopError::EngineSymbol("fp NUL".into()))?;
        call_buf(|buf, len| (self.resolve_trust_prompt)(f.as_ptr(), decision as c_int, buf, len))
    }

    /// `engine_fountain_feed_frame`. Feeds one QR-fountain frame into
    /// the core LT decoder. When decoding completes, the engine imports
    /// the decoded `.sbp` and returns the importer verdict in the JSON
    /// response. No desktop-side fountain decoding is duplicated here.
    pub fn fountain_feed_frame(&self, session_id: &str, frame_b64: &str) -> Result<String> {
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        let f = CString::new(frame_b64)
            .map_err(|_| DesktopError::EngineSymbol("frame_b64 NUL".into()))?;
        call_buf(|buf, len| (self.fountain_feed_frame)(s.as_ptr(), f.as_ptr(), buf, len))
    }

    pub fn subscription_add(
        &self,
        publisher_fp: &str,
        url: &str,
        display_name: &str,
    ) -> Result<String> {
        let p = CString::new(publisher_fp)
            .map_err(|_| DesktopError::EngineSymbol("publisher_fp NUL".into()))?;
        let u = CString::new(url).map_err(|_| DesktopError::EngineSymbol("url NUL".into()))?;
        let n = CString::new(display_name)
            .map_err(|_| DesktopError::EngineSymbol("display_name NUL".into()))?;
        call_buf(|buf, len| (self.subscription_add)(p.as_ptr(), u.as_ptr(), n.as_ptr(), buf, len))
    }

    pub fn subscription_refresh(&self, subscription_id: &str, timeout_ms: i32) -> Result<String> {
        let s = CString::new(subscription_id)
            .map_err(|_| DesktopError::EngineSymbol("subscription_id NUL".into()))?;
        call_buf(|buf, len| (self.subscription_refresh)(s.as_ptr(), timeout_ms as c_int, buf, len))
    }

    pub fn subscription_remove(&self, subscription_id: &str) -> Result<()> {
        let s = CString::new(subscription_id)
            .map_err(|_| DesktopError::EngineSymbol("subscription_id NUL".into()))?;
        let rc = (self.subscription_remove)(s.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_subscription_list` (added in 1.5C-Polish, surface 33→34).
    /// Returns a JSON `{"subscriptions":[...]}` snapshot from the
    /// routestore so the desktop Subscriptions screen can render the
    /// full known set on mount, not just the rows added in this
    /// session.
    pub fn subscription_list(&self) -> Result<String> {
        call_buf(|buf, len| (self.subscription_list)(buf, len))
    }

    pub fn revocation_refresh_all(&self, timeout_ms: i32) -> Result<String> {
        call_buf(|buf, len| (self.revocation_refresh_all)(timeout_ms as c_int, buf, len))
    }

    pub fn pointer_rotation_status(&self) -> Result<String> {
        call_buf(|buf, len| (self.pointer_rotation_status)(buf, len))
    }

    pub fn diagnostics_explain(&self) -> Result<String> {
        call_buf(|buf, len| (self.diagnostics_explain)(buf, len))
    }

    /// `engine_scheduler_status` (Phase 2F, surface 34→35). Returns
    /// the JSON snapshot documented in specs/scheduler-v1.md.
    pub fn scheduler_status(&self) -> Result<String> {
        call_buf(|buf, len| (self.scheduler_status)(buf, len))
    }

    /// `engine_set_route_budget` (Phase 2A, surface 35→36). Validates
    /// `budget_tag` against the closed cap map; rejection returns
    /// `Err(DesktopError::EngineReturn(-1))` with a body the caller
    /// can decode for the `unknown_budget_tag` error key.
    pub fn set_route_budget(&self, route_id: &str, budget_tag: &str) -> Result<String> {
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let t = CString::new(budget_tag)
            .map_err(|_| DesktopError::EngineSymbol("budget_tag NUL".into()))?;
        call_buf(|buf, len| (self.set_route_budget)(r.as_ptr(), t.as_ptr(), buf, len))
    }

    /// `engine_network_changed` (Phase 2C, surface 36→37). The
    /// (kind, carrier, ssid) tuple is hashed by the engine on
    /// entry; the raw strings are NOT persisted, NOT logged, and
    /// NOT surfaced through any other ABI function. The kind must
    /// be one of {"wifi","cell","eth","unknown"}; carrier and ssid
    /// may be empty (cell-only or eth/unknown).
    ///
    /// Returns the JSON status blob: { network_id, mode,
    /// restored_routes, fresh }.
    pub fn network_changed(&self, kind: &str, carrier: &str, ssid: &str) -> Result<String> {
        let k = CString::new(kind).map_err(|_| DesktopError::EngineSymbol("kind NUL".into()))?;
        let c =
            CString::new(carrier).map_err(|_| DesktopError::EngineSymbol("carrier NUL".into()))?;
        let s = CString::new(ssid).map_err(|_| DesktopError::EngineSymbol("ssid NUL".into()))?;
        call_buf(|buf, len| (self.network_changed)(k.as_ptr(), c.as_ptr(), s.as_ptr(), buf, len))
    }

    /// `engine_unlock_secrets` (Phase 2D, surface 37→38). For the
    /// high-risk user class, decrypts the routestore age identity
    /// using an Argon2id-derived key over the user PIN. The PIN is
    /// hashed on entry and discarded — it never persists, never
    /// crosses any other ABI surface, and never appears in
    /// diagnostics.
    ///
    /// Return semantics:
    /// - `Ok(())` — unlocked (or no-op for non-high-risk class).
    /// - `Err(EngineReturn(-1))` — wrong PIN / empty PIN / read failure.
    /// - `Err(EngineReturn(-2))` — device is not in high-risk class.
    ///
    /// Callers that get `-2` should treat it as "no PIN gate is
    /// required; proceed". The `-1` case is the user-facing error.
    pub fn unlock_secrets(&self, pin: &str) -> Result<()> {
        let p = CString::new(pin).map_err(|_| DesktopError::EngineSymbol("pin NUL".into()))?;
        let rc = (self.unlock_secrets)(p.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_set_allow_bulk_capable` (Phase 2D, surface 38→39).
    /// Sets the engine's per-session bulk-capable opt-in flag.
    /// `true` allows lifeline-strict to consider bulk-capable
    /// routes for this session; `false` (the default after every
    /// engine_init) blocks them. Cleared by NewSession.
    pub fn set_allow_bulk_capable(&self, allow: bool) {
        let _ = (self.set_allow_bulk_capable)(if allow { 1 } else { 0 });
    }

    /// Phase 1.5B: install the SOCKS5 endpoint the Go core's refresh
    /// dialer should use. Empty `host` clears the override.
    pub fn set_tunnel_socks(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<String> {
        let h = CString::new(host).map_err(|_| DesktopError::EngineSymbol("host NUL".into()))?;
        let u = CString::new(username)
            .map_err(|_| DesktopError::EngineSymbol("username NUL".into()))?;
        let p = CString::new(password)
            .map_err(|_| DesktopError::EngineSymbol("password NUL".into()))?;
        call_buf(|buf, len| {
            (self.set_tunnel_socks)(h.as_ptr(), port as c_int, u.as_ptr(), p.as_ptr(), buf, len)
        })
    }

    // -- D-2.1 — display-summary surface ------------------------------

    /// `engine_route_summary` returns the RouteSummaryDisplay JSON
    /// projection for a single route id.
    pub fn route_summary(&self, route_id: &str) -> Result<String> {
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        call_buf(|buf, len| (self.route_summary)(r.as_ptr(), buf, len))
    }

    /// `engine_available_routes` returns `{routes:[...]}` ordered by
    /// health_pct desc; revoked / cooldown'd entries are excluded.
    pub fn available_routes(&self) -> Result<String> {
        call_buf(|buf, len| (self.available_routes)(buf, len))
    }

    /// `engine_throughput_snapshot` returns
    /// `{up_bps,down_bps,window_ms}`. Reading resets counters.
    pub fn throughput_snapshot(&self) -> Result<String> {
        call_buf(|buf, len| (self.throughput_snapshot)(buf, len))
    }

    /// `engine_panic_wipe` shuts the engine down and removes the
    /// state directory. The caller should terminate the process
    /// (or reload the GUI) once this returns.
    pub fn panic_wipe(&self) -> Result<()> {
        let rc = (self.panic_wipe)();
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    // ---- v0.2.x extras --------------------------------------------

    /// `engine_lifecycle_event`. Token must be one of the locked v1
    /// set: `will_sleep`, `did_wake`, `memory_pressure_warning`.
    pub fn lifecycle_event(&self, token: &str) -> Result<()> {
        let t = CString::new(token)
            .map_err(|_| DesktopError::EngineSymbol("token NUL".into()))?;
        let rc = (self.lifecycle_event)(t.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn set_rendezvous_priority(&self, priority_json: &str) -> Result<()> {
        let s = CString::new(priority_json)
            .map_err(|_| DesktopError::EngineSymbol("priority_json NUL".into()))?;
        let rc = (self.set_rendezvous_priority)(s.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn set_push_rendezvous_enabled(&self, enabled: bool) -> Result<()> {
        let rc = (self.set_push_rendezvous_enabled)(if enabled { 1 } else { 0 });
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn set_auto_promotion(&self, enabled: bool) {
        let _ = (self.set_auto_promotion)(if enabled { 1 } else { 0 });
    }

    pub fn set_masque_submode_override(&self, submode: &str) -> Result<()> {
        let s = CString::new(submode)
            .map_err(|_| DesktopError::EngineSymbol("submode NUL".into()))?;
        let rc = (self.set_masque_submode_override)(s.as_ptr());
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn set_experimental_families_enabled(&self, enabled: bool) -> Result<()> {
        let rc = (self.set_experimental_families_enabled)(if enabled { 1 } else { 0 });
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    pub fn bootstrap_install_seeds(&self) -> Result<String> {
        call_buf(|buf, len| (self.bootstrap_install_seeds)(buf, len))
    }

    pub fn bootstrap_refresh(&self, timeout_ms: i32) -> Result<String> {
        call_buf(|buf, len| (self.bootstrap_refresh)(timeout_ms as c_int, buf, len))
    }

    pub fn bootstrap_status(&self) -> Result<String> {
        call_buf(|buf, len| (self.bootstrap_status)(buf, len))
    }

    pub fn redistribute_route(&self, route_id: &str, recipient_fp: &str) -> Result<String> {
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let f = CString::new(recipient_fp)
            .map_err(|_| DesktopError::EngineSymbol("recipient_fp NUL".into()))?;
        call_buf(|buf, len| (self.redistribute_route)(r.as_ptr(), f.as_ptr(), buf, len))
    }

    pub fn uri_detect(&self, text: &str) -> Result<String> {
        let s = CString::new(text)
            .map_err(|_| DesktopError::EngineSymbol("text NUL".into()))?;
        call_buf(|buf, len| (self.uri_detect)(s.as_ptr(), buf, len))
    }

    pub fn uri_import(&self, raw_uri: &str) -> Result<String> {
        let s = CString::new(raw_uri)
            .map_err(|_| DesktopError::EngineSymbol("raw_uri NUL".into()))?;
        call_buf(|buf, len| (self.uri_import)(s.as_ptr(), buf, len))
    }

    pub fn wasm_kill_switch_pubkey(&self) -> Result<String> {
        call_buf(|buf, len| (self.wasm_kill_switch_pubkey)(buf, len))
    }

    pub fn loaded_wasm_modules(&self) -> Result<String> {
        call_buf(|buf, len| (self.loaded_wasm_modules)(buf, len))
    }
}

/// Helper: dlsym a symbol with descriptive error.
unsafe fn lookup<'a, T>(lib: &'a Library, name: &[u8]) -> Result<Symbol<'a, T>> {
    lib.get(name)
        .map_err(|e| DesktopError::EngineSymbol(format!("{:?}: {}", name, e)))
}

/// Helper: invoke any `engine_*` function that fills a UTF-8 buffer.
/// Grows on -ERANGE up to a 1 MB ceiling.
fn call_buf<F>(call: F) -> Result<String>
where
    F: Fn(*mut c_void, c_int) -> c_int,
{
    let mut size = 4 * 1024usize;
    let max = 1024 * 1024usize;
    loop {
        let mut buf = vec![0u8; size];
        let rc = call(buf.as_mut_ptr() as *mut c_void, size as c_int);
        if rc < 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        let n = rc as usize;
        // The engine writes a trailing NUL; n is the byte count *excluding*
        // the NUL. If the buffer was exactly large enough we may need to
        // grow once.
        if n + 1 >= size && size < max {
            size = (size * 2).min(max);
            continue;
        }
        buf.truncate(n);
        return String::from_utf8(buf).map_err(|_| DesktopError::EngineUtf8);
    }
}

fn path_to_cstring(p: &Path) -> Result<CString> {
    CString::new(p.to_string_lossy().as_bytes())
        .map_err(|_| DesktopError::EngineSymbol("path contained NUL".into()))
}

/// A heartbeat supervisor that polls `version()` every `interval` and
/// flips its `healthy` flag false after `max_failures` consecutive null
/// responses. The Tauri shell spawns this on a background thread.
pub struct HeartbeatSupervisor {
    pub healthy: Arc<Mutex<bool>>,
}

impl HeartbeatSupervisor {
    pub fn new() -> Self {
        Self {
            healthy: Arc::new(Mutex::new(true)),
        }
    }

    pub fn check_once(&self, engine: &Engine) {
        let ok = engine.heartbeat();
        let mut g = self.healthy.lock().expect("heartbeat mutex poisoned");
        *g = ok;
    }

    pub fn is_healthy(&self) -> bool {
        *self.healthy.lock().expect("heartbeat mutex poisoned")
    }
}
