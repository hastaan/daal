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
use std::sync::atomic::{AtomicBool, Ordering};
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

    /// True from a successful `engine_init` until `engine_shutdown`.
    /// Every wrapper below except `version_str` / `heartbeat` /
    /// `init` / `shutdown` refuses to cross the FFI while this is
    /// false: an engine_* export called without a Core does not return
    /// an error, it PANICS inside the Go runtime (`abi.mustCore`), and
    /// a Go panic in a c-shared library takes the whole process with
    /// it. That turned "the engine could not start" into "the app
    /// cannot be opened". See `ensure_ready`.
    ready: AtomicBool,
    /// Why the engine is not ready, in the host's own words; `None`
    /// while it is ready or before `init` was ever called.
    start_error: Mutex<Option<String>>,

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
    route_delete: extern "C" fn(*const c_char) -> c_int,
    publisher_delete: extern "C" fn(*const c_char) -> c_int,
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

    // Wave 2 — restore scheduled refresh on in-process-sing-box hosts.
    // Takes no endpoint and no credential: both belong to the engine's
    // own loopback SOCKS inlet (core/engine/inlet.go), and handing the
    // credential to the host would put a live proxy password in the
    // JVM heap for nothing.
    set_tunnel_refresh: extern "C" fn(c_int, *mut c_void, c_int) -> c_int,

    // Phase 2F — In-engine scheduler (1 added function, surface 34→35).
    scheduler_status: extern "C" fn(*mut c_void, c_int) -> c_int,

    // Gap 4-recipient — host-driven scheduler tick. Required so the
    // per-row ProfileUpdateMin cadence in scheduler.Plan actually
    // fires; the Tauri shell calls this on a 60 s timer.
    scheduler_tick: extern "C" fn() -> c_int,

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

    // Wave 4 Step 11 — LAN / offline-share transport (Phase 1C exports
    // that had never been dlsym'd). The desktop build is the second
    // peer: it can be the SENDER (share_begin publishes a per-session
    // self-signed cert + its SPKI pin and binds private addresses only)
    // or the RECEIVER (share_pull / share_pull_url).
    //
    // `share_browse` is deliberately absent: core/abi/share.go's
    // ShareBrowse is a hardcoded empty-list stub with no Go-side mDNS
    // browser behind it, so resolving it here would manufacture a
    // "search the network" capability that can only ever find nothing.
    share_begin: extern "C" fn(*const c_char, c_int, *const c_char, *mut c_void, c_int) -> c_int,
    share_end: extern "C" fn(*const c_char) -> c_int,
    share_pull: extern "C" fn(
        *const c_char,
        c_int,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut c_void,
        c_int,
    ) -> c_int,
    share_pull_url:
        extern "C" fn(*const c_char, *const c_char, *const c_char, *mut c_void, c_int) -> c_int,
    fountain_next_frame: extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,

    // Phase 45 — TUN-fd handoff + protect() callback (release surface
    // 53 → 56). Takes ownership of fd on success; the caller must
    // NOT close(fd) after a successful set call.
    set_tun_fd: extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
    clear_tun_fd: extern "C" fn(*mut c_void, c_int) -> c_int,
    register_protect_callback: extern "C" fn(usize, *mut c_void, c_int) -> c_int,

    /// `engine_route_precheck` — would `engine_set_route` be refused?
    /// Optional on purpose: it is newer than every other symbol here,
    /// and a library without it must still load (the host then simply
    /// attempts the route and reads the refusal afterwards).
    route_precheck: Option<extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int>,
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
            let route_delete = *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                &lib,
                b"engine_route_delete",
            )?;
            let publisher_delete = *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(
                &lib,
                b"engine_publisher_delete",
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
            let set_tunnel_refresh = *lookup::<
                unsafe extern "C" fn(c_int, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_set_tunnel_refresh")?;
            let scheduler_status = *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                &lib,
                b"engine_scheduler_status",
            )?;
            let scheduler_tick = *lookup::<unsafe extern "C" fn() -> c_int>(
                &lib,
                b"engine_scheduler_tick",
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

            // Wave 4 Step 11 — LAN / offline share.
            let share_begin = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    c_int,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_share_begin")?;
            let share_end =
                *lookup::<unsafe extern "C" fn(*const c_char) -> c_int>(&lib, b"engine_share_end")?;
            let share_pull = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    c_int,
                    *const c_char,
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_share_pull")?;
            let share_pull_url = *lookup::<
                unsafe extern "C" fn(
                    *const c_char,
                    *const c_char,
                    *const c_char,
                    *mut c_void,
                    c_int,
                ) -> c_int,
            >(&lib, b"engine_share_pull_url")?;
            let fountain_next_frame = *lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_fountain_next_frame")?;

            // Phase 45 — TUN-fd + protect callback.
            let set_tun_fd =
                *lookup::<unsafe extern "C" fn(c_int, *mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_set_tun_fd",
                )?;
            let clear_tun_fd =
                *lookup::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_clear_tun_fd",
                )?;
            let register_protect_callback =
                *lookup::<unsafe extern "C" fn(usize, *mut c_void, c_int) -> c_int>(
                    &lib,
                    b"engine_register_protect_callback",
                )?;

            let route_precheck = lookup::<
                unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int,
            >(&lib, b"engine_route_precheck")
            .ok()
            .map(|sym| *sym);

            // Reinterpret each unsafe-extern as the safe-extern variant
            // we store in the struct. The wrapper methods enforce all
            // borrow / lifetime invariants before crossing the FFI.
            let engine = Engine {
                _lib: lib,
                ready: AtomicBool::new(false),
                start_error: Mutex::new(None),
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
                route_delete: std::mem::transmute(route_delete),
                publisher_delete: std::mem::transmute(publisher_delete),
                subscription_list: std::mem::transmute(subscription_list),
                revocation_refresh_all: std::mem::transmute(revocation_refresh_all),
                pointer_rotation_status: std::mem::transmute(pointer_rotation_status),
                diagnostics_explain: std::mem::transmute(diagnostics_explain),
                set_tunnel_socks: std::mem::transmute(set_tunnel_socks),
                set_tunnel_refresh: std::mem::transmute(set_tunnel_refresh),
                scheduler_status: std::mem::transmute(scheduler_status),
                scheduler_tick: std::mem::transmute(scheduler_tick),
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
                share_begin: std::mem::transmute(share_begin),
                share_end: std::mem::transmute(share_end),
                share_pull: std::mem::transmute(share_pull),
                share_pull_url: std::mem::transmute(share_pull_url),
                fountain_next_frame: std::mem::transmute(fountain_next_frame),
                set_tun_fd: std::mem::transmute(set_tun_fd),
                clear_tun_fd: std::mem::transmute(clear_tun_fd),
                register_protect_callback: std::mem::transmute(register_protect_callback),
                route_precheck: route_precheck.map(|f| std::mem::transmute(f)),
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

    /// Liveness probe used by `HeartbeatSupervisor::check_once`, which
    /// the GUI pulls on a timer (there is no supervisor thread). Cheap
    /// and side-effect-free: it asks the library for its version string
    /// and reports only whether the call came back. A `true` here says
    /// the library answered, NOT that traffic is flowing.
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
            // engine_init reports nothing but -1, and the diagnostics
            // export that could say more needs the Core that was not
            // made. The state directory is the one thing known to be
            // involved; its path holds no secret.
            let why = format!(
                "engine_init returned {rc} for state directory {}",
                state_dir.display()
            );
            self.ready.store(false, Ordering::SeqCst);
            *self.start_error.lock().unwrap_or_else(|p| p.into_inner()) = Some(why);
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        *self.start_error.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// True between a successful `init` and `shutdown`.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Why the engine is not usable, or `None` when it is. Stable
    /// enough to show in a details area; never contains a credential.
    pub fn unavailable_reason(&self) -> Option<String> {
        if self.is_ready() {
            return None;
        }
        Some(
            self.start_error
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
                .unwrap_or_else(|| "the engine has not been started".to_string()),
        )
    }

    /// The gate in front of every engine_* call that needs a Core.
    /// Returns `DesktopError::EngineUnavailable` instead of letting the
    /// call reach `abi.mustCore`, which would abort the process.
    fn ensure_ready(&self) -> Result<()> {
        match self.unavailable_reason() {
            None => Ok(()),
            Some(why) => Err(DesktopError::EngineUnavailable(why)),
        }
    }

    /// Builds the error for an engine_* call that returned `rc` (< 0,
    /// or non-zero for the status-only calls).
    ///
    /// The C ABI has no last-error accessor: an export hands back -1
    /// and the Go `error` is dropped at the boundary. What the engine
    /// does keep is a short `recent_errors` list in its diagnostics
    /// export (core/abi/export_errors.go: `{time, call, text, count}`,
    /// already scrubbed of addresses and credentials on the Go side),
    /// so on a failure that list is read once and the newest entry FOR
    /// THIS CALL travels with the return code. When the list is missing
    /// (an older engine), has nothing recent for this call, or cannot
    /// be read, the result is the bare `EngineReturn(rc)` it always
    /// was — never another call's error, never a guess.
    fn failed(&self, call: &str, rc: i32) -> DesktopError {
        if !self.is_ready() {
            return DesktopError::EngineReturn(rc);
        }
        // The free `call_buf`, not `self.call_buf`: a diagnostics export
        // that itself fails must not ask the diagnostics export why.
        let blob = match call_buf(|buf, len| (self.export_diagnostics)(buf, len)) {
            Ok(b) => b,
            Err(_) => return DesktopError::EngineReturn(rc),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        match newest_engine_error(&blob, call, now) {
            Some(detail) => DesktopError::EngineFailed { code: rc, detail },
            None => DesktopError::EngineReturn(rc),
        }
    }

    /// `call_buf` for the wrappers below: the same call, with the
    /// engine's own words attached when it fails (see `failed`).
    fn call_buf<F>(&self, name: &str, call: F) -> Result<String>
    where
        F: Fn(*mut c_void, c_int) -> c_int,
    {
        call_buf(call).map_err(|e| match e {
            DesktopError::EngineReturn(rc) => self.failed(name, rc),
            other => other,
        })
    }

    /// `engine_shutdown`.
    pub fn shutdown(&self) -> Result<()> {
        // Not ready from here on, whatever shutdown returns: the Core
        // is gone (or going), and a call that slipped in behind this
        // one would find none.
        self.ready.store(false, Ordering::SeqCst);
        let rc = (self.shutdown)();
        if rc != 0 {
            return Err(DesktopError::EngineReturn(rc as i32));
        }
        Ok(())
    }

    /// `engine_set_route`. `route_id` empty-string clears the route.
    pub fn set_route(&self, route_id: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id contained NUL".into()))?;
        let rc = (self.set_route)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_set_route", rc as i32));
        }
        Ok(())
    }

    /// `engine_clear_route`.
    pub fn clear_route(&self) -> Result<()> {
        self.ensure_ready()?;
        let rc = (self.clear_route)();
        if rc != 0 {
            return Err(self.failed("engine_clear_route", rc as i32));
        }
        Ok(())
    }

    /// `engine_set_mode`. Mode is one of `lifeline`, `normal`, `bulk`.
    pub fn set_mode(&self, mode: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(mode)
            .map_err(|_| DesktopError::EngineSymbol("mode contained NUL".into()))?;
        let rc = (self.set_mode)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_set_mode", rc as i32));
        }
        Ok(())
    }

    /// `engine_apply_cooldown`.
    pub fn apply_cooldown(&self, route_id: &str, seconds: i32) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let rc = (self.apply_cooldown)(s.as_ptr(), seconds as c_int);
        if rc != 0 {
            return Err(self.failed("engine_apply_cooldown", rc as i32));
        }
        Ok(())
    }

    pub fn probe_udp(&self, timeout_ms: i32) -> i32 {
        if !self.is_ready() {
            return -1;
        }
        (self.probe_udp)(timeout_ms as c_int) as i32
    }
    pub fn probe_dns(&self, timeout_ms: i32) -> i32 {
        if !self.is_ready() {
            return -1;
        }
        (self.probe_dns)(timeout_ms as c_int) as i32
    }
    pub fn probe_tcp443(&self, timeout_ms: i32) -> i32 {
        if !self.is_ready() {
            return -1;
        }
        (self.probe_tcp443)(timeout_ms as c_int) as i32
    }

    /// `engine_stats_redacted`. Returns the JSON payload as a String.
    pub fn stats_redacted(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_stats_redacted", |buf, len| (self.stats_redacted)(buf, len))
    }

    pub fn export_diagnostics(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_export_diagnostics", |buf, len| (self.export_diagnostics)(buf, len))
    }

    /// `engine_import_sbp`. Returns the verdict JSON.
    pub fn import_sbp(&self, path: &Path) -> Result<String> {
        self.ensure_ready()?;
        let p = path_to_cstring(path)?;
        self.call_buf("engine_import_sbp", |buf, len| (self.import_sbp)(p.as_ptr(), buf, len))
    }

    /// `engine_resolve_trust_prompt`.
    /// decision: 0=trust, 1=once, 2=cancel.
    pub fn resolve_trust_prompt(&self, fingerprint: &str, decision: i32) -> Result<String> {
        self.ensure_ready()?;
        let f =
            CString::new(fingerprint).map_err(|_| DesktopError::EngineSymbol("fp NUL".into()))?;
        self.call_buf("engine_resolve_trust_prompt", |buf, len| (self.resolve_trust_prompt)(f.as_ptr(), decision as c_int, buf, len))
    }

    /// `engine_fountain_feed_frame`. Feeds one QR-fountain frame into
    /// the core LT decoder. When decoding completes, the engine imports
    /// the decoded `.sbp` and returns the importer verdict in the JSON
    /// response. No desktop-side fountain decoding is duplicated here.
    pub fn fountain_feed_frame(&self, session_id: &str, frame_b64: &str) -> Result<String> {
        self.ensure_ready()?;
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        let f = CString::new(frame_b64)
            .map_err(|_| DesktopError::EngineSymbol("frame_b64 NUL".into()))?;
        self.call_buf("engine_fountain_feed_frame", |buf, len| (self.fountain_feed_frame)(s.as_ptr(), f.as_ptr(), buf, len))
    }

    /// `engine_share_begin`. Builds a signed `.sbp` from the named
    /// on-device routes and, when `include_lan` is set, starts the LAN
    /// transport: an HTTPS listener bound to private addresses only, a
    /// fresh per-session self-signed cert, and a 6-digit PIN.
    ///
    /// The returned JSON carries `lan_spki` (base64url SHA-256 of the
    /// cert's SubjectPublicKeyInfo) and `lan_uris` (`daalshare://lan?...`
    /// strings that already embed that pin). Whichever of those the UI
    /// shows the friend, the receiver ends up with the pin — which is
    /// mandatory on the other side, so a UI that drops it produces a
    /// receiver that refuses to connect rather than one that connects
    /// insecurely.
    pub fn share_begin(
        &self,
        route_ids_csv: &str,
        include_lan: bool,
        static_qr_uri: &str,
    ) -> Result<String> {
        self.ensure_ready()?;
        let ids = CString::new(route_ids_csv)
            .map_err(|_| DesktopError::EngineSymbol("route_ids NUL".into()))?;
        let qr = CString::new(static_qr_uri)
            .map_err(|_| DesktopError::EngineSymbol("static_qr_uri NUL".into()))?;
        let lan = if include_lan { 1 } else { 0 };
        self.call_buf("engine_share_begin", |buf, len| (self.share_begin)(ids.as_ptr(), lan as c_int, qr.as_ptr(), buf, len))
    }

    /// `engine_share_end`. Stops the mDNS advertisement, closes every
    /// listener opened for the session, and zeroes the bundle bytes, the
    /// PIN and the bearer token in the engine's memory.
    pub fn share_end(&self, session_id: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        let rc = (self.share_end)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_share_end", rc as i32));
        }
        Ok(())
    }

    /// `engine_share_pull` — the mDNS path. `expected_spki` is the
    /// `spki=` field of the sender's TXT record and is REQUIRED: the
    /// engine refuses the TLS handshake when it is empty or does not
    /// match the presented certificate, so there is no "connect anyway"
    /// spelling of this call to reach by accident.
    pub fn share_pull(
        &self,
        host: &str,
        port: i32,
        pin: &str,
        session_id: &str,
        expected_spki: &str,
    ) -> Result<String> {
        self.ensure_ready()?;
        let h = CString::new(host).map_err(|_| DesktopError::EngineSymbol("host NUL".into()))?;
        let p = CString::new(pin).map_err(|_| DesktopError::EngineSymbol("pin NUL".into()))?;
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        let k = CString::new(expected_spki)
            .map_err(|_| DesktopError::EngineSymbol("expected_spki NUL".into()))?;
        self.call_buf("engine_share_pull", |buf, len| {
            (self.share_pull)(
                h.as_ptr(),
                port as c_int,
                p.as_ptr(),
                s.as_ptr(),
                k.as_ptr(),
                buf,
                len,
            )
        })
    }

    /// `engine_share_pull_url` — the QR / paste fallback for networks
    /// that filter mDNS. `share_uri` is either
    /// `daalshare://lan?u=..&p=..&s=..` or a bare
    /// `https://<private-ip>:<port>/bundle.sbp#spki=..`; the SPKI pin
    /// rides inside the URI, so this path is pinned by construction.
    pub fn share_pull_url(&self, share_uri: &str, pin: &str, session_id: &str) -> Result<String> {
        self.ensure_ready()?;
        let u = CString::new(share_uri)
            .map_err(|_| DesktopError::EngineSymbol("share_uri NUL".into()))?;
        let p = CString::new(pin).map_err(|_| DesktopError::EngineSymbol("pin NUL".into()))?;
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        self.call_buf("engine_share_pull_url", |buf, len| (self.share_pull_url)(u.as_ptr(), p.as_ptr(), s.as_ptr(), buf, len))
    }

    /// `engine_fountain_next_frame`. Pulls the next LT-fountain frame for
    /// a session opened by `share_begin`; the caller renders it as a QR.
    /// The counterpart `fountain_feed_frame` was already wired, so this
    /// completes the pair and lets a desktop screen be the sender for a
    /// phone camera.
    pub fn fountain_next_frame(&self, session_id: &str) -> Result<String> {
        self.ensure_ready()?;
        let s = CString::new(session_id)
            .map_err(|_| DesktopError::EngineSymbol("session_id NUL".into()))?;
        self.call_buf("engine_fountain_next_frame", |buf, len| (self.fountain_next_frame)(s.as_ptr(), buf, len))
    }

    pub fn subscription_add(
        &self,
        publisher_fp: &str,
        url: &str,
        display_name: &str,
    ) -> Result<String> {
        self.ensure_ready()?;
        let p = CString::new(publisher_fp)
            .map_err(|_| DesktopError::EngineSymbol("publisher_fp NUL".into()))?;
        let u = CString::new(url).map_err(|_| DesktopError::EngineSymbol("url NUL".into()))?;
        let n = CString::new(display_name)
            .map_err(|_| DesktopError::EngineSymbol("display_name NUL".into()))?;
        self.call_buf("engine_subscription_add", |buf, len| (self.subscription_add)(p.as_ptr(), u.as_ptr(), n.as_ptr(), buf, len))
    }

    pub fn subscription_refresh(&self, subscription_id: &str, timeout_ms: i32) -> Result<String> {
        self.ensure_ready()?;
        let s = CString::new(subscription_id)
            .map_err(|_| DesktopError::EngineSymbol("subscription_id NUL".into()))?;
        self.call_buf("engine_subscription_refresh", |buf, len| (self.subscription_refresh)(s.as_ptr(), timeout_ms as c_int, buf, len))
    }

    /// Hard-delete one imported route (engine_route_delete).
    pub fn route_delete(&self, route_id: &str) -> Result<()> {
        self.ensure_ready()?;
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let rc = (self.route_delete)(r.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_route_delete", rc as i32));
        }
        Ok(())
    }

    /// Hard-delete a publisher and all its routes (engine_publisher_delete).
    /// Returns the number of routes removed.
    pub fn publisher_delete(&self, publisher_id: &str) -> Result<i32> {
        self.ensure_ready()?;
        let p = CString::new(publisher_id)
            .map_err(|_| DesktopError::EngineSymbol("publisher_id NUL".into()))?;
        let rc = (self.publisher_delete)(p.as_ptr());
        if rc < 0 {
            return Err(self.failed("engine_publisher_delete", rc as i32));
        }
        Ok(rc as i32)
    }

    pub fn subscription_remove(&self, subscription_id: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(subscription_id)
            .map_err(|_| DesktopError::EngineSymbol("subscription_id NUL".into()))?;
        let rc = (self.subscription_remove)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_subscription_remove", rc as i32));
        }
        Ok(())
    }

    /// `engine_subscription_list` (added in 1.5C-Polish, surface 33→34).
    /// Returns a JSON `{"subscriptions":[...]}` snapshot from the
    /// routestore so the desktop Subscriptions screen can render the
    /// full known set on mount, not just the rows added in this
    /// session.
    pub fn subscription_list(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_subscription_list", |buf, len| (self.subscription_list)(buf, len))
    }

    pub fn revocation_refresh_all(&self, timeout_ms: i32) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_revocation_refresh_all", |buf, len| (self.revocation_refresh_all)(timeout_ms as c_int, buf, len))
    }

    pub fn pointer_rotation_status(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_pointer_rotation_status", |buf, len| (self.pointer_rotation_status)(buf, len))
    }

    pub fn diagnostics_explain(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_diagnostics_explain", |buf, len| (self.diagnostics_explain)(buf, len))
    }

    /// `engine_scheduler_status` (Phase 2F, surface 34→35). Returns
    /// the JSON snapshot documented in specs/scheduler-v1.md.
    pub fn scheduler_status(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_scheduler_status", |buf, len| (self.scheduler_status)(buf, len))
    }

    /// `engine_scheduler_tick` (Gap 4-recipient). Drives one
    /// scheduler tick. The Tauri shell calls this on a ~60 s timer
    /// while the GUI is running so per-row subscription cadence
    /// actually fires. Returns Ok(()) on success; -1 from the
    /// engine surfaces as `DesktopError::EngineReturn`.
    pub fn scheduler_tick(&self) -> Result<()> {
        self.ensure_ready()?;
        let rc = (self.scheduler_tick)();
        if rc != 0 {
            return Err(self.failed("engine_scheduler_tick", rc as i32));
        }
        Ok(())
    }

    /// `engine_set_route_budget` (Phase 2A, surface 35→36). Validates
    /// `budget_tag` against the closed cap map; rejection returns
    /// `Err(DesktopError::EngineReturn(-1))` with a body the caller
    /// can decode for the `unknown_budget_tag` error key.
    pub fn set_route_budget(&self, route_id: &str, budget_tag: &str) -> Result<String> {
        self.ensure_ready()?;
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let t = CString::new(budget_tag)
            .map_err(|_| DesktopError::EngineSymbol("budget_tag NUL".into()))?;
        self.call_buf("engine_set_route_budget", |buf, len| (self.set_route_budget)(r.as_ptr(), t.as_ptr(), buf, len))
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
        self.ensure_ready()?;
        let k = CString::new(kind).map_err(|_| DesktopError::EngineSymbol("kind NUL".into()))?;
        let c =
            CString::new(carrier).map_err(|_| DesktopError::EngineSymbol("carrier NUL".into()))?;
        let s = CString::new(ssid).map_err(|_| DesktopError::EngineSymbol("ssid NUL".into()))?;
        self.call_buf("engine_network_changed", |buf, len| (self.network_changed)(k.as_ptr(), c.as_ptr(), s.as_ptr(), buf, len))
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
        self.ensure_ready()?;
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
        if !self.is_ready() {
            return;
        }
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
        self.ensure_ready()?;
        let h = CString::new(host).map_err(|_| DesktopError::EngineSymbol("host NUL".into()))?;
        let u = CString::new(username)
            .map_err(|_| DesktopError::EngineSymbol("username NUL".into()))?;
        let p = CString::new(password)
            .map_err(|_| DesktopError::EngineSymbol("password NUL".into()))?;
        self.call_buf("engine_set_tunnel_socks", |buf, len| {
            (self.set_tunnel_socks)(h.as_ptr(), port as c_int, u.as_ptr(), p.as_ptr(), buf, len)
        })
    }

    /// `engine_set_tunnel_refresh` — point the Go core's refresh dialer
    /// at the engine's OWN in-process loopback SOCKS inlet, or clear it.
    ///
    /// This is the Android shape of `set_tunnel_socks`. There is no
    /// sidecar on Android: sing-box runs inside libdaalcore, so the
    /// inlet's port and credential are engine-side state and the host
    /// only says on/off. Must be called after `set_route` has succeeded
    /// — the engine only publishes the inlet once the instance is up and
    /// its inbounds are bound — and cleared before `clear_route`.
    ///
    /// `Err(EngineReturn(-1))` means "no live inlet"; refresh then stays
    /// fail-closed rather than dialling from the device's real address.
    pub fn set_tunnel_refresh(&self, enabled: bool) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_set_tunnel_refresh", |buf, len| {
            (self.set_tunnel_refresh)(if enabled { 1 } else { 0 }, buf, len)
        })
    }

    // -- D-2.1 — display-summary surface ------------------------------

    /// `engine_route_summary` returns the RouteSummaryDisplay JSON
    /// projection for a single route id.
    pub fn route_summary(&self, route_id: &str) -> Result<String> {
        self.ensure_ready()?;
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        self.call_buf("engine_route_summary", |buf, len| (self.route_summary)(r.as_ptr(), buf, len))
    }

    /// `engine_available_routes` returns `{routes:[...]}` ordered by
    /// health_pct desc; revoked / cooldown'd entries are excluded.
    pub fn available_routes(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_available_routes", |buf, len| (self.available_routes)(buf, len))
    }

    /// `engine_throughput_snapshot` returns
    /// `{up_bps,down_bps,window_ms}`. Reading resets counters.
    pub fn throughput_snapshot(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_throughput_snapshot", |buf, len| (self.throughput_snapshot)(buf, len))
    }

    /// `engine_panic_wipe` shuts the engine down and removes the
    /// state directory. The caller should terminate the process
    /// (or reload the GUI) once this returns.
    pub fn panic_wipe(&self) -> Result<()> {
        self.ensure_ready()?;
        let rc = (self.panic_wipe)();
        if rc != 0 {
            return Err(self.failed("engine_panic_wipe", rc as i32));
        }
        Ok(())
    }

    // ---- v0.2.x extras --------------------------------------------

    /// `engine_lifecycle_event`. Token must be one of the locked v1
    /// set: `will_sleep`, `did_wake`, `memory_pressure_warning`.
    pub fn lifecycle_event(&self, token: &str) -> Result<()> {
        self.ensure_ready()?;
        let t = CString::new(token)
            .map_err(|_| DesktopError::EngineSymbol("token NUL".into()))?;
        let rc = (self.lifecycle_event)(t.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_lifecycle_event", rc as i32));
        }
        Ok(())
    }

    pub fn set_rendezvous_priority(&self, priority_json: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(priority_json)
            .map_err(|_| DesktopError::EngineSymbol("priority_json NUL".into()))?;
        let rc = (self.set_rendezvous_priority)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_set_rendezvous_priority", rc as i32));
        }
        Ok(())
    }

    pub fn set_push_rendezvous_enabled(&self, enabled: bool) -> Result<()> {
        self.ensure_ready()?;
        let rc = (self.set_push_rendezvous_enabled)(if enabled { 1 } else { 0 });
        if rc != 0 {
            return Err(self.failed("engine_set_push_rendezvous_enabled", rc as i32));
        }
        Ok(())
    }

    pub fn set_auto_promotion(&self, enabled: bool) {
        if !self.is_ready() {
            return;
        }
        let _ = (self.set_auto_promotion)(if enabled { 1 } else { 0 });
    }

    pub fn set_masque_submode_override(&self, submode: &str) -> Result<()> {
        self.ensure_ready()?;
        let s = CString::new(submode)
            .map_err(|_| DesktopError::EngineSymbol("submode NUL".into()))?;
        let rc = (self.set_masque_submode_override)(s.as_ptr());
        if rc != 0 {
            return Err(self.failed("engine_set_masque_submode_override", rc as i32));
        }
        Ok(())
    }

    pub fn set_experimental_families_enabled(&self, enabled: bool) -> Result<()> {
        self.ensure_ready()?;
        let rc = (self.set_experimental_families_enabled)(if enabled { 1 } else { 0 });
        if rc != 0 {
            return Err(self.failed("engine_set_experimental_families_enabled", rc as i32));
        }
        Ok(())
    }

    pub fn bootstrap_install_seeds(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_bootstrap_install_seeds", |buf, len| (self.bootstrap_install_seeds)(buf, len))
    }

    pub fn bootstrap_refresh(&self, timeout_ms: i32) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_bootstrap_refresh", |buf, len| (self.bootstrap_refresh)(timeout_ms as c_int, buf, len))
    }

    pub fn bootstrap_status(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_bootstrap_status", |buf, len| (self.bootstrap_status)(buf, len))
    }

    pub fn redistribute_route(&self, route_id: &str, recipient_fp: &str) -> Result<String> {
        self.ensure_ready()?;
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        let f = CString::new(recipient_fp)
            .map_err(|_| DesktopError::EngineSymbol("recipient_fp NUL".into()))?;
        self.call_buf("engine_redistribute_route", |buf, len| (self.redistribute_route)(r.as_ptr(), f.as_ptr(), buf, len))
    }

    pub fn uri_detect(&self, text: &str) -> Result<String> {
        self.ensure_ready()?;
        let s = CString::new(text)
            .map_err(|_| DesktopError::EngineSymbol("text NUL".into()))?;
        self.call_buf("engine_uri_detect", |buf, len| (self.uri_detect)(s.as_ptr(), buf, len))
    }

    pub fn uri_import(&self, raw_uri: &str) -> Result<String> {
        self.ensure_ready()?;
        let s = CString::new(raw_uri)
            .map_err(|_| DesktopError::EngineSymbol("raw_uri NUL".into()))?;
        self.call_buf("engine_uri_import", |buf, len| (self.uri_import)(s.as_ptr(), buf, len))
    }

    pub fn wasm_kill_switch_pubkey(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_wasm_kill_switch_pubkey", |buf, len| (self.wasm_kill_switch_pubkey)(buf, len))
    }

    pub fn loaded_wasm_modules(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_loaded_wasm_modules", |buf, len| (self.loaded_wasm_modules)(buf, len))
    }

    // ----------------------------------------------------------------
    // Phase 45 — TUN-fd handoff + protect callback.
    //
    // `set_tun_fd` takes ownership of the fd. After a successful return
    // the host MUST NOT close it; the engine closes it on
    // `clear_tun_fd` or `Shutdown`. Negative fds are rejected by the
    // engine.

    pub fn set_tun_fd(&self, fd: c_int) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_set_tun_fd", |buf, len| (self.set_tun_fd)(fd, buf, len))
    }

    pub fn clear_tun_fd(&self) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_clear_tun_fd", |buf, len| (self.clear_tun_fd)(buf, len))
    }

    /// `register_protect_callback` installs a C function pointer of
    /// type `int (*)(int fd)` that the in-process driver invokes for
    /// every upstream socket it opens. Pass 0 to clear.
    ///
    /// On Android the pointer is a host-side trampoline that turns
    /// around and calls `DaalCoreBridge.invokeProtect(fd)` via JNI;
    /// on desktop the call site is currently a no-op.
    /// `engine_route_precheck`: asks whether `set_route(route_id)` would
    /// be refused right now, starting and stopping nothing. Returns the
    /// engine's JSON — `{"route_id", "refused": "" | code,
    /// "active_route"}` — or `Ok(None)` when this library predates the
    /// call. A refusal is not an error; the engine also records it in
    /// its diagnostics (`connect_refused`) exactly as a refused
    /// `set_route` does, so the page learns the reason either way.
    pub fn route_precheck(&self, route_id: &str) -> Result<Option<String>> {
        self.ensure_ready()?;
        let Some(precheck) = self.route_precheck else {
            return Ok(None);
        };
        let r = CString::new(route_id)
            .map_err(|_| DesktopError::EngineSymbol("route_id NUL".into()))?;
        self.call_buf("engine_route_precheck", |buf, len| (precheck)(r.as_ptr(), buf, len))
            .map(Some)
    }

    pub fn register_protect_callback(&self, fn_ptr: usize) -> Result<String> {
        self.ensure_ready()?;
        self.call_buf("engine_register_protect_callback", |buf, len| (self.register_protect_callback)(fn_ptr, buf, len))
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

/// How old a `recent_errors` entry may be and still be blamed for the
/// call that just failed. The list is read immediately after the
/// failing call returns, so the entry that belongs to it is seconds
/// old at most; anything older is some earlier call's error.
const ENGINE_ERROR_MAX_AGE_SECS: i64 = 15;

/// Longest engine error text carried in a `DesktopError`.
const ENGINE_ERROR_MAX_CHARS: usize = 300;

/// Picks the newest `recent_errors` entry for `call` out of an
/// `engine_export_diagnostics` blob and renders it as one line.
///
/// The entries are `{time, call, text, count}` (export_errors.go),
/// oldest first; `time` is UTC `YYYY-MM-DDTHH:MM:SSZ`, the moment of
/// the most recent occurrence. An entry is used only when its `call` is
/// the call that just failed and its time is within
/// `ENGINE_ERROR_MAX_AGE_SECS` of `now_unix` — so a call that fails
/// without recording anything is never given some earlier call's
/// words. An entry whose time cannot be read is treated as not recent.
pub fn newest_engine_error(diagnostics_json: &str, call: &str, now_unix: i64) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(diagnostics_json).ok()?;
    let list = v.get("recent_errors")?.as_array()?;
    let text = list.iter().rev().find_map(|entry| {
        let o = entry.as_object()?;
        if o.get("call")?.as_str()? != call {
            return None;
        }
        let at = parse_utc_seconds(o.get("time")?.as_str()?)?;
        if (now_unix - at).abs() > ENGINE_ERROR_MAX_AGE_SECS {
            return None;
        }
        let text = o.get("text")?.as_str()?.trim();
        if text.is_empty() {
            None
        } else {
            Some(text.to_string())
        }
    })?;
    let one_line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(ENGINE_ERROR_MAX_CHARS)
        .collect();
    let one_line = one_line.trim().to_string();
    if one_line.is_empty() {
        None
    } else {
        Some(one_line)
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` → unix seconds. Exactly that shape (what the
/// Go side writes); anything else is `None`.
fn parse_utc_seconds(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':'
        || b[16] != b':' || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm), proleptic Gregorian.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

/// The part of an `engine_export_diagnostics` blob the Android VPN
/// service needs (see `DaalCoreBridge.engineState`). `active_route` is
/// and `route_running` are passed through as the engine gave them — a
/// string / a boolean, or JSON null when the field is absent — and the
/// four closed codes default to "".
pub fn connection_state_json(diagnostics_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(diagnostics_json).ok()?;
    let o = v.as_object()?;
    let code = |k: &str| o.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let active = match o.get("active_route").and_then(|x| x.as_str()) {
        Some(s) => serde_json::Value::String(s.to_string()),
        None => serde_json::Value::Null,
    };
    let running = match o.get("route_running").and_then(|x| x.as_bool()) {
        Some(b) => serde_json::Value::Bool(b),
        None => serde_json::Value::Null,
    };
    Some(
        serde_json::json!({
            "active_route": active,
            "route_running": running,
            "route_check": code("route_check"),
            "route_check_category": code("route_check_category"),
            "connect_refused": code("connect_refused"),
            "connect_refused_route": code("connect_refused_route"),
        })
        .to_string(),
    )
}

fn path_to_cstring(p: &Path) -> Result<CString> {
    CString::new(p.to_string_lossy().as_bytes())
        .map_err(|_| DesktopError::EngineSymbol("path contained NUL".into()))
}

/// Liveness flag for the engine library, pulled by the GUI.
///
/// WHAT THIS ACTUALLY MEASURES, precisely: `check_once` calls
/// `engine_version` and records whether the returned pointer was
/// non-NULL. That is "the shared library is loaded and its Go runtime
/// answers a call" — nothing more. It does NOT probe the network, the
/// data plane, or the active route, so a build with no data plane
/// linked (see core/abi/dataplane.go) reports healthy while being
/// unable to carry a single byte. Callers must not render it as
/// "the tunnel is fine".
///
/// There is no interval and no failure counter here: the GUI owns the
/// cadence (App.tsx polls `heartbeat_tick` every 2s) and a single NULL
/// flips the flag immediately. The previous version of this comment
/// described an `interval` field, a `max_failures` consecutive-failure
/// threshold and a background supervisor thread; none of the three
/// ever existed.
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

#[cfg(test)]
mod engine_error_text_tests {
    use super::{newest_engine_error, parse_utc_seconds};

    // 2026-11-19T10:00:00Z
    const NOW: i64 = 1_795_082_400;

    #[test]
    fn utc_seconds() {
        assert_eq!(parse_utc_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc_seconds("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_utc_seconds("2026-11-19T10:00:00Z"), Some(NOW));
        assert_eq!(parse_utc_seconds("2026-11-19 10:00:00Z"), None);
        assert_eq!(parse_utc_seconds("2026-13-19T10:00:00Z"), None);
        assert_eq!(parse_utc_seconds(""), None);
    }

    #[test]
    fn absent_or_empty_list_is_none() {
        assert_eq!(newest_engine_error(r#"{"posture":"x"}"#, "engine_x", NOW), None);
        assert_eq!(newest_engine_error(r#"{"recent_errors":[]}"#, "engine_x", NOW), None);
        assert_eq!(newest_engine_error(r#"{"recent_errors":null}"#, "engine_x", NOW), None);
        assert_eq!(newest_engine_error("not json", "engine_x", NOW), None);
    }

    #[test]
    fn takes_the_newest_entry_of_the_failing_call() {
        let j = r#"{"recent_errors":[
            {"time":"2026-11-19T09:59:58Z","call":"engine_subscription_list","text":"first","count":1},
            {"time":"2026-11-19T09:59:59Z","call":"engine_subscription_list","text":"database is locked","count":3},
            {"time":"2026-11-19T10:00:00Z","call":"engine_route_summary","text":"someone else's","count":1}
        ]}"#;
        assert_eq!(
            newest_engine_error(j, "engine_subscription_list", NOW).as_deref(),
            Some("database is locked")
        );
    }

    #[test]
    fn another_calls_error_is_never_borrowed() {
        let j = r#"{"recent_errors":[
            {"time":"2026-11-19T10:00:00Z","call":"engine_route_summary","text":"not mine","count":1}
        ]}"#;
        assert_eq!(newest_engine_error(j, "engine_subscription_list", NOW), None);
    }

    #[test]
    fn a_stale_or_undated_entry_is_not_blamed() {
        let j = r#"{"recent_errors":[
            {"time":"2026-11-19T09:00:00Z","call":"engine_x","text":"an hour ago","count":1}
        ]}"#;
        assert_eq!(newest_engine_error(j, "engine_x", NOW), None);
        let j = r#"{"recent_errors":[{"time":"soon","call":"engine_x","text":"t","count":1}]}"#;
        assert_eq!(newest_engine_error(j, "engine_x", NOW), None);
    }

    #[test]
    fn text_is_one_bounded_line() {
        let long = "e".repeat(2000);
        let j = serde_json::json!({ "recent_errors": [
            {"time":"2026-11-19T10:00:00Z","call":"engine_x","text":format!("a\nb\t{long}"),"count":1}
        ] })
        .to_string();
        let got = newest_engine_error(&j, "engine_x", NOW).unwrap();
        assert!(!got.contains('\n') && !got.contains('\t'));
        assert!(got.chars().count() <= 300);
        assert!(got.starts_with("a b "));
    }
}

#[cfg(test)]
mod connection_state_tests {
    use super::connection_state_json;

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(&connection_state_json(s).unwrap()).unwrap()
    }

    #[test]
    fn refused_switch_keeps_the_old_route() {
        let v = parse(
            r#"{"active_route":"r1","route_running":true,"route_check":"ok","connect_refused":"cooldown",
                "connect_refused_route":"r2","public_ip":"203.0.113.9"}"#,
        );
        assert_eq!(v["active_route"], "r1");
        assert_eq!(v["connect_refused"], "cooldown");
        assert_eq!(v["connect_refused_route"], "r2");
        assert_eq!(v["route_check"], "ok");
        assert_eq!(v["route_running"], true);
        // Nothing but the six fields crosses to the JVM.
        assert_eq!(v.as_object().unwrap().len(), 6);
    }

    #[test]
    fn nothing_connected_is_empty_and_an_old_engine_is_null() {
        let v = parse(r#"{"active_route":"","route_check":"failed","route_check_category":"timeout"}"#);
        assert_eq!(v["active_route"], "");
        assert_eq!(v["route_check_category"], "timeout");
        let v = parse(r#"{"route_check":"ok"}"#);
        assert!(v["active_route"].is_null());
        assert!(v["route_running"].is_null());
        assert!(connection_state_json("[]").is_none());
        assert!(connection_state_json("nope").is_none());
    }
}
