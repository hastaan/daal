//! The engine must be unusable, not fatal, when `engine_init` failed.
//!
//! An engine_* export called without a Core panics inside the Go
//! runtime (`abi.mustCore`), and a Go panic in a c-shared library
//! aborts the process: with a damaged route store that was a crash on
//! every launch. `Engine` therefore refuses every Core-needing call
//! until `init` has succeeded.
//!
//! Two tests:
//!  * `every_core_call_is_gated` reads the wrapper source and needs no
//!    engine library, so it always runs;
//!  * `failed_init_leaves_a_usable_process` drives the real library
//!    and skips when none is built (same rule as engine_load.rs).

use std::path::PathBuf;

use daal_desktop_core::engine::Engine;
use daal_desktop_core::DesktopError;

/// Wrappers that may cross the FFI without a Core: they are how a Core
/// comes to exist, or they only ask the library for its version.
const NO_CORE_NEEDED: &[&str] = &["load", "init", "shutdown", "version_str", "heartbeat"];

/// Methods of `impl Engine` that make no engine call at all.
const NOT_A_CALL: &[&str] = &["is_ready", "unavailable_reason", "ensure_ready", "failed", "call_buf"];

#[test]
fn every_core_call_is_gated() {
    let src = include_str!("../src/engine.rs");
    let start = src.find("impl Engine {").expect("impl Engine");
    let end = src[start..]
        .find("\n}\n")
        .map(|i| start + i)
        .expect("end of impl Engine");
    let body = &src[start..end];

    let mut checked = 0;
    let mut rest = body;
    while let Some(i) = rest.find("\n    pub fn ").or_else(|| rest.find("\n    fn ")) {
        let after = &rest[i + 1..];
        let sig_end = after.find('(').expect("fn has (");
        let name = after[..sig_end]
            .trim()
            .trim_start_matches("pub fn ")
            .trim_start_matches("fn ")
            .split('<')
            .next()
            .unwrap()
            .trim()
            .to_string();
        // The method's text: up to the next method at the same depth.
        let next = after[1..]
            .find("\n    pub fn ")
            .into_iter()
            .chain(after[1..].find("\n    fn "))
            .min()
            .map(|n| n + 1)
            .unwrap_or(after.len());
        let text = &after[..next];
        rest = &after[next..];

        if NO_CORE_NEEDED.contains(&name.as_str()) || NOT_A_CALL.contains(&name.as_str()) {
            continue;
        }
        let call = text
            .find("(self.")
            .or_else(|| text.find("self.route_precheck"))
            .unwrap_or_else(|| panic!("{name}: expected an engine call"));
        let gate = text
            .find("self.ensure_ready()?;")
            .into_iter()
            .chain(text.find("if !self.is_ready() {"))
            .min()
            .unwrap_or_else(|| panic!("Engine::{name} reaches the engine without a readiness gate"));
        assert!(
            gate < call,
            "Engine::{name}: the readiness gate must come before the engine call"
        );
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} wrappers found — the scan is broken");
}

fn locate_lib() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DAAL_ENGINE_LIB") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    ["/tmp/libdaalcore.so", "../target/libdaalcore.so", "target/libdaalcore.so"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

#[test]
#[cfg_attr(
    any(target_os = "macos", target_os = "windows"),
    ignore = "in-process Go c-shared is unreliable on these hosts; see engine_load.rs"
)]
fn failed_init_leaves_a_usable_process() {
    let Some(path) = locate_lib() else {
        // `./daal test` builds the engine from the tree and sets both
        // variables: there a missing library is a failure, not a skip
        // that prints "ok". Elsewhere (a bare `cargo test` on a machine
        // without Go) the test still skips, and says so.
        assert!(
            std::env::var("DAAL_REQUIRE_ENGINE_LIB").as_deref() != Ok("1"),
            "DAAL_REQUIRE_ENGINE_LIB=1 but no engine library was found (DAAL_ENGINE_LIB={:?})",
            std::env::var("DAAL_ENGINE_LIB").ok()
        );
        eprintln!("SKIPPED (not a pass): set DAAL_ENGINE_LIB to the path of libdaalcore.so to run this test");
        return;
    };
    let engine = Engine::load(&path).expect("engine load");
    assert!(!engine.is_ready());

    // A state "directory" that is a regular file: nothing can be
    // created under it, so engine_init must fail whatever the store
    // recovery does.
    let tmp = tempfile::tempdir().unwrap();
    let not_a_dir = tmp.path().join("state");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let err = engine.init(&not_a_dir, "warn").expect_err("init must fail");
    assert!(matches!(err, DesktopError::EngineReturn(_)), "{err}");
    assert!(!engine.is_ready());
    let why = engine.unavailable_reason().expect("a reason");
    assert!(why.contains("engine_init returned"), "{why}");

    // Each of these aborted the process before the gate existed.
    for r in [
        engine.diagnostics_explain(),
        engine.export_diagnostics(),
        engine.subscription_list(),
        engine.available_routes(),
    ] {
        match r {
            Err(DesktopError::EngineUnavailable(w)) => assert_eq!(w, why),
            other => panic!("expected EngineUnavailable, got {other:?}"),
        }
    }
    assert!(matches!(
        engine.set_route("r1"),
        Err(DesktopError::EngineUnavailable(_))
    ));
    assert!(matches!(
        engine.scheduler_tick(),
        Err(DesktopError::EngineUnavailable(_))
    ));
    assert_eq!(engine.probe_udp(10), -1);
    engine.set_auto_promotion(true);
    engine.set_allow_bulk_capable(true);
    let text = engine.subscription_list().unwrap_err().to_string();
    assert!(text.starts_with("engine_unavailable: "), "{text}");

    // The library itself is fine, and a good directory still starts it.
    assert!(engine.version_str().starts_with("daal-core 0.9"));
    let good = tempfile::tempdir().unwrap();
    engine.init(good.path(), "warn").expect("init on a good dir");
    assert!(engine.is_ready());
    assert!(engine.unavailable_reason().is_none());
    engine.subscription_list().expect("a real call now works");

    // A call that fails says why — when this library records why
    // (`recent_errors`; older ones do not, and the bare code is all
    // there is).
    let records_errors = engine
        .export_diagnostics()
        .expect("diagnostics")
        .contains("\"recent_errors\"");
    let err = engine
        .route_summary("no-such-route")
        .expect_err("an unknown route has no summary");
    if records_errors {
        match &err {
            DesktopError::EngineFailed { code, detail } => {
                assert!(*code < 0);
                assert!(!detail.trim().is_empty());
                assert!(err.to_string().starts_with("engine call returned -1: "), "{err}");
            }
            other => panic!("expected the engine's own words, got {other:?}"),
        }
    } else {
        assert!(matches!(err, DesktopError::EngineReturn(_)), "{err:?}");
    }

    // The pre-check answers without starting anything; a library that
    // predates it answers None and the host just attempts the route.
    if let Some(answer) = engine.route_precheck("no-such-route").expect("precheck") {
        let v: serde_json::Value = serde_json::from_str(&answer).expect("precheck json");
        assert_eq!(v["route_id"], "no-such-route");
        assert!(!v["refused"].as_str().unwrap_or("").is_empty(), "{answer}");
        assert!(v["active_route"].is_string(), "{answer}");
    }
    let _ = engine.shutdown();
    assert!(!engine.is_ready());
    assert!(matches!(
        engine.subscription_list(),
        Err(DesktopError::EngineUnavailable(_))
    ));
}
