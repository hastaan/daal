//! End-to-end test: dlopen the actual libdaalcore.so produced by the
//! Go cshared build, call init/version/set_tunnel_socks/shutdown.
//!
//! Requires the engine library to have been built first. Set
//! `DAAL_ENGINE_LIB` to the absolute path of `libdaalcore.{so,dll,dylib}`.
//! If the env var is unset, the test SKIPS so unit-test runs in CI
//! without a Go toolchain still pass.

use std::env;
use std::path::PathBuf;

use daal_desktop_core::engine::Engine;

fn locate_lib() -> Option<PathBuf> {
    if let Ok(p) = env::var("DAAL_ENGINE_LIB") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    // Convenience: also pick up the path the local README / Justfile
    // suggests.
    let candidates = [
        "/tmp/libdaalcore.so",
        "../target/libdaalcore.so",
        "target/libdaalcore.so",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[test]
#[cfg_attr(
    any(target_os = "macos", target_os = "windows"),
    ignore = "in-process Go cgo c-shared is unreliable on darwin/arm64 (deadlocks) \
              and on windows-latest (intermittent STATUS_ACCESS_VIOLATION during \
              dlclose / Go-runtime teardown); tracked at hastaan/daal#1 — \
              subprocess harness blocks first non-alpha"
)]
fn engine_loads_and_sets_tunnel_socks() {
    let path = match locate_lib() {
        Some(p) => p,
        None => {
            eprintln!("skipping: set DAAL_ENGINE_LIB to path of libdaalcore.so to run this test");
            return;
        }
    };

    let engine = Engine::load(&path).expect("engine load");
    let tmp = tempfile::tempdir().unwrap();
    engine.init(tmp.path(), "warn").expect("engine_init");

    let v = engine.version_str();
    assert!(v.starts_with("daal-core 0.9"), "engine_version: {}", v);

    // Install a SOCKS endpoint, confirm the response carries it.
    let body = engine
        .set_tunnel_socks("127.0.0.1", 17891, "", "")
        .expect("set_tunnel_socks");
    assert!(
        body.contains(r#""endpoint":"127.0.0.1:17891""#),
        "body: {}",
        body
    );

    // Clear it.
    let body2 = engine.set_tunnel_socks("", 0, "", "").expect("clear");
    assert!(body2.contains(r#""endpoint":"""#), "body: {}", body2);

    // Diagnostics-explain returns a JSON object even with no active
    // route — proves the rest of the ABI surface is wired.
    let exp = engine.diagnostics_explain().expect("diagnostics_explain");
    assert!(exp.contains(r#""state""#), "exp: {}", exp);

    // 1.5C-Polish #2: subscription_list returns a JSON object with a
    // `subscriptions` array, even on a fresh state dir where the array
    // is empty. This proves the new symbol resolves and the wrapper
    // serializes correctly.
    let body = engine.subscription_list().expect("subscription_list");
    assert!(
        body.contains("\"subscriptions\""),
        "subscription_list body: {}",
        body
    );

    // Phase 2F: scheduler_status returns a JSON object with a
    // `cadence` and `next_due` array. This proves the new ABI symbol
    // is wired and the in-engine scheduler instantiates against the
    // bound store.
    let sched = engine.scheduler_status().expect("scheduler_status");
    assert!(
        sched.contains("\"cadence\"") && sched.contains("\"next_due\""),
        "scheduler_status body: {}",
        sched
    );
    // Phase 2F also adds budget-reset to next_due alongside subscription
    // / revocation / bootstrap.
    assert!(
        sched.contains("\"budget-reset\""),
        "expected budget-reset in scheduler_status: {}",
        sched
    );

    // Phase 2A: set_route_budget rejects unknown tags with a body that
    // contains the `unknown_budget_tag` error key. The wrapper returns
    // an Err with the engine's negative return code.
    match engine.set_route_budget("nonexistent-route", "definitely-not-a-tag") {
        Ok(b) => panic!("unexpected success on bad tag: {}", b),
        Err(_) => {
            // Expected; the engine returns -1 + a JSON body the host
            // would decode in production.
        }
    }

    engine.shutdown().expect("shutdown");
}
