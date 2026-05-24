// Package scheduler is the deterministic, in-engine ticker that drives
// subscription refresh, revocation refresh, and bootstrap-directory
// refresh on a fixed cadence.
//
// Phase 2F replaces the rig-side scheduling done by the 1.5C blackout
// soak driver. The rig kept day-by-day pacing in its own code; the
// production engine must do the same thing inside the engine process,
// using the same `time.Now` injection point already wired through
// 1.5A so every callsite is testable.
//
// Design constraints:
//
//   - Deterministic. Given the same store + same Now sequence, Plan()
//     emits the same ordered set of due actions. This is the V2 entry
//     criterion: a parity test replays a 1.5C 30-day artifact through
//     the in-engine scheduler and asserts byte-equal invariant ledger.
//
//   - Append-only ABI. Adds exactly one release symbol,
//     `engine_scheduler_status`, bringing the surface from 34 to 35.
//     Engine version bumps to `daal-core 0.5.0+survivability` because
//     Phase 2F opens V2.
//
//   - No background goroutines by default. Tick(now) is the unit of
//     work; Start(ctx) is a thin convenience that spawns a goroutine
//     calling Tick on a real time.Ticker. Both production hosts (Tauri
//     desktop, Android service) and tests can drive ticks directly,
//     so production behavior and parity tests share the same code path.
//
// Cadences (per V1.5.1 / V1.5.2 of the roadmap):
//
//   - Subscription refresh: each row's `profile_update_min` clamped to
//     [60, 10080] minutes (= 1 h to 7 d). The clamp is documented in
//     specs/scheduler-v1.md so operators know the floor and ceiling.
//
//   - Revocation refresh: every 6 h per publisher with a revocation URL.
//
//   - Bootstrap-directory refresh: every 24 h.
//
//   - Pointer-rotation re-check: piggybacks on the bootstrap-directory
//     refresh because rotation envelopes ride on the same fetch path.
package scheduler
