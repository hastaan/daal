# Phase 3-Soak — V3 Success-Metric Soak — Handover

**Status:** SHIPPED.
**Date:** 2026-04-28.
**Engine version:** `daal-core 0.9.0+v3-share` **(unchanged from 3F)**.
**ABI release surface:** 48 **(unchanged from 3F)**.

## What shipped

Phase 3-Soak is a **verification-shaped** phase. It ships:

- A 5-metric V3 success-metric aggregate verifier
  (`internal/v3verifier/`).
- An auto-promotion threshold A-vs-B comparison harness
  (`internal/threshold_compare/`) — observation-only.
- A platform-mix dispatcher (`internal/load/platform_mix.go`)
  that distributes synthetic clients across three real
  OS-distinct binary stubs at the LOCKED 60/35/5 mix.
- Two new platform-stub binaries (Android, iOS) under `cmd/`
  that fork-exec the Linux soak-engine with platform-shaped
  `GOMEMLIMIT` (200 MiB / 50 MiB) and `DAAL_SOAK_PLATFORM` env.
- Five new V3 soak scenarios + the `--scenarios v3-superset`
  selector (26 → **31** scenarios, additive on the 3F-locked
  v2-superset).
- Two new specs: `specs/v3-success-metric-v1.md` (the V3 ship
  criterion) and `specs/v3-closure-v1.md` (the formal V3
  closure record / V4 gate).
- Removal of the deprecated `state` field from
  `engine_export_diagnostics`. Diagnostics consumers MUST use
  `posture` (the 8-state FSM from 2B). ABI-neutral.

3-Soak ships **no new engine code** and **no new release
symbols**. The release ABI surface stays at 48.

## What 3-Soak does NOT change

| Surface | Locked at | 3-Soak value |
|---------|-----------|--------------|
| `nm libdaalcore.so | grep ' T engine_'` | 3F | **48** unchanged |
| Engine `Version` | 3F | `daal-core 0.9.0+v3-share` unchanged |
| `--scenarios legacy` count | 1.5C | 5 unchanged |
| `--scenarios v2-superset` count | 3F | 26 unchanged |
| Auto-promotion thresholds (engine) | 2G | LOCKED-A unchanged |

## Locked invariants (16, per spec)

All 16 locked invariants from
`phases of development/27-phase-3-soak-success-metric.md` §3
preserved end-to-end. The most-load-bearing ones:

1. No new release ABI symbols (verified: nm = 48).
2. Engine Version unchanged (verified: `Version` constant).
3. Three real platform stubs; 60/35/5 mix (LockedDefaultMix
   regression-tested).
4. 5-metric aggregate, all five independent (v3verifier
   regression-tested).
5. Formal V3 closure spec (`specs/v3-closure-v1.md` shipped).
6. v2-superset stays 26; v3-superset NEW (26→31, regression
   test in `cmd/soak-driver/v3_superset_test.go`).
13. Deprecated `State` diagnostics field removed.
15. Position B preserved (no telemetry added).
16. V3 closure is gate to V4.

## Closure criteria (from `specs/v3-closure-v1.md`)

V3 closes when ALL of:

1. Primary metric green (cross-platform pickup ≤ 24h on every
   platform stub).
2. Secondary 1 green (experimental-gate cross-product).
3. Secondary 2 green (trust-UI parity).
4. Secondary 3 green (no V1/V2 regression).
5. Secondary 4 green (per-family burn rate).
6. Engine version unchanged at closure.
7. ABI release surface unchanged at closure.
8. All 3F regression matrix green.

The release-cut operator runs `--scenarios v3-superset` against
all three platform binaries, captures the
`internal/v3verifier.Aggregate{...AllPass=true}` JSON, appends
the closure attestation to `specs/v3-closure-v1.md`, and writes
the threshold-comparison memo to
`phases of development/27-phase-3-soak-threshold-comparison.md`.

## Files added / modified

```
phases of development/27-phase-3-soak-success-metric.md          REPLACED (locked spec)
phases of development/27-phase-3-soak-threshold-comparison.md    NEW (memo template)
phases of development/27-phase-3-soak-success-metric.handover.md NEW (this doc)

specs/v3-success-metric-v1.md                                    NEW
specs/v3-closure-v1.md                                           NEW
specs/blackout-soak-rig-v1.md                                    AMENDED (3-Soak section)

cmd/daal-soak-engine-android/main.go                            NEW (200 MiB GOMEMLIMIT, fork-exec wrapper)
cmd/daal-soak-engine-android/go.mod                             NEW
cmd/daal-soak-engine-ios/main.go                                NEW (50 MiB GOMEMLIMIT, fork-exec wrapper)
cmd/daal-soak-engine-ios/go.mod                                 NEW

test-rigs/distribution-failure/scenarios/v3-cross-platform-pickup.json            NEW
test-rigs/distribution-failure/scenarios/v3-experimental-gate-cross-product.json  NEW
test-rigs/distribution-failure/scenarios/v3-bulk-capable-cross-product.json       NEW
test-rigs/distribution-failure/scenarios/v3-auto-promotion-threshold-A-vs-B.json  NEW
test-rigs/distribution-failure/scenarios/v3-mixed-family-directory.json           NEW

test-rigs/distribution-failure/soak-driver/internal/load/platform_mix.go              NEW (PlatformTag enum, LockedDefaultMix 60/35/5, ParseMix, PlatformPool.Spawn)
test-rigs/distribution-failure/soak-driver/internal/load/platform_mix_test.go         NEW (7 tests)
test-rigs/distribution-failure/soak-driver/internal/v3verifier/v3verifier.go          NEW (5-metric aggregate verifier; LockedFamilyMaturity)
test-rigs/distribution-failure/soak-driver/internal/v3verifier/v3verifier_test.go     NEW (13 tests)
test-rigs/distribution-failure/soak-driver/internal/threshold_compare/threshold_compare.go      NEW (LockedA, LockedB, Compare, RenderMemo)
test-rigs/distribution-failure/soak-driver/internal/threshold_compare/threshold_compare_test.go NEW (9 tests)

test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go               MODIFIED (+v3-superset case)
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/v3_superset_test.go   NEW (count = 31)

core/abi/abi.go                                                  MODIFIED (removed `state` from ExportDiagnostics)
```

## Final regression sweep

```
$ cd core && go test -count=1 ./...
ok  	daal/core/abi	(31.8s)
[+ 22 other core packages — all PASS]

$ cd test-rigs/distribution-failure/soak-driver && go test -count=1 ./...
ok  	daal/soak-driver/cmd/soak-driver
ok  	daal/soak-driver/internal/load            (7 platform_mix tests)
ok  	daal/soak-driver/internal/v3verifier      (13 verifier tests)
ok  	daal/soak-driver/internal/threshold_compare (9 harness tests)
[+ 8 other soak-driver packages — all PASS]

$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l
48          # unchanged from 3F

$ go build cmd/daal-soak-engine cmd/daal-soak-engine-android cmd/daal-soak-engine-ios
[all three binaries build clean]
```

## Architecture highlights

### Platform stubs are fork-exec wrappers, not duplicate dispatchers

The Android + iOS stubs do not re-implement the soak-engine
dispatch loop. They set `GOMEMLIMIT` + `DAAL_SOAK_PLATFORM` env
vars then exec the Linux soak-engine. This satisfies the spec's
"three real binaries" requirement (separate executables,
OS-distinct names, platform-shaped resource limits) while
preserving the proven Linux dispatch loop without code
duplication. See `cmd/daal-soak-engine-android/main.go` and
`cmd/daal-soak-engine-ios/main.go`.

### V3 verifier is pure-data, not engine-coupled

`internal/v3verifier/` consumes observation tuples
(`PickupObservation`, `Activation`, `TrustUIObservation`,
`FamilyBurn`) and produces an `Aggregate` verdict. It does NOT
import the engine. The soak driver records observations during
the run and replays them through the verifier at end of run.

### Threshold A-vs-B harness is observation-only

`internal/threshold_compare/` evaluates LOCKED-B (4 families ×
20 min × ladder ≥ 4) against the same Skipped-family ledger the
engine evaluates LOCKED-A on. Neither set is promoted to engine
default at 3-Soak. The memo informs V4 freeze.

## Position B preserved

No telemetry added. No phone-home. The 3-Soak rig produces all
artefacts locally; nothing leaves the soak machine without an
explicit operator action. The locked maturity table publishes
user-facing trust signals at build time; it is not derived from
runtime telemetry.

## Next phase

V3 closure (per `specs/v3-closure-v1.md`) is the gate to V4.
Phase 3G Track A (lifeline relay) remains LOCKED at the spec
filed in
`phases of development/26-phase-3g-lifeline-relay.md` but is
**NOT shipping** until the five hard pre-conditions are met
(partner, MOU, audit, threat model, kill-switch test) per
`phases of development/26-phase-3g-lifeline-relay.handover.md`.
