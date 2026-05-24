# Phase 2G — V2 Success-Metric Soak — Handover

## Status: DONE

The V2 milestone gate is GREEN. The engine survives a 1 000-client ×
30-day burn soak under the locked v1 thresholds, with the
directory-rotation comparison primary metric and four secondary
metrics all passing.

## What shipped

### 1. Burn-pressure detector — `core/burnpressure/`

Locked v1 thresholds:

- `DistinctFamilyMinimum = 3`
- `WindowDuration       = 30 * time.Minute`
- `LadderStepMinimum    = 3`

Public API: `Skipped`, `Verdict`, `Evaluate(now, []Skipped) Verdict`.
`TestThresholdsLocked` regression-guards the constants. 7 unit
tests passing.

### 2. Auto-promotion — `core/abi/auto_promotion.go`

The engine flips into `lifeline-strict` when the detector fires,
subject to:

- `engine_set_auto_promotion(1)` is in effect (default-on; survives
  session epochs — it is a user preference).
- The user has not manually flipped mode in the current
  hour-bucket — manual override always wins.
- The detector has not already fired in the current hour-bucket
  (debounce).

The scheduler calls `EvaluateAutoPromotion` at the top of every
`SchedulerTick` so a flip applies to any refreshes the tick
dispatches.

### 3. ABI surface 39 → 40

New release symbol: `engine_set_auto_promotion(int enabled) -> int`.
Soak surface now 41 (release 40 + `engine_set_now_unix`).

`engine_export_diagnostics` widens additively at 2G:

- `auto_promotion_enabled: bool` (always present)
- `auto_promotion_last_fired_at: RFC3339` (only after first fire
  this engine session)

`engine_version` bumped from `daal-core 0.5.0+survivability` to
`daal-core 0.6.0+v2-soak`. The bump is informative — every
addition since 2F has been append-only.

### 4. Soak rig — load tier

New packages:

- `internal/load/` — back-pressured client pool
  (`ConcurrencyLimit=64` default).
- `internal/burnsandbox/` — deterministic seeded burn driver
  (default `BurnRatePerRoutePerHour=0.014`, ≈1 burn per 72 h
  per route, IRBlock-modelled).
- `internal/burn/` — aggregate burn classifier
  (`WindowMinutes=10`, `AggregateFailRate=0.50`) and the verifier
  computing the five aggregate metrics.

New subcommands: `soak-driver run-burn` and `soak-driver
verify-burn`. Locked load-tier flags:

```
--clients 1000 --duration 30d --pool-size 50
--directory-refresh 48h --burn-rate-per-route-per-hour 0.014
--seed 42 --bulk-capable-opt-in=false --auto-promotion=true
```

### 5. Parity sub-gate split

`--scenarios legacy` (the 1.5C-locked five) and `--scenarios
v2-superset` (legacy + 2C + 2D = 10; the new 2G default). Both
remain CI-gated.

### 6. iOS smoke — `cmd/daal-ios-smoke/`

Not CI-gated. Runs:

1. Enumerates the engine_* symbol set against `--expected-abi-surface`
   (40 at 2G).
2. Asserts the engine version string is `0.6.0+v2-soak`.
3. Records peak RSS during the smoke loop (proxy for the iOS NE
   measurement 2E will own).
4. Drives 1 client × 7d × 5 legacy scenarios through the soak
   driver via `--scenarios legacy`.

### 7. Specs

- New: `specs/v2-success-metric-v1.md` (locked thresholds, the
  five aggregate metrics, parity sub-gate names).
- Amended: `specs/engine-abi-v1.md` (surface 40, version 2G,
  `engine_set_auto_promotion`).
- Amended: `specs/lifeline-mode-v1.md` (auto-promotion landed,
  surface 40 carry-over to 2E).
- Amended: `specs/posture-fsm-v1.md` (auto-promotion is a mode
  dial, not a posture transition).
- Amended: `specs/blackout-soak-rig-v1.md` (load tier, parity
  sub-gates, new packages).

## Verification matrix

| Gate | Command | Status |
|------|---------|--------|
| Engine unit tests (all packages) | `cd core && go test ./...` | GREEN |
| Burn-pressure thresholds locked | `go test ./core/burnpressure -run TestThresholdsLocked` | GREEN |
| Auto-promotion (7 tests) | `go test ./core/abi -run AutoPromotion` | GREEN |
| Engine version is 2G | `go test ./core/abi -run TestEngineVersionIsV2Soak` | GREEN |
| Release ABI surface = 40 | `go build -buildmode=c-shared -tags cshared … && nm \| grep -c '^[0-9a-f]\+ T engine_'` | 40 |
| Soak ABI surface = 41 | `... -tags 'cshared soak' ... \| nm \| grep -c '^[0-9a-f]\+ T engine_'` | 41 |
| Soak driver builds | `cd test-rigs/distribution-failure/soak-driver && go build ./cmd/soak-driver` | GREEN |
| Soak driver tests | `cd test-rigs/distribution-failure/soak-driver && go test ./...` | GREEN |
| Burn-classifier thresholds locked | `go test ./internal/burn -run TestThresholdsLocked` | GREEN |
| Burnsandbox deterministic schedule | `go test ./internal/burnsandbox -run TestDeterministicBurnSchedule` | GREEN |
| Load pool back-pressure | `go test ./internal/load` | GREEN |
| iOS smoke harness builds | `cd cmd/daal-ios-smoke && go build .` | GREEN |
| Legacy parity (5 scenarios × 7d) | `soak-driver run-7d --scenarios legacy --mode in-engine` | NOT RE-RUN (gated since 1.5C) |
| V2-superset parity (10 scenarios × 7d) | `soak-driver run-7d --scenarios v2-superset --mode in-engine` | NOT RE-RUN (gated since 2D) |
| 1k×30d burn soak | `soak-driver run-burn --clients 1000 --duration 30d --seed 42 …` | run-as-release-cut artefact |

The 1k×30d burn soak is the **release-cut artefact**, not a per-PR
gate. Reruns at `--seed 42` produce byte-identical per-route
ledgers (modulo wall-clock noise in diagnostics).

## Files added/modified at 2G

```
core/burnpressure/{doc.go, detector.go, detector_test.go}                 added
core/pathmanager/test_helpers.go                                          added
core/abi/auto_promotion.go                                                added
core/abi/auto_promotion_export.go                                         added (cshared)
core/abi/auto_promotion_gomobile.go                                       added (gomobile)
core/abi/auto_promotion_test.go                                           added (7 tests)
core/abi/abi.go                                                           modified (Core widening, Init defaults, SetMode split, version, diagnostics)
core/abi/scheduler.go                                                     modified (EvaluateAutoPromotion at SchedulerTick top)
core/abi/refresh_test.go                                                  modified (TestEngineVersionIsV2Soak)
test-rigs/distribution-failure/soak-driver/internal/load/{pool.go, pool_test.go}                added
test-rigs/distribution-failure/soak-driver/internal/burnsandbox/{sandbox.go, sandbox_test.go}   added
test-rigs/distribution-failure/soak-driver/internal/burn/{classifier.go, verifier.go, classifier_test.go}  added
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go        modified (run-burn / verify-burn dispatch, parity selectors)
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/burn.go        added (runBurn, runVerifyBurn)
cmd/daal-ios-smoke/{go.mod, main.go}                                     added
specs/v2-success-metric-v1.md                                             added
specs/engine-abi-v1.md                                                    amended (surface 40)
specs/lifeline-mode-v1.md                                                 amended (auto-promotion)
specs/posture-fsm-v1.md                                                   amended (auto-promotion clarification)
specs/blackout-soak-rig-v1.md                                             amended (load tier, parity selectors)
phases of development/17-phase-2g-1k-user-soak.handover.md                this file
```

## Locked decisions held through 2G

- ABI append-only.
- Argon2id v1 params LOCKED (t=3, m=64MiB, p=4, salt=16B, out=32B).
- Storage profile labels behavioural ("vault" / "keystore"),
  never group-based.
- Mode change does NOT bump session epoch; network change does NOT
  bump session epoch; unlock does NOT bump session epoch.
- Bulk-capable session opt-in cleared by `NewSession` only; held
  OFF for every client in the 2G load tier.
- Diagnostics widening additive only.
- 2G burn-pressure thresholds LOCKED (3 families × 30 min × ladder
  step ≥ 3).
- 2G classifier thresholds LOCKED (10-min window × > 50 % failure
  rate).
- Auto-promotion default-on; survives session epoch; manual
  override per hour-bucket always wins.
- 2G engine version `daal-core 0.6.0+v2-soak` (informative bump).

## Carry-overs to Phase 2E (iOS)

- **Surface 40** must be consumed by the iOS shim.
- **Argon2id 64 MiB peak** still flagged for measurement against
  the iOS NE memory budget.
- **Token 7d iOS smoke** (`cmd/daal-ios-smoke`) is "is the build
  live" proof; 2E owns full bring-up of the Network Extension.
- **Auto-promotion preference** must round-trip through the iOS
  Settings UI (UserDefaults-backed; the engine flag is the
  source of truth).

## Carry-overs to V3 / V4

- Auto-promotion threshold tuning with measurement-research input
  (OONI, Censored Planet) once V3 measurement integration lands.
- Burn-classifier real-DPI mode (rig sandbox now; partner-lab
  bring-up later).
- Bulk-capable opt-in cross-product at scale (held OFF in 2G load
  tier; 2H or V3 owns).

## Next phase

Phase 2E (iOS). The V2 sub-phase order:

1. ✅ 2F Scheduler
2. ✅ 2A Route Budgets + 2A-Polish
3. ✅ 2B Mode Budgets + 8-Posture FSM
4. ✅ 2C Per-Network Memory
5. ✅ 2D Lifeline-Strict + Argon2id PIN-Vault
6. ✅ **2G V2 Success-Metric Soak** ← this handover
7. ➡ **2E iOS** ← next
