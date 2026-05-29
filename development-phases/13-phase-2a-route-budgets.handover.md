# Phase 2A Handover

## What landed

Engine version unchanged (`daal-core 0.5.0+survivability`). Release
ABI surface 35 → **36** with one new append-only function:
`engine_set_route_budget`.

New packages:

- `core/budget/` — pure byte-counter + cap enforcer (caps map, hour
  windowing, persistence binding). 6 source files (doc, caps, engine,
  persist, plus 3 *_test.go).
- `core/proxy/` — byte-counter spine. `Pipe`, `PipeAuthGuarded`,
  `Counter` interface, `AuthFailedSentinel` + `IsAuthFailed`. 4 source
  files.

ABI additions:

- `core/abi/budget.go` — `SetRouteBudget` Go helper + lazy
  `ensureBudget` singleton.
- `core/abi/budget_export.go` — `engine_set_route_budget` cshared.
- `core/abi/budget_gomobile.go` — gomobile facade.
- `core/abi/budget_test.go` — round-trip + diagnostics + cap-boundary
  tests.

Updated:

- `core/abi/abi.go` — `Shutdown` now resets the budget singleton;
  `ExportDiagnostics` widens its body additively with a `budgets`
  array when the engine has been instantiated.
- `core/routestore/store.go` — added `UpdateRouteScarcity` and
  `UpdateRouteBytesHour`.
- `core/pathmanager/fsm.go` — added `StateBudgetExhausted` state and
  `Manager.BudgetExhausted(routeID, family)` transition.
- `core/scheduler/plan.go` — added `KindBudgetReset`,
  `Cadence.BudgetReset` (default 1 h), `Source.LastBudgetReset()`.
- `core/scheduler/scheduler.go` — added
  `Executor.RefreshBudgetReset(ctx, now)`.
- `core/scheduler/{plan,scheduler,parity}_test.go` — fakeSource +
  recordingExecutor + replayingSource updated with the new method;
  expected ledgers updated.
- `core/abi/scheduler.go` — `storeSource.LastBudgetReset` reads
  `secrets_kv["scheduler:last-budget-reset"]`;
  `refreshExecutor.RefreshBudgetReset` calls
  `budget.Engine.HourRollover(now)` and stamps the cursor.
- `cmd/daal-soak-engine/main.go` — added `set-route-budget` and
  `export-diagnostics` commands.
- `test-rigs/.../soak-driver/internal/client/client.go` — added
  `SchedulerStatus` already-present, plus new `ExportDiagnostics`,
  `SetRouteBudget`.
- `client-desktop/daal-desktop-core/src/engine.rs` — resolves
  `engine_set_route_budget`; `set_route_budget(route_id, tag) ->
  Result<String>` Rust wrapper.
- `client-desktop/daal-desktop-core/tests/engine_load.rs` — calls
  `set_route_budget("nonexistent", "definitely-not-a-tag")` and
  asserts the Err is returned.

Specs:

- **New** `specs/route-budgets-v1.md`.
- **Amended** `specs/engine-abi-v1.md` — surface 35→36, version row,
  Phase 2A function block.
- **Amended** `specs/scheduler-v1.md` — cadence row + kind
  discriminator updated.

## Test results (last local run)

```
$ cd /home/daal/core && go test -count=1 ./...
ok  daal/core
ok  daal/core/abi
ok  daal/core/bootstrap
ok  daal/core/bootstrap/embedded
ok  daal/core/budget                  <-- new
ok  daal/core/diagnostics
ok  daal/core/engine
ok  daal/core/pathmanager
ok  daal/core/proxy                   <-- new
ok  daal/core/refresh
ok  daal/core/routestore
ok  daal/core/scheduler
ok  daal/core/share
ok  daal/core/trust

$ cd /home/daal/bundle/go && go test -count=1 ./...
all 5 packages green

$ cd /home/daal/test-rigs/distribution-failure/soak-driver && go test -count=1 ./...
all 5 packages green

$ cd /home/daal/test-rigs/censor-lab/lab-driver && go test -count=1 ./...
all 2 packages green

$ cd /home/daal/client-desktop && \
  DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace
ok  bundle-rs
ok  daal-desktop-core (engine_load + parity_with_go)
ok  daal-tun-helper (3 unit + 1 e2e)

$ nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'
36

$ /tmp/soak-driver run-7d  --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-rig       --mode rig
ALL SCENARIOS PASSED

$ /tmp/soak-driver run-7d  --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-inengine  --mode in-engine
ALL SCENARIOS PASSED

$ /tmp/soak-driver run-30d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d-inengine --mode in-engine
ALL SCENARIOS PASSED
```

The V2 entry-criterion regression (in-engine 30-day parity) still
passes after the scheduler gained the `budget-reset` action, because
the synthetic source's `LastBudgetReset` mirrors the same first-tick
+ stamp pattern as bootstrap; the parity ledger remains
deterministic.

## Architectural decisions captured

See `specs/route-budgets-v1.md`. The locked points:

1. The cap table is closed. Adding a tag or changing a cap is a
   roadmap-level decision because it breaks V2 success-metric soak
   parity.
2. Hour bucket = `now.Truncate(time.Hour).UTC()`. `Engine.Add`
   compares the persisted bucket cursor with the current bucket; on
   mismatch the counter zeroes before charging. This is the
   canonical rollover path — `HourRollover` and `Reset` are both
   conveniences over the same primitive.
3. `auth_failed` errors are exempt. The canonical seam is
   `proxy.PipeAuthGuarded(... preflight)`; outbound integrations
   classify the upstream error and route through this seam.
4. The diagnostics `budgets` array is widened additively. Pre-2A
   callers see the original JSON shape until they instantiate the
   engine via `engine_set_route_budget` or any successful `Add`.
5. The scheduler's `budget-reset` action fires every hour and is
   part of the V2 entry-criterion parity contract.

## Carry-overs into 2B

- `Engine.EffectiveCap(routeID, mode)` slot is reserved on the
  engine. 2B fills it by multiplying `caps[tag]` by the active mode's
  factor. The `Add` path threads `mode` from a future
  `pathmanager.CurrentMode()` accessor.
- `core/proxy.Pipe` is the byte-counter spine. 2B's mode-aware route
  ranking lives in `core/pathmanager/rank.go`; the byte-counting code
  doesn't move.
- `BudgetExhausted` is the first FSM state added at V2; 2B's 8-state
  expansion adds the per-cause cooldowns (DialFail / HandshakeFail /
  AuthFail / Quarantined / Retired).
- The desktop `set_route_budget` Rust wrapper is unused by Tauri
  commands today; 2B wires it into the new mode picker + budget
  table page.

## Carry-overs into 2C

- The budget engine is keyed by `(routeID)` only at 2A; 2C wraps it
  in a per-network layer keyed by `(routeID, networkID)`. The
  `RoutestoreStore` binding does NOT need to change because the
  network ID is appended to the secrets_kv cursor key.
- The diagnostics `budgets` array does not yet carry a
  `network_id`; 2C extends the snapshot.

## How to repeat 2A locally

```sh
# 1. Rebuild the cshared engine (now 36 release symbols):
cd /home/daal/core
go build -tags cshared -buildmode=c-shared \
    -o /tmp/libdaalcore.so ./cmd/libdaalcore

# 2. Verify symbol count + version:
nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'   # → 36
nm /tmp/libdaalcore.so | grep '^[0-9a-f]\+ T engine_set_route_budget'

# 3. Build the soak engine + driver:
cd /home/daal/cmd/daal-soak-engine
go build -tags soak -o /tmp/daal-soak-engine-soak .
cd /home/daal/test-rigs/distribution-failure/soak-driver
go build -o /tmp/soak-driver ./cmd/soak-driver

# 4. Parity sweep:
/tmp/soak-driver run-7d  --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-inengine  --mode in-engine
/tmp/soak-driver run-30d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d-inengine --mode in-engine

# 5. Desktop:
export DAAL_ENGINE_LIB=/tmp/libdaalcore.so
cd /home/daal/client-desktop && cargo test --workspace
```

## Known limitations

- The auth-failed exemption is implemented at the seam in
  `core/proxy.PipeAuthGuarded`, but the engine has no in-tree relay
  outbound today. The seam ships pre-positioned for 2E (iOS) /
  whichever phase first wires sing-box. `core/budget` tests + the
  ABI integration test exercise the cap-boundary directly through
  `Engine.Add`.
- The `budgets` diagnostics array currently shows a `consumed_bytes`
  of zero for routes whose persisted bucket is stale (so a stale
  hour-bucket reads as "fresh" in the snapshot). The persisted row
  is rolled over either by the next `Add` or by the scheduler's
  hourly `budget-reset` action.

## Engine ABI version policy reminder

`daal-core 0.5.0+survivability` (unchanged through 2A). Release
surface 36. CI `nm` step in `.github/workflows/desktop.yml` should be
updated to expect 36.

V2 sub-phase order: **2F ✅ → 2A ✅ → 2A-Polish (NEXT) → 2B → 2C →
2D → 2G → 2E**.

## Faithfulness audit (April 2026) — drift to fix in 2A-Polish

A roadmap-faithfulness audit against `daal-roadmap-v3.md` V2.1
identified two gaps in what 2A landed:

1. The roadmap's V2.1 cap table specifies BOTH per-hour AND
   per-session caps (e.g., emergency 50 MiB/h **AND** 200 MiB/sess).
   2A only landed per-hour. **2A-Polish closes this** — adds the
   `Cap.Session` column, an in-process `sessionConsumed` map, and
   wires `engine_init` as the canonical session boundary.
2. The roadmap's V2.1 table's `Allowed modes` column was not
   encoded anywhere in `core/budget`. **2A-Polish closes this**
   too — `Cap.ModesAllowed` carries the column; the budget engine
   exposes it; pathmanager (2B) reads it for mode-aware ranking.

Both fixes are append-only at the engine boundary (no new ABI
function; `engine_export_diagnostics` widens its `budgets[]` rows
additively). `nm` count stays at 36. Engine version unchanged.

Spec amendments live in `specs/route-budgets-v1.md` and
`specs/engine-abi-v1.md`. Phase doc:
`13b-phase-2a-polish.md`.
