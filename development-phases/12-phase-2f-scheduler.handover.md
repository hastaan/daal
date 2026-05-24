# Phase 2F Handover

## What landed

`daal-core 0.5.0+survivability` (engine version bumped). Release ABI
surface 34 → 35. New crates / packages:

- `core/scheduler/` — pure planner + thin Scheduler wrapper. 7 source
  files (doc, plan, scheduler, plan_test, scheduler_test,
  parity_test).
- `core/abi/scheduler.go`, `scheduler_export.go`,
  `scheduler_gomobile.go` — host binding (Tauri / gomobile / cshared).
- `cmd/daal-soak-engine/main.go` — added `scheduler-status` and
  `scheduler-tick` commands.
- `test-rigs/distribution-failure/soak-driver/internal/soak/soak.go`
  — `Mode` enum + `Mode = ModeInEngine` driver.
- `test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go`
  — `--mode rig|in-engine` flag.

Updated:

- `core/abi/abi.go` — `Version` constant; `resetSchedulerForShutdown`
  in Shutdown.
- `core/abi/refresh_test.go` — version assertion.
- `client-desktop/daal-desktop-core/src/{engine,errors}.rs` — required
  prefix bumped to `daal-core 0.5`.
- `client-desktop/daal-desktop-core/tests/engine_load.rs` — version
  assertion + `scheduler_status` call.
- `client-desktop/tauri/src/App.tsx` — required prefix.
- `specs/engine-abi-v1.md` — surface count, version, two new function
  rows (subscription_list from 1.5C-Polish + scheduler_status).
- `specs/scheduler-v1.md` — new spec.

## Test results (last local run)

```
$ cd /home/daal/core && go test -count=1 ./...
ok  daal/core
ok  daal/core/abi
ok  daal/core/bootstrap
ok  daal/core/bootstrap/embedded
ok  daal/core/diagnostics
ok  daal/core/engine
ok  daal/core/pathmanager
ok  daal/core/refresh
ok  daal/core/routestore
ok  daal/core/scheduler              <-- new
ok  daal/core/share
ok  daal/core/trust

$ cd /home/daal/test-rigs/distribution-failure/soak-driver && \
  DAAL_REPO=/home/daal go test -count=1 ./...
ok  daal/soak-driver/internal/{artifacts,censor,clock,origin,wallclock}

$ cd /home/daal/client-desktop && \
  DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace
ok  bundle-rs (5+1)
ok  daal-desktop-core (engine_load + parity_with_go)
ok  daal-tun-helper (3 unit + 1 e2e)

$ nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'
35

$ cd /home/daal/test-rigs/distribution-failure/soak-driver
$ /tmp/soak-driver run-7d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-rig --mode rig
ALL SCENARIOS PASSED

$ /tmp/soak-driver run-7d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-inengine --mode in-engine
ALL SCENARIOS PASSED

$ /tmp/soak-driver run-30d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d-inengine --mode in-engine
ALL SCENARIOS PASSED
```

**The V2 entry-criterion ("the V2 scheduler must replay the 1.5C
30-day artifact and produce the same invariant ledger") is satisfied
in the lab.**

## Architectural decisions captured

See `specs/scheduler-v1.md`. The locked points:

1. `Plan` is a pure function. No clock reads, no I/O, no goroutines.
2. The Executor interface is the seam between the planner and the
   refreshers. Tests inject recorders.
3. Cadences are constants for revocation (6 h) and bootstrap (24 h).
   Subscription cadence is per-row from `profile_update_min`, clamped
   to `[60, 10080]` minutes by both the routestore writer AND the
   planner. Changing these constants breaks the parity contract and
   is a roadmap-level decision.
4. The bootstrap-refresh "last fired" timestamp persists in
   `secrets_kv` under `scheduler:last-bootstrap-refresh`. The next
   24-h gate then prevents re-firing.
5. Per-publisher revocation cadence is deferred to 2A; today the
   scheduler asks for revocation and the executor calls
   `RevocationRefresher.RefreshAll` (one sweep across all
   publishers).

## Carry-overs into 2A

- Per-publisher revocation cadence: the scheduler already plans
  per-publisher; it's the executor that fans out to RefreshAll.
  Splitting this is a one-line change in `refreshExecutor` once the
  Refresher exposes `Refresh(ctx, publisherID)`.
- Mode-aware cadence: lifeline mode should multiply subscription
  cadence by 1/0.33 ≈ 3 (refresh less often). The Cadence struct
  already accepts overrides; 2D wires it through.

## How to run locally

```sh
# Build the cshared engine (now 35 release symbols):
cd /home/daal/core
go build -tags cshared -buildmode=c-shared \
    -o /tmp/libdaalcore.so ./cmd/libdaalcore

# Verify symbol count and version:
nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'   # → 35

# Build the soak engine for `--mode in-engine`:
cd /home/daal/cmd/daal-soak-engine
go build -tags soak -o /tmp/daal-soak-engine-soak .

# Build the soak driver:
cd /home/daal/test-rigs/distribution-failure/soak-driver
go build -o /tmp/soak-driver ./cmd/soak-driver

# Parity sweep:
/tmp/soak-driver run-7d  --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-7d-inengine  --mode in-engine
/tmp/soak-driver run-30d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d-inengine --mode in-engine
```

## Engine ABI version policy

`daal-core 0.5.0+survivability` (bumped at 2F). Release surface 35.
Desktop required prefix: `daal-core 0.5`. CI `nm` step in
`.github/workflows/desktop.yml` should be updated to expect 35.

V2 sub-phase order (locked, scheduler-first):
2F → 2A → 2B → 2C → 2D → 2G → 2E. 2A is unblocked.
