# Phase 2F — In-Engine Auto-Refresh Scheduler

## Roadmap Coverage

Closes the 1.5A carry-over ("auto-refresh scheduler") and satisfies
the V2 entry-criterion ("the V2 scheduler must replay the 1.5C rig's
30-day artifact and produce the same invariant ledger"). This is the
first sub-phase of V2; engine version bumps to
`daal-core 0.5.0+survivability`.

## Goal

Move the rig-side scheduler that the 1.5C blackout-soak driver carries
in its day loop into the engine itself, as a deterministic, pure-
planner + side-effecting executor. Cadence policy from V1.5.1 / V1.5.2:
subscriptions clamp to `[60, 10080]` minutes; revocation 6 h per
publisher; bootstrap 24 h.

## Scope

- New `core/scheduler/` package — pure `Plan(src, cad, now)` + thin
  `Scheduler` wrapper (Start / Stop / Tick / StatusJSON).
- One new release ABI function — `engine_scheduler_status`. Surface
  34 → 35.
- Soak-engine subcommands `scheduler-status` and `scheduler-tick` so
  the rig can drive the in-engine scheduler instead of the rig-side
  loop.
- `soak-driver --mode in-engine` — the parity flag. Drives the
  scheduler via `scheduler-tick`; the resulting invariant ledger
  must be PASS on every scenario × day combination.
- Engine version constant bump.
- Spec amendments: new `scheduler-v1.md`, amended
  `engine-abi-v1.md`.

## Out of scope (deferred)

- Per-publisher revocation cadence (currently the executor calls the
  existing `RevocationRefresher.RefreshAll`; per-publisher dispatch
  lands when 2A wires per-publisher cadence).
- Subscription cadence learning (the planner uses the row's stored
  `profile_update_min`; adaptive shortening on consecutive failures
  is a 2A budget concern).

## Implementation Details

### Plan (pure)

```go
func Plan(src Source, c Cadence, now time.Time) []Action
```

`Source` is a tiny snapshot interface — `Subscriptions()`,
`PublishersWithRevocation()`, `LastBootstrapRefresh()`. The engine's
binding reads from `routestore.Store`; tests use a stub. `Plan` does
NOT call `time.Now`. Outputs are sorted by `(kind, ref)` for
determinism. Items with `LastGoodRefresh.IsZero()` are returned with
`next_due = now − 1 ns` so first-tick fires.

### Scheduler

```go
type Scheduler struct { ... }
func New(src Source, exe Executor, cad Cadence) *Scheduler
func (s *Scheduler) Tick(now time.Time)
func (s *Scheduler) Start(ctx context.Context)
func (s *Scheduler) Stop()
func (s *Scheduler) StatusJSON() ([]byte, error)
```

`Executor` interface has three methods (RefreshSubscription,
RefreshRevocation, RefreshBootstrap); the production binding in
`core/abi/scheduler.go` delegates to the existing `refresh.Refresher`,
`RevocationRefresher`, and `bootstrap.Provider`. Tests use a recorder.

### ABI

```c
int engine_scheduler_status(char* out, int out_len);
```

Schema: see `specs/scheduler-v1.md`. Surface 34 → 35.

### Engine version

```go
const Version = "daal-core 0.5.0+survivability"
```

The desktop's required prefix moves from `daal-core 0.4.1` to
`daal-core 0.5`. The Tauri app's ABI mismatch banner copy follows.
Release CI `nm` count now expects 35.

### Parity surfaces

1. **Unit-level** —
   `core/scheduler/parity_test.go::TestParity30DayLedger` — replays
   a synthetic 30-day source-state series through `Plan` and asserts
   byte-identical ledgers across re-runs and re-instantiation.

2. **Soak-level** — `soak-driver run-30d --mode in-engine`. Drives
   the in-engine scheduler via `scheduler-tick` instead of the
   rig-side per-day command sweep.

## Testing Requirements

- Unit tests for `Plan` (clamps, ordering, never-refreshed-is-due,
  recently-refreshed-not-due).
- Unit tests for `Scheduler` (invokes every due action, tolerates
  executor errors, Start/Stop, StatusJSON shape).
- Parity unit test (`TestParity30DayLedger`).
- `soak-driver run-7d --mode in-engine` and
  `run-30d --mode in-engine` both green on all 5 scenarios.
- `engine_load.rs::engine_loads_and_sets_tunnel_socks` extended to
  call `scheduler_status` and assert the response shape.
- All existing core / bundle / soak-driver / desktop tests still
  green.

## Exit criteria

1. Surface count = 35 (`nm libdaalcore.so | grep ...`).
2. Engine version = `daal-core 0.5.0+survivability`.
3. Desktop `cargo test --workspace` green with the 0.5.0 engine.
4. `core/scheduler` package fully tested.
5. Parity unit test green.
6. Soak-driver `run-30d --mode in-engine` ALL SCENARIOS PASSED.
7. `specs/scheduler-v1.md` and amended `engine-abi-v1.md` shipped.

## Handover to Phase 2A

Phase 2A receives:
- A 35-function release ABI ready for one more append:
  `engine_set_route_budget` (35 → 36).
- An in-engine scheduler the route-budget code can re-use as the
  cadence layer for budget-cleanup tasks.
- A wired `nowUTC()` clock that the budget engine inherits for free.

V2 sub-phase order from the master spec (locked at scheduler-first):
2F → 2A → 2B → 2C → 2D → 2G → 2E.
