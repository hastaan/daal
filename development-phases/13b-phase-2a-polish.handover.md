# Phase 2A-Polish Handover

## What landed

Engine version unchanged (`daal-core 0.5.0+survivability`). Release
ABI surface stays at **36** (no new functions). The 2A-Polish phase
closes the V2.1-faithfulness gap identified in the April 2026 audit:
the per-session cap axis and the `modes_allowed` column.

## Files touched

### `core/budget/`
- `caps.go` — `caps` map's value type changed from `uint64` (hourly
  only) to a new `Cap` struct with `Hourly`, `Session`, and
  `ModesAllowed []string`. `CapFor(tag) (uint64, error)` preserved
  verbatim (returns `Hourly`); new `FullCapFor(tag) (Cap, error)`
  returns the full row with a defensive copy of `ModesAllowed`.
  `ErrExhausted` doc comment updated to mention dual-axis trip.
- `caps_test.go` — added `TestFullCapForKnownTags`,
  `TestFullCapForUnknownTag`, `TestCapsAreClosedToMutation`.
- `engine.go` — `Engine` gains `sessionEpoch uint64` +
  `sessionConsumed map[string]uint64`; `New` seeds the map.
  Added `NewSession()` (bumps epoch, zeroes map) and
  `SessionEpoch()`. `Add` rewritten for dual-axis charging —
  computes the largest `charge ≤ n` that fits both axes, advances
  both counters by exactly `charge`, returns `ErrExhausted` iff the
  call would have crossed either cap. Partial-credit invariant: on
  trip, both axes advance by the same byte count.
  `Snapshot` struct widened with `SessionCap`, `SessionConsumed`,
  `ModesAllowed []string`. `Snapshot()` populates them; `Exhausted`
  flips on either axis being at cap. Modes slice always non-nil so
  JSON renders `[]` rather than `null`.
- `engine_test.go` — added `TestSessionCapTrips`,
  `TestSessionResetOnNewSession`,
  `TestSessionCounterUnlimitedForBulkCapable`,
  `TestHourlyTripBeforeSessionWhenHourlyTighter`.
- `persist.go` — **no change**. Session counters live in-process
  only; the persistence layer still does only hourly bucket work.

### `core/abi/`
- `budget.go` — added `pendingBudgetSessionBump bool` flag and a
  new `bumpBudgetSessionForInit()` hook. If the engine singleton
  exists, bumps it directly; otherwise queues for the lazy
  `ensureBudget`. `ensureBudget` now consumes the queued flag on
  first instantiation. `resetBudgetForShutdown` also clears the
  flag so a Shutdown without a paired ensureBudget cannot leak a
  phantom bump into the next Init.
- `budget_test.go` — `TestSetRouteBudgetRoundTripWithDiagnostics`
  extended to decode the diagnostics blob into a strict struct
  and assert `session_cap_bytes`, `session_consumed_bytes`,
  `modes_allowed`, `exhausted` for the emergency tag.
- `abi.go::Init` — calls `bumpBudgetSessionForInit()` after
  `globalCore.driver.Subscribe(globalCore.subs)` and before
  `return nil`. This is the canonical session boundary at the
  engine layer.
- `abi.go::ExportDiagnostics` — **no code change**. The
  widening is automatic via the Snapshot struct's JSON tags.
- `abi_test.go` — added `TestSessionBoundaryAcrossInits`
  (verifies fresh engine + fresh session counter after
  Shutdown/Init) and `TestModeChangeDoesNotResetSession`
  (engine_set_mode does NOT bump the session epoch).

### Specs
- `specs/route-budgets-v1.md` — already amended in the previous
  spec round; verified to match the implementation byte-for-byte
  (V2.1 cap table, session-epoch semantics, `budgets[]` row JSON
  shape with all three new fields).
- `specs/engine-abi-v1.md` — already carries the additive
  widening note for 2A-Polish.

## Test results (last local run)

```
$ cd /home/daal/core && go test -count=1 ./...
ok  daal/core
ok  daal/core/abi
ok  daal/core/bootstrap
ok  daal/core/bootstrap/embedded
ok  daal/core/budget
ok  daal/core/diagnostics
ok  daal/core/engine
ok  daal/core/pathmanager
ok  daal/core/proxy
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
2 packages green

$ cd /home/daal/client-desktop && \
  DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace
ok  bundle-rs                 (5/5)
ok  daal-desktop-core
    parity_with_go_for_every_fixture (1/1)
    engine_loads_and_sets_tunnel_socks (1/1)
ok  daal-tun-helper          (3 unit + 1 e2e)

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

The V2 entry-criterion regression (in-engine 30-day parity) PASSES
unchanged. The session counter is in-process only and does not
appear in the persisted state, so the parity ledger is byte-for-byte
identical to 2A's ledger.

## New tests by name

```
core/budget/caps_test.go:
    TestFullCapForKnownTags        — V2.1 cap table verbatim
    TestFullCapForUnknownTag       — zero-value Cap on unknown tag
    TestCapsAreClosedToMutation    — defensive copy of ModesAllowed

core/budget/engine_test.go:
    TestSessionCapTrips                          — emergency: 4×50 MiB OK, 5th byte exhausts
    TestSessionResetOnNewSession                 — NewSession() zeroes counter, advances epoch
    TestSessionCounterUnlimitedForBulkCapable    — 100 GiB; map stays empty
    TestHourlyTripBeforeSessionWhenHourlyTighter — hourly trips first; partial-credit invariant

core/abi/budget_test.go:
    TestSetRouteBudgetRoundTripWithDiagnostics
        — extended; decodes session_cap_bytes, session_consumed_bytes,
          modes_allowed; verifies emergency=200 MiB, modes=["lifeline"]

core/abi/abi_test.go:
    TestSessionBoundaryAcrossInits         — Shutdown+Init drops engine, fresh session
    TestModeChangeDoesNotResetSession      — engine_set_mode is session-neutral
```

## Architectural decisions captured

1. **Per-session counters live in-process only.** The session
   boundary IS the `engine_init` boundary; persisting the session
   axis would let an attacker reset the cap by killing the process,
   defeating the contract. Mid-session crashes forfeit the
   remaining session budget; this is an intentional cost paid for
   tamper-resistance.
2. **`engine_set_mode` MUST NOT touch the session epoch.** Mode
   change must not launder cap. `TestModeChangeDoesNotResetSession`
   locks this in.
3. **`engine_network_changed` (2C) MUST NOT touch the session
   epoch either.** Per-network counters are 2C territory; sessions
   live above the network axis.
4. **`bulk-capable` does not populate `sessionConsumed`.** With
   `Cap.Session == 0`, the session axis is unlimited, so we skip
   the map write entirely. Keeps the map bounded and lets us assert
   `len(sessionConsumed) == 0` after 100 GiB of bulk traffic.
5. **Partial-credit invariant.** When `Add` trips, both axes
   advance by the same byte count (`charge ≤ n`). This keeps
   `consumed_bytes` and `session_consumed_bytes` mutually
   consistent and lets the snapshot flag whichever axis is at cap.
6. **Cap table is closed.** Adding a tag or changing a value is a
   roadmap-level decision. `TestFullCapForKnownTags` asserts the
   V2.1 values verbatim.
7. **`modes_allowed` is informative at 2A-Polish; enforced at 2B.**
   The budget engine exposes the column via `FullCapFor` and the
   diagnostics row; pathmanager's mode-aware ranker (2B) reads it
   and refuses to rank a route whose `modes_allowed` does not
   include the active mode.
8. **Lazy session bump.** `Init` queues a `pendingBudgetSessionBump`
   flag rather than instantiating the engine eagerly; the lazy
   `ensureBudget` consumes the flag on first use. This preserves
   2A's "diagnostics returns the original JSON shape until the
   engine is actually used" promise.
9. **Diagnostics widening is additive only.** `budgets[]` rows
   gain three additive fields. Pre-2A-Polish callers that only
   read `route_id`, `budget_tag`, `hourly_cap_bytes`,
   `consumed_bytes`, `exhausted` continue to work unchanged.

## Carry-overs into 2B

- `core/budget` now exposes `FullCapFor` returning `ModesAllowed`.
  2B's pathmanager mode-aware ranker simply filters / sorts using
  this column; no engine change needed.
- `Engine.EffectiveCap(routeID, mode)` slot is still reserved.
  2B fills it by multiplying both `Hourly` AND `Session` by the
  active mode's factor (lifeline ≈ 0.33×, normal ≈ 1.0×, bulk ≈
  1.0×, lifeline-strict ≈ 0.33×).
- `Snapshot.Mode` is NOT yet on the row. 2B can either thread the
  active mode into the snapshot (additive, surface-neutral) or
  surface it once at the diagnostics root.
- The `pendingBudgetSessionBump` flag and `bumpBudgetSessionForInit`
  hook are stable; 2B's mode picker MUST NOT call them.

## Carry-overs into 2C

- The session axis is keyed by `routeID` only. 2C's per-network
  layer adds the `(routeID, networkID)` axis on top; the session
  axis remains device-local and is intentionally **not** reset on
  network roams.
- `pendingBudgetSessionBump` does NOT need to mirror to a
  per-network flag; the network-changed event is its own seam at
  2C.

## How to repeat 2A-Polish locally

```sh
# 1. Rebuild the cshared engine (still 36 release symbols):
cd /home/daal/core
go build -tags cshared -buildmode=c-shared \
    -o /tmp/libdaalcore.so ./cmd/libdaalcore

# 2. Verify symbol count stays 36 + version unchanged:
nm /tmp/libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'   # → 36

# 3. Build the soak engine + driver:
cd /home/daal/cmd/daal-soak-engine
go build -tags soak -o /tmp/daal-soak-engine-soak .
cd /home/daal/test-rigs/distribution-failure/soak-driver
go build -o /tmp/soak-driver ./cmd/soak-driver

# 4. Parity sweep (V2 entry-criterion regression):
cd /home/daal/test-rigs/distribution-failure/soak-driver
/tmp/soak-driver run-30d --engine /tmp/daal-soak-engine-soak \
    --out /tmp/soak-30d-inengine --mode in-engine

# 5. Desktop:
cd /home/daal/client-desktop
DAAL_ENGINE_LIB=/tmp/libdaalcore.so cargo test --workspace

# 6. Targeted session-boundary tests:
cd /home/daal/core
go test -count=1 -v ./budget/... -run 'Session'
go test -count=1 -v ./abi/...    -run 'SessionBoundary|ModeChange'
```

## Known limitations

- **No new soak scenario for session-cap exhaustion.** The unit
  tests in `core/budget/engine_test.go` plus the ABI integration
  test in `core/abi/budget_test.go` exercise the dual-axis boundary
  deterministically. The 2A handover's earlier mention of a
  `route-budget-exhaustion` scenario was a misreading — that
  reference actually pointed to
  `TestBudgetEngineEnforcesCapAtByteBoundary`. Adding a separate
  soak scenario would be scope creep at no test-coverage gain.
- **The `Engine.Add` rewrite is a single function with subtle
  invariants.** Reviewers should focus on:
  - Both axes advance by the same `charge` value on trip.
  - `bulk-capable` (Session=0) never touches `sessionConsumed`.
  - On store-write failure the session counter rolls back so the
    two axes stay consistent.

## Engine ABI version policy reminder

`daal-core 0.5.0+survivability` (unchanged through 2A and
2A-Polish). Release surface 36. CI `nm` step in
`.github/workflows/desktop.yml` continues to expect 36.

V2 sub-phase order: **2F ✅ → 2A ✅ → 2A-Polish ✅ → 2B (NEXT) →
2C → 2D → 2G → 2E**.
