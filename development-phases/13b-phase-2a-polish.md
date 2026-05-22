# Phase 2A-Polish — Per-Session Caps + `modes_allowed` Pre-Positioning

## Roadmap Coverage

V2.1 ("Route survivability — byte budgets per route, enforced in
engine"). 2A landed the **hourly** half of the V2.1 cap table; this
polish phase lands the **per-session** half plus the `modes_allowed`
column that 2B's mode-aware ranker reads.

A faithfulness audit (April 2026) against
`daal-roadmap-v3.md` showed 2A had drifted from the canonical V2.1
table on two axes:

1. The roadmap's V2.1 table specifies BOTH a per-hour cap AND a
   per-session cap (e.g., emergency 50 MB/h **AND** 200 MB/sess);
   2A only implemented per-hour. A long-running session on a small
   route could blow well past the per-session cap because no
   counter watched it.
2. The roadmap's V2.1 table includes a `Allowed modes` column
   (lifeline-only / lifeline,normal / all). 2A explicitly deferred
   `modes_allowed` to 2B, which is fine — but the *spec* did not
   say so explicitly, leaving the contract loose. This polish locks
   the deferral in writing and pre-positions the data path so 2B
   only adds the mode-aware filter.

The polish is **append-only** at the engine boundary: no new
release ABI function, no widening of `engine_set_route_budget`'s
argument list. Per-session counters reset on `engine_init` (≡ start
of a new session); `modes_allowed` is encoded into the closed cap
table in `caps.go` and surfaced through `engine_export_diagnostics`.

## Goal

1. Add a per-session byte counter alongside the existing per-hour
   counter. Both counters consult the same `Engine.Add` charge; the
   first to be exhausted returns `ErrExhausted`.
2. Encode the V2.1 `Allowed modes` column in `core/budget`'s closed
   tag table. The budget engine itself does NOT enforce mode
   filtering (that's pathmanager's job in 2B); it merely exposes
   the column to its callers.
3. Surface both new fields in `engine_export_diagnostics` output
   under `budgets[]` — `session_cap_bytes`, `session_consumed_bytes`,
   `modes_allowed[]`.
4. Wire a session boundary to `engine_init` / `engine_shutdown`.
   Every successful `engine_init` increments a process-local
   session epoch; the budget engine zeroes the per-session
   counters on epoch change.

## Scope

- `core/budget/caps.go` — extend the `caps` map's value type from
  `uint64` (hourly only) to a `Cap` struct holding hourly, session,
  and `modesAllowed`. Existing call sites stay source-compatible
  via `CapFor(tag) (uint64, error)` returning the hourly cap; new
  call sites use `FullCapFor(tag) (Cap, error)`.
- `core/budget/engine.go` — add `sessionConsumed map[string]uint64`
  + `sessionEpoch uint64` to `Engine`. Increment epoch via
  `Engine.NewSession()` (called from `engine_init`). `Add` charges
  both counters.
- `core/budget/persist.go` — session counters live in-process
  (NOT persisted across `engine_init` because the session boundary
  IS `engine_init`). The persistence layer keeps doing only hourly
  bucket work.
- `core/abi/budget.go` — `ensureBudget` calls `NewSession()`.
- `core/abi/abi.go::Init` (the file that owns `engine_init`)
  — every successful init increments the budget engine's session
  epoch via a new `bumpBudgetSessionForInit()` hook, mirroring the
  existing `resetBudgetForShutdown()` cleanup. The init-side hook
  AND the shutdown-side reset together enforce the canonical
  session boundary.
- `engine_export_diagnostics` — `budgets[]` rows widen to include
  `session_cap_bytes`, `session_consumed_bytes`, `modes_allowed`.
- **No new release ABI function.** Surface stays at **36**.
- Spec amendment: `specs/route-budgets-v1.md` adds the per-session
  column, the `modes_allowed` column, and the session-epoch
  semantics. The cap table becomes the canonical V2.1 table.
- Spec amendment: `specs/engine-abi-v1.md` documents the additive
  widening of `engine_export_diagnostics`'s `budgets[]` rows.

## Out of scope (deferred)

- **Mode-aware ranking** (in `bulk` mode, prefer `bulk-capable`
  first; `lifeline` mode multiplier on top of caps). Lands in 2B.
- **Mode-aware enforcement** (`lifeline` mode refusing to dial a
  `bulk-capable`-only route). Lands in 2B.
- **Per-network session counters** — sessions are device-local
  until 2C; a roam does not reset the per-session counter.

## Implementation Details

### `Cap` struct

```go
// core/budget/caps.go
type Cap struct {
    Hourly        uint64   // 0 == unlimited
    Session       uint64   // 0 == unlimited
    ModesAllowed  []string // sorted; closed set: lifeline, normal, bulk
}

var caps = map[string]Cap{
    TagEmergency:    {Hourly: 50 * MiB,   Session: 200 * MiB, ModesAllowed: []string{"lifeline"}},
    TagLifelineOnly: {Hourly: 100 * MiB,  Session: 500 * MiB, ModesAllowed: []string{"lifeline"}},
    TagLow:          {Hourly: 500 * MiB,  Session: 2 * GiB,   ModesAllowed: []string{"lifeline", "normal"}},
    TagNormal:       {Hourly: 5 * GiB,    Session: 0,         ModesAllowed: []string{"lifeline", "normal"}},
    TagBulkCapable:  {Hourly: 0,          Session: 0,         ModesAllowed: []string{"lifeline", "normal", "bulk"}},
    TagExperimental: {Hourly: 5 * GiB,    Session: 0,         ModesAllowed: []string{"lifeline", "normal"}}, // alias of normal
}

// `modes_allowed` lists the THREE roadmap V2.2 modes only —
// "lifeline", "normal", "bulk". The 2D-introduced `lifeline-strict`
// mode is treated as a strict super-set of `lifeline` for filtering
// purposes (a route allowed in "lifeline" is also allowed in
// "lifeline-strict"); the rank-time stability bias and bulk-capable
// refusal in `lifeline-strict` are pathmanager concerns, not
// budget-engine concerns. See specs/lifeline-mode-v1.md.

// CapFor preserves the existing 2A signature; it returns the hourly
// cap only.
func CapFor(tag string) (uint64, error) { ... }

// FullCapFor returns the entire Cap row.
func FullCapFor(tag string) (Cap, error) { ... }
```

### Session counters

```go
type Engine struct {
    store           Store
    now             func() time.Time
    mu              sync.Mutex
    sessionEpoch    uint64
    sessionConsumed map[string]uint64
}

// NewSession bumps the epoch and zeroes per-session counters. Called
// once per successful engine_init.
func (e *Engine) NewSession() {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.sessionEpoch++
    e.sessionConsumed = map[string]uint64{}
}
```

`Engine.Add` checks both counters:

```go
func (e *Engine) Add(routeID string, n uint64) error {
    // ... (existing hourly logic) ...
    cap, _ := FullCapFor(tag)
    if cap.Session > 0 {
        if e.sessionConsumed[routeID] >= cap.Session {
            return ErrExhausted
        }
        if e.sessionConsumed[routeID]+n > cap.Session {
            e.sessionConsumed[routeID] = cap.Session
            return ErrExhausted
        }
        e.sessionConsumed[routeID] += n
    }
    // ... (existing hourly write) ...
}
```

The hourly check still fires first if it would trip first; both
caps charge atomically under `e.mu`.

### Diagnostics widening

```json
{
  "budgets": [
    {
      "route_id": "abc",
      "budget_tag": "emergency",
      "hourly_cap_bytes": 52428800,
      "consumed_bytes": 12345,
      "session_cap_bytes": 209715200,
      "session_consumed_bytes": 45678,
      "modes_allowed": ["lifeline"],
      "exhausted": false
    }
  ]
}
```

Pre-2A-Polish callers that did not decode the new fields keep
working. The `exhausted` boolean is now true if EITHER counter is
at cap.

### Session boundary wiring

`core/abi/abi.go::Init` (the function that backs `engine_init`)
calls `bumpBudgetSessionForInit()` after the routestore is open
and before returning success. The hook calls
`budgetEngine.NewSession()` if the singleton is already
instantiated; otherwise it queues the bump for the lazy
`ensureBudget` to apply on first use.

`core/abi/abi.go::Shutdown` continues to call
`resetBudgetForShutdown()` (added in 2A); this drops the engine
singleton entirely. A clean shutdown followed by another `Init` is
the canonical session boundary, matching the user's mental model
of "I quit the app and re-opened it."

Mode changes (`engine_set_mode`) MUST NOT touch the session epoch.
Network changes (`engine_network_changed`, 2C) MUST NOT touch the
session epoch.

### `auth_failed` exemption

Unchanged from 2A. The `PipeAuthGuarded` seam still bypasses
`Engine.Add` entirely on auth failure; neither counter charges.

## Testing Requirements

- `core/budget/engine_test.go` — new tests:
  - `TestSessionCapTrips` — pick `emergency` (hourly 50 MiB,
    session 200 MiB). Drive 5 hourly-rollover charges of 50 MiB
    each (250 MiB cumulative if uncapped). The fakeClock advances
    by exactly 1 hour between charges so each hourly bucket
    starts fresh. Assert that `ErrExhausted` returns at 200 MiB
    cumulative — i.e., the session cap trips during the 4th
    charge, before the 5th hour rolls.
  - `TestSessionResetOnNewSession` — exhaust session, call
    `NewSession`, assert next `Add` succeeds and the in-process
    `sessionConsumed` map is empty.
  - `TestSessionCounterUnlimitedForBulkCapable` — driving 100 GiB
    through a `bulk-capable`-tagged route never exhausts on
    either axis.
  - `TestModeChangeDoesNotResetSession` — exhaust session, call
    `engine_set_mode` to change the mode, assert the next `Add`
    still returns `ErrExhausted` (mode change must not launder
    the session counter).
- `core/abi/budget_test.go` — assert `engine_export_diagnostics`
  returns `session_cap_bytes`, `session_consumed_bytes`, and
  `modes_allowed[]` populated correctly for each tag.
- `core/abi/abi_test.go` — extend the existing
  `Init`/`Shutdown` test to assert two `Init` calls bracket a
  session boundary; the second init's `bumpBudgetSessionForInit`
  zeroes per-session counters.
- Soak: extend `route-budget-exhaustion` to drive the 5-hour
  rollover sweep on an `emergency` route and assert exhaustion
  at the session cap (200 MiB) before the 5th hour rolls.
- `nm` count = **36** (unchanged).

## Exit criteria

1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **36**
   (no new functions).
2. Engine version unchanged at `daal-core 0.5.0+survivability`.
3. `core/budget`, `core/abi` tests green.
4. Extended soak scenario `route-budget-exhaustion` PASS in both
   modes; the per-session cap trips on the documented 5-hour
   sweep.
5. `specs/route-budgets-v1.md` shows the canonical V2.1 cap table
   with hourly + session + modes_allowed columns.
6. `specs/engine-abi-v1.md` notes the additive `budgets[]`
   widening.

## Handover to Phase 2B

Phase 2B receives:
- A budget engine that already exposes `modes_allowed` per tag.
  2B's mode-aware ranker simply filters / sorts using this column;
  the engine itself does not need to learn modes.
- Per-session counters that 2B's `EffectiveCap(routeID, mode)`
  multiplier slots into trivially: `effective.Session = session ×
  modeFactor[mode]` mirrors `effective.Hourly = hourly ×
  modeFactor[mode]`.
- An `engine_init`-bound session boundary that 2B's mode picker
  does NOT bump (mode change must NOT reset the session — that
  would be a budget-laundering bug).
