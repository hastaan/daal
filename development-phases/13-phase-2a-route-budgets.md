# Phase 2A — Route Budget Engine

## Roadmap Coverage

V2.1 ("Route survivability — byte budgets per route, enforced in
engine"). Implements V2.1's quota schedule:

| Tag | Hourly cap |
|---|---|
| `emergency` | 50 MB |
| `lifeline-only` | 100 MB |
| `low` | 500 MB |
| `normal` | 5 GB |
| `bulk-capable` | unlimited (NULL) |

Closes the carry-over from 2F ("per-publisher revocation cadence; mode
multipliers wire through `Cadence` overrides") by introducing the
authoritative byte counter the rest of V2 builds on.

## Goal

Make Daal middleware the **authoritative byte counter** for every
proxied byte. Clash's stats are display-only. The engine enforces a
per-route per-hour cap derived from the route's `budget_tag`. When
the cap is reached, the route is moved to a `BudgetExhausted` cooldown
until the rolling hour resets.

`auth_failed` errors are exempt — a failed authentication MUST NOT
count against the route's budget (otherwise a single misconfigured
upstream could drain a healthy route).

## Scope

- New `core/budget/` package — `Engine{ Add(routeID, n) error;
  Snapshot() Snapshot; Reset(routeID) }`. Hourly windowing. Persist
  per-route counters across engine restart in
  `secrets_kv` under `budget:<routeID>:<hourBucket>`.
- Daal middleware integration — every byte that crosses
  `core/proxy.Pipe` (sing-box inlet → outlet) is `Add`-counted.
  Existing pipe integrates through a `byteCounter` interface so tests
  inject a recorder.
- New release ABI function `engine_set_route_budget(route_id,
  budget_tag)`. Surface 35 → **36**.
- Status JSON in `engine_export_diagnostics` gains a `budgets` array:
  `[{ "route_id":"...", "budget_tag":"normal",
       "hourly_cap_bytes":N, "consumed_bytes":N,
       "consumed_at":"YYYY-MM-DDTHH:00:00Z",
       "exhausted":bool }]`.
- Cooldown FSM expansion — `BudgetExhausted` state alongside the
  existing cooldown set. Transitions back to Healthy at the next hour
  bucket. The full 8-state FSM is 2B's scope; 2A only adds this one
  state.
- `auth_failed` exemption — `core/proxy.Pipe` checks the upstream
  error class and skips `Add` when the connection failed
  authentication.
- Spec: new `specs/route-budgets-v1.md`; amend
  `specs/engine-abi-v1.md` to surface 36; amend
  `specs/scheduler-v1.md` (executor signature gains
  `RefreshBudgetReset(now)` for the hourly reset task).

## Out of scope (deferred)

- **Mode multipliers** (lifeline 0.33×, normal 1.0×, bulk unlocks
  bulk-capable). Lands in 2B alongside the full mode-budget UI.
- **Per-network memory** of consumed bytes (so a budget is not reset
  when the user roams networks). Lands in 2C.
- **Route prioritisation under exhaustion** — falling through from a
  budget-exhausted route to the next-best route is the FSM's job and
  is fully wired in 2B.
- **UI** — surfacing the `budgets` array in the desktop banner. 2B.

## Implementation Details

### Package layout

```
core/budget/
  doc.go
  engine.go        # Engine + Snapshot + hour windowing
  engine_test.go
  caps.go          # tag → cap_bytes lookup
  caps_test.go
  persist.go       # secrets_kv (de)serialisation
  persist_test.go
```

### Engine

```go
package budget

type Snapshot struct {
    RouteID        string
    BudgetTag      string
    HourlyCap      uint64    // 0 == unlimited
    ConsumedBytes  uint64
    HourBucket     time.Time // truncated to the hour, UTC
    Exhausted      bool
}

type Engine struct { ... }

// New constructs an Engine. `now` is the clock — production binding
// passes nowUTC; tests pass an injected clock.
func New(store secretskv.Store, now func() time.Time) *Engine

// SetTag assigns or updates the route's budget tag. Idempotent.
// Returns ErrUnknownTag if tag is not in caps.go.
func (e *Engine) SetTag(routeID, tag string) error

// Add charges n bytes against routeID at the current hour bucket.
// Returns ErrExhausted if the route's hourly cap is exceeded; the
// caller MUST treat this as a soft fail and stop pushing more bytes.
// Idempotent under truncated retries (the caller handles the partial
// write itself).
func (e *Engine) Add(routeID string, n uint64) error

// Snapshot returns the current per-route view. Sorted by route_id for
// stability.
func (e *Engine) Snapshot() []Snapshot

// Reset clears the consumed-bytes counter for routeID at the current
// hour bucket. Used by the scheduler at hour rollover.
func (e *Engine) Reset(routeID string)
```

### Hourly windowing

The hour bucket is `now.Truncate(time.Hour).UTC()`. On every `Add`,
the engine compares the route's cached bucket with the current
bucket; on mismatch, the counter zeroes and the new bucket replaces
the old one. The persistence key is
`budget:<route_id>:<RFC3339-hour-bucket>`. Old keys age out via a
sweep at the top of each hour from the scheduler.

### Caps

```go
package budget

const (
    Emergency     = "emergency"
    LifelineOnly  = "lifeline-only"
    Low           = "low"
    Normal        = "normal"
    BulkCapable   = "bulk-capable"
)

var caps = map[string]uint64{
    Emergency:    50 * 1024 * 1024,
    LifelineOnly: 100 * 1024 * 1024,
    Low:          500 * 1024 * 1024,
    Normal:       5 * 1024 * 1024 * 1024,
    BulkCapable:  0, // unlimited
}
```

The map is closed; new tags require a roadmap-level decision. `0`
means unlimited and the engine NEVER returns `ErrExhausted` for that
route.

### Daal middleware integration

```go
// core/proxy/pipe.go (existing)
func Pipe(ctx context.Context, in, out net.Conn, c Counter) error
```

`Counter` is a one-method interface:

```go
type Counter interface {
    Add(routeID string, n uint64) error
}
```

The existing `Pipe` already does the byte-shovelling; we add an
`Add` after every successful `out.Write`. On `ErrExhausted`, the
pipe closes both sides cleanly and returns; the FSM observes this
and transitions to `BudgetExhausted`.

The auth exemption is a guard at the entry of `Pipe`:

```go
if isAuthFailed(err) {
    // Do not call counter.Add. The connection drops without
    // burning the route's budget.
    return err
}
```

The `isAuthFailed` predicate inspects the upstream sing-box dialer
error class.

### ABI surface

Append-only:

```c
int engine_set_route_budget(const char* route_id,
                            const char* budget_tag,
                            char* out, int out_len);
```

Returns `{"applied":true, "route_id":"...", "budget_tag":"...",
"hourly_cap_bytes":N}`. `N=0` for `bulk-capable`. `ErrUnknownTag`
returns negative + `{"error":"unknown_budget_tag"}`.

Surface 35 → **36**.

### Cooldown FSM addition

Today the FSM has Healthy + a small set of cooldown reasons (probe
fail, etc). 2A adds:

```
[Healthy] --on Add() returning ErrExhausted--> [BudgetExhausted]
[BudgetExhausted] --on next hour bucket--> [Healthy]
```

Transitions are observed by the existing pathmanager; 2A does not
restructure the FSM (2B does that).

### Scheduler integration

The scheduler's executor gains:

```go
RefreshBudgetReset(ctx context.Context, now time.Time) error
```

Cadence: at the top of every hour. The planner emits a `budget-reset`
action; the executor calls `budget.Engine.HourRollover(now)` which
sweeps stale keys and refreshes the per-route bucket.

## Testing Requirements

- Unit tests for `core/budget/`:
  - Tag lookup / ErrUnknownTag.
  - Hourly windowing (Add at HH:59:59 + Add at HH+1:00:00 → counters
    are independent).
  - Snapshot ordering (stable by route_id).
  - Persistence round-trip across `New`/`SetTag`/`Add`.
  - `bulk-capable` never returns ErrExhausted.
- Unit tests for the auth-failed exemption (recording counter, fake
  upstream that returns the auth-failed sentinel).
- Integration test in `core/abi/`: `engine_set_route_budget` then
  `engine_export_diagnostics` shows the route in `budgets`; refusing
  an unknown tag returns the documented error.
- Soak-driver: a new scenario (`route-budget-exhaustion`) drives 1
  KiB writes to a 50 MB-tagged route past 50 MB and asserts the FSM
  moves to BudgetExhausted at exactly the right byte and that the
  route returns to Healthy at the next simulated hour bucket. The
  scenario runs in both `--mode rig` and `--mode in-engine`.
- `engine_load.rs` extended to call `engine_set_route_budget` on a
  fresh state and read back the diagnostics export.
- `nm` count = 36.

## Exit criteria

1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **36**.
2. Engine version unchanged at `daal-core 0.5.0+survivability`.
3. `core/budget` and `core/abi` tests green.
4. New soak scenario `route-budget-exhaustion` PASS in both modes.
5. All existing core / bundle / soak-driver / desktop tests still
   green (no regressions).
6. `specs/route-budgets-v1.md` shipped; `engine-abi-v1.md` and
   `scheduler-v1.md` amended.

## Handover to Phase 2B

Phase 2B receives:
- A 36-function release ABI ready for the FSM expansion (no new ABI
  for FSM internals; 2C adds `engine_network_changed`).
- A budget engine that already understands tag → cap. Mode multipliers
  fold in by wrapping `caps[tag]` with the active mode's factor at
  read time; the underlying counter does not change.
- A `BudgetExhausted` cooldown state to slot into the 8-state FSM.
- The auth-failed exemption pattern, reusable for other classes of
  free transport (e.g., handshake bytes, control-plane traffic).
