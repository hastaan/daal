# Route Budgets v1

## Status

**Frozen at the end of Phase 2A; widened additively at Phase
2A-Polish; mode-multiplier wiring landed at Phase 2B.** The cap
table (hourly + session + allowed-modes), hour-bucket semantics,
session-epoch semantics, and ABI shape are part of the V2
entry-criterion contract. Mode multipliers (`lifeline` 0.33×,
`normal` 1.0×, `bulk` 1.0×, `lifeline-strict` 0.33×) ride on top
of this engine — see `specs/mode-budgets-v1.md` for the V2.2 mode
spec; per-network bucketing rides on top in 2C. The
`lifeline-strict` mode shares the 0.33× factor with `lifeline`; it
differs by *behaviour* (stability-biased ranker, `bulk-capable`
refused for general traffic, refresh gate, permanent banner), not
by multiplier. Adding a tag or changing a cap is a roadmap-level
decision because it breaks the V2 success-metric soak parity.

Phase 2B threading note: `Engine.Add` and `Engine.Snapshot` now
consult `ModeFactor(e.mode)` and surface the *effective*
(post-multiplier) caps. `Engine.SetMode(mode)` is called by
`abi.SetMode` after validation; mode change MUST NOT bump the
session epoch (2A-Polish rule) and MUST NOT clear hourly counters
(rolling caps are mode-neutral; only the ceiling moves).

Naming note: the budget **tag** `lifeline-only` (V2.1 row 2) is a
*scarcity_class* value attached to a route. It is distinct from the
2D *mode* `lifeline-strict`. The two namespaces never overlap; a
`lifeline-only`-tagged route is selectable in any mode whose
`modes_allowed` includes the active mode.

## Roadmap coverage

V2.1 ("Route survivability — byte budgets per route, enforced in
engine"). Closes the 1.5A carry-over ("budget engine is a V2 entry
item; today we just stamp `bytes_used_this_hour` on `routes` rows
without enforcement").

## Goal

Make Daal middleware the **authoritative byte counter** for every
proxied byte. Clash / sing-box stats are display-only. The engine
enforces a per-route hourly cap derived from the route's
`scarcity_class` (a.k.a. `budget_tag`). Crossing the cap moves the
route into `StateBudgetExhausted`; the cap resets at the next hour
bucket via the scheduler's `budget-reset` action.

`auth_failed` errors are exempt — a failed authentication MUST NOT
count against the route's budget (otherwise a single misconfigured
upstream could drain a healthy route through retries).

## Cap table

This is the canonical V2.1 table. All three columns — hourly,
session, allowed-modes — are part of the closed cap map and the V2
entry-criterion soak parity contract.

| Tag | Hourly cap | Session cap | Allowed modes |
|---|---|---|---|
| `emergency` | 50 MiB | 200 MiB | `lifeline` |
| `lifeline-only` | 100 MiB | 500 MiB | `lifeline` |
| `low` | 500 MiB | 2 GiB | `lifeline`, `normal` |
| `normal` | 5 GiB | unlimited | `lifeline`, `normal` |
| `bulk-capable` | unlimited | unlimited | `lifeline`, `normal`, `bulk` |
| `experimental` | 5 GiB | unlimited | `lifeline`, `normal` |

`unlimited` means `Engine.Add` never returns ErrExhausted on that
axis for the row. `0` is the in-code representation of unlimited.

The map is closed; new tags require a roadmap-level decision and a
roll of the V2 success-metric soak.

### Phase 3A interaction with new transport families

Phase 3A introduces the V3 transport-family taxonomy in
`specs/transport-families-v1.md`. Budget computation is
family-agnostic at the engine level: a `webtunnel` route at
scarcity class `normal` is charged identically to a
`vless-reality` route at scarcity class `normal`. The cap
table above is unchanged and remains closed.

One per-family parse-time rule does land at 3A:
**`transport_family: webtunnel` is REJECTED at parse time
when `scarcity_class: bulk-capable`** (per
`specs/webtunnel-route-v1.md`). The WebTunnel bridge model is
not capacity-rated for bulk traffic; the rule prevents
publishers from pinning a `bulk-capable` budget tag on a
WebTunnel route at all. Other 3A-era families (the rest of
the V3.x families add families later) inherit the full cap
table without restriction; family-specific scarcity-class
exclusions, if any, ride in their own per-family specs and are
enforced by the bundle parser, NOT by `core/budget`.

### Allowed-modes column (informative at 2A; enforced at 2B)

The budget engine exposes `modes_allowed` to its callers but does
NOT itself filter by mode. The pathmanager's mode-aware ranker
(Phase 2B) reads this column and refuses to rank a route whose
`modes_allowed` does not contain the active mode. This split keeps
`core/budget` policy-free; it counts bytes and exposes constants,
nothing else.

## Hour-bucket semantics

The hour bucket is `now.Truncate(time.Hour).UTC()`. Every `Add` call
compares the route's persisted bucket cursor with the current bucket;
on mismatch the counter zeroes before charging the new bytes. The
bucket cursor lives in `secrets_kv` under `budget:bucket:<route_id>`
(RFC3339 string); the consumed counter lives in
`routes.bytes_used_this_hour`.

The scheduler's `budget-reset` action (see
`specs/scheduler-v1.md`) fires every hour and calls
`Engine.HourRollover(now)`, which sweeps every known route in one
pass.

## Session-epoch semantics

A *session* is the lifetime between one successful `engine_init` and
the next. Every `engine_init` call invokes
`Engine.NewSession()`, which:

- Increments an in-process session epoch counter.
- Zeroes the in-memory `sessionConsumed` map.

Per-session counters are deliberately **not persisted** across
`engine_init`. The session boundary IS the init boundary; persisting
session counters would let an attacker who restarted the process
re-roll the cap. The engine being killed mid-session forfeits any
remaining session budget, which is an intentional (small) cost paid
to keep the session-cap contract simple and tamper-resistant.

Mode changes (`engine_set_mode`) MUST NOT bump the session epoch.
Doing so would let a user launder budget between modes by toggling
the mode dial.

Network changes (`engine_network_changed`, Phase 2C) MUST NOT bump
the session epoch either; per-network counters live elsewhere
(per-network memory in 2C), not on the session axis.

## Auth-failed exemption

`core/proxy.PipeAuthGuarded(ctx, dst, src, routeID, counter, opts,
preflight)` is the canonical seam. If `preflight != nil` and
`IsAuthFailed(preflight) == true`, `Pipe` is NOT invoked and zero
bytes are charged. Outbound dialer integrations that have classified
the upstream error MUST route through this seam; a direct call to
`Pipe` after a successful handshake is also fine because there is no
auth state to leak.

## ABI

One new release function lands at Phase 2A (count 35 → 36):

```c
int engine_set_route_budget(const char* route_id,
                            const char* budget_tag,
                            char* out, int out_len);
```

Behavior:

- Validates `budget_tag` against the closed cap map; rejection writes
  `{"error":"unknown_budget_tag","tag":"..."}` to the output buffer
  and returns `-1`.
- On success, calls `routestore.Store.UpdateRouteScarcity` and
  returns
  `{"applied":true,"route_id":"...","budget_tag":"normal","hourly_cap_bytes":N}`
  with `N=0` for `bulk-capable`.

`engine_export_diagnostics` widens its body additively with a
`budgets` array; existing fields are unchanged. The array is rendered
only when the budget engine has been instantiated (an
`engine_set_route_budget` call or any successful `Engine.Add`),
preserving the pre-2A JSON shape for callers that have not yet
updated.

The `budgets[]` row shape, after the 2A-Polish widening:

```json
{
  "route_id": "...",
  "budget_tag": "emergency",
  "hourly_cap_bytes": 52428800,
  "consumed_bytes": 12345,
  "session_cap_bytes": 209715200,
  "session_consumed_bytes": 45678,
  "modes_allowed": ["lifeline"],
  "exhausted": false
}
```

`exhausted` is true when EITHER counter is at cap. `0` in
`hourly_cap_bytes` or `session_cap_bytes` means unlimited on that
axis.

## FSM

`core/pathmanager` adds one state at 2A:

```
StateBudgetExhausted
```

Two new transitions:

- `Healthy --on Add() returning ErrExhausted--> BudgetExhausted`
- `BudgetExhausted --on next hour bucket--> Healthy` (driven by the
  scheduler's `budget-reset` action plus `Engine.HourRollover`)

The full 8-state FSM expansion is 2B's scope; 2A keeps the addition
minimal.

## Scheduler integration

`core/scheduler` gains a fourth Kind:

```go
KindBudgetReset Kind = "budget-reset"
```

Cadence: 1 h. Source carries `LastBudgetReset()` for deterministic
plan replay; the executor's `RefreshBudgetReset(ctx, now)`
implementation calls `Engine.HourRollover(now)` and stamps
`secrets_kv["scheduler:last-budget-reset"]`.

The 30-day parity test
(`core/scheduler/parity_test.go::TestParity30DayLedger`) sees
`budget-reset:` rows once per simulated hour. The expected ledger
already accommodates this addition because the synthetic source's
`LastBudgetReset()` returns zero at start and is stamped on every
fire — exactly the same pattern as bootstrap.

## Privacy invariants

- The budget engine does NOT inspect payload contents.
- The diagnostics `budgets` array surfaces only the route_id, the
  budget tag, the hourly cap (a public constant), the consumed byte
  count for the current hour bucket, and a boolean exhaustion flag.
  No URLs, no peer addresses, no protocol bytes.
- The hour bucket is hour-truncated (per V0.3 redaction policy);
  it leaks at most a 1-hour window of activity timing.

## Stability

- The cap table and the cadence (1 h budget-reset) are part of the
  V2 entry-criterion parity contract.
- `engine_set_route_budget` is append-only; the function signature
  MAY NOT change.
- The diagnostics `budgets` array is widened additively only.

## 2C cross-reference: per-network memory

At Phase 2C the budget engine grows a `(SetActiveNetwork,
CaptureNetwork, RestoreNetwork)` triple keyed by the V2.4 network
hash (`specs/network-memory-v1.md`). The persisted hourly counter
remains device-wide on the storage axis (so the V2 entry-criterion
30-day soak parity is preserved byte-for-byte). The per-network
restore rides on top: on `engine_network_changed`, the engine
captures the outgoing network's per-route hourly snapshot,
overlays the incoming network's snapshot if present, and tags
new accruals with the active network so the next capture is
clean. Pre-2C callers that do not call `SetActiveNetwork` observe
the legacy single-bucket behaviour unchanged.

## Files

- `core/budget/doc.go`
- `core/budget/caps.go` — closed cap map + KnownTags
- `core/budget/caps_test.go`
- `core/budget/engine.go` — Engine, Snapshot, HourRollover
- `core/budget/engine_test.go`
- `core/budget/persist.go` — `RoutestoreStore` binding
- `core/budget/persist_test.go`
- `core/proxy/doc.go`
- `core/proxy/classes.go` — `AuthFailedSentinel`, `IsAuthFailed`
- `core/proxy/classes_test.go`
- `core/proxy/pipe.go` — `Pipe`, `PipeAuthGuarded`, `Counter`
- `core/proxy/pipe_test.go`
- `core/abi/budget.go` — `SetRouteBudget` + lazy `ensureBudget`
- `core/abi/budget_export.go` — `engine_set_route_budget` cshared
- `core/abi/budget_gomobile.go` — gomobile facade
- `core/abi/budget_test.go` — round-trip + cap-boundary tests
- `core/pathmanager/fsm.go` — `StateBudgetExhausted`, `BudgetExhausted()`
- `core/scheduler/plan.go` — `KindBudgetReset` + `LastBudgetReset()`
- `core/scheduler/scheduler.go` — `Executor.RefreshBudgetReset`
- `core/abi/scheduler.go` — `LastBudgetReset` source +
  `RefreshBudgetReset` executor
- `cmd/daal-soak-engine/main.go` — `set-route-budget` and
  `export-diagnostics` commands
- `test-rigs/.../soak-driver/internal/client/client.go` — wrappers
- `client-desktop/daal-desktop-core/src/engine.rs` —
  `set_route_budget` symbol resolution + Rust wrapper
- `client-desktop/daal-desktop-core/tests/engine_load.rs` —
  asserts unknown-tag rejection round-trips through dlopen

## Phase 2D amendment

The `bulk-capable` family is the canonical filtered family in
`lifeline-strict`. Default behaviour: routes whose
`route.bulk_capable == true` are filtered out of the
lifeline-strict ranker output. The user can opt back in for the
session via `engine_set_allow_bulk_capable(1)`; the flag is
cleared by `NewSession` and is surfaced in diagnostics as
`session_allows_bulk_capable: bool`. See `lifeline-mode-v1.md`.
