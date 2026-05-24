# Phase 2D — Lifeline Mode Strict Variant (Local Policy Only)

## Roadmap Coverage

V2.5 ("Lifeline mode (local policy only — relay deferred to V3)").
Closes 2C's carry-over ("a network the user has flagged as hostile
remembers it across sessions"). The roadmap is explicit about what
this phase IS and IS NOT:

> Lifeline mode in V2 is **purely local**: a user-selectable mode
> flag that changes how the path manager and route-budget engine
> behave. It is not a server-side relay, and shipping it does not
> require any new infrastructure.
>
> *No relay is involved; nothing leaves the device differently from
> Normal mode except for budget enforcement and route choice.*

The remote-fetch *relay* is V3.7 territory and only ships if a
partner is ready to operate it. 2D ships without it.

A previous draft of this phase doc (April 2026) drifted on two
axes:

1. It proposed filtering relay-class routes out of the ranker —
   that is **wrong**. Excluding relay routes would break messaging,
   search, and news for exactly the user this mode is for. The
   roadmap V2.5 is explicit: "no relay is involved … nothing leaves
   the device differently from Normal mode except for budget
   enforcement and route choice."
2. It named the new mode `lifeline-only`, which collides with the
   existing V2.1 budget *tag* `lifeline-only` (a `scarcity_class`
   value). To preserve the V2.1 cap-table tag namespace and keep
   the mode-string namespace clean, the V2D mode is named
   **`lifeline-strict`** at the engine boundary. The user-visible
   UI label can still read "Lifeline mode" or "Lifeline (local-only)"
   per the roadmap's prose; the rename is engine-internal.

This rewrite re-aligns 2D with the roadmap and resolves the
namespace collision.

## Goal

Add a fourth user-selectable mode, `lifeline-strict`, that:

1. Tightens route-budget caps by ~3× (factor 0.33×, identical to
   `lifeline`'s factor) — a `normal`-class route's hourly cap
   drops from 5 GiB to ~1.65 GiB in `lifeline-strict` mode, per
   the roadmap V2.5 example "5 GB → 1.5 GB."
2. Biases route selection toward stability over speed — prefer
   routes whose recent failure rate on this network is lowest,
   even if their measured throughput is lower.
3. Refuses to use `bulk-capable` routes for *general* traffic;
   reserves them for explicit user opt-in per session.
4. Disables background refresh of large content. Subscription
   refresh still runs, but only when actively triggered or when
   an existing subscription is approaching expiry.
5. Surfaces a permanent banner: *"Lifeline mode: bandwidth is
   conserved and bulk traffic is restricted. Switch to Normal for
   full apps and video."*

This is the user's "I am on a degraded connection; protect my
scarce routes from being burned by background traffic" switch.

## Roadmap-faithful semantics (what 2D is NOT)

Cross-referenced from `daal-roadmap-v3.md` V2.5:

- **NO relay-route filter.** All transport families remain
  selectable. The roadmap does not introduce a `Kind == relay`
  filter; relay is a V3 *infrastructure* concept, not a V2 route
  attribute.
- **NO server-side anything.** Nothing leaves the device
  differently from Normal mode except for budget enforcement and
  route choice.
- **NO disabling of subscription refresh entirely.** Refresh runs
  at *user trigger* or *near-expiry* only; a route that is about
  to expire still gets refreshed because losing the route is
  worse than the small refresh fetch.
- **NO automatic mode entry.** The user toggles into and out of
  `lifeline-strict` manually at 2D. 2G's burn detector adds
  opt-in auto-promotion.

## Mode-factor table (multiplicative on top of 2A-Polish caps)

The `lifeline-strict` factor is **0.33** (same as `lifeline`).
The roadmap example "5 GB → 1.5 GB" is precisely a 0.30× to 0.33×
reduction — we land at 0.33× to keep the multiplier set small and
predictable.

```go
// core/budget/effective.go
var modeFactor = map[string]float64{
    "lifeline":         0.33,  // 2B
    "normal":           1.0,   // 2B
    "bulk":             1.0,   // 2B (does not enlarge cap; bulk-capable only)
    "lifeline-strict":  0.33,  // 2D — same factor as lifeline; differs by behaviour
}
```

The DIFFERENCE between `lifeline` and `lifeline-strict` is
therefore NOT in the budget multiplier; it is in the four
behavioural changes (#2–#5 above). Both modes get the 0.33×
factor; they diverge on:

| Behaviour | `lifeline` | `lifeline-strict` |
|---|---|---|
| Budget multiplier | 0.33× | 0.33× |
| Stability-biased ranker | no | **yes** |
| `bulk-capable` for general traffic | allowed (deranked) | **refused** unless explicit per-session opt-in |
| Background subscription refresh | normal cadence | **only at expiry approach or user trigger** |
| Permanent banner | no | **yes** |
| Relay-route filter | (no) | **(no — explicitly NOT introduced)** |

## Scope

- **Mode flag** — extend `engine_set_mode` to accept
  `"lifeline-strict"`. ABI signature unchanged. Persisted
  per-network via 2C.
- **Stability-biased ranker** — `core/pathmanager/rank.go` adds a
  branch for `lifeline-strict` mode that ranks by recent
  failure-rate (per-network) ascending, not by least-burned.
  Falls back to least-burned within ties.
- **`bulk-capable` for general traffic refused** —
  `core/pathmanager/rank.go` filters `bulk-capable` OUT of the
  selectable set in `lifeline-strict` mode UNLESS a per-session
  opt-in flag is set. The opt-in flag is set by a one-shot
  affordance in the desktop UI (a checkbox under the mode picker:
  "Allow bulk-capable routes this session").
- **Subscription refresh gate** — `core/refresh.Refresher` gains
  a `mode-aware` predicate. In `lifeline-strict` mode, the
  cadence is honored ONLY when:
  - `time_until_expiry < 24h`, OR
  - the user explicitly triggered the refresh.
- **Permanent banner** — desktop Home shows a non-dismissible
  banner whenever the active mode is `lifeline-strict`. Persian
  + English copy. Banner uses the existing `data-banner-kind`
  CSS scaffold from 1.5C-Polish
  (`data-banner-kind="lifeline-strict"`).
- **No new ABI surface.** Surface stays at **37** (the +1 from 2C).
- Spec: new `specs/lifeline-mode-v1.md`; amend
  `specs/mode-budgets-v1.md` to document the fourth mode and
  the engine-vs-UI naming distinction.

## Out of scope (deferred)

- **Auto-entry to `lifeline-strict` on burn detection.** That is
  2G's scope (the burn detector + auto-promotion).
- **Server-side relay** (V3.7). The roadmap is explicit: ships
  only if a partner is ready; defaults to "does not ship" through
  V3 and V4.
- **iOS** — the mode is desktop + Android only at 2D. iOS lands
  at 2E.
- **Sneakernet / share-bundle integration as an only-data-plane.**
  The mode permits it (LAN sharing remains available because LAN
  sharing is not a "route" subject to mode filtering), but does
  not require it.

## Implementation Details

### Mode set

```go
package modes

const (
    Lifeline       = "lifeline"
    LifelineStrict = "lifeline-strict"
    Normal         = "normal"
    Bulk           = "bulk"
)
```

### Stability-biased ranker

```go
// core/pathmanager/rank.go
func Rank(rs []Route, mode string, snap budget.Snapshot, netmem netmem.View) []Route {
    rs = filterByModesAllowed(rs, mode)
    if mode == modes.LifelineStrict {
        rs = filter(rs, func(r Route) bool {
            // Refuse bulk-capable unless per-session opt-in.
            return r.Tag != budget.TagBulkCapable || sessionFlags.AllowBulkCapable
        })
        sort.SliceStable(rs, func(i, j int) bool {
            // Stability bias: ascending failure rate per this network,
            // tie-break by least-burned.
            fi := netmem.FailureRate(rs[i].RouteID)
            fj := netmem.FailureRate(rs[j].RouteID)
            if fi != fj {
                return fi < fj
            }
            return burnRatio(rs[i], snap) < burnRatio(rs[j], snap)
        })
        return rs
    }
    // ... existing ranking for lifeline / normal / bulk ...
    return rs
}
```

`netmem.FailureRate(routeID)` is a thin accessor over the
per-network memory's per-route success/failure counters added in
2C. Note `lifeline-strict` reuses the V2C `modes_allowed` filter
through a "treat lifeline-strict as a strict super-set of lifeline
for filtering" rule (a route allowed in `lifeline` is also
allowed in `lifeline-strict`); the strict-mode-only behavioural
deltas — bulk-capable refusal and stability bias — are applied on
top.

### Subscription refresh gate

```go
// core/refresh/refresher.go
func (r *Refresher) shouldFire(now time.Time, sub Subscription, mode string,
                                userTriggered bool) bool {
    if mode != modes.LifelineStrict {
        return /* existing cadence check */
    }
    if userTriggered {
        return true
    }
    // lifeline-strict: only fire if expiry is within 24h.
    return sub.ExpiresAt.Sub(now) <= 24*time.Hour
}
```

The scheduler's `subscription` action consults the mode through
a new `mode` argument on
`RefreshExecutor.RefreshSubscription`; the existing cadence stays
as the upper bound.

### Diagnostics

```json
{
  "mode": "lifeline-strict",
  "lifeline_strict_active_since": "2026-04-26T18:00:00Z",
  "session_allows_bulk_capable": false
}
```

The `relay_routes_filtered` field that an earlier draft proposed
is **removed** — there is no relay-route filter; emitting that
field would lie. The boolean `session_allows_bulk_capable` is the
only new diagnostic.

### Desktop UI

```
client-desktop/tauri/src/pages/Home.tsx
  + LifelineStrictBanner (permanent when active)
  + Mode picker now lists 4 options
  + AllowBulkCapableThisSession checkbox (visible only when mode == lifeline-strict)
client-desktop/tauri/src/i18n/{en,fa}.json
  + lifelineStrict.banner
  + lifelineStrict.modeLabel        // user-facing label, can read "Lifeline (local-only)"
  + lifelineStrict.modeDescription
  + lifelineStrict.allowBulkCapableThisSession
```

The banner is `data-banner-kind="lifeline-strict"` and uses the
same classification CSS scaffold the pointer-rotation banner
uses.

User-facing label policy: the `lifelineStrict.modeLabel` i18n key
can render as "Lifeline mode" or "Lifeline (local-only)" — both
match the roadmap's prose. The internal mode identifier
`lifeline-strict` is what the engine sees; the UI label is what
the user sees. They diverge intentionally to preserve the engine
namespace.

## Testing Requirements

- `core/pathmanager/rank_test.go`:
  - In `lifeline-strict` mode, `bulk-capable` routes are
    filtered out by default.
  - When `sessionFlags.AllowBulkCapable=true`, `bulk-capable`
    routes return to the selectable set, ranked according to
    stability bias.
  - **NO route with `Kind == "relay"` is filtered out** by the
    mode change — the test asserts a relay route remains
    selectable in every mode (including `lifeline-strict`).
- `core/budget/effective_test.go` — assert `lifeline-strict`
  and `lifeline` produce identical caps for every tag.
- `core/refresh/refresher_test.go` — table tests for the gate:
  user-triggered fires; expiry < 24h fires; otherwise does not
  fire in `lifeline-strict`.
- Soak: new scenario `lifeline-strict-policy` — the soak rig
  blackouts every relay channel EXCEPT one; the user
  (synthetic) toggles `lifeline-strict`; the rig asserts (a)
  the surviving relay route is STILL used (no relay filter),
  (b) `bulk-capable` routes are not selected by default, (c)
  subscription refresh does not fire on the rolling cadence
  alone. Runs in both `--mode rig` and `--mode in-engine`.
- Soak: new scenario `lifeline-strict-roam` — confirms 2C
  correctly remembers `lifeline-strict` on the `cafe-wifi`
  network and auto-restores it when the user roams back from
  `home-wifi`.
- Desktop e2e: switching to `lifeline-strict` renders the banner
  and the per-session opt-in checkbox; Persian copy renders RTL
  correctly.
- `nm` count still **37**.

## Exit criteria

1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **37**.
2. Engine version unchanged at `daal-core 0.5.0+survivability`.
3. `core/pathmanager`, `core/budget`, `core/refresh` tests green.
4. New soak scenarios green in both modes.
5. Desktop renders the four-option mode picker, the
   `lifeline-strict` banner, and the per-session bulk-capable
   opt-in checkbox; both languages.
6. `specs/lifeline-mode-v1.md` shipped; `mode-budgets-v1.md`
   amended; the spec text matches the roadmap's "no relay
   involved" wording verbatim and documents the
   engine-vs-UI naming split (`lifeline-strict` vs
   "Lifeline (local-only)").

## Handover to Phase 2G

Phase 2G receives:
- A working `lifeline-strict` mode that the burn detector can
  flip the user into automatically (with consent) at 2G.
- A network-memory layer that already remembers per-network
  `lifeline-strict` state.
- A stable mode-set the 1000-client soak can sweep across.
- An explicit non-feature: no relay filter, no server-side relay,
  no remote-fetch lifeline. V3.7's optional partner-operated
  relay is the next-and-only place where a remote-fetch endpoint
  enters the architecture.
