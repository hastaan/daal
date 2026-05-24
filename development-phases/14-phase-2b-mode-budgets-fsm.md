# Phase 2B — Mode Budgets + V2.3 8-State FSM

## Roadmap Coverage

V2.2 ("Mode budgets — three modes ride on top of 2A's per-route
caps") + V2.3 ("Cooldown FSM — exactly the eight named states the
roadmap freezes; no machine learning"). Builds directly on 2A's
budget engine and 2A-Polish's `modes_allowed` column.

## Goal

1. Wire mode multipliers (`lifeline 0.33×`, `normal 1.0×`,
   `bulk 1.0×`) on top of 2A's per-route hourly + session caps.
   `bulk` mode does NOT enlarge caps; it unlocks `bulk-capable`
   routes via the `modes_allowed` filter.
2. Replace the existing ad-hoc `Healthy / Connecting / Connected /
   Cooldown / Failed / BudgetExhausted` enum with the V2.3
   canonical **8-state FSM** at the *application-posture* layer.
   Per-route cooldown reasons are an orthogonal attribute keyed
   strictly by the V0.3 failure taxonomy.
3. Surface mode + per-route budget consumption + per-route
   cooldown reason on the desktop.

## Roadmap-faithful FSM (V2.3)

The roadmap names exactly eight application-posture states. Every
in-progress draft of 2B that drifted from these names is wrong; the
spec freezes at **these**:

| State | Meaning |
|---|---|
| `NoRoute` | No usable route in the store. UI prompts the user to import or share. |
| `BootstrapDiscovery` | Tier-2 seeds + Tier-1 directory pointers active; trying to fetch a real directory through any working tunnel. |
| `ImportedActive` | A subscription / paste / file-import route is selected and pumping bytes. |
| `SharedActive` | A friend-shared `.sbp` route is selected and pumping bytes. |
| `Recovery` | The previous active route just failed; attempting next-best in shortlist. |
| `Lifeline` | User has selected lifeline budget mode. (Distinct from 2D's `LifelineOnly` mode, which is local-only.) |
| `OfflineSharing` | The user is sending or receiving an `.sbp` over LAN / animated QR; tunnel may or may not be up. |
| `Experimental` | An Experimental-feature-flag transport family is selected; UI shows the warning. |

These are the user-facing *posture* states. They DO NOT enumerate
every possible per-route cooldown reason — the roadmap's V0.3
taxonomy is the canonical cooldown-reason set, and a route in any
of `BootstrapDiscovery`, `ImportedActive`, `SharedActive`,
`Recovery`, `Lifeline`, `OfflineSharing`, `Experimental` may have
zero, one, or many routes in cooldown for a V0.3 reason at any
moment.

## V0.3 cooldown-reason attribute (per-route, orthogonal)

Cooldown reasons are taken **verbatim** from
`specs/failure-taxonomy-v1.md`. Per-route state is therefore a
two-tuple `(posture, cooldownReason | nil)`:

```go
// core/pathmanager/fsm.go
type Posture string

const (
    PostureNoRoute            Posture = "NoRoute"
    PostureBootstrapDiscovery Posture = "BootstrapDiscovery"
    PostureImportedActive     Posture = "ImportedActive"
    PostureSharedActive       Posture = "SharedActive"
    PostureRecovery           Posture = "Recovery"
    PostureLifeline           Posture = "Lifeline"
    PostureOfflineSharing     Posture = "OfflineSharing"
    PostureExperimental       Posture = "Experimental"
)

// CooldownReason is a V0.3 category. Defined in core/diagnostics.
type CooldownReason = diagnostics.Category

// RouteHealth is the per-route attribute the path-manager tracks.
type RouteHealth struct {
    RouteID         string
    InCooldown      bool
    CooldownReason  CooldownReason   // V0.3 category, or empty
    CooldownUntil   time.Time
    BudgetExhausted bool             // 2A's per-route boolean
}
```

The V0.3 categories that drive per-route cooldowns at 2B:

- `dns_poisoned` — 30 min cooldown.
- `dns_timeout` — 5 min.
- `tcp_connect_timeout` — 5 min.
- `tcp_reset` — 30 min route + 5 min family.
- `tls_handshake_failed` — try alternate family on this network.
- `tls_sni_or_cert_block_suspected` — 1 h family on this network.
- `udp_unavailable` — disable UDP families 2 h on this network.
- `quic_unavailable` — disable QUIC specifically.
- `auth_failed` — **no cooldown** (V0.3's hardest rule); surface
  to UI.
- `route_expired` — route disabled; refresh path offered.
- `publisher_revoked` — all publisher's routes revoked; UI warns.
- `publisher_key_changed` — block import; require re-confirmation.
- `subscription_unreachable` — use cached profiles.
- `engine_crash` — restart once; if persistent, fall back family.
- `bundle_signature_invalid` — reject; never auto-retry.
- `bundle_corrupted` — reject.
- `network_offline` — halt route attempts.
- `unknown` — surface raw diagnostic; no automatic action.

Plus 2A's per-route boolean `BudgetExhausted`, which is **NOT** a
V0.3 category (the roadmap is explicit: `auth_failed` is one thing,
budget is another). `BudgetExhausted` is a separate field; the
two-tuple becomes a three-tuple in practice.

## Family-cooldown exponential backoff ladder (V2.3)

Per V2.3: *"A failing route family enters cooldown with an
exponential backoff (5min, 15min, 1h, 4h, 24h, capped)."*

The pathmanager already tracks family-level failures (in
`Manager.failures` keyed by family); 2B generalises the existing
"3+ failures in 1 hour → 1h family cooldown" branch into the
explicit roadmap ladder:

```go
// core/pathmanager/family.go (new)
var familyBackoffLadder = []time.Duration{
    5  * time.Minute,
    15 * time.Minute,
    1  * time.Hour,
    4  * time.Hour,
    24 * time.Hour,
}

// FamilyCooldownStep returns the ladder step for n consecutive
// failure escalations. n>=len(ladder) clamps to the cap (24 h).
func FamilyCooldownStep(n int) time.Duration {
    if n <= 0 { return 0 }
    if n > len(familyBackoffLadder) {
        n = len(familyBackoffLadder)
    }
    return familyBackoffLadder[n-1]
}
```

The escalation counter advances when:
- A new failure on `family` arrives while `family` is already in
  cooldown — this is "the family is still broken even after the
  last cooldown expired."

The escalation counter resets when:
- A successful attempt on the same family + same network
  completes (the family is back).
- The user roams to a different network ID (per-network counters
  are independent in 2C).

The escalation counter is keyed `(family × network_id)`, so a
family burning on `home-wifi` does not pre-cooldown the same
family on `cafe-wifi`. In 2B (before 2C lands) the network_id is
a fixed sentinel `"global"`; 2C swaps in the hashed network ID.

User-visible diagnostics surface the ladder step explicitly per
the V2.3 example: *"VLESS-Reality routes are cooling down — last
failure: 12 minutes ago. Trying Hysteria2 routes."*

## Mode multipliers

Mode is a separate axis from posture. Roadmap V2.2 specifies
exactly three budget modes — `lifeline`, `normal`, `bulk`. 2D adds
a fourth, `lifeline-strict`, which is a local-only behavioural
mode, NOT a separate multiplier (it shares the 0.33× factor with
`lifeline`; see 16-phase-2d).

Naming note: do NOT call the 2D mode `lifeline-only` — that string
is already used as a `scarcity_class` budget tag in the V2.1 cap
table, and the namespace collision would break tag/mode lookup
disambiguation. The V2D mode is `lifeline-strict` at the engine
boundary; the user-visible UI label can still read "Lifeline mode"
or "Lifeline (local-only)" per the roadmap's prose.

```go
// core/budget/effective.go (new in 2B)
var modeFactor = map[string]float64{
    "lifeline": 0.33,
    "normal":   1.0,
    "bulk":     1.0, // bulk does not enlarge cap; it unlocks bulk-capable
}

func (e *Engine) EffectiveCap(routeID, mode string) Cap {
    cap, err := FullCapFor(e.tagOf(routeID))
    if err != nil {
        return Cap{}
    }
    f, ok := modeFactor[mode]
    if !ok { f = 1.0 }
    eff := cap
    if cap.Hourly  != 0 { eff.Hourly  = uint64(float64(cap.Hourly)  * f) }
    if cap.Session != 0 { eff.Session = uint64(float64(cap.Session) * f) }
    return eff
}
```

The `Add` path consults `EffectiveCap(routeID, currentMode)` each
charge. Mode changes do NOT bump the session epoch (per 2A-Polish
spec rule).

## `bulk` mode is a filter, not a preference

Roadmap V2.2 is explicit: *"Bulk — explicit opt-in, only on
bulk-capable routes."* In `bulk` mode the engine selects ONLY
routes whose `modes_allowed` contains `"bulk"`. Per 2A-Polish, the
only tag whose `modes_allowed` includes `"bulk"` is
`bulk-capable`. So the V2.2 "bulk on bulk-capable only" semantics
fall directly out of the `modes_allowed` filter; there is no
ranking-table magic involved.

```go
// core/pathmanager/rank.go
func Rank(rs []Route, mode string, snap budget.Snapshot) []Route {
    // 1. Filter: drop any route whose modes_allowed does NOT contain mode.
    //    In `bulk` mode this leaves bulk-capable routes only.
    //    In `lifeline` / `normal` modes, bulk-capable routes
    //    remain selectable because their modes_allowed includes
    //    "lifeline" and "normal".
    rs = filter(rs, func(r Route) bool {
        return contains(r.ModesAllowed, mode)
    })
    // 2. Rank by posture: ImportedActive > SharedActive >
    //    BootstrapDiscovery > Recovery > Lifeline > OfflineSharing >
    //    Experimental > NoRoute. (See V2.3 ordering.)
    // 3. Within posture, in `lifeline` and `normal` modes,
    //    deprefer `bulk-capable` (rank last) — these are typically
    //    paid / high-capacity routes the user probably did not
    //    intend to burn for chat-class traffic.
    //    In `bulk` mode the only candidates are bulk-capable, so
    //    no deprefer step.
    // 4. Within ranking class, least-burned (consumed/cap)
    //    ascending. `bulk-capable` (unlimited) sorts as 0
    //    consumed-fraction; this is fine because the deprefer
    //    step in (3) has already pushed them down in the
    //    non-bulk modes.
    // 5. Stable tie-break by route_id.
    return rs
}
```

Behavioural summary:

| Mode | Visible routes | Note |
|---|---|---|
| `lifeline` | every route whose `modes_allowed` contains `lifeline` | `bulk-capable` ranks last |
| `normal` | every route whose `modes_allowed` contains `normal` | `bulk-capable` ranks last |
| `bulk` | `bulk-capable` only | per V2.2 explicit-opt-in semantics |
| `lifeline-strict` (2D) | `lifeline` set MINUS `bulk-capable` (unless per-session opt-in) | stability-biased ranker; see 2D |

## Scope

- `core/budget/effective.go` — `EffectiveCap(routeID, mode) Cap`.
- `core/pathmanager/posture.go` — the eight `Posture` constants and
  the transition table; pure data, no IO.
- `core/pathmanager/fsm.go` — replace the legacy `State` enum with
  `Posture`; preserve the existing public method names where the
  desktop already calls them; deprecate the old enum behind a
  `LegacyState() State` shim that maps `Posture → State` for
  callers not yet updated.
- `core/pathmanager/rank.go` — pure `Rank(routes, mode, snapshot)
  []Route`.
- `core/diagnostics` — already defines the V0.3 categories. No
  change.
- `engine_export_diagnostics` — widen with:
  ```json
  {
    "posture": "ImportedActive",
    "mode": "normal",
    "mode_transitions": [
      {"at":"YYYY-MM-DDTHH:00:00Z", "from":"lifeline", "to":"normal"}
    ],
    "route_health": [
      {
        "route_id": "abc",
        "in_cooldown": true,
        "cooldown_reason": "tcp_reset",
        "cooldown_until": "YYYY-MM-DDTHH:00:00Z",
        "budget_exhausted": false
      }
    ]
  }
  ```
- **No new ABI surface.** `engine_set_mode` already exists (1B);
  its accepted set widens to `{lifeline, normal, bulk}` (still
  three values; `lifeline-strict` is added by 2D). Surface stays
  at **36**.
- **Desktop UI:**
  - `Home.tsx` mode picker (lifeline / normal / bulk) backed by
    `engine_set_mode`. (2D adds `lifeline-strict` as a fourth
    option.)
  - `RouteBudgetTable` reads `budgets[]` on mount and on every
    mode change.
  - `RouteHealthTable` reads `route_health[]` and renders V0.3
    cooldown-reason labels (English + Persian copy already in
    `specs/failure-taxonomy-v1.md`).
  - **V2.1 rate-limit prompt.** When any `budgets[]` row's
    `consumed_bytes / hourly_cap_bytes >= 0.9` (90% threshold) AND
    the active mode is not `bulk`, the desktop renders the V2.1
    canonical prompt verbatim:
    > *"This route is rate-limited. Switch to bulk mode? (uses a
    > paid subscription if available)"*
    The prompt is dismissible per session and re-arms on the next
    distinct route crossing the threshold. Persian translation
    matches the V0.6 i18n catalog.
- Spec: new `specs/mode-budgets-v1.md`; amend
  `specs/route-budgets-v1.md` to reference the multiplier table;
  amend `specs/engine-abi-v1.md` to document the additive
  widening of `engine_export_diagnostics`.

## Out of scope (deferred)

- **Per-network memory** of mode + posture + route health. 2C.
- **`lifeline-strict` local-only mode.** 2D.
- **Mode auto-switching based on success rate.** Always manual at
  2B; auto-switching is 2G's burn detector.
- **Removal of the legacy `State` enum.** Kept as a shim until V3;
  removing it is a separate refactor with its own changelog.

## Testing Requirements

- `core/budget/effective_test.go` — table tests over every
  (tag × mode) pair. `bulk-capable` returns `Cap{0,0,...}` in
  every mode (unlimited stays unlimited, not multiplied).
- `core/pathmanager/posture_test.go` — exhaustive transition
  coverage for the eight states. Illegal transitions are explicit
  errors; every cell of the (state × event) table is asserted.
- `core/pathmanager/rank_test.go`:
  - In `bulk` mode, only `bulk-capable`-tagged routes survive
    the `modes_allowed` filter; every other tag is filtered
    OUT (not just deranked).
  - In `normal` and `lifeline` modes, `bulk-capable` routes
    remain selectable (their `modes_allowed` includes those
    modes) but rank last per the deprefer step.
  - Routes tagged `lifeline-only` (the `scarcity_class` tag,
    not the V2D `lifeline-strict` mode) are FILTERED OUT in
    `normal` and `bulk` modes because their `modes_allowed`
    is `["lifeline"]` only.
  - Ties break by `route_id` deterministically.
- `core/pathmanager/family_test.go`:
  - `FamilyCooldownStep` returns the documented ladder
    (5min, 15min, 1h, 4h, 24h) and clamps at 24h for n>5.
  - The escalation counter advances on consecutive failures
    after a cooldown expiry, and resets on a successful attempt.
- Integration: drive `engine_set_mode("lifeline")` then
  `engine_export_diagnostics`; assert `mode_transitions[]` shows
  the change; assert `budgets[].hourly_cap_bytes` is 0.33× the
  raw cap.
- Soak: extend `route-budget-exhaustion` to drive lifeline mode and
  assert exhaustion at 1/3 the byte count. New scenario
  `mode-bulk-unlock` proves `bulk-capable` is dead-last in normal
  and first in bulk. New scenario `posture-recovery-cycle` drives
  `tcp_reset` on the active route, asserts posture transitions
  `ImportedActive → Recovery → ImportedActive` within the
  cooldown window, and that the cooldown_reason carries the V0.3
  category through the transition.
- Desktop e2e (manual): switch modes; verify the budget table
  updates; verify the Persian copy renders RTL correctly.
- All previous tests green.
- `nm` count still **36**.

## Exit criteria

1. `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` = **36**
   (no new functions).
2. Engine version unchanged at `daal-core 0.5.0+survivability`.
3. `core/pathmanager` and `core/budget` tests green.
4. New soak scenarios green in both modes.
5. Desktop renders mode picker + budget table + route-health
   table; both Persian and English copy land.
6. `specs/mode-budgets-v1.md` shipped; spec cross-refs amended.

## Handover to Phase 2C

Phase 2C receives:
- Eight V2.3 posture constants whose state can now be persisted
  per-network.
- A budget engine whose hourly + session counters can now be
  keyed per-network (the per-network store key includes the
  network ID; the session epoch stays device-global).
- A mode dial whose default value can become per-network.
- Per-route V0.3 cooldown reasons that can travel with a network's
  remembered state — so a route that was `tcp_reset` on
  `home-wifi` does not get pre-cooldowned on `cafe-wifi`.
