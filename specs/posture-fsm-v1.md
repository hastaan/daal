# Posture FSM v1

## Status

**Frozen at the end of Phase 2B.** The 8 application-posture states,
the closed event vocabulary, the legal-transition table, and the
V2.3 family-cooldown ladder are part of the V2 entry-criterion
contract.

The pre-2B `pathmanager.State` enum (`NoRoute / Connecting /
Connected / Cooldown / Failed / BudgetExhausted`) is preserved
unchanged — the V2.3 8-state vocabulary lives on a **parallel
axis** as `pathmanager.Posture`. Diagnostics renders both. Removal
of `State` is deferred to V3 as a separate refactor.

## Roadmap coverage

V2.3 ("Cooldown state machine — exactly the eight named states the
roadmap freezes; no machine learning"). The 8 names are taken
verbatim from `daal-roadmap-v3.md` line 552:

```
NoRoute, BootstrapDiscovery, ImportedActive, SharedActive,
Recovery, Lifeline, OfflineSharing, Experimental
```

## Posture states

| Posture | Meaning |
|---|---|
| `NoRoute` | No usable route in the store. UI prompts the user to import or share. |
| `BootstrapDiscovery` | Tier-2 seeds + Tier-1 directory pointers active; trying to fetch a real directory through any working tunnel. |
| `ImportedActive` | A subscription / paste / file-import route is selected and pumping bytes. |
| `SharedActive` | A friend-shared `.sbp` route is selected and pumping bytes. |
| `Recovery` | The previous active route just failed; attempting next-best in shortlist. |
| `Lifeline` | User has selected lifeline budget mode. Distinct from the 2D `lifeline-strict` mode, which is local-only behaviour on top of `Lifeline`. |
| `OfflineSharing` | User is sending or receiving an `.sbp` over LAN / animated QR; tunnel may or may not be up. |
| `Experimental` | An Experimental-feature-flag transport family is selected; UI shows the warning. |

These are user-facing posture states. They DO NOT enumerate every
possible per-route cooldown reason — V0.3's failure taxonomy is the
canonical cooldown-reason set, and a route in any of
`BootstrapDiscovery / ImportedActive / SharedActive / Recovery /
Lifeline / OfflineSharing / Experimental` may have zero, one, or
many routes in cooldown for a V0.3 reason at any moment.

## V0.3 cooldown-reason orthogonality

Per-route cooldown is a separate axis from posture. The
per-route attribute the path manager tracks at 2B:

```go
// core/pathmanager/fsm.go
type RouteHealth struct {
    RouteID         string
    InCooldown      bool
    CooldownReason  diagnostics.Category   // V0.3 category, or empty
    CooldownUntil   time.Time
    BudgetExhausted bool
}
```

The full V0.3 category set is the canonical cooldown vocabulary;
see `specs/failure-taxonomy-v1.md`. `auth_failed` is exempt — it is
recorded in `RouteHealth` for surfacing but never sets
`InCooldown = true`.

## Family-cooldown ladder (V2.3)

Per V2.3: *"A failing route family enters cooldown with an
exponential backoff (5min, 15min, 1h, 4h, 24h, capped)."*

```go
// core/pathmanager/family.go
var familyBackoffLadder = []time.Duration{
    5 * time.Minute,
    15 * time.Minute,
    1 * time.Hour,
    4 * time.Hour,
    24 * time.Hour,
}
```

`FamilyCooldownStep(n)` returns the duration for ladder step n
(1-indexed). n>5 clamps to the 24h cap.

### Hybrid trigger policy (Phase 2B locked)

Family cooldowns are tripped via two paths:

- **Family-class V0.3 categories** (`tls_sni_or_cert_block_suspected`,
  `udp_unavailable`, `quic_unavailable` per `IsFamilyClass`) trigger
  a family cooldown immediately at the next ladder step on the
  FIRST occurrence. These are network-wide indicators: a single
  failure means the entire family is blocked on this network.
- **Per-route V0.3 categories** (`tcp_reset`, `tls_handshake_failed`,
  `tcp_connect_timeout`, `dns_*`) keep the legacy "3 failures in
  the same hour bucket on the same family → fire family cooldown"
  trigger. The duration on trip is now drawn from the V2.3 ladder
  rather than the pre-2B hard-coded 1 h.

The escalation counter advances on each family-cooldown event and
resets when:
- A successful `Connected()` on a route in the same family, OR
- (At 2C) a network-roam event. At 2B, network ID is implicitly
  the sentinel `"global"`, so no roam events.

The escalation counter is keyed by family at 2B; 2C widens to
`(family × network_id)`.

## ABI

`engine_export_diagnostics` widens additively with:

```json
{
  "posture": "ImportedActive",
  "route_health": [
    {
      "route_id": "abc",
      "in_cooldown": true,
      "cooldown_reason": "tcp_reset",
      "cooldown_until": "2026-04-27T13:00:00Z",
      "budget_exhausted": false
    }
  ],
  "skipped_families": [
    {
      "family": "vless-reality",
      "until": "2026-04-27T13:05:00Z",
      "ladder_step": 1
    }
  ]
}
```

The legacy `state` and `why` fields are unchanged. Surface stays at
**36** (no new release function).

## Legal transitions (closed table)

The complete transition table is `pathmanager.LegalTransitions`.
Tests assert:
- Every entry references a known `Posture` and known
  `PostureEvent`.
- No self-loops (`From == To`).
- Every active posture has at least one path to `NoRoute` (the
  user can always disconnect).
- `IsLegal(from, event, to)` returns true for every entry and
  false for representative non-entries.

Illegal transitions return an error from `Manager.SetPosture`; the
posture is NOT changed and `LastReason` records the violation.

## Files

- `core/pathmanager/posture.go` — Posture constants,
  PostureEvent, LegalTransitions, IsLegal.
- `core/pathmanager/posture_test.go` — exhaustive transition
  coverage.
- `core/pathmanager/family.go` — V2.3 ladder + IsFamilyClass.
- `core/pathmanager/family_test.go` — ladder + hybrid-trigger
  + escalation-reset coverage.
- `core/pathmanager/fsm.go` — Manager extended with parallel
  posture axis, RouteHealth map, familyEscalation counter, plus
  Posture/SetPosture/RouteHealth/SkippedFamilies accessors.
- `core/pathmanager/rank.go` — pure mode-aware filter+sort.
- `core/pathmanager/rank_test.go` — filter + deprefer + tie-break.
- `core/abi/abi.go::ExportDiagnostics` — widened JSON.

## Cross-references

- `specs/failure-taxonomy-v1.md` — V0.3 cooldown reasons.
- `specs/route-budgets-v1.md` — `BudgetExhausted` boolean.
- `specs/mode-budgets-v1.md` — `Lifeline` posture is set by
  `engine_set_mode("lifeline")`.
- `specs/network-memory-v1.md` — at 2C the family-escalation
  counter is keyed `(family, networkID)`. A roam to a different
  network resets the V2.3 ladder for that family on the new
  network; the original network's escalation state is intentionally
  preserved. Empty active-network collapses to the legacy
  family-only key for 2B back-compat.

## Stability

- The 8 posture names are part of the V2 entry-criterion contract;
  adding or renaming requires a roadmap revision.
- The family-backoff ladder values are fixed; the hybrid-trigger
  policy is locked at 2B.
- Diagnostics widening is additive only.

## Phase 2D amendment

`lifeline-strict` flips `PostureLifeline` exactly the same way
`lifeline` does — the posture axis sees a single Lifeline state.
The behavioural deltas of the strict variant (stability-biased
ranker, bulk-capable filter, refresh gate) live in the path
manager, the budget engine, and the refresher; they do NOT
introduce a new posture.

Auto-promotion to `lifeline-strict` on burn detection **shipped in
Phase 2G**. The detector lives in `core/burnpressure/` (locked v1
thresholds: 3 distinct families × 30-min window × ladder step ≥ 3)
and is consulted by `core/abi/EvaluateAutoPromotion`, which the
scheduler invokes on every Tick. Manual mode picks within the same
hour-bucket suppress auto-promotion for that bucket — the user's
choice always wins. The preference is set via
`engine_set_auto_promotion(int enabled)` (default-on; survives
session epochs). The 8-posture FSM itself is unchanged at 2G —
auto-promotion is a mode dial, not a posture transition.
