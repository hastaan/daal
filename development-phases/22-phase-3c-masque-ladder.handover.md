# Phase 3C — MASQUE Ladder — HANDOVER

## Status

**SHIPPED.** All 10 sub-tasks landed. Engine version
`daal-core 0.7.2+v3-transport`. Release ABI count **45**
(44 → 45; +1 new symbol, append-only).

## Roadmap line

V3.3 ("MASQUE ladder: HTTP/3 → HTTP/2 → Lifeline"). The 3C
landing turns MASQUE into a single transport family with three
sub-modes that the engine cascades through automatically.
Selection is private to `core/transports/masque/`; the path
manager sees one family and one set of routes.

## What landed

### Engine

- **`core/transports/masque/`** — new package, stdlib-only.
  - `FamilyID = "masque"`.
  - 3 sub-mode constants (`SubmodeH3QUIC`, `SubmodeH2Connect`,
    `SubmodeLifeline`); `AllSubmodes()` exposes the closed v1
    list.
  - `Handler.Dial(ctx, route, override)` runs the private
    `chooseSubmode` cascade and routes to one of three
    callback dialers (`H3QUICDialer`, `H2ConnectDialer`,
    `LifelineDialer`). Callback shape keeps the package free
    of `quic-go` / `golang.org/x/net/http2` until the
    upstream dialers wire in (future polish).
  - `chooseSubmode` cascade order (locked v1):
    1. ABI override set + valid → use override (lifeline-strict
       still clamps).
    2. `mode == "lifeline-strict"` → hint `masque_lifeline`.
    3. Netmem `last_used_masque_submode` in v1 list → start there.
    4. UDPProbeOK → `masque_h3_quic`.
    5. UDPProbeOK false → `masque_h2_connect`.
    6. h2 burned + mode ∈ {lifeline, lifeline-strict} → drop
       to `masque_lifeline`.
- **Routestore widening** (1 new column).
  - `masque_endpoint` (default `''`).
  - `UpsertRoute` carries the field through. `UpsertRoute`
    MUST NOT clobber engine-recorded sub-mode state held in
    `secrets_kv` under `masque_submode:<route_id>`.
- **Netmem widening.**
  - `Snapshot.LastUsedMasqueSubmode` field.
  - `Empty()` updated.
  - New methods `RecordLastUsedMasqueSubmode` /
    `LookupLastUsedMasqueSubmode`.
- **ABI.**
  - **1 new release symbol** (cshared + gomobile).
    `engine_set_masque_submode_override` (45). Empty string
    clears (engine returns to auto cascade); unknown sub-mode
    returns `-3`. Persists in secrets KV under
    `masque_submode_override`. Survives session epochs.
    Accepted in BOTH the keystore and vault profiles
    (MASQUE has no FCM/APNS surface; no profile rejection).
  - Diagnostics widen additively with `masque_submode`
    (always present; the most recently chosen sub-mode this
    session, OR empty) and `masque_submode_override` (always
    present; the engine-pinned override, OR empty). Both
    enumerable; never URLs / IPs.
  - `RecordChosenMasqueSubmode(routeID, submode)` writes the
    per-route record in secrets KV AND the per-network
    snapshot field.
  - Init daaltes the per-engine override from secrets KV;
    survives session epochs (user preference).

### Bundle format (sbp-v1 widening)

- `manifest.routes[].masque_endpoint: string` (optional).
  - MUST be a parseable `https://host[:port]/path` URL with a
    non-empty path when present.
  - Only meaningful on `transport_family = "masque"` routes;
    presence on any other family rejects the bundle
    (`ErrMasqueEndpointOnNonMasqueRoute`).
  - Malformed URL rejects with `ErrMasqueEndpointMalformed`.
  - Empty / absent on a MASQUE route is accepted; the engine
    treats the route as having no usable endpoint and filters
    at activation time.
- The widening is JSON-additive: 3A / 3B clients reading a 3C
  bundle ignore the new field silently.

### Publisher tooling

- `daal-publish masque-bridge` subcommand. Produces a
  `routes[]` entry stub for a MASQUE upstream endpoint:
  - `--endpoint` (required) — `https://host[:port]/path`.
  - `--route-id` (optional; defaults to `mq-<host>`).
  - `--validity` (optional; default 7d).
  - `--caveat-fa-ir` (optional; Persian region caveat).
  - `--experimental-min-engine-version` (optional; semver pin).
  - `--out` (required).
- The emitted route stub carries
  `transport_family: "masque"`, `scarcity_class:
  "experimental"` (locked at 3C), the validated
  `masque_endpoint`, and an empty
  `family_specific_config: {}` (reserved for future per-route
  knobs at the H2 / H3 rung).

### Soak

- 2 new scenarios:
  - `masque-udp-failover.json`
  - `masque-lifeline-rung.json`
- `--scenarios v2-superset` whitelist widens 17 → **19**.
- Soak driver client adds `SetMasqueSubmodeOverride` and
  `SoakBurnMasqueSubmode`.
- `runEngineActions` dispatches the 2 new 3C action names
  AND the 4 missing 3B action names that the 3B handover
  flagged as "soak hooks not yet wired" (the 3B dispatch
  cases for `set-rendezvous-priority`,
  `set-push-rendezvous-enabled`,
  `soak-burn-rendezvous-channel`,
  `soak-simulate-push-payload` landed alongside the 3C
  dispatch wiring).
- Two new `-tags soak` files in `core/abi/`:
  - `masque_soak.go` — `MarkMasqueSubmodeBurned` /
    `IsMasqueSubmodeBurned`.
  - `rendezvous_soak.go` — `MarkRendezvousChannelBurned`,
    `IsRendezvousChannelBurned`, `SimulatePushPayload`,
    `PopSimulatedPushPayload` (3B knobs that the 3B handover
    flagged as deferred).

### Specs

- **New:** `specs/masque-ladder-v1.md`.
- **Amended:** `specs/transport-families-v1.md`,
  `specs/sbp-v1.md`, `specs/publisher-cli-v1.md`,
  `specs/engine-abi-v1.md`, `specs/route-object-v1.md`,
  `specs/routestore-v1.md`, `specs/network-memory-v1.md`,
  `specs/failure-taxonomy-v1.md`.

## Locked decisions held through 3C

1. ABI append-only; +1 release symbol; 0 removed; 0 renamed.
2. MASQUE is opportunistic — auto-promotion (2G) NEVER
   promotes a network whose only available family is `masque`.
3. Sub-mode is per-route-per-session; netmem only biases the
   *start* rung of the next session.
4. Override is per-engine, NOT per-network (cross-product is
   a fingerprint surface; same reasoning as 3A's experimental
   gate and 3B's rendezvous priority).
5. Lifeline rung respects 2D's `lifeline-strict` budgets;
   strict mode clamps even an explicit override down to
   `masque_lifeline`.
6. Closed sub-mode list (3); a 4th value is a roadmap-level
   decision.
7. `UpsertRoute` MUST NOT clobber engine-recorded state. The
   per-route secrets-KV record and per-network netmem hint are
   never overwritten by a bundle re-import.
8. Diagnostic `masque_submode` is enumerable. Never URLs / IPs.
9. No `core/ladder/` package at 3C; the chooser is a private
   switch inside `core/transports/masque/`. Lifting to
   `core/ladder/` is a 3D / 3E roadmap decision.
10. MASQUE override is accepted in BOTH storage profiles. The
    3B vault-rejection pattern does NOT apply because MASQUE
    has no FCM/APNS surface.

## Test surfaces

| Package                       | New tests | Status |
|-------------------------------|-----------|--------|
| `core/transports/masque`      | 7         | green  |
| `core/routestore`             | +1 (3C)   | green  |
| `core/netmem`                 | +1 (3C)   | green  |
| `core/abi` masque             | 8         | green  |
| `bundle/go/bundle` (3C)       | 5         | green  |
| `bundle/go/publisher` (3C)    | 4         | green  |
| Soak driver                   | builds    | green  |

`core/...` full suite: green. `bundle/go/...` full suite:
green. `cmd/daal-soak-engine` builds clean both with and
without `-tags soak`.

## Known follow-ups (3-Soak)

- Wire upstream MASQUE dialers (`H3QUICDialer`,
  `H2ConnectDialer`, `LifelineDialer`) into the engine
  initialisation path. The `core/transports/masque/`
  package is dialer-agnostic at 3C; the path manager wires
  the actual `quic-go` / `golang.org/x/net/http2` callbacks
  at 3-Soak when the family handler joins the activation
  flow.
- Wire the bundle importer → trust adapter → routestore for
  `routes[].masque_endpoint`. The bundle parser validates
  the field at 3C; end-to-end activation lands when the
  masque family handler joins the path manager (3-Soak).
- Per-route + per-network MASQUE failure-cosmetic surface
  in the diagnostics ring buffer (`masque_h3_blocked` /
  `masque_h2_blocked` / `masque_lifeline_blocked`). The
  taxonomy is locked at 3C in
  `specs/failure-taxonomy-v1.md`; the diagnostics emitter
  hooks up at 3-Soak.
- Auto-promotion (2G) opt-out for masque-only networks. The
  rule is locked at 3C; the detector update lands at
  3-Soak when the soak rig finishes the masque-only-network
  scenario.
- 4-rung MASQUE (a hypothetical `masque_h2_lite`) — closed
  at v1; a 4th sub-mode is a roadmap decision for V4.

## Carry-overs to V4

- Fourth MASQUE sub-mode (closed at v1).
- Per-network MASQUE override (deliberately not a v1 feature
  because of the fingerprint cross-product).
- Generalised `core/ladder/` package (lift the chooser when
  3D / 3E reach for the same shape).
- WASM-loaded MASQUE rungs — 3E (placeholder).

## Handover to 3D

3D receives:

- A MASQUE substrate Conjure-class transports can ride on
  (Conjure registers the user's flow as MASQUE-shaped
  traffic the censor's middleboxes treat as innocuous HTTP).
- The single-family-multiple-submodes pattern (3 sub-modes,
  private switch) as a reference for refraction's similar
  shape. The `core/transports/masque/` package is the
  template for `core/transports/<name>/`.
- The closed sub-mode taxonomy + private chooser cascade as a
  template (3D MAY adopt the same pattern OR move to a
  shared `core/ladder/` if the cascade widens to span
  multiple families).
- ABI release surface = 45; append-only.
- Engine version `daal-core 0.7.2+v3-transport`.

## Files added/modified at 3C

```
specs/masque-ladder-v1.md                    NEW
specs/{transport-families, sbp, publisher-cli, engine-abi,
       route-object, routestore, network-memory,
       failure-taxonomy}-v1.md               AMENDED

core/transports/masque/masque.go             NEW
core/transports/masque/masque_test.go        NEW (7 tests)

core/routestore/schema.go                    +1 ALTER (masque_endpoint)
core/routestore/store.go                     widened (RouteRow.MasqueEndpoint, UpsertRoute, GetRoute, ListRoutes)
core/routestore/store_test.go                +TestUpsertRoute_3CFieldsRoundTrip + default check

core/netmem/snapshot.go                      +LastUsedMasqueSubmode + Empty()
core/netmem/store.go                         +Record/LookupLastUsedMasqueSubmode
core/netmem/store_test.go                    +TestRecordLastUsedMasqueSubmode

core/abi/abi.go                              widened (Core fields, Init daalte, diagnostics, Version=0.7.2)
core/abi/masque.go                           NEW (Set/Get override + RecordChosenMasqueSubmode + loadMasqueState)
core/abi/masque_export.go                    NEW (cshared symbol 45)
core/abi/masque_gomobile.go                  NEW (gomobile facade)
core/abi/masque_test.go                      NEW (8 tests)
core/abi/masque_soak.go                      NEW (-tags soak; Mark/IsMasqueSubmodeBurned)
core/abi/rendezvous_soak.go                  NEW (-tags soak; 3B knobs deferred from 3B handover)
core/abi/rendezvous_test.go                  version-string regression updated to 0.7.2
core/abi/refresh_test.go                     version-string regression updated to 0.7.2

bundle/go/bundle/types.go                    +MasqueEndpoint on RouteManifestEntry
bundle/go/bundle/sbp.go                      +validate3CRouteFields + net/url import
bundle/go/bundle/errors.go                   +ErrMasqueEndpointOnNonMasqueRoute, ErrMasqueEndpointMalformed
bundle/go/bundle/v3c_test.go                 NEW (5 tests)

bundle/go/publisher/masque.go                NEW
bundle/go/publisher/masque_test.go           NEW (4 tests)
bundle/go/cmd/daal-publish/main.go          +masque-bridge subcommand + usage line

cmd/daal-soak-engine/main.go                +6 dispatch cases (3B+3C); rcError + itoa helpers

test-rigs/distribution-failure/scenarios/masque-udp-failover.json    NEW
test-rigs/distribution-failure/scenarios/masque-lifeline-rung.json   NEW
test-rigs/distribution-failure/soak-driver/internal/client/client.go +2 methods
test-rigs/distribution-failure/soak-driver/internal/soak/soak.go     +2 cases
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go   v2-superset 17→19
```
