# Transport Families V1 — V3 Scaffold

## Status

**Locked at the start of Phase 3A.** This spec defines the
contract every V3+ transport family rides on: the closed family
taxonomy, the experimental gate, the per-family kill-switch
shape, and the rules every later V3 sub-phase (3B Snowflake,
3C MASQUE, 3D Psiphon/Conjure, 3E WASM, 3G Lifeline relay) MUST
follow when adding a family. Families MAY be added; the
contract MAY NOT be relaxed without a roadmap-level decision.

Implementation: `core/routestore/family.go` (taxonomy);
`core/abi/experimental.go` (gate);
`core/pathmanager/family_filter.go` (experimental-gate
filtering).

## Roadmap coverage

V3 ("Ecosystem integrations and transport agility"). The
critical V3 invariant — *new transports arrive as new route
families that the path manager learns to use without changing
the V1/V2 user experience or trust model* — is enforced by this
spec.

## Family taxonomy

The set of valid `transport_family` values is a CLOSED list.
Adding a family is a roadmap-level decision; the bundle parser
rejects unknown values with `bundle_corrupted` at import time.

The `other` value preserved from V0 SBP-v1 remains accepted by
the parser for forward compatibility but is NEVER selected by
the path manager (it carries no engine-side handler). It exists
solely so a future spec revision can introduce a family without
older clients producing `bundle_corrupted` on the spot.

**This table is a MIRROR.** The authority is
`core/routestore/family.go`'s `familyMaturity` map, reconciled
family-by-family — with the evidence for each verdict — in
`docs/transport-family-inventory.md`. Wave 5 corrected the table
below; before that correction it graded nine families higher than
the code did, including `wireguard`, `amneziawg` and `tor-bridge`
as *stable* when the engine could not express any of the three
(two of those three were repaired by other Wave-5 lanes; the
`amneziawg` claim was simply false).

| Family | Phase | Engine handler | Maturity | Notes |
|---|---|---|---|---|
| `vless-reality` | 1B | sing-box | stable | V1 baseline TCP/443 family |
| `naive` | 1B | sing-box | stable | V1 baseline; treated as TCP/443 |
| `websocket-tls` | 1B | sing-box | stable | V1 baseline; TCP/443 |
| `hysteria2` | 1B | sing-box | stable | UDP family; UDP probe gates |
| `tuic` | 1B / Wave 5 | sing-box (`with_quic`) | **experimental** | Whole chain exists after Wave 5: opt-in `tuic-in` on the box (uuid+password per recipient, mandatory `alpn:["h3"]` — sing-quic sets no default for tuic and quic-go refuses a TLS config without one), 8443/udp opened in both firewalls **only on relays that serve it**, client outbound, rotation. **Never soaked.** The one family a relay can be provisioned WITHOUT, so its port never joins the fleet-wide constant. `relayports` puts it on 8443/udp because hysteria2 owns 443/udp (BUG-14). **Copy constraint:** 8443 is outside the target country's 53/80/443 egress whitelist AND it is UDP, which the adversary states the intent to block completely — Daal already ships one UDP tier, so this is diversity on other networks, never a second lifeline there |
| `shadowsocks` | 1B | sing-box | **experimental** | Dialable and paste-importable; never soaked. Demoted from stable in Wave 1 |
| `anytls` | Wave 5 | sing-box | **experimental** | Padding scheme + native session reuse are protocol features. Whole chain exists (publisher mints, box serves, port assigned); missing only a device soak. Requires `spec_version >= 5` |
| `tor-bridge` | 1B / Wave 5 | sing-box `tor` outbound | **experimental** | Carries obfs4, meek_lite, **webtunnel and snowflake** as bridge lines. Publisher-independent — the only route Daal offers with no Daal relay in existence. Experimental because the outbound execs a tor binary the release has to package |
| `wireguard` | 1B / Wave 5 | sing-box `endpoints[]` (`with_wireguard`) | **experimental** | Was unsupported; the Wave-5 wireguard lane added the `endpoints[]` slot to `SingBoxConfig` and a real endpoint object to the importer. Daal does not SERVE it — paste/import only. **Copy constraint:** plain WireGuard is a named immediate-block target in Iran and must not borrow AmneziaWG's track record |
| `amneziawg` | 1B | **none** | **unsupported** | sing-box 1.13.12 contains no AmneziaWG code at all, so the `Jc/S1/H1..H4` obfuscation that IS the family has nowhere to live. An AmneziaWG conf imports as a **downgraded plain-wireguard** route, labelled `wireguard` |
| `webtunnel` | 3A | **none as a family** | **unsupported** | A Tor PLUGGABLE TRANSPORT, not a protocol. Reachable in this build only as `Bridge webtunnel …` inside a `tor-bridge` route. **Effective in China; FAILS in Iran**, our primary target |
| `snowflake` | 3B | **none as a family** | **unsupported** | Also a Tor PT — reachable as `Bridge snowflake …` under `tor-bridge`. The Phase 3B WebRTC handler was deleted in Wave 5; `pion/webrtc` is not being vendored into `core/go.mod` |
| `masque` | 3C | **none** | **unsupported** | No masque outbound exists in sing-box 1.13.12, and a self-hosted MASQUE proxy has none of the provider-anonymity-set value that motivates RFC 9298. Dormant, not deferred |
| `psiphon` | 3D | **none, ever** | **unsupported** | A third party's proprietary NETWORK. A client can hand off to it; a publisher cannot host it. psiphon-tunnel-core has never been in `core/go.mod` |
| `conjure` | 3D | **none, ever** | **unsupported** | Refraction requires a COOPERATING ISP running a station on a transit link. A rented VPS has neither. gotapdance has never been in `core/go.mod` |
| `transport_module` | 3E | core/wasm + wazero | **unsupported** | The runtime is real and compiled in; `core/wasm.Dial` has no production caller and nothing turns a module into a sing-box outbound. The one entry here that is a genuine "not yet" |
| `lifeline_relay` | 3G (conditional) | **none** | **unsupported** | `core/lifelinerelay` does not exist |
| `other` | 1B | none — parser-only forward-compat | n/a | Never selected by path manager |

**Three of these are STRUCTURALLY unavailable**, not deferred:
`psiphon`, `conjure` and `masque` cannot be served by anyone
self-hosting, for reasons that are properties of the protocols.
The reasons are written onto the enum values themselves in
`bundle/go/bundle/types.go` so the question is not re-opened. The
enum values stay reserved forever — removing one is a wire break
for older clients and buys nothing.

## Maturity ladder

A family transitions through three maturity levels:

1. **Experimental** — first ship of every new family. Routes of
   this family are filtered out of selection unless the per-engine
   experimental gate is enabled. Auto-promotion (2G) cannot
   promote into a network whose only available routes are
   experimental.
2. **Promotion candidate** — declared in a roadmap-level
   decision after a measurement window (typically one full V3
   sub-phase or 30 days of soak parity, whichever is later).
   Still gated by the experimental flag in the engine, but the
   trust UI shows a "promotion candidate" badge instead of
   "experimental." (Reserved for a later phase; 3A introduces
   the level but ships nothing in it.)
3. **Stable** — gate-independent. Family is selectable in any
   build with the appropriate transport-family handler compiled
   in.

Two further levels exist in the code and are not on this ladder,
because they are not stages a family passes through:
`MaturityUnhandled` (the V0 `other` forward-compat slot) and
`MaturityUnsupported` — "this build knows the family by name and
has verified it cannot carry it". Unsupported is deliberately
NOT Experimental: Experimental invites the user to enable the
experimental gate and try, and for these families there is
nothing behind the gate to enable. Eight of the eighteen values
sit at Unsupported after Wave 5.

3A locked `webtunnel` at experimental; **Wave 5 moved it to
unsupported** along with every other V3 family — see the table.
Promotion up the ladder requires a roadmap-level decision and a
fresh soak run. Moving a family DOWN the ladder is not a breaking
change and has now happened twice (Wave 1: wireguard, amneziawg,
tor-bridge, tuic, shadowsocks; Wave 5: the V3 set). A label that
overstates what a route can do costs the user a failed connection
at the moment they need it; correcting it costs nothing.

## Experimental gate

A single per-engine boolean flag, persisted in the secrets KV
under key `experimental_families_enabled`, default **false**.
Set by the new release ABI symbol
`engine_set_experimental_families_enabled(int)` (3A adds this
symbol; see `engine-abi-v1.md`).

### Gate semantics

- **Survives session epoch.** The flag is a user preference,
  not session state. Mode change does not clear it; network
  change does not clear it; unlock does not clear it.
- **Cleared only by user toggle.** No cooldown clears it; no
  auto-promotion clears it.
- **Filtering rule.** With the gate OFF, the pathmanager
  rank phase removes every route whose family is at
  Experimental maturity *before* the trust / budget /
  network-memory layers see them. The route still EXISTS in
  the routestore, surfaces in "All routes" lists, and shows
  the experimental badge — but cannot be SELECTED.
- **Auto-promotion interaction.** When the burn-pressure
  detector (2G) considers promoting to `lifeline-strict`, it
  consults the post-filter route set. A network whose only
  available routes are experimental is treated as having no
  routes; auto-promotion behaves as on a fully-burned network.
- **Diagnostics widening (additive).**
  `experimental_families_enabled: bool` — always present.
  `experimental_routes_skipped: int` — count of routes
  filtered by the gate in the last rank pass.
- **Skip ledger entry.** Each filtered route appears in the
  pathmanager's skip ledger (the existing 2A `Skipped` slice
  consumed by the burn-pressure detector) under
  `reason: "experimental_family_disabled"`. The detector
  ignores entries with this reason — an experimental-only
  network must NOT trigger a burn-pressure auto-promotion.

### Privacy invariant

The gate is per-engine, not per-network. Enabling it in one
network does not "remember" that for the next network — but it
does not get re-prompted either. The choice is global and
persistent. Per-network experimental decisions are deliberately
NOT a feature: the resulting cross-product would be a privacy
fingerprint surface for the censor.

## Family-level kill-switch (provisional shape)

3A introduces the kill-switch CONTRACT but does not yet ship a
project-level kill-switch publisher key — that ships at 3E (the
WASM transport slot is what actually requires a kill-switch).
The contract is documented here so 3B–3D ship into a stable
shape:

A signed delta from the kill-switch publisher key disables
`(family, route_id)` tuples client-side. The engine refuses to
select any matching route on next activation. The delta is
fetched on the standard refresh path (1.5A subscription / 1D
directory) — no new transport.

The 3E spec (`wasm-kill-switch-v1.md`) will lock the delta
format. 3A's bundle parser is forward-compatible: kill-switch
deltas land in a new top-level entry whose name is reserved at
3A — `kill_switches[]` — but unused until 3E.

## Trust UI per family

A new family entering at Experimental maturity MUST surface:

1. **Experimental badge** on the route card. Copy locked en + fa
   in `specs/trust-ui-v1.md` 3A amendment.
2. **One-time explainer modal** when the user first toggles the
   experimental gate ON. Documents the auto-promotion exclusion
   rule and the "fail-fast" expectation.
3. **Region-soft-caveat banner.** Shown when the user's
   detected locale is `fa-IR` (carrier hint, IP geolocation
   fallback NOT used — the carrier hint comes from the same
   source 2C consumes for network identity). The banner copy is
   per-family; 3A locks the WebTunnel copy
   in `webtunnel-route-v1.md`. Future families MAY supply their
   own region caveat through the bundle (`routes[].caveat_fa_ir`
   string), or fall back to a generic "experimental" caveat.

A new family entering at Promotion candidate maturity MUST
surface only the promotion-candidate badge; no explainer modal,
no region caveat.

A new family entering at Stable maturity MUST surface no
family-specific UI; existing trust ladder applies.

## Bundle format extension

The SBP-v1 manifest's `transport_family` enum is widened to
include all values in the family taxonomy table above. The
`other` value is retained for forward compatibility.

Three new optional fields on `routes[]` ride this spec; each
is consumed only by the family that defines it (per-family
specs document the schema):

- `caveat_fa_ir: string` — overrides the generic Iranian
  region caveat for this route. Optional.
- `experimental_min_engine_version: string` — semver pin; if
  the engine is older, the route is filtered as if
  experimentally-gated regardless of the user toggle. Optional.
- `family_specific_config: object` — opaque-to-routestore
  family-specific config. Each family spec documents its keys.
  3A's WebTunnel spec defines `webtunnel_secret_path`,
  `webtunnel_sni`, `webtunnel_alpn` here.

The bundle parser validates `transport_family` against the
closed list; rejects routes with `experimental_min_engine_version`
that fails to parse as semver; passes `family_specific_config`
through verbatim.

## Routestore extension

Three new columns on `routes` (additive ALTER):

- `family_specific_config_json: TEXT NOT NULL DEFAULT '{}'`
- `caveat_fa_ir: TEXT NOT NULL DEFAULT ''`
- `experimental_min_engine_version: TEXT NOT NULL DEFAULT ''`

Migration follows the 1.5A additive-only pattern in
`routestore.applySchema`.

## Path manager integration

The rank pipeline (Phase 2B) gains one new filter step BEFORE
trust / budget / network-memory:

```
shortlist = routes_for_active_network()
shortlist = experimental_filter(shortlist)        // NEW (3A)
shortlist = trust_filter(shortlist)
shortlist = budget_filter(shortlist)
shortlist = network_memory_filter(shortlist)
shortlist = mode_filter(shortlist)                // 2B
return rank(shortlist)
```

The new step:

```
function experimental_filter(in):
    if engine.experimental_families_enabled:
        return in
    out = []
    for route in in:
        if family_maturity(route.transport_family) == Experimental:
            skip_ledger.append(route, "experimental_family_disabled")
            continue
        out.append(route)
    return out
```

The filter is pure: no state mutation outside the skip ledger.

## Soak coverage

Two new scenarios at 3A:

- `experimental-gate-respected.json` — half the synthetic
  clients have the gate ON, half OFF; rig asserts the path
  manager respects the gate per-client and the burn-pressure
  detector ignores the skipped-experimental entries.
- `webtunnel-handshake.json` — locked in
  `webtunnel-route-v1.md`.

`--scenarios v2-superset` whitelist widens 12 → 14 at 3A.

## ABI surface change

3A adds **one** release ABI symbol:

```
engine_set_experimental_families_enabled(enabled int) int
```

- Returns 0 on success, -1 on engine-not-initialised.
- Persists in secrets KV; survives session epoch.
- Diagnostics widen: `experimental_families_enabled` (always
  present), `experimental_routes_skipped` (per-rank-pass).
- Canonical regression:
  `core/abi/experimental_test.go::TestExperimentalGateSurvivesSessionEpoch`.

Release surface: 41 → **42**. Engine version bumps to
`daal-core 0.7.0+v3-transport`.

## Locked invariants

- Family taxonomy is a closed list; new families are
  roadmap-level decisions.
- Experimental maturity is the entry point for every new
  family.
- Auto-promotion ignores experimental-only networks.
- The experimental gate is per-engine, not per-network.
- Network success NEVER promotes a family from Experimental
  to Stable (the trust-UI invariant from 1B generalises here:
  field success is a route property, not a family property).
- Family-specific config is opaque to the routestore; only
  the family's engine handler interprets it.
- A family may be present in a bundle without being installed
  in the engine; in that case the route is silently filtered
  (treated as if it had `experimental_min_engine_version`
  failing).

## Phase 3C amendment — MASQUE family lands

Phase 3C lands `masque` at Experimental maturity. Locked at
3C:

- `masque` is a SINGLE family with three sub-modes
  (`masque_h3_quic`, `masque_h2_connect`, `masque_lifeline`).
  The sub-modes are NOT separate families; the bundle parser
  accepts only the family token, never a sub-mode token.
- Sub-mode selection is private to `core/transports/masque/`;
  the path manager sees the family, not the sub-mode. The
  rank pipeline is unchanged.
- One new optional `routes[]` field at 3C: `masque_endpoint`.
  Validated by the bundle parser; only meaningful on
  `transport_family = "masque"` routes. See
  `specs/masque-ladder-v1.md`.
- Auto-promotion (2G) explicitly ignores masque-only networks
  ("MASQUE is opportunistic, never required"). The
  experimental filter from 3A continues to run unchanged.
- The trust-UI region-soft-caveat for MASQUE reuses the
  `caveat_fa_ir` mechanism documented in 3A; publishers MAY
  supply a Persian caveat per route, otherwise the generic
  experimental caveat applies.
- One new release ABI symbol — `engine_set_masque_submode_override`
  — see `specs/masque-ladder-v1.md` and `specs/engine-abi-v1.md`.
  Surface 44 → 45.

## Phase 3D amendment — Refraction families land

Phase 3D lands `psiphon` and `conjure` at Experimental maturity.
Locked at 3D:

- Both families are gated by the 3A experimental-families flag.
- `IsOpportunistic` is added to the family registration record.
  `psiphon` is **NOT opportunistic** (auto-promotion MUST NOT
  promote a network whose only family is psiphon); `conjure`
  IS opportunistic; `masque` is retroactively annotated as
  opportunistic (the 3C invariant is now expressed via the
  registry rather than as a special-case in the auto-promotion
  detector).
- ~~`psiphon` ships with the vendored `psiphon-tunnel-core` tree
  under GPLv3, isolated behind the `-tags no_psiphon` build
  excluder. `psiphon_compiled_in` (diagnostic) flips to `false`
  under that tag and the engine refuses psiphon-route activation.
  `conjure` (Apache-2.0) ships unconditionally; the
  `conjure_compiled_in` flag is reserved for future build-tag
  conditioning but is constant `true` at 3D.~~

  > **SUPERSEDED — WAVE 5.** This paragraph described a build that
  > never existed. Neither `psiphon-tunnel-core` nor `gotapdance` has
  > ever been in `core/go.mod`, and no build script has ever passed
  > `-tags no_psiphon`. Both `psiphon_compiled_in` and
  > `conjure_compiled_in` are now constant `false`, and the
  > corresponding recorders refuse rather than record. Both families
  > are `unsupported` in `core/routestore/family.go` for structural
  > reasons — psiphon is a third party's network you hand off to
  > rather than host; conjure needs a cooperating ISP running a
  > refraction station on a transit link it owns. See
  > `core/abi/refraction_compiled.go`, `specs/psiphon-route-v1.md`
  > and `specs/conjure-route-v1.md`.
- Four new optional `routes[]` fields (`psiphon_bundle_blob_b64`,
  `conjure_phantom_subnets`, `conjure_station_pubkey`,
  `conjure_decoy_pool`); see `specs/sbp-v1.md` "Phase 3D
  widening".
- **No new release ABI symbols** at 3D. The
  `RecordPsiphonActiveRoute` / `RecordConjureActivation`
  Go-level entry points are package-internal. Surface stays at
  45.
- The `conjure_phantom_in_use` diagnostic carries the 8-byte
  SHA-256 truncation of the raw phantom IP (16 hex chars). The
  raw IP NEVER appears in diagnostics. Mirrors the 2C SSID and
  2D PIN no-leak invariants.

## Phase 3E amendment — WASM transport slot lands

Phase 3E lands `transport_module` at Experimental maturity.
Locked at 3E:

- `transport_module` is **NOT opportunistic**. Auto-promotion
  MUST NOT promote a network whose only family is
  `transport_module` (parity with `psiphon`). The reasoning
  is identical: a sandboxed unproven transport SHOULD NOT be
  the auto-pivot signal.
- The wazero runtime is the **only** WASM runtime supported at
  3E; future runtimes are NEW family slots, not amendments.
- The WATER v1 host ABI is closed (`dial`, `read`, `write`,
  `close`); future ABI versions are NEW family slots.
- The `wasm_compiled_in` diagnostic flag flips to `false`
  under `-tags no_wasm`; the two release symbols (46 + 47)
  are still emitted (empty surface) so consumers do NOT
  branch on absence.
- The kill-switch surface is **per-module** (per-sha256), NOT
  blanket; see `specs/wasm-kill-switch-v1.md`.

## Carry-overs

- Family-level kill-switch publisher key & delta format
  (kill the entire `psiphon` or `masque` family in one delta)
  → 3F.
- Promotion-candidate maturity copy and badge → first family
  to actually be a promotion candidate.
- Per-network family disablement → V4 (deliberate; see
  privacy invariant above).
- Generalised "single-family multi-submode" abstraction
  (lift the masque chooser into `core/ladder/`) → V4 (3E
  did not need it).
