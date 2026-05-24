# Phase 3A — WebTunnel + Transport-Family Scaffold

## Roadmap Coverage

V3.1 ("WebTunnel-style routes"). Adds the `webtunnel` transport
family AND lays the scaffold every later V3 sub-phase reuses:
the signed `.sbp` `transport_family` taxonomy widening, the
Experimental UI badge, the per-region soft-caveat banner, and
the `engine_set_experimental_families_enabled` ABI symbol.

## Goal

Land WebTunnel as the *first* new transport family of V3 with
the lowest possible novelty risk — WebTunnel is HTTPS-shaped,
research-validated, and well-documented upstream — while in
parallel building the integration shape that 3B–3G will all
ride on. Treat 3A as 50% WebTunnel, 50% scaffold.

## Scope

### Engine

- **Transport family taxonomy.** Widen the family enum in
  `core/routestore/family.go` with `webtunnel` and a reserved
  `experimental_*` band for 3E. The taxonomy stays a closed
  list — adding `webtunnel` is a one-time edit; later phases
  add their families the same way.
- **WebTunnel route handling.** Vendor `webtunnel` PT support
  into the engine layer (Tor Project's reference Go
  implementation). The route's address is a publisher-chosen
  HTTPS URL with a secret path; on activation the engine
  performs the standard WebSocket Upgrade handshake.
- **Experimental gate.** New release ABI symbol
  `engine_set_experimental_families_enabled(int)` (0/1). When
  disabled (default), the path manager filters experimental
  families out of route selection entirely. Auto-promotion
  cannot promote into an experimental-only network. The flag
  is per-engine-session; survives unlock; survives mode change;
  survives network change. Cleared only by user toggle.
- **Diagnostics widening (additive).**
  - `experimental_families_enabled: bool` — always present.
  - `route_family` already in diagnostics; gains `webtunnel`
    as a possible value.

### Bundle format

- Spec amendment: `specs/bundle-format-v1.md` widens the
  `routes[].family` enum and documents the WebTunnel-specific
  optional fields (`webtunnel_secret_path`, `webtunnel_sni`,
  `webtunnel_alpn`).
- Test vectors added in `specs/bundle-test-vectors/`. A signed
  WebTunnel-bearing `.sbp` and a signed mixed-family `.sbp`
  (VLESS + WebTunnel) round-trip through the parser.

### Publisher tooling

- `daal-publish webtunnel-bridge` subcommand generates the
  secret path, the valid CA-cert verification helper, and the
  Tor `bridge` line. Documented in `specs/publisher-cli-v1.md`.
- The CLI refuses to mix unsigned and signed routes in the
  same `.sbp`.

### Trust UI

- **"Experimental" badge** on routes from
  `webtunnel` and any later experimental family. Copy locked
  en + fa.
- **Region-soft-caveat banner.** Research says WebTunnel has
  limited Iran value (TLS fingerprint filtering at the time of
  V3 start). The UI shows a soft caveat banner when the user's
  detected locale is `fa-IR`: *"WebTunnel routes have limited
  effectiveness in Iran today. Use only if your other routes
  are blocked."* Banner is informational, not blocking; the
  user can still enable.
- **Settings toggle** for "Allow experimental transports",
  off by default. When toggled on, the UI surfaces a one-time
  explainer modal documenting that experimental routes may
  fail-fast and that auto-promotion will not consider them.

### Soak

- New scenario `webtunnel-handshake.json` — models the
  WebSocket Upgrade handshake under three conditions:
  - clean (handshake succeeds, route runs normally),
  - TLS-fingerprint-filtered (handshake fails fast, route
    burns under the same classifier 2G uses),
  - intermittent (handshake succeeds 30% of the time;
    classifier eventually burns).
- New scenario `experimental-gate.json` — asserts the path
  manager filters experimental families out when the gate is
  off, and includes them when on.
- `--scenarios v2-superset` whitelist widens 12 → 14.

## Out of scope (held for later V3 sub-phases)

- Snowflake / multi-rendezvous (3B).
- MASQUE (3C).
- Refraction (3D).
- WASM transport slot (3E) — uses the experimental gate from
  3A but adds the runtime hosting separately.
- One-tap share (3F) — uses the new family taxonomy but adds
  delegate-key sharing separately.
- Lifeline relay (3G).

## Implementation Details

### ABI surface

Phase 3A adds **one** release ABI symbol:

```
engine_set_experimental_families_enabled(enabled: int) -> int
```

- Returns 0 on success, -1 on engine-not-initialised.
- The flag persists in the secrets KV.
- Diagnostics field `experimental_families_enabled` is always
  present (`true` / `false`).

Release surface: 41 → **42**. Engine version bumps to
**`daal-core 0.7.0+v3-transport`** signalling the V3 line.

### Spec deliverables

- **New:** `specs/transport-families-v1.md` — the taxonomy,
  the experimental gate semantics, the rules every later V3
  family must follow.
- **New:** `specs/webtunnel-route-v1.md` — the WebTunnel
  route fields, handshake state machine, classifier behaviour.
- **Amend:** `specs/engine-abi-v1.md` (surface 42, the new
  symbol, the diagnostics widening).
- **Amend:** `specs/bundle-format-v1.md` (family enum
  widening, WebTunnel optional fields, new test vectors).
- **Amend:** `specs/publisher-cli-v1.md`
  (`webtunnel-bridge` subcommand).
- **Amend:** `specs/route-budgets-v1.md` (no rule changes,
  but documents that `webtunnel` budgets are computed
  identically to other TCP/443 families).

### Privacy invariants

- WebTunnel SNI / ALPN choices are publisher-supplied. The
  engine logs them only in the in-memory ring buffer.
- The WebSocket Upgrade does not leak any device identifiers.
- Diagnostics export remains redacted — no per-route addresses
  appear in user-shareable diagnostics.

### Decision deviations

The roadmap notes WebTunnel "currently does not work in Iran";
3A ships it anyway, gated as experimental, with the soft
caveat banner. Reasons: (a) the scaffold work is necessary for
3B–3G regardless, (b) WebTunnel may become viable in Iran via
upstream Tor Project mitigations during V3, (c) shipping the
family unblocks publishers who want to operate WebTunnel
bridges for users outside Iran.

## Testing Requirements

- Engine unit tests: family enum widening, WebTunnel route
  parsing, experimental-gate flag persistence + diagnostics.
- Bundle parser tests: WebTunnel-bearing `.sbp` round-trip,
  mixed-family `.sbp` round-trip, malformed WebTunnel route
  rejection.
- Publisher CLI tests: `webtunnel-bridge` subcommand generates
  expected output; refuses unsigned mixing.
- Soak: `webtunnel-handshake` and `experimental-gate` scenarios
  PASS in `--mode rig` and `--mode in-engine`.
- Trust UI tests (desktop): Experimental badge appears for
  WebTunnel routes; soft-caveat banner appears for `fa-IR`
  locale; one-time explainer modal fires once on first toggle.
- Android UI tests: same as desktop.
- iOS UI tests: same as desktop.
- All previous V1/V2 tests green.
- `nm` count = **42** on `libdaalcore.so`.

## Exit criteria

1. Release ABI surface is **42**;
   `engine_set_experimental_families_enabled` present.
2. `webtunnel` family in the taxonomy; bundle parser accepts
   WebTunnel-bearing `.sbp`.
3. `daal-publish webtunnel-bridge` ships and is documented.
4. Trust UI Experimental badge + region-caveat banner +
   one-time explainer ship on all three UIs.
5. Both new soak scenarios PASS in both modes.
6. `specs/transport-families-v1.md` and
   `specs/webtunnel-route-v1.md` shipped; existing specs
   amended.
7. Engine version is `daal-core 0.7.0+v3-transport`.

## Handover to 3B

Phase 3B receives:
- The transport-family taxonomy (it adds `snowflake`).
- The experimental-gate symbol (Snowflake ships gated
  experimental on first release).
- The bundle-format extension shape (it adds rendezvous-hint
  entries).
- The Experimental badge + caveat banner UI patterns.
- A working WebSocket-style handshake implementation pattern
  in the engine.
