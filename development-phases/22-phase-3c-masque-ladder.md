# Phase 3C — MASQUE Ladder (HTTP/3 → HTTP/2 → Lifeline)

## Roadmap Coverage

V3.3 ("MASQUE ladder"). Implements RFC 9298 (UDP over HTTP)
and RFC 9484 (IP over HTTP) as a single transport family with
three sub-modes selected by the engine based on per-network
UDP probe results from 2C.

## Goal

Add `masque` as a single transport family the engine can
operate in three sub-modes — HTTP/3 over QUIC where UDP works,
HTTP/2 Extended CONNECT where UDP fails, and Lifeline mode at
the bottom rung. MASQUE is opportunistic, never required.

## Scope

### Engine

- **`masque` transport family** — single family with three
  sub-modes (`masque_h3_quic`, `masque_h2_connect`,
  `masque_lifeline`).
- **Sub-mode selection algorithm.**
  1. Read the 2C per-network UDP probe result for the active
     network.
  2. If UDP works → start at `masque_h3_quic`.
  3. If UDP fails → start at `masque_h2_connect`.
  4. If `masque_h2_connect` burns under the 2G classifier and
     the active mode is `lifeline` or `lifeline-strict` →
     drop to `masque_lifeline` (a TCP-shaped Reader-mode-only
     sub-mode).
  5. The selection is per-route per-session; on disconnect,
     reset to the per-network probe result.
- **HTTP/3 over QUIC.** Vendored from `quic-go` (already
  pinned in the engine; reused here).
- **HTTP/2 Extended CONNECT fallback.** Vendored from
  `golang.org/x/net/http2`.
- **Lifeline sub-mode.** TCP-only; integrates with the
  `lifeline-strict` budget rules from 2D — only TCP/443
  routes, no bulk-capable, low capacity.

### Bundle format

- `routes[].family = "masque"` accepted.
- `routes[].masque_endpoint` — the publisher's MASQUE
  endpoint URL.
- `routes[].masque_target` — the target the publisher
  authorises this route to reach (per RFC 9298 the target
  is encoded into the request).

### Trust UI

- MASQUE routes show the Experimental badge on first release.
- Diagnostics widen additively with `masque_submode`
  (`h3_quic` / `h2_connect` / `lifeline`); absent for
  non-MASQUE routes.

### Soak

- New scenario `masque-udp-failover.json` — drives the 2C
  per-network UDP probe to fail mid-session and asserts the
  engine swaps to `h2_connect` without burning the route.
- New scenario `masque-lifeline-rung.json` — burns the
  `h2_connect` sub-mode under the classifier while the active
  mode is `lifeline-strict` and asserts the engine drops to
  `masque_lifeline`.
- `--scenarios v2-superset` whitelist widens 16 → 18.

## Out of scope

- A MASQUE proxy / server (Daal is a client).
- Refraction (3D) — MASQUE is the substrate Conjure can later
  ride on, but 3D ships independently.
- WASM transport slot (3E).

## Implementation Details

### ABI surface

Phase 3C adds **zero** release ABI symbols. MASQUE plugs into
the existing path manager and route activation surfaces.
Diagnostics widen additively with `masque_submode`.

Release surface stays at **42**. Engine version stays at
`daal-core 0.7.0+v3-transport`.

### Spec deliverables

- **New:** `specs/masque-ladder-v1.md` — the three sub-modes,
  the selection algorithm, the integration with 2C UDP probes
  and 2D lifeline-strict budgets.
- **Amend:** `specs/transport-families-v1.md` (masque added).
- **Amend:** `specs/bundle-format-v1.md` (MASQUE optional
  fields).
- **Amend:** `specs/network-memory-v1.md` (the UDP probe is
  consumed by MASQUE; per-network record gains a
  `masque_submode_last_used` field, additive only).

### Decision deviations

The roadmap notes "MASQUE is opportunistic, never required."
3C respects this: the engine never auto-promotes solely into
MASQUE; MASQUE routes coexist with other families and the path
manager's standard trust + budget rules apply unchanged.

## Testing Requirements

- Engine unit tests: sub-mode selection per UDP probe
  outcome; per-session reset on disconnect; lifeline
  sub-mode budget enforcement.
- Bundle parser tests: MASQUE route fields round-trip.
- Soak: both new scenarios PASS in both modes.
- All previous V1/V2/3A/3B tests green.

## Exit criteria

1. `masque` family registered in the 3A taxonomy with three
   sub-modes.
2. Sub-mode selection consumes the 2C per-network UDP probe.
3. `lifeline_submode` integrates with the 2D
   `lifeline-strict` budget.
4. Both new soak scenarios PASS.
5. `specs/masque-ladder-v1.md` shipped; existing specs
   amended.
6. `nm` count remains **42**.

## Handover to 3D

Phase 3D receives:
- A MASQUE substrate that Conjure-class transports can later
  ride on.
- The single-family-multiple-submodes pattern as a reference
  for refraction's similar shape.
