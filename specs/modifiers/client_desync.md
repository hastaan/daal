# Modifier: client_desync

## Identity

- **kind**: `client_desync`
- **sing-box reference**: n/a (raw-socket modifier; below sing-box)

## Description

`client_desync` is a family of client-side TCP-desynchronisation /
FakeSNI techniques applied to outgoing packets before they leave the
recipient's machine. Common variants prepend a fake TLS ClientHello
carrying an innocuous SNI (e.g. a major Iranian domain) ahead of the
real ClientHello, segment the real ClientHello across TCP boundaries
the censor's DPI cannot reassemble, or both. The mutation lives below
the transport library and requires raw-socket capability — on Linux
this is `CAP_NET_RAW` or running as root; mobile sandboxes do not
permit it.

The supplement §11.6 reserves this kind to defeat Iranian DPI's
SNI-based filtering of TLS-shaped routes (vless-reality, naive,
websocket-tls) without changing the recipient's `exposure_mode`. A
`direct_vps` candidate carrying `client_desync` is still a
`direct_vps` candidate for cooldown attribution per §13.4 — only the
packet shape changes.

## Pass record

- **status**: PENDING
- **methodology**: TBD — censor-lab plan must specify target ASNs
  (Iranian residential + mobile + corporate), target services
  (vless-reality + naive + websocket-tls candidates), trial count
  per cell (≥30), control vs experiment cohorts, instrumentation
  (per-flow capture + DPI-event timestamps).
- **observed**: TBD — pending censor-lab run.
- **reviewer**: TBD
- **date**: TBD

## Phase gating

- **min_phase**: PostV2

`client_desync` is reserved post-V2. Even on PASS sign-off, this
modifier is not accepted at V1.5 / V1.6 (locked invariant 39).

## Platform gating

- **platforms**: `["linux-desktop"]`

Raw-socket modifiers are Linux-desktop-only. The engine importer on
Windows / macOS / Android / iOS rejects any candidate carrying
`client_desync` regardless of validator state, with error code
`IMP_MODIFIER_PLATFORM` (locked invariant 40). Per supplement §11.6,
mobile sandboxes do not grant the packet capability `client_desync`
needs; Windows + macOS desktop ports are deferred to a future phase
that proves the equivalent capability on each platform under
censor-lab conditions.

## Validator behavior

- **V1.5**: reject — pass record PENDING (RP013 hard-rejects all
  non-empty `modifiers[]` at V15).
- **V1.6**: reject — pass record PENDING (RP013 hard-rejects all
  non-empty `modifiers[]` at V16).
- **PostV2**: reject — pass record PENDING (registry status is
  PENDING; registry's `AllowedKindsAt(PostV2)` returns empty for
  this kind; RP013's per-kind allow-list rejects).

## Risk notes

- **Effect on probing_risk_class**: per supplement §11.6, a candidate
  carrying `client_desync` has its effective `probing_risk_class`
  bumped upward (the mutation itself can be fingerprintable if the
  censor adapts; the racing/preference logic in §15 should treat the
  candidate as higher-risk than its base class).
- **Cooldown attribution**: unchanged. A `direct_vps` +
  `client_desync` candidate is attributed as `direct_vps` per §13.4.
- **Per-candidate scoping**: a misfire on the `client_desync`-bearing
  candidate does NOT burn sibling candidates in the same RelayPack
  (locked invariant 41).
- **Self-fingerprintability**: the censor-lab review must specifically
  rule out the case where the mutation itself becomes a Daal
  signature. This is the highest-risk failure mode and the primary
  reason `min_phase: PostV2` + PENDING status hold.

## References

- Supplement §11.6 — field-observed tactical modifiers table (the
  `client_desync` row).
- Supplement §12.2.2.bis — `modifiers[]` schema slot.
- Supplement §13.4 — cooldown attribution (modifier-bearing candidate
  retains its base `exposure_mode` for cooldown).
- Supplement §15 — racing / preference logic that consumes the
  bumped effective `probing_risk_class`.
- `docs/modifier-review-process.md` — censor-lab methodology.
- FRP-12 phase doc: `phases of development/42-phase-frp-12-modifier-framework.md`.
