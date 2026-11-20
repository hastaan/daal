# Modifier: tls_fragment

## Identity

- **kind**: `tls_fragment`
- **sing-box reference**: TBD — finalised at censor-lab review.
  Candidate libraries include sing-box's `tls_fragment` outbound
  filter (if upstream stabilises) or a Daal-side equivalent below
  the sing-box layer.

## Description

`tls_fragment` is a family of TLS-record-fragmentation /
packet-mutation techniques applied to outgoing TLS handshakes. The
mutation splits the TLS ClientHello (and optionally subsequent
records) across TCP segment boundaries the censor's DPI is known to
mis-reassemble, defeating SNI-based filtering without prepending a
fake hello. Distinct from `client_desync`: `tls_fragment` does not
require raw-socket capability — it operates at the TLS-library layer
and is in principle reachable from sandboxed mobile platforms.

The supplement §11.6 reserves this kind. Final semantics (which
library, which fragmentation policy, whether to include record-layer
re-segmentation in addition to TCP-segment manipulation) are pending
the censor-lab review that gates the PASS record.

## What the shipped engine can do today (2026-11-20)

Read from the vendored source, not measured. Recorded so nobody
"enables" this on a tier where it cannot run, and so nobody closes it
as a no-op on the tier where it can. Source: the review section of
`docs/exotic-transports-plan.md` (item A6), which corrects that plan's
"no-op on every tier".

- REALITY cannot fragment in sing-box 1.13.12.
  `common/tls/reality_client.go` builds `utls.UClient` on the raw
  connection (:127) and never wraps `tf.NewConn`, so neither
  `fragment` nor `record_fragment` reaches a `vless-reality` hello.
- `record_fragment` on the `websocket-tls` uTLS path can.
  `common/tls/utls_client.go:61-62` (and std TLS,
  `common/tls/std_client.go:53-54`) wrap the connection in
  `tf.NewConn` when `record_fragment` is set. `fragment` alone, with
  `record_fragment` unset, does not wrap on either path.
- Unmeasured. Nothing in `test-rigs/` or the field has run it, against
  any censor model.
- It only splits at an SNI. `common/tlsfragment/conn.go` `Write`
  splits the first packet only when `IndexTLSServerName` finds a
  server name. Today's `websocket-tls` pack puts the relay IP in
  `server_name`, which Go and uTLS strip
  (`publisher/deploy/relaypack/client_outbound.go`, near
  `pinnedTLSOpts`), so the hello has no SNI and the wrapper passes it
  through unchanged. It can matter only after the real-SNI work (plan
  W2-R) lands.
- `naive` refuses both options outright
  (`protocol/naive/outbound.go:75-76`).
- Iran evidence is split. Older work says the DPI reads only the
  first packets and does not reassemble
  (`research/intel-and-some-working-methods.md:77`); a 2026
  single-user report says it reassembles 10-30 byte fragments and
  still reads the SNI. Our relays mostly avoid a blocked-SNI problem
  anyway: REALITY sends an allowed cover name.

The status stays PENDING. Nothing above is a pass or a rejection; it
narrows the methodology to the one tier that can carry the modifier.

## Pass record

- **status**: PENDING
- **methodology**: TBD — censor-lab plan must finalise the
  fragmentation policy under test (single canonical policy or a
  parameterised family), define the target ASNs and services, and
  specify the falsifying observation that would flip the record to
  `REJECTED`.
- **observed**: TBD — pending censor-lab run. Only `websocket-tls`
  with `record_fragment` can be tested at all (see "What the shipped
  engine can do today"); REALITY cannot fragment in this engine.
- **reviewer**: TBD
- **date**: TBD

## Phase gating

- **min_phase**: PostV2

`tls_fragment` is reserved post-V2. Even on PASS sign-off, this
modifier is not accepted at V1.5 / V1.6 (locked invariant 39).

## Platform gating

- **platforms**: `[]`

Empty array — no platform yet enabled. Per supplement §11.6 the
`tls_fragment` row says "post-V2"; the platform list is finalised at
censor-lab review (the fragmentation library choice in the
methodology determines which platforms can carry it). Empty platforms
list means the engine importer rejects this modifier on every
platform regardless of validator state, with error code
`IMP_MODIFIER_PLATFORM` (locked invariant 40).

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
  carrying `tls_fragment` has its effective `probing_risk_class`
  bumped upward.
- **Cooldown attribution**: unchanged. A `direct_vps` + `tls_fragment`
  or `cdn_fronted` + `tls_fragment` candidate retains its base
  `exposure_mode` for cooldown per §13.4.
- **Per-candidate scoping**: misfire does NOT burn siblings (locked
  invariant 41).
- **Self-fingerprintability**: the censor-lab review must specifically
  rule out the case where the fragmentation pattern itself becomes a
  Daal signature. The risk is higher than for `client_desync`
  because `tls_fragment` operates at a layer the censor's DPI
  inspects directly. This is why `min_phase: PostV2` + PENDING +
  empty `platforms[]` hold.

## References

- Supplement §11.6 — field-observed tactical modifiers table (the
  `tls_fragment` row).
- Supplement §12.2.2.bis — `modifiers[]` schema slot.
- Supplement §13.4 — cooldown attribution.
- `docs/modifier-review-process.md` — censor-lab methodology.
- FRP-12 phase doc: `phases of development/42-phase-frp-12-modifier-framework.md`.
