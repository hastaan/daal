# Phase 3 — Ecosystem Integrations and Transport Agility (umbrella)

## Roadmap Coverage

V3 — Ecosystem integrations (V3.1 through V3.7). Transport
agility without changing the V1/V2 user experience or trust
model. New transports arrive as new route families that the
path manager learns to use.

## Goal

Ship at least one new transport family through the signed-supply
chain to all four platforms (Linux, Windows, Android, iOS)
without an app update. Add the rendezvous, MASQUE, and
refraction integrations the roadmap names. Land the WASM
transport slot as the V3 success-metric milestone. Decide
lifeline relay only if a credible partner is ready.

The critical invariant: **V3 does not change V1/V2 user
experience or trust UI**. Existing budget engine, mode budgets,
8-posture FSM, per-network memory, lifeline-strict, and
auto-promotion all apply unchanged to every new family. The
trust UI must already work for any new family the moment it
ships through `.sbp`.

## Sub-phase order (locked at V3 start)

| # | Sub-phase | Roadmap | Header |
|---|-----------|---------|--------|
| 1 | **3A — WebTunnel + transport-family scaffold** | V3.1 | `20-phase-3a-webtunnel-scaffold.md` |
| 2 | **3B — Multi-rendezvous library + Snowflake integration** | V3.2 | `21-phase-3b-snowflake-rendezvous.md` |
| 3 | **3C — MASQUE ladder (HTTP/3 → HTTP/2)** | V3.3 | `22-phase-3c-masque-ladder.md` |
| 4 | **3D — Psiphon / Conjure refraction hooks** | V3.4 | `23-phase-3d-refraction-hooks.md` |
| 5 | **3E — WASM transport slot (WATER)** | V3.5 | `24-phase-3e-wasm-transport.md` |
| 6 | **3F — One-tap "send working routes" + delegate keys** | V3.6 | `25-phase-3f-one-tap-share.md` |
| 7 | **3G — Optional partner-operated lifeline relay** *(conditional)* | V3.7 | `26-phase-3g-lifeline-relay.md` |
| 8 | **3-Soak — V3 success-metric soak** | success metric | `27-phase-3-soak-success-metric.md` |

3A is first because it sets the *pattern* every later family
follows: signed `.sbp` route type + trust-UI plumbing +
Experimental flag. 3E is the V3 success-metric milestone
("ship a transport family without an app update"). 3G ships
only if a partner organisation is operationally ready under the
hard constraints; otherwise it is documented as not-shipping
and V3 closes at 3F.

## Decisions to lock at V3 start

Per the roadmap "Decision points" table, these decisions land
at the start of V3, before any sub-phase begins:

1. **Snowflake integration: V3 vs V4.** Default V3.2. Lock at
   3A start.
2. **WASM transport slot: V3 vs V4.** Default V3.5. Lock at
   3A start.
3. **Lifeline relay: ship in V3 / never.** Default: ship only
   if partner ready; otherwise never. Re-evaluated at 3G start.
4. **Lifeline relay run by project vs partner.** Pre-condition
   for 3G. Default: partner only.
5. **Bundle format extension** — new `transport_module` route
   type and rendezvous-hint entry type — spec-frozen at 3A
   start before any sub-phase touches the bundle parser.

## Cross-cutting items that ride through V3

These items do not get their own sub-phase but must be picked
up *during* V3:

- **CC.1 (audits).** End-of-V2 client audit, scheduled at V3
  start.
- **CC.7 (Persian wordlist).** Commission the lexicographer
  for 4-word fingerprints.
- **Auto-promotion threshold tuning** with OONI / Censored
  Planet input (carry-over from 2G).
- **Burn-classifier real-DPI mode** — partner-lab bring-up
  (carry-over from 2G).
- **Bulk-capable opt-in cross-product at scale** — held OFF in
  2G load tier; treated in 3-Soak (carry-over from 2G).
- **`State` field removal** in the FSM diagnostic surface
  (carry-over from 2B).

## Locked invariants held through V3

These survive every sub-phase and may not be relaxed without an
explicit roadmap-level decision:

- **No changes to V1/V2 trust UI.** New families plug into
  existing trust ladders.
- **Existing budget engine and FSM apply unchanged.**
- **All new transports are signed-supply route families.** No
  unsigned out-of-band loading.
- **Experimental transports are clearly labelled** in the UI.
- **Kill-switches are signed.** A signed bundle delta can
  disable any new family or any WASM module client-side.
- **No transport assumes global reachability.** Per-network
  probe results from 2C gate UDP / WebRTC / fronted families.
- **UDP-based families are opportunistic**, never required.
- **Telemetry posture (CC.6) is unchanged.** No measurement
  output leaves the device.
- **ABI append-only.** Each sub-phase MAY add release symbols;
  none MAY change.

## V3 success metric

Quoted from the roadmap, locked here for V3 ship:

> A new transport family ships to all platforms via a signed
> `.sbp` bundle without an app update. iOS, Android, and desktop
> pick it up within 24 hours of publication, gated behind the
> Experimental flag. Existing trust UI works correctly for the
> new family. No regression on V1/V2 metrics.

The 3-Soak sub-phase is the verification gate.

## Out of scope (deferred to V4+)

- Refraction infrastructure operations (V4 partnership work).
- Publisher economics / payment intake.
- Adversarial reverse-engineering watch operations.
- UPGen / China-specific transports.
- Mesh / Bluetooth / Nearby cross-OS (in-OS limited mesh stays
  as research).
- Hardware-token integration for high-risk users.
- Localization beyond Persian + English.

## Handover to V4+

Phase 3 hands V4 a mature cross-platform client with a stable
multi-family transport surface, a signed module pipeline, an
external-audit trail, and operational lessons from real
deployment. V4 pivots from feature delivery to sustainability,
partnerships, and selective research.
