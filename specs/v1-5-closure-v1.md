# V1.5 Closure (v1)

> **Status: HOLD — pilot run pending.**
>
> This spec is the formal closure record for the V1.5 milestone of
> the Daal anti-censorship project. The engineering surface is
> SHIPPED at FRP-7 (commits 04dd0d9 .. this); the closure record
> is gated on a real five-FRP pilot run per the supplement §22.1
> success metric. FRP-7.5 sub-key-chain hardening is also
> engineering-SHIPPED on the V1.5 closure path; it does not
> change the live-pilot gate. The project lead flips this status to SHIPPED
> by appending a `## Closure run YYYY-MM-DD` section once the
> pilot evidence template (`docs/pilot/frp-7-pilot-template.md`)
> aggregate roll-up returns 5/5 (or ≥ 4/5 per its rules) on every
> success-metric row.

V1.5 is the **diaspora-helper line**: ship a self-service Family
Relay Publisher tool so a single diaspora operator with a
Hetzner account and a phone-call's worth of help to a family
member in Iran can stand up a working RelayPack, get the family
online, keep them online for at least seven consecutive days,
and survive at least one selector-driven rotation along the way
— all without project-operated infrastructure on either end.

## Closure criteria

V1.5 closes when **all** of the following hold on a single
real-pilot run with five FRPs:

1. **Primary metric (V1.5-P1) green.**
   For ≥ 4 of 5 pilot FRPs the wizard's
   `wizard.start → operator-record-persisted` wall-clock is
   ≤ 10 minutes. See `daal-roadmap-v3-supplement-diaspora-helper.md`
   §22.1.

2. **Primary metric (V1.5-P2) green.**
   For ≥ 4 of 5 pilot FRPs at least one designated recipient is
   online (`engine_diagnostics_explain.posture == "connected"`)
   within 60 seconds of scanning the QR code, on first attempt.

3. **Stay-online metric (V1.5-S1) green.**
   For ≥ 4 of 5 pilot FRPs the family-side anonymized session
   uptime is ≥ 99 % over a 7-day window.

4. **Rotation metric (V1.5-S2) green.**
   For ≥ 4 of 5 pilot FRPs at least one selector-driven rotation
   was observed during the 7-day window AND the recipient saw a
   plain-language Explanation when the rotation occurred AND
   end-to-end recovery wall-clock was ≤ 60 s.

5. **Schema-correctness metric (V1.5-S3) green.**
   The mode-aware schema (`exposure_mode` + `public_risk_tags[]`
   + `origin_risk_tags[]`) was exercised end-to-end through
   validator → importer → store → selector → UI in the
   `v1-5-mode-aware-schema-end-to-end` synthetic soak scenario,
   AND no real-pilot RelayPack drifted from the V1.5 phase
   contract (`freshness_url=""`, every candidate
   `exposure_mode=direct_vps`; `.sbp` `spec_version=3` for
   root-signed RelayPacks or `spec_version=4` for FRP-7.5
   sub-key-signed RelayPacks).

6. **Engine version unchanged at closure.**
   `daal-core 0.9.0+v3-share` (the 3F shipped version,
   unchanged through 3-Soak and FRP-0..FRP-7).

7. **ABI release surface unchanged at closure.**
   `nm libdaalcore.so | grep ' T engine_' | wc -l` = **48**,
   unchanged from 3F.

8. **All 3F + 3-Soak regression matrix green.**
   The full v3-superset 31-scenario matrix returns the same
   byte-for-byte verdict it returned at 3F + 3-Soak ship. Any
   drift is a regression and blocks closure.

9. **Synthetic V1.5 soak rig green.**
   `--scenarios v1-5-superset` (6 scenarios) returns PASS on
   every scenario. The synthetic rig is the gate the engineering
   side controls; the live pilot is the gate operations
   controls. Both are required.

10. **Pilot consent collected.**
    All five pilot FRPs signed
    `docs/pilot/consent-template.md` (current git SHA at
    signing). Aggregate consent counts may be cited here; no
    individual consent records are committed to this repo.

## Position B preserved

V1.5 closure is consistent with the project's position-B
telemetry stance:

* No phone-home from the running engine (unchanged through V1.5).
* No telemetry pipeline added by the V1.5 surface.
* The pilot evidence template captures only operational
  measurements; no real names, IPs, ASNs, or device identifiers
  ever land in the repo.
* Filled evidence forms and signed consent records live
  out-of-tree per `.gitignore`.

## V1.5 → V1.6 gate

V1.6 is the **CDN milestone** line: extend the FRP wizard to
produce RelayPacks mixing `direct_vps` and `cdn_fronted`
candidates per supplement §11.7 + §14.4. V1.5 closure is the
precondition for opening V1.6:

* V1.6 spec at `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md`
  (filed but NOT shipping at V1.5).
* V1.6 engine target is `daal-core 0.9.0+v3-share` UNCHANGED
  (the V1.5 schema reservations land cdn_fronted as a no-op at
  V1.5 already). FRP-7.5's sub-key cert chain may emit
  `spec_version=4` bundles; this is still V1.5 hardening, not
  a V1.6 transport expansion.
* The V1.6 phase MUST NOT begin until V1.5 closure is recorded
  here. Engineering may begin spec work on V1.6 in parallel,
  but no `cdn_fronted` candidate ships in production until V1.5
  is closed.

## Closure record contents

Once the live pilot completes the project lead appends:

1. The aggregate roll-up table from the pilot evidence template
   (no per-FRP rows; only the 7 metric rows).
2. Pilot consent count (e.g. `5 of 5 signed`).
3. The synthetic-soak verdict on `v1-5-superset` (6/6 scenarios
   PASS).
4. The 3F + 3-Soak regression-matrix re-verification log.
5. The handover documents at
   `docs/handovers/frp-7-handover.md` and
   `docs/handovers/frp-7-5-handover.md`.
6. A one-line attestation by the project lead.

This spec is appended-to (not edited) when V1.5 actually closes:
when the live-pilot run delivers the green aggregate the
operator appends a `## Closure run YYYY-MM-DD` section recording
the run ID, the aggregate roll-up, and the attestation. Until
then the above sections describe the gate.

## Pilot results

(Empty until live pilot completes. The aggregate roll-up table
from `docs/pilot/frp-7-pilot-template.md` is transcribed here.
No per-FRP rows. No identifying information.)

| Metric | FRPs PASSING | FRPs FAILING | Median observed |
|---|---|---|---|
| V1.5-P1: provisioning ≤ 10 min |   /5 |   /5 | |
| V1.5-P2: family online ≤ 60 s |   /5 |   /5 | |
| V1.5-S1: 7-day uptime ≥ 99 % |   /5 |   /5 | |
| V1.5-S2: rotation observed + plain-language Explanation + recovery ≤ 60 s |   /5 |   /5 | |
| V1.5-S3: mode-aware schema E2E inert at V1.5 |   /5 |   /5 | n/a |

## Carry-overs to V1.6

(Empty until live pilot completes.)
