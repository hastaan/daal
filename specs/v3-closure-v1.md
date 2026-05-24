# V3 Closure (v1)

This spec is the **formal closure record** for the V3 milestone of
the Daal anti-censorship project. V3 closes when the criteria
below are met on a single release-cut run; this spec is the gate
to V4.

V3 is the "transport agility" line: ship a new transport family
without shipping a new app. Phases 3A through 3F built the V3
surface; phase 3-Soak verifies it.

## Closure criteria

V3 closes when **all** of the following hold on a single
release-cut soak run:

1. **Primary metric (V3-1) green.**
   `engine_loaded_wasm_modules` contains every published
   `transport_module` slug on every platform stub (Linux + Android
   + iOS) within 24 simulated hours of publication. See
   `specs/v3-success-metric-v1.md` §primary.

2. **Secondary 1 (V3-S1) green.**
   Experimental-gate cross-product: gate-OFF clients never
   activate an Experimental-tier family; gate-ON clients activate
   at least one. See `specs/v3-success-metric-v1.md` §secondary 1.

3. **Secondary 2 (V3-S2) green.**
   Trust-UI parity: every observed badge equals the locked
   maturity of its family per `specs/transport-families-v1.md`.

4. **Secondary 3 (V3-S3) green.**
   No V1/V2 regression: `--scenarios v2-superset` (26 scenarios)
   passes its primary + four secondaries per
   `specs/v2-success-metric-v1.md`.

5. **Secondary 4 (V3-S4) green.**
   Per-family burn rate: no family burns faster than the directory
   refresh cadence (default 48h).

6. **Engine version unchanged at closure.**
   `daal-core 0.9.0+v3-share` (the 3F shipped version). The 3-Soak
   phase is verification-shaped — it ships no new engine code.

7. **ABI release surface unchanged at closure.**
   `nm libdaalcore.so | grep ' T engine_' | wc -l` = **48**, the
   3F shipped count. The 3-Soak phase exposes no new release
   symbols.

8. **All 3F regression matrix green.**
   The full v2-superset 26-scenario matrix returns the same
   byte-for-byte verdict it returned at 3F ship. Any drift is a
   regression and blocks closure.

## Position B preserved

V3 closure is consistent with the project's position-B telemetry
stance:

* No phone-home from the running engine.
* No telemetry pipeline added by the V3 surface.
* The 3-Soak rig produces all artefacts locally; nothing leaves
  the soak machine without an explicit operator action (publishing
  the comparison memo, shipping the handover doc).

The locked maturity table publishes user-facing trust signals at
build time; it is not derived from runtime telemetry.

## V4 gate

V4 is the "lifeline relay" line. V3 closure is the precondition
for opening V4:

* V4 spec at `phases of development/26-phase-3g-lifeline-relay.md`
  (filed as locked but NOT shipping at 3-Soak; the five hard
  pre-conditions remain unmet at this writing).
* V4 Track A engine target is `daal-core 0.10.0+v3-relay`; the
  ABI grows from 48 to 50 release symbols at execution time.
* The V4 phase MUST NOT begin until the five Track-A
  pre-conditions are satisfied (partner, MOU, audit, threat
  model, kill-switch test) — see
  `phases of development/26-phase-3g-lifeline-relay.handover.md`.

## Closure record contents

The closure run produces:

1. The verifier output JSON
   (`internal/v3verifier.Aggregate{...AllPass=true}`).
2. The threshold-comparison memo at
   `phases of development/27-phase-3-soak-threshold-comparison.md`.
3. The 3F regression-matrix re-verification log.
4. The handover document at
   `phases of development/27-phase-3-soak-success-metric.handover.md`.

This spec is appended-to (not edited) when V3 actually closes:
when the release-cut run delivers a green aggregate the operator
appends a `## Closure run YYYY-MM-DD` section recording the run ID,
the verifier output, and a one-line attestation. Until then the
above sections describe the gate.
