# V3 Success Metric (v1)

Phase 3-Soak locks the **single roadmap-canonical pass criterion**
for the V3 milestone, plus four secondary metrics that protect the
engine against regressions outside the cross-platform-pickup
surface.

This spec is the contract the soak rig's
`--scenarios v3-superset` selector and the `internal/v3verifier`
package implement.

## Primary metric: cross-platform pickup ≤ 24 simulated hours

> For every `transport_module` (3E) freshly published into the
> subscription URL during the soak run, every platform stub —
> Linux, Android, iOS — observes the module's locked slug in
> `engine_loaded_wasm_modules` within 24 simulated hours of the
> publication timestamp.

The platform stubs are real OS-distinct binaries:

* `daal-soak-engine` — Linux desktop, no GOMEMLIMIT.
* `daal-soak-engine-android` — Android, GOMEMLIMIT = 200 MiB.
* `daal-soak-engine-ios` — iOS, GOMEMLIMIT = 50 MiB (the 2E NE
  budget).

The 24h cadence is a run-input flag
(`--cross-platform-pickup-cadence`, default `24h`); the V3 v1
LOCKED value is **24h**.

A run that publishes zero `transport_module` slugs passes the
primary metric trivially.

The interpretation: the V3 thesis is "ship a new transport without
shipping a new app". The primary metric is the operational floor —
within one calendar day of publishing the module, the user fleet
on every supported platform has it.

## Secondary metrics

The four secondaries are independent — a single failure does not
short-circuit the others. The verifier reports every failure so
operators can fix in one pass.

### Secondary 1: experimental-gate cross-product

50% of the load-tier fleet starts with
`engine_set_experimental_families_enabled(0)` ("gate-OFF") and 50%
with `(1)` ("gate-ON"). The verifier asserts:

1. Every gate-OFF client's per-client activation ledger contains
   **zero** activations of an Experimental-tier family
   (`webtunnel`, `snowflake`, `masque`, `psiphon`, `conjure`,
   `transport_module`).
2. Every gate-ON client has **at least one** Experimental-tier
   activation by simulated end of soak.

The cross-product proves the gate is honoured at scale and that
the gate-ON path actually exercises the experimental ladder.

### Secondary 2: trust-UI parity

For every (client, family) observation recorded at end of soak,
the badge surfaced by the trust-UI subsystem equals the family's
**locked maturity** as published in
`specs/transport-families-v1.md`.

The V3 locked maturity table (mirrored in
`internal/v3verifier.LockedFamilyMaturity`):

| Family | Maturity |
|--------|----------|
| `vless` | GA |
| `hysteria2` | GA |
| `wireguard` | GA |
| `webtunnel` | Experimental |
| `snowflake` | Experimental |
| `masque` | Experimental |
| `psiphon` | Experimental |
| `conjure` | Experimental |
| `transport_module` | Experimental |

A badge that disagrees with the table is a regression.

### Secondary 3: no V1/V2 regression

The soak driver runs `--scenarios v2-superset` (26 scenarios) in
the same run pass the v3-superset adds. The v2-superset's primary
+ secondaries (per `specs/v2-success-metric-v1.md`) MUST stay
green. The verifier reads the v2-superset's pass/fail boolean and
folds it into the V3 aggregate.

V3 is additive — V1 and V2 ship-criteria stay live.

### Secondary 4: per-family burn rate

For every transport family that experiences at least one burn in
the soak run, `first_burn_at - first_publish_at ≥
directory_refresh_cadence`. Mirror of the V2 primary, applied
per-family rather than per-route.

A family with zero burns trivially passes. The directory cadence
is the same `--directory-refresh` flag the V2 spec uses (default
`48h`).

## Locked thresholds (v1)

| Surface | Threshold | Defined in |
|---------|-----------|------------|
| Cross-platform pickup cadence | 24h | `--cross-platform-pickup-cadence`, default 24h |
| Platform mix | 60% Linux / 35% Android / 5% iOS | `internal/load.LockedDefaultMix` |
| GOMEMLIMIT (Android) | 200 MiB | `cmd/daal-soak-engine-android/main.go` |
| GOMEMLIMIT (iOS) | 50 MiB | `cmd/daal-soak-engine-ios/main.go` |
| Experimental gate cross-product | 50% gate-OFF / 50% gate-ON | run-input fixed at v1 |
| Bulk-capable cross-product | 25% opt-in / 75% off | run-input fixed at v1 |
| V3 family maturity | (table above) | `specs/transport-families-v1.md` |
| Directory refresh cadence | 48h | `specs/v2-success-metric-v1.md` (carried over) |
| Soak load tier | 1000 clients × 30 days × 50 routes × seed 42 | `specs/blackout-soak-rig-v1.md` |

All thresholds carry `TestLocked*` regression guards in their
package's test files. Changes require a roadmap amendment and a
fresh GREEN run on every parity sub-gate.

## Parity sub-gates (CI scope)

Phase 3-Soak splits the parity tier into three named whitelists:

* `--scenarios legacy` — the 1.5C-locked five (5 scenarios).
  **CI-gated since 1.5C.**
* `--scenarios v2-superset` — legacy + 21 V2 scenarios (26 total).
  **CI-gated since 3F.**
* `--scenarios v3-superset` — v2-superset + 5 V3 scenarios (31
  total). **CI-gated since 3-Soak.**

All three must remain GREEN through every V3 sub-phase and beyond.
The V3-superset adds the cross-platform-pickup load tier
non-interactively in CI; the 1k × 30d run is a release-cut
artefact, not a per-PR gate.

## Run identity

The 3-Soak release-cut run is identified by the manifest:
`run-id = ts-$EPOCH-clients-1000-days-30-seed-42-mix-60-35-5`.
Reruns at the same seed produce byte-identical per-route ledgers
(modulo diagnostics noise from real wall-clock variation and
fork-exec scheduling jitter on Android + iOS stubs).

## Auto-promotion threshold A-vs-B (memo only)

Per locked decision 9 of
`phases of development/27-phase-3-soak-success-metric.md`, the
3-Soak run carries the auto-promotion threshold tuning forward as
an **observation-only A-vs-B comparison**:

* LOCKED-A — the 2G default (3 families × 30 min × ladder ≥ 3),
  which the engine actually runs with.
* LOCKED-B — the tightened candidate (4 families × 20 min ×
  ladder ≥ 4), which the rig evaluates in parallel against the
  same Skipped-family ledger.

Neither set is promoted to engine default at 3-Soak. The
`internal/threshold_compare` package renders the comparison memo
to `phases of development/27-phase-3-soak-threshold-comparison.md`;
that memo informs the V4 freeze.

## Closure

The V3 milestone closes when this spec's primary + four secondaries
are all green on a single release-cut run on all three platform
stubs. The closure record is `specs/v3-closure-v1.md`.
