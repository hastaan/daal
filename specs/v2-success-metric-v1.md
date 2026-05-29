# V2 Success Metric (v1)

Phase 2G locks the **single roadmap-canonical pass criterion** for the
V2 milestone, plus four secondary metrics that protect the engine
against regressions outside the burn-survival surface.

This spec is the contract the soak rig's `run-burn` and `verify-burn`
subcommands implement.

## Primary metric: directory-rotation comparison

> For every route published into the directory across the soak run,
> `first_burn_at - first_publish_at ≥ directory_refresh_cadence`.

The burn sandbox stamps `first_burn_at` deterministically from a
seeded RNG (see `internal/burnsandbox/`). The directory cadence is a
run-input flag (`--directory-refresh`, default `48h`); the soak v1
LOCKED value is **48h**.

A route that is never burned passes the primary metric trivially.

The interpretation: the engine is allowed to lose a route, but the
directory must rotate it out at least as fast as real adversaries
burn it. This is the exact condition the V2 milestone in the
roadmap declares as "survives a partial-burn week without a manual
mode flip".

## Secondary metrics

The four secondaries are independent — a single failure does not
short-circuit the others. The verifier reports every failure so
operators can fix in one pass.

### Secondary 1: rotation correctness

The directory-refresh cadence claimed in the manifest matches the
cadence observed in the per-route ledger. A run that publishes a
new batch every 47h and 30min does not pass even if the primary
metric holds — operators are entitled to trust the cadence flag.

### Secondary 2: budget enforcement

Across the run, no client exceeded its per-mode session-cap budget
or per-route budget, as observed via post-run diagnostics
(`session_route_pulls`, `session_route_quota`, mode-axis quotas).
Inherits from `route-budgets-v1.md` and `mode-budgets-v1.md`.

### Secondary 3: failure-reason coverage

Every cooldown surfaced in the per-network ledger carries a
non-empty `last_failure_reason` from the `failure-taxonomy-v1.md`
v1 set. A blank reason indicates an engine bug masking the
diagnostic surface.

### Secondary 4 (Quinary in the verifier output): auto-promotion correctness

The 2G ship-gate metric. Two assertions:

1. Every client's post-run diagnostics report
   `auto_promotion_enabled=true` (the preference survives session
   epochs and ships on by default).
2. If at any point during the soak the burn sandbox produced ≥3
   route burns inside any 30-minute window, then **at least one**
   client's post-run diagnostics MUST carry
   `auto_promotion_last_fired_at` — proving the burn-pressure
   detector's path-from-skipped-families to lifeline-strict is
   live in the engine the soak ran against.

The 30-minute window is a conservative lower bound on the v1
detector window (see `core/burnpressure/`); the load tier collapses
hour buckets into 2-hour pairs to side-step half-hour boundary
effects.

## Locked thresholds (v1)

| Surface | Threshold | Defined in |
|---------|-----------|------------|
| Burn-pressure detector | 3 distinct families × 30-min window × ladder step ≥ 3 | `core/burnpressure/detector.go` |
| Burn classifier (rig) | 10-min window × > 50% aggregate failure rate | `internal/burn/classifier.go` |
| Default sandbox burn rate | 0.014 / route / hour (≈ 1 burn / 72h, IRBlock-modelled) | `internal/burnsandbox/sandbox.go` |
| Directory refresh cadence | 48h | `--directory-refresh` flag, default 48h |
| Soak load tier | 1000 clients × 30 days × 50 routes × seed 42 × bulk-capable OFF | `cmd/soak-driver/burn.go` |

All thresholds have `TestThresholdsLocked` regression guards in
their package's test file. Changes require a roadmap amendment and
a fresh GREEN run on every parity sub-gate.

## Parity sub-gates (CI scope)

Phase 2G splits the parity tier into two named whitelists:

* `--scenarios legacy` — the 1.5C-locked five
  (`github-unreachable`, `bootstrap-directory-mirror-unreachable`,
  `telegram-unreachable`, `subscription-url-unreachable`,
  `publisher-revocation-url-unreachable`). **CI-gated since 1.5C.**
* `--scenarios v2-superset` — legacy + 3 from 2C
  (`network-roam`, `mode-bulk-unlock`, `posture-recovery-cycle`)
  + 2 from 2D (`lifeline-strict-policy`, `lifeline-strict-roam`).
  **CI-gated since 2D; default whitelist at 2G.**

Both must remain GREEN through every V2 sub-phase. The V2-superset
adds the burn-survival load tier non-interactively in CI; the
1k×30d run is a release-cut artefact, not a per-PR gate.

## Run identity

The 2G load-tier run is identified by the manifest:
`run-id = ts-$EPOCH-clients-1000-days-30-seed-42`. Reruns at the
same seed produce byte-identical per-route ledgers (modulo
diagnostics noise from real wall-clock variation).
