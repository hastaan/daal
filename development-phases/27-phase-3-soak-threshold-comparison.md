# Phase 3-Soak — Auto-Promotion Threshold Comparison Memo

**Status:** Template / pre-run.
**Locked decision:** 9 (per
`phases of development/27-phase-3-soak-success-metric.md`).
**Engine version unchanged:** `daal-core 0.9.0+v3-share`.
**ABI release surface unchanged:** 48.

This memo is the operator-facing record for the auto-promotion
threshold A-vs-B comparison. The 3-Soak rig observes both
threshold sets in parallel against the same Skipped-family
ledger; the engine itself only ever runs LOCKED-A (the 2G default).
This memo informs **V4 freeze** — at 3-Soak neither set is
promoted to engine default.

## Locked-A — `locked-A (2G default)`

- DistinctFamilyMinimum = 3
- WindowDuration        = 30m
- LadderStepMinimum     = 3

Source of truth: `core/burnpressure/detector.go` v1 constants.

## Locked-B — `locked-B (tightened candidate)`

- DistinctFamilyMinimum = 4
- WindowDuration        = 20m
- LadderStepMinimum     = 4

Source of truth:
`test-rigs/distribution-failure/soak-driver/internal/threshold_compare.LockedB`.

## How the comparison is computed

`internal/threshold_compare.Compare` walks every scheduler-tick
Skipped-family snapshot recorded during the soak run and counts
the ticks at which each threshold set would have fired
auto-promotion. The two counts are independent — the engine flips
into lifeline-strict on LOCKED-A; the rig records what LOCKED-B
would have done.

## Run record (fill in at release-cut)

> The release-cut operator runs the soak with `--scenarios
> v3-superset` and appends the per-set Comparison records (rendered
> by `threshold_compare.RenderMemo`) below.

```
Run ID: ts-<EPOCH>-clients-1000-days-30-seed-42-mix-60-35-5

Locked-A: TickCount=<…> Fires=<…> FirstFire=<…> LastFire=<…>
Locked-B: TickCount=<…> Fires=<…> FirstFire=<…> LastFire=<…>

Delta: Locked-B fired <MORE/LESS/the SAME number of times> than
       Locked-A across the run (Δ = <…> ticks).
```

## Recommendation (fill in at release-cut)

> The engineer reviewing the run writes the recommendation here
> in plain prose. The harness reports data; the recommendation is
> human.

The decision matrix to consider:

* If LOCKED-B fires significantly fewer times AND the run is
  green on every secondary metric, LOCKED-B is a candidate for
  V4 default (proceeds to V4 freeze proposal).
* If LOCKED-B fires roughly as often as LOCKED-A, the tightening
  produced no signal-to-noise benefit; LOCKED-A stays.
* If LOCKED-B fires MORE often, the candidate is wrong-direction;
  LOCKED-A stays and the recommendation is to investigate why.

Any decision to promote LOCKED-B is a roadmap amendment with its
own pre-conditions and cannot land at 3-Soak.

## Per-3-Soak locked decision 9

> The 3-Soak run is verification-shaped. No engine code ships.
> The threshold comparison is observation-only. Promotion of any
> threshold set to engine default requires a separate roadmap
> amendment with its own ship-criteria and is gated on V4
> opening.
