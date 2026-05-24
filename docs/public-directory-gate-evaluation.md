# Public-directory gate evaluation — operational process

This document is the operational process for re-evaluating the FRP-13 public-directory gate. It is the contract for who, when, and how the gate is checked.

## 1. Cadence

**Quarterly**, on the first business day of the quarter. The cadence is operational, not enforced by code (the project is small; a CI check that warns on stale gate history is a future improvement). Recommended evaluation dates:

- 2026-Q3: 2026-07-01 (or first business day after).
- 2026-Q4: 2026-10-01.
- Etc.

A skipped quarter is recorded explicitly in the next quarter's file ("2026-Q3 was not evaluated; resuming at 2026-Q4 with the following observations…"). The audit trail is meaningful only if it is honest.

## 2. Who evaluates

**The project lead** (or an explicit delegate). Evaluation is a single-person job at small scale; multi-reviewer concurrence is required only when a condition transitions from `HOLD` to `PASS` or from `HOLD` to `FAIL` (those transitions are load-bearing for the gate verdict).

## 3. Steps

For each quarterly evaluation:

```
1. cd $REPO && cd cmd/daal-gate-eval && go run . --repo $REPO
   Capture the exit code and stdout.

2. Compare each condition's stdout status to the latest in
   specs/public-directory-gate-v1.md §3.

3. For each condition that has new evidence since the last
   evaluation:
   a. If evidence is "yes the condition is met":
        - Edit specs/public-directory-gate-v1.md §3 to flip the
          condition's status to PASS.
        - Replace the evidence: TBD placeholder with a non-empty
          narrative pointing to the underlying audit / log /
          report. The CLI rejects PASS records whose evidence is
          empty / TBD / null.
        - Require a second reviewer to sign off (PR comment
          suffices) before merging.
   b. If evidence is "no the condition is empirically not met":
        - Flip the condition's status to FAIL.
        - Document the failing observation in evidence.
        - Surface the FAIL in the next quarter's history file
          and in any follow-on remediation plan.
   c. If no new evidence:
        - Leave the condition's status as HOLD.

4. For each §22.4 threshold with a new observation, update the
   observed_* field and re-evaluate the threshold's status. A
   threshold marked PASS must meet or exceed its declared numeric
   threshold; the transparency-log threshold marked PASS must include
   a non-empty observed_url. The CLI downgrades unmet threshold PASS
   rows to FAIL.

5. Re-run cmd/daal-gate-eval to confirm the verdict.

6. Append a new file at
   specs/public-directory-gate-history/<YYYY-QN>.md recording:
   - the date,
   - the CLI exit code,
   - the per-condition status table,
   - any narrative the evaluator wishes to preserve.

7. Commit the changes with a message
   'FRP-13 gate eval: <YYYY-QN>: <verdict>'.

8. If the verdict transitions from HOLD to PASS:
   - Open a separate phase doc at
     phases of development/post-track/01-public-directory-impl.md
     to begin the post-track implementation phase.
   - The FRP track itself remains closed (FRP-track terminator
     locked at FRP-13).
```

## 4. Rules of engagement

- **No silent flips.** A condition's status MUST NOT be flipped from HOLD to PASS without recorded evidence, and a threshold's status MUST NOT be flipped to PASS unless the observed value meets the threshold. The CLI enforces this by downgrading PASS-without-evidence and unmet-threshold PASS rows to FAIL.
- **No backdated evidence.** Evidence dates MUST be on or after the date the condition was first observed; back-dating is forbidden.
- **No partial PASSes.** A condition either has its evidence_required threshold met across the entire observation window or it does not. "Mostly met" is HOLD.
- **Prerequisite gating.** If `specs/cell-closure-v1.md` is HOLD, the gate verdict is HOLD regardless of any condition status. Per locked invariant 48: cell closure MUST flip first.
- **Acceptable outcome: never ship.** Per locked invariant 49: if the gate never flips, the public directory never ships, and the FRP track terminates cleanly at FRP-12 + FRP-11. This is by design, not a failure mode.

## 5. Reviewer pool

The reviewer pool for PASS / FAIL transitions is the same as the censor-lab reviewer pool documented in `docs/modifier-review-process.md` §2 — operators with access to instrumented vantage points and the technical depth to validate the underlying audit reports. The pool composition is recorded in `docs/modifier-reviewers.md` (created in the first concrete-modifier post-track phase).

For purely operational thresholds (§22.4 active-FRP count, percentage of FRPs in cells, etc.), no specialised reviewer is required; the project lead's quarterly count from operational telemetry is sufficient — provided that telemetry remains aligned with Position B (no per-recipient identifiers; only aggregate counts).

## 6. Tooling

The single tool is `cmd/daal-gate-eval`. There is no other code path. Future improvements (e.g. a CI check that warns on stale gate history; a JSON-export endpoint for project external transparency reports) are post-track.

## 7. What happens if a condition transitions FAIL

A FAIL transition (e.g. metadata-leak audit finds a leak; social-engineering attempt succeeds undetected) MUST trigger:

1. An immediate quarterly evaluation (do not wait for the regular cadence).
2. A documented remediation plan at `specs/public-directory-gate-remediation/<YYYY-MM-DD>.md` (this directory is created at first need; not at FRP-13 ship).
3. The remediation plan's exit criterion is the FAIL transitioning back to HOLD with documented mitigations; the condition then re-enters the regular evaluation cycle.

A FAIL is not a permanent disqualification of the public directory; it is an empirical observation that the architecture is not yet ready to ship the directory.

## 8. Cross-references

- Supplement §17.2 — six conditions canonical source.
- Supplement §17.6 — FRP-13 gate-evaluation lock (added at v2.3.12).
- Supplement §22.4 — V3 success metric.
- `specs/public-directory-v1.md` — protocol contract.
- `specs/public-directory-gate-v1.md` — machine-readable gate spec.
- `specs/public-directory-closure-v1.md` — closure record (HOLD).
- `specs/public-directory-gate-history/` — quarterly evaluation log.
- `cmd/daal-gate-eval/` — CLI consumer.
- `docs/modifier-review-process.md` §2 — reviewer pool.
- `phases of development/43-phase-frp-13-public-directory.md` — phase doc.

End — operational process for the FRP-13 gate.
