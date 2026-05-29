# Public Directory gate v1 — machine-readable §17.2 + §22.4 evaluation

**Status:** SHIPPED at FRP-13 (the gate spec ships; the gate is HOLD).
**Consumer:** `cmd/daal-gate-eval` reads the YAML block in §3 and prints a per-condition status table.
**Refresh cadence:** quarterly evaluation appended to `specs/public-directory-gate-history/<YYYY-Q[1-4]>.md` (locked invariant 48 enforcement vector).

## 1 Purpose

This document is the **executable contract** for the FRP-13 gate. It exists so the question "should the public-directory implementation phase start?" has a yes/no answer driven by observable evidence, not by vibes.

The §17.2 conditions and §22.4 success metric are re-stated **verbatim** from the supplement so this document is self-contained for `cmd/daal-gate-eval` consumption. The supplement remains the canonical narrative source; this document is the canonical machine-readable mirror. If the two diverge, the supplement wins and this document MUST be updated.

## 2 Prerequisite

A separate prerequisite to the §17.2 gate is `specs/cell-closure-v1.md` SHIPPED. The CLI reads that file's YAML frontmatter; if its status is HOLD, the gate verdict is HOLD regardless of §17.2 condition status.

## 3 Gate spec (consumed by cmd/daal-gate-eval)

```yaml
gate_id: daal-public-directory-gate-v1
prerequisite:
  cell_closure_doc: specs/cell-closure-v1.md
  required_status:  SHIPPED

# §17.2 six abuse-handling-maturity conditions (verbatim from supplement v2.3.5+).
conditions:
  - id: sybil_spam_absent
    statement: "Sybil spam absent or trivially recoverable across at least 90 days of cell-only operation."
    evidence_required: "operational log over a >=90-day window across the V2 cell deployment showing zero sybil-spam incidents OR documented incidents that were each contained within one cell-internal revocation cycle."
    status: HOLD
    evidence: TBD

  - id: poisoned_relaypack_mttr_under_24h
    statement: "Poisoned-RelayPack incidents detected and revoked in <24 hours mean-time-to-revocation across at least 5 simulated incidents."
    evidence_required: ">=5 simulated incidents with timestamps; mean MTTR <24h."
    status: HOLD
    evidence: TBD

  - id: cloud_provider_takedown_survived
    statement: "Cloud-provider takedowns survived without user-side outage in at least 2 real incidents."
    evidence_required: ">=2 documented real incidents (not simulated) with per-recipient outage duration =0s."
    status: HOLD
    evidence: TBD

  - id: social_engineering_caught
    statement: "Social-engineering attempts on cell admins caught in at least 2 simulated red-team exercises."
    evidence_required: ">=2 red-team exercise reports; both report attempt detected and contained."
    status: HOLD
    evidence: TBD

  - id: fake_helper_malware_closed
    statement: "Fake-helper malware vector closed via reproducible-build + signature-verification UX confirmed in audit."
    evidence_required: "external audit report citing reproducible-build chain and the signature-verification UX flow as closing the vector."
    status: HOLD
    evidence: TBD

  - id: metadata_leak_audit_clean
    statement: "Metadata-leakage audit shows no per-recipient identifiable data carried in cell directories or RelayPacks."
    evidence_required: "external metadata-leak audit report; verdict CLEAN."
    status: HOLD
    evidence: TBD

# §22.4 V3 public-directory success metric (verbatim from supplement v2.3.5+).
success_metric:
  blackout_documented_by: ["OONI", "Censored Planet"]
  thresholds:
    - id: active_frps
      statement: "At least 1,000 active FRPs."
      threshold: 1000
      observed: null
      status: HOLD

    - id: frps_in_cells_pct
      statement: "At least 30% of FRPs are in cells."
      threshold_pct: 30
      observed_pct: null
      status: HOLD

    - id: cells_in_directory_pct
      statement: "At least 10% of cells are opted into the public directory."
      threshold_pct: 10
      observed_pct: null
      status: HOLD

    - id: avg_relaypack_burn_days
      statement: "Directory's average per-RelayPack burn lifetime is at least 7 days."
      threshold_days: 7
      observed_days: null
      status: HOLD

    - id: directory_key_transparency_log
      statement: "Project directory-key signing operations are auditable in a public log."
      threshold: "non-empty transparency_log_url field on every signing operation"
      observed_url: null
      status: HOLD
```

## 4 Status enum

Per condition / threshold:

- `HOLD` — no evidence yet observed. Default at FRP-13 ship for every condition.
- `PASS` — evidence observed and recorded; condition met.
- `FAIL` — evidence observed and recorded; condition NOT met (e.g. social-engineering attempt succeeded; metadata-leak audit found a leak).

Gate verdict combinator:

- All conditions PASS AND all thresholds PASS AND prerequisite (`specs/cell-closure-v1.md` status) is SHIPPED → gate verdict `PASS` → CLI exit 0.
- Any condition / threshold HOLD → gate verdict `HOLD` → CLI exit 1.
- Any condition / threshold FAIL → gate verdict `FAIL` → CLI exit 2 (distinct from HOLD because FAIL means the project should pause investing in the public-directory implementation pending a documented remediation).

## 5 Update protocol

To move a condition from HOLD to PASS or FAIL:

1. Edit this file's YAML block in §3.
2. Set the condition's `status` field to `PASS` or `FAIL`.
3. Replace the `evidence: TBD` placeholder with a non-empty narrative + link(s) to the underlying audit report / log dump / red-team report. The CLI rejects PASS records whose `evidence` is empty / `TBD` / `null`.
4. Append a corresponding entry to `specs/public-directory-gate-history/<YYYY-QN>.md` quoting the new status, the evidence, and the date of the evaluation.
5. Re-run `cmd/daal-gate-eval` and confirm the verdict changes as expected.

## 6 Anti-tampering note

This file is in the same git tree as the rest of Daal. Any change to it is reviewable in PR diff. The CLI exits non-zero on parse error so a malformed file cannot silently flip the gate. It validates the closed six-condition + five-threshold row set, rejects duplicate / unknown IDs, rejects invalid status tokens, and does not trust any field whose value is missing, empty, `null`, or `TBD`. Threshold rows marked PASS must also meet their numeric threshold; the directory-key transparency row marked PASS must carry a non-empty `observed_url`.

## 7 Cross-references

- Supplement §17.2 — six conditions canonical source.
- Supplement §17.6 — FRP-13 gate-evaluation lock (added at v2.3.12).
- Supplement §22.4 — V3 public-directory success metric.
- `specs/public-directory-v1.md` — protocol contract (GATED).
- `specs/public-directory-closure-v1.md` — closure record (HOLD).
- `specs/public-directory-gate-history/` — quarterly evaluation log.
- `cmd/daal-gate-eval/` — CLI consumer.

End — gate spec SHIPPED; gate verdict HOLD.
