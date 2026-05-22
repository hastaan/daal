# Public Directory closure v1 (FRP-13 successor)

**Status:** HOLD. Pending §17.2 gate flip + V3 success-metric soak.
**Gate criterion:** per supplement §17.2 + §22.4 — the six abuse-handling-maturity conditions evaluated against real V2 cell deployments AND the V3 success metric (≥1,000 active FRPs / ≥30% in cells / ≥10% of cells in directory / ≥7-day avg per-RelayPack burn / directory key in transparency log) PASS during a documented Iranian internet blackout.

## 1 Purpose

This document is the post-track implementation phase's exit record. When and if the §17.2 gate flips AND the V3 metric PASSES, this status flips from HOLD to SHIPPED, the FRP track closes definitively at V3, and a packaging tag records the V3 release. Until that flip the public directory is OFF, by deliberate design (locked invariants 48, 49).

The presence of this file at FRP-13 does NOT imply the public directory is shipping. FRP-13 ships only the gate-evaluation framework; this document is the **closure template** for a future post-track phase if the gate flips.

## 2 Closure record fields (to be filled when status flips)

```yaml
status: SHIPPED
flipped_at: 20XX-YY-ZZ
gate_evaluation:
  cell_closure: SHIPPED-AT: 20XX-YY-ZZ
  six_conditions:
    sybil_spam_absent:               { status: PASS, evidence: ... }
    poisoned_relaypack_mttr_under_24h:{ status: PASS, evidence: ... }
    cloud_provider_takedown_survived:{ status: PASS, evidence: ... }
    social_engineering_caught:       { status: PASS, evidence: ... }
    fake_helper_malware_closed:      { status: PASS, evidence: ... }
    metadata_leak_audit_clean:       { status: PASS, evidence: ... }
v3_success_metric:
  active_frps:                       { observed: ..., threshold: 1000, status: PASS }
  frps_in_cells_pct:                 { observed: ..., threshold: 30,   status: PASS }
  cells_in_directory_pct:            { observed: ..., threshold: 10,   status: PASS }
  avg_relaypack_burn_days:           { observed: ..., threshold: 7,    status: PASS }
  directory_key_transparency_log_url:"https://..."
  blackout_event:
    documented_by:                   "OONI | Censored Planet"
    started_at:                      "20XX-YY-ZZ"
    ended_at:                        "20XX-YY-ZZ"
    project_infra_in_path:           false  # MUST be false (Position B preserved)
artifacts:
  spec_path:                         "specs/public-directory-v1.md"
  packaging_tag:                     "v3-public-directory-YYYY-MM-DD"
  transparency_log_url:              "https://..."
  closure_doc:                       "specs/public-directory-closure-v1.md"
```

## 3 Anti-rollback guarantees

Once flipped to SHIPPED, this record is immutable for audit purposes. Subsequent operational changes (e.g. gate quarantine of a misbehaving cell) are recorded in `specs/public-directory-gate-history/` and never by editing this closure record.

A later regression (e.g. directory key compromise) is recorded as a separate closure-revocation document at `specs/public-directory-revocation-v1.md` (NOT created at FRP-13; created if and when needed). The closure record itself stays SHIPPED with a forward pointer to the revocation.

## 4 Cross-references

- Supplement §17.2, §17.6, §21.4, §22.4.
- `specs/public-directory-v1.md` — the protocol contract (Status: GATED at FRP-13).
- `specs/public-directory-gate-v1.md` — machine-readable gate spec.
- `specs/cell-closure-v1.md` — separate prerequisite (also HOLD at FRP-13).
- `phases of development/43-phase-frp-13-public-directory.md`.

End — HOLD pending the §17.2 gate flip + V3 success metric PASS.
