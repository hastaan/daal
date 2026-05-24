# FRP-13 handover — Public-directory gate-evaluation framework

**Date:** 2026-05-05.
**Status:** SHIPPED — gate-evaluation framework only.
**Engine line:** `daal-core 0.9.0+v3-share`. ABI=48. spec_version=4. UNCHANGED.
**FRP track:** TERMINATES at FRP-13.

## What shipped

Eight commits on `main`:

| # | sha (head)  | summary                                                                  |
|---|-------------|--------------------------------------------------------------------------|
| 1 | `7976081`   | `specs/public-directory-v1.md` (Status: GATED at FRP-13)                 |
| 2 | `109e36d`   | `specs/public-directory-closure-v1.md` (HOLD)                            |
| 3 | `0787708`   | `specs/public-directory-gate-v1.md` (machine-readable gate spec)         |
| 4 | `744afb2`   | `cmd/daal-gate-eval/` CLI + test suite                                  |
| 5 | `de2afae`   | `specs/public-directory-gate-history/2026-Q2.md` (first HOLD eval)       |
| 6 | `079f66b`   | `docs/public-directory-gate-evaluation.md` (operational process)         |
| 7 | `730d069`   | phase doc + `frp-track-v1.md` flips + supplement v2.3.12 + new §17.6     |
| 8 | this commit | this handover + FRP-track terminator confirmation                        |

## What did NOT ship

- **The public directory itself.** No `publisher/directory/` Go package. No directory probe, builder, signer, distributor, or recipient-side fetcher. No transparency-log integration. Source-grep guard `rg "publisher/directory" --type=go` returns empty.
- **No engine code change.** ABI=48 unchanged. `core/` and `bundle/go/` untouched. No new C-shared symbol. Asymmetric guard `core → bundle, never reverse` clean.
- **No `spec_version` bump.** Stays at 4.

## Gate verdict at FRP-13 ship

```
$ cd /home/daal/cmd/daal-gate-eval && go run . --repo /home/daal
FRP-13 Public-Directory Gate Status

Prerequisite (cell closure):
  specs/cell-closure-v1.md         HOLD   (need SHIPPED, got HOLD)

§17.2 Conditions:
  sybil_spam_absent                            HOLD
  poisoned_relaypack_mttr_under_24h            HOLD
  cloud_provider_takedown_survived             HOLD
  social_engineering_caught                    HOLD
  fake_helper_malware_closed                   HOLD
  metadata_leak_audit_clean                    HOLD

§22.4 V3 success metric:
  active_frps                                  HOLD
  frps_in_cells_pct                            HOLD
  cells_in_directory_pct                       HOLD
  avg_relaypack_burn_days                      HOLD
  directory_key_transparency_log               HOLD

Gate verdict: HOLD
exit 1
```

This is the **expected** outcome at FRP-13 ship. The framework's first run records the HOLD baseline. The next quarterly evaluation lands at 2026-Q3 (2026-07-01 or first business day after).

## Engine-line verification

| Check                                                | Expected | Actual                     |
|------------------------------------------------------|----------|----------------------------|
| `bundle/go/...` tests                                | PASS     | PASS (all 9 packages green) |
| `core/...` tests                                     | PASS     | PASS (all packages green)  |
| `publisher/...` tests                                | PASS     | PASS (all packages green)  |
| `cmd/daal-gate-eval/...` tests                      | PASS     | PASS (12 tests)            |
| `rg "publisher/directory" --type=go`                 | empty    | empty                      |
| `rg '^\s*"daal/publisher' core/ bundle/`            | empty    | empty (asymmetric guard)   |
| ABI version                                          | 48       | 48 (unchanged from FRP-12) |
| `spec_version`                                       | 4        | 4 (unchanged)              |
| Engine release symbols                               | unchanged | unchanged                 |

## Eight new locked invariants (48–55) at v2.3.12

48. GATED start preserved (post-track impl phase MUST NOT start until cell-closure SHIPPED + gate-eval verdict PASS).
49. Acceptable outcome: never ship.
50. No silent flips (PASS-without-evidence downgrades to FAIL).
51. Engine line UNCHANGED at FRP-13.
52. No `publisher/directory/` package at FRP-13 (source-grep guard).
53. FRP-track terminator (no `phases of development/44-…` ever).
54. Quarterly audit-trail append-only.
55. Position B preserved.

Total locked invariants across the FRP track: **63** (16 inherited from V1.5 + 47 phase-specific accumulated FRP-1 through FRP-13).

## What the next maintainer should know

### Immediate operational tasks

- **None at FRP-13 ship.** The gate-evaluation framework is in place; the next routine task is the 2026-Q3 quarterly evaluation, which is operational, not a phase.
- **2026-Q3 evaluation procedure:** see `docs/public-directory-gate-evaluation.md` §3. TL;DR: run the CLI, edit `specs/public-directory-gate-v1.md` if any condition has new evidence, append `specs/public-directory-gate-history/2026-Q3.md`, commit with message `FRP-13 gate eval: 2026-Q3: <verdict>`.

### Post-track work

The FRP track is closed at FRP-13. Future implementation phases live outside the FRP-NN naming scheme. Candidate phases (in priority order, all post-track):

1. **First concrete modifier PASS record** (post-FRP-12 carry-over): Linux-desktop censor-lab review of `client_desync`, then `tls_fragment` library + semantics. Lives at `phases of development/post-track/01-modifier-client-desync-pass.md` if and when started.
2. **Public-directory implementation** (post-FRP-13 carry-over): only if and when `cmd/daal-gate-eval` verdict flips to PASS. Lives at `phases of development/post-track/02-public-directory-impl.md` if and when started. Carry-overs noted in supplement §17.6: `publisher/directory/` package design; signed-directory format spec amendment; recipient-side directory fetcher with cell-closure cross-check; transparency-log integration; first-quarter post-flip soak; `--quarterly` flag on `cmd/daal-gate-eval` for auto-regeneration of next history file.
3. **V4 research-driven items**: real-DPI burn classifier (per supplement §15.7); HSM publisher hardening; iOS port resumption (currently stub-only). These do NOT depend on the public directory.

### Per locked invariant 49: an acceptable outcome is that nothing further ships

If the §17.2 gate never flips — e.g. because the V2 trusted-cell pilot never starts, or because the Iranian threat landscape evolves in a direction that makes a public directory net-harmful — then V2 trusted cells become the project's permanent endpoint, the public directory never runs, and the FRP track terminates cleanly at FRP-12 + FRP-11 + FRP-13's framework. **This is by design, not a failure mode.**

## Files added at FRP-13

```
specs/public-directory-v1.md                              (commit 1, GATED)
specs/public-directory-closure-v1.md                      (commit 2, HOLD)
specs/public-directory-gate-v1.md                         (commit 3, machine-readable)
cmd/daal-gate-eval/go.mod                                (commit 4)
cmd/daal-gate-eval/go.sum                                (commit 4)
cmd/daal-gate-eval/main.go                               (commit 4, ~330 lines)
cmd/daal-gate-eval/main_test.go                          (commit 4 + hardening, 12 tests)
specs/public-directory-gate-history/README.md             (commit 5)
specs/public-directory-gate-history/2026-Q2.md            (commit 5, first HOLD eval)
docs/public-directory-gate-evaluation.md                  (commit 6, process)
docs/handovers/frp-13-handover.md                         (commit 8, this file)
```

## Files modified at FRP-13

```
phases of development/43-phase-frp-13-public-directory.md (status flip)
specs/frp-track-v1.md                                     (§4.15, §6, terminator paragraph)
daal-roadmap-v3-supplement-diaspora-helper.md            (v2.3.11 -> v2.3.12, +§17.6)
```

## Cross-references

- Supplement §17.2 — six gate conditions canonical source.
- Supplement §17.6 — FRP-13 gate-evaluation lock (added at v2.3.12).
- Supplement §22.4 — V3 success metric.
- `specs/public-directory-v1.md` — protocol contract.
- `specs/public-directory-gate-v1.md` — machine-readable gate spec.
- `specs/public-directory-closure-v1.md` — closure-record template.
- `specs/cell-closure-v1.md` — prerequisite (HOLD).
- `cmd/daal-gate-eval/` — CLI consumer.
- `docs/public-directory-gate-evaluation.md` — operational process.
- `phases of development/43-phase-frp-13-public-directory.md` — phase doc.
- Previous handovers: `docs/handovers/frp-12-handover.md`, `docs/handovers/frp-11-handover.md`.

End — FRP-13 SHIPPED. **FRP track closed.**
