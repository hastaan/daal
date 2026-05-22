# Phase 43 (FRP-13) — Public Directory Gate Evaluation

**Status:** SHIPPED 2026-05-05 — gate-evaluation framework only. The public-directory implementation remains GATED and does not start until `cmd/daal-gate-eval` returns PASS.
**Roadmap line:** *"V3 — Public directory (gated). Iran-side fallback: when no Tier-1/Tier-2/cell routes are reachable, query the public directory. Gate to V4: 1,000+ active FRPs; >=30% in cells; >=10% of cells opted into the public directory; documented evidence of carrying users through a multi-day blackout."* — `daal-roadmap-v3-supplement-diaspora-helper.md` §17.2, §17.6, §21.4, §22.4
**Supplement target:** v2.3.12.
**Engine `Version` target:** `daal-core 0.9.0+v3-share` **(UNCHANGED).**
**ABI release surface target:** **48** **(UNCHANGED).**
**Maturity:** gate framework shipped; implementation explicitly not started.

**Predecessor:** Phase 42 (FRP-12) — modifier framework shipped. `specs/cell-closure-v1.md` remains HOLD from FRP-11, so the public-directory gate correctly remains HOLD at FRP-13 exit.
**Successor:** none on the FRP track. The track ends at FRP-13.

## 1. Strategic frame

FRP-13 is not a directory implementation phase. It ships the falsifiable gate machinery that decides whether a future post-track public-directory implementation may start.

The public directory is intentionally later and riskier than family relays and trusted cells. It increases scale by publishing opt-in cell metadata, but it also increases abuse and discovery pressure. The supplement's position is therefore empirical: the directory starts only if real trusted-cell operation proves the project can handle abuse.

The six §17.2 abuse-handling-maturity conditions are the canonical gate:

1. Sybil spam absent or trivially recoverable across at least 90 days of cell-only operation.
2. Poisoned-RelayPack incidents detected and revoked in less than 24 hours mean time to revocation across at least five simulated incidents.
3. Cloud-provider takedowns survived without user-side outage in at least two real incidents.
4. Social-engineering attempts on cell admins caught in at least two simulated red-team exercises.
5. Fake-helper malware vector closed via reproducible-build plus signature-verification UX confirmed in audit.
6. Metadata-leakage audit shows no per-recipient identifiable data carried in cell directories or RelayPacks.

The five §22.4 V3 success metrics are the operational scale gate:

1. At least 1,000 active FRPs.
2. At least 30% of FRPs are in cells.
3. At least 10% of cells are opted into the public directory.
4. Average per-RelayPack burn lifetime is at least 7 days.
5. Project directory-key signing operations are auditable in a public log.

The acceptable outcome is permanent HOLD. If the gate never flips, V2 trusted cells are the architecture's endpoint.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| FRP-13 scope | Gate-evaluation framework only: specs, CLI, history directory, operational process, and handover. |
| Directory implementation | Not shipped. No `publisher/directory/` package, directory signer, directory fetcher, transparency-log integration, recipient fallback implementation, or directory soak scenarios. |
| Gate source | `specs/public-directory-gate-v1.md`, consumed by `cmd/daal-gate-eval`. |
| Prerequisite | `specs/cell-closure-v1.md` must be SHIPPED. It is HOLD at FRP-13 exit, so the public-directory verdict is HOLD. |
| Gate rows | Closed set: six §17.2 condition IDs plus five §22.4 threshold IDs. Missing, duplicate, unknown, or invalid-status rows are parse errors. |
| PASS evidence | Condition PASS requires non-empty, non-TBD evidence. Threshold PASS requires observed values meeting the declared threshold; transparency-log PASS requires a non-empty observed URL. |
| CLI verdict | `PASS` exit 0, `HOLD` exit 1, `FAIL` exit 2. |
| Telemetry | Position B preserved. The gate records aggregate operator-supplied evidence only; it does not add recipient telemetry. |
| Engine version | None. `core/abi/abi.go` stays `daal-core 0.9.0+v3-share`; ABI stays 48. |
| Track status | FRP track terminates at FRP-13. Any directory implementation is post-track and starts only after a PASS gate verdict. |

## 3. Locked invariants

Tracks invariants 1-47 inherited. Phase-specific invariants added at v2.3.12:

48. **GATED start preserved.** A post-track public-directory implementation phase MUST NOT start until both `specs/cell-closure-v1.md` is SHIPPED and `cmd/daal-gate-eval` exits 0.
49. **Acceptable outcome: never ship.** Permanent HOLD is an acceptable architecture state.
50. **No silent flips.** PASS without evidence or unmet thresholds is rejected by the CLI.
51. **Engine line unchanged.** `core/abi/abi.go` Version and ABI count remain unchanged.
52. **No public-directory package.** `rg "publisher/directory" --type=go` MUST return empty at FRP-13 exit.
53. **FRP-track terminator.** No `phases of development/44-*` phase exists in the FRP track.
54. **Quarterly audit trail append-only.** Gate evaluations are appended under `specs/public-directory-gate-history/`.
55. **Position B preserved.** No telemetry ingestion or recipient-query logging is added.

## 4. Shipped sub-task breakdown

| # | Task | Status |
|---|---|---|
| 1 | `specs/public-directory-v1.md` protocol contract with Status: GATED. | SHIPPED |
| 2 | `specs/public-directory-closure-v1.md` closure template with Status: HOLD. | SHIPPED |
| 3 | `specs/public-directory-gate-v1.md` machine-readable gate spec. | SHIPPED |
| 4 | `cmd/daal-gate-eval` CLI with text and JSON output. | SHIPPED |
| 5 | `specs/public-directory-gate-history/2026-Q2.md` first HOLD evaluation. | SHIPPED |
| 6 | `docs/public-directory-gate-evaluation.md` quarterly operational process. | SHIPPED |
| 7 | Supplement v2.3.12 §17.6 and FRP-track status flips. | SHIPPED |
| 8 | `docs/handovers/frp-13-handover.md` and FRP-track terminator confirmation. | SHIPPED |

## 5. Gate spec behavior

`cmd/daal-gate-eval` is intentionally fail-closed:

- The gate ID must be `daal-public-directory-gate-v1`.
- `prerequisite.required_status` must be `SHIPPED`.
- The condition list must contain exactly the six required §17.2 IDs.
- The threshold list must contain exactly the five required §22.4 IDs.
- Status tokens are closed to `HOLD`, `PASS`, and `FAIL`.
- A condition marked PASS with empty, `TBD`, or `null` evidence is downgraded to FAIL.
- A threshold marked PASS without a numeric observed value, with an observed value below threshold, or without an observed transparency URL is downgraded to FAIL.

## 6. Build matrix at FRP-13 exit

```
$ cd cmd/daal-gate-eval && go test ./...                 # PASS
$ cd cmd/daal-gate-eval && go run . --repo /home/daal   # HOLD, exit 1
$ cd publisher && go test ./...                           # PASS
$ cd bundle/go && go test ./...                           # PASS
$ cd core && go test ./...                                # PASS
$ rg "publisher/directory" --type=go                      # empty
$ rg '^\s*"daal/publisher' core/ bundle/                 # empty
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l     # 48
$ grep -E '^const Version' core/abi/abi.go                # daal-core 0.9.0+v3-share
```

## 7. Deliverables

**New:**

- `specs/public-directory-v1.md`
- `specs/public-directory-closure-v1.md`
- `specs/public-directory-gate-v1.md`
- `specs/public-directory-gate-history/README.md`
- `specs/public-directory-gate-history/2026-Q2.md`
- `cmd/daal-gate-eval/`
- `docs/public-directory-gate-evaluation.md`
- `docs/handovers/frp-13-handover.md`

**Amended:**

- `phases of development/43-phase-frp-13-public-directory.md`
- `specs/frp-track-v1.md`
- `daal-roadmap-v3-supplement-diaspora-helper.md`

**Not amended:**

- `core/abi/`
- `bundle/go/`
- `publisher/directory/` (does not exist)

## 8. Out of scope

- Public-directory implementation.
- Directory key custody and transparency-log integration.
- Directory query/fallback in recipient clients.
- Directory soak scenarios.
- Project-operated relay infrastructure.
- Centralized abuse aggregator.
- Real-DPI burn classifier.
- HSM publisher hardening.
- iOS port.

## 9. Post-track path

The next routine action is operational, not a phase: run the quarterly gate evaluation and append the next history entry. If a future evaluation returns PASS, the public-directory implementation starts under a post-track phase name, not FRP-14.

End — FRP-13 SHIPPED as gate-evaluation framework only. FRP track closed.
