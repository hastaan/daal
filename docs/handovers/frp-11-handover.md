# FRP-11 handover — Trusted cells + federation primitives

**Status:** SHIPPED on 2026-05-05.
**Engine version:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI release surface:** 48 UNCHANGED.
**Spec version:** 4 UNCHANGED.
**Locked invariants:** 30 (FRP-10) → 36 (FRP-11; added 31–36).
**Supplement:** v2.3.9 → v2.3.10 (two new subsections: §16.6 + §17.4).

## 1. What landed

11 commits, all on `main`:

| # | Title | Tests | Surface delta |
|---|---|---|---|
| 1 | Bundle-side cell types + cellcanon | +8 | new bundle/go/bundle/cellcanon.go |
| 2 | bundle ParseCellDocs accessor | +6 | bundle/go/bundle/sbp.go capture |
| 3 | publisher/cell core types + admin-quorum signing | +12 | new publisher/cell/cell.go |
| 4 | publisher/cell aggregator | +15 after hardening | new publisher/cell/aggregator.go |
| 5 | publisher/cell/freshness + R2/GH-Pages adapters | +8 | new publisher/cell/freshness/ |
| 6 | core/trust/cell_verify + labels | +19 after hardening | new core/trust/{cell_verify,labels}.go |
| 7 | cmd/daal-deploy cell-* subcommands | +8 after hardening | publisher/deploy/cli/cli_cell.go |
| 8 | desktop wizard V008 + cell UI + i18n | +9 wizard | wizard 89→98; +50 EN +50 FA i18n |
| 9 | Android cell-join receive surface | +13 + 1 guard after hardening | Android 34→48 |
| 10 | abuse-ticket + cell-internal revocation | +9 | publisher/cell/abuse.go + core/trust/cell_revocation.go |
| 11 | specs + supplement v2.3.10 + handover | n/a | specs/cell-v1.md, federation-primitives-v1.md, cell-closure-v1.md HOLD |

## 2. Locked answers honoured

1. **Admin keypair** — fresh per-admin Ed25519 keypair (`publisher/cell.NewAdminKeypair`); never reused as publisher key. Persisted via wizard's encrypted keystore aliased by `cells.admin_priv_alias`.
2. **Android cell surface** — cell-JOIN ONLY. CellGuardTest source-grep enforces invariant 36 (no admin signing tokens anywhere under `client-android/app/src/main`).
3. **Cell publication channel** — abstract `CellPublisher` interface; reuses FRP-9 R2 + GH-Pages backends via `NewR2Adapter` / `NewGHPagesAdapter` thin wrappers. Live SDK wiring is a V2 alpha pilot carry-over.
4. **Trust labels** — `core/trust/labels.go::MemoryLabelStore`. AES-GCM (32-byte key), AEAD AD = cellIDFPHex. Engine-side, encrypted at rest, never serialised.

## 3. Locked invariants (FRP-11 additions)

| # | Invariant |
|---|---|
| 31 | Cell admin scheme is M-of-N independent Ed25519. NO threshold cryptosystem. N ∈ [1, 25]; M ≤ N. |
| 32 | `spec_version` UNCHANGED at 4. Cell aggregation reuses FRP-7.5 manifest contract via two new bundle files. |
| 33 | `bundle/go/bundle/` MUST NOT import `daal/core`. Recipient chain walk lives at `core/trust/cell_verify.go`. |
| 34 | No public directory. Per-cell directories only; FRP-13 gate. |
| 35 | No new `engine_*` C-shared symbols. ABI count stays 48. |
| 36 | Android cell-admin signing absent. Source-grep guard. |

## 3.1 Post-review hardening

The readiness review before FRP-12 added four enforcement pins:

* `core/trust.VerifyCellChain` now rejects expired membership docs, compares `delegation.bundle_signer_pubkey` directly to archive `publisher.pub` bytes even when the manifest fingerprint is empty, and requires every route to carry `_relaypack._inner_provenance` naming a signed membership entry.
* `publisher/cell.Aggregate` now writes route profile files into the aggregate archive, injects signed per-route inner provenance, and refuses expired memberships / missing profiles / non-RelayPack routes / non-member provenance before producing an `.sbp`.
* `daal-deploy cell-sign` no longer accepts admin private keys through argv; it reads a base64 raw Ed25519 key from a regular mode-0600 `--priv-file`.
* Android cell-join now rejects expired membership docs before persisting local cell state.

## 4. Engine-line check (run on FRP-11 head)

```
nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l        # 48 unchanged
grep -E '^const Version' core/abi/abi.go                    # daal-core 0.9.0+v3-share unchanged
! rg -n '^\s*"daal/core' bundle/go/bundle/                 # exits non-zero (no hits)
! rg -n 'daal/publisher' core/ bundle/go/                  # exits non-zero (asymmetric guard)
```

## 5. Test-surface deltas

| Surface | Before FRP-11 | After FRP-11 |
|---|---|---|
| bundle/go/bundle | baseline | +14 |
| publisher/cell | 0 | 36 (new package, including aggregate provenance hardening) |
| publisher/cell/freshness | 0 | 8 |
| cmd/daal-deploy (cell subcommands) | baseline | +8 |
| core/trust (cell_verify + labels) | baseline | +19 |
| client-desktop/daal-wizard lib | 89 | **98** |
| client-android :app:testDebugUnitTest | 34 | **48** (+13 cell + 1 guard) |

Post-review test count is higher than the original FRP-11 landing count; all listed surfaces are green at HEAD.

## 6. Carry-overs (V2 cell alpha pilot)

* **Live R2 / GH Pages cell-directory pilot URL allocation.** `CellPublisher` adapters wrap FRP-9 backends whose live SDK wiring is itself an alpha-pilot carry-over from FRP-9.
* **Cell-admin UX studies.** M-of-N quorum picker, how much to surface to non-technical operators.
* **AndroidKeystorePublisherKey + gomobile-bound `Deploy.aar`** — still carried from FRP-10.
* **FA copy review** for ~50 new desktop strings + ~12 Android cell-join strings (placeholder `[FA]`-tagged English ships at FRP-11; native review per V2 alpha pilot).
* **Live V2 alpha pilot.** Gates `specs/cell-closure-v1.md` flip from HOLD to SHIPPED.
* **Cross-cell ticket forwarding.** Deliberately NOT shipped at FRP-11; admins' authority terminates at the cell boundary.
* **`.pubex` signed publisher exchange.** RESERVED primitive; not shipped at FRP-11.

## 7. What FRP-11 unblocks

* **FRP-12 (modifier framework).** Bundle-format-additive; cellcanon's pattern of "new bundle file with admin-quorum signature, no manifest schema change" is reused by per-modifier PASS-record files.
* **FRP-13 (public directory gate).** Needs §17.2's six abuse-handling-maturity conditions measured against real V2 cells; FRP-11 ships the cells the gate measures against.

## 8. Files added / modified at FRP-11

```
specs/
  cell-v1.md                                    NEW
  federation-primitives-v1.md                   NEW
  cell-closure-v1.md                            NEW (HOLD)
  delegate-keys-v1.md                           amended (§9 V2 cell-scope read)
  relaypack-v1.md                               amended (§V2 cell aggregation)

bundle/go/bundle/
  types.go                                      +5 cell types, +2 file slots
  errors.go                                     +9 closed errors
  cellcanon.go                                  NEW
  cellcanon_test.go                             NEW (8 tests)
  cellcanon_parse_test.go                       NEW (6 tests)
  sbp.go                                        +cell file capture in ParseSBP

publisher/cell/                                 NEW package
  cell.go                                       admin keypair + builders
  aggregator.go                                 cell-aggregated .sbp sealer; injects _inner_provenance + profile files
  abuse.go                                      abuse ticket + cell revocation
  cell_test.go (12), aggregator_test.go (15), abuse_test.go (9)
  freshness/                                    NEW sub-package
    publisher.go, canonical.go, r2.go, ghpages.go
    publisher_test.go (8)

core/trust/
  cell_verify.go                                NEW (chain walk)
  labels.go                                     NEW (AES-GCM label store)
  cell_revocation.go                            NEW (recipient revocation)
  cell_verify_test.go                           NEW (19 tests)

publisher/deploy/cli/
  cli.go                                        +5 dispatcher cases + usage text
  cli_cell.go                                   NEW (cell-create/invite/sign/verify/status)
  cli_cell_test.go                              NEW (8 tests)

client-desktop/
  daal-wizard/migrations/V008__cells.sql       NEW
  daal-wizard/src/operator_db.rs               +CellRow, +6 methods, +9 tests
  tauri/src/wizard/i18n/wizard.{en,fa}.json     +50 keys each (243→293)

client-android/app/src/main/java/ai/daal/app/publisher/cell/
  CellJoin.kt                                   NEW (envelope, verifier, joiner)
  CellState.kt                                  NEW

client-android/app/src/test/java/ai/daal/app/publisher/
  CellGuardTest.kt                              NEW (invariant 36 source-grep)
  CellJoinTest.kt                               NEW (13 tests)

phases of development/
  41-phase-frp-11-trusted-cells.md              status flipped to SHIPPED

daal-roadmap-v3-supplement-diaspora-helper.md  v2.3.9 → v2.3.10 (+§16.6 +§17.4)

docs/handovers/
  frp-11-handover.md                            NEW (this file)
```

## 9. Recipient-side cell-aware import flow (FRP-11 head)

```
1. core/import/relaypack imports .sbp.
2. bundle.VerifyBundle returns nil (manifest sig under bundle-signer key).
3. core/trust.VerifyCellChain(b, now):
   a. ParseCellDocs(b) → membership, delegation (or ErrCellChainNotPresent).
   b. VerifyCellMembershipQuorum(membership) — M-of-N independent Ed25519.
   c. VerifyCellDelegationQuorum(membership, delegation).
   d. membership valid_until and delegation valid_from..valid_until window checks.
   e. delegation.bundle_signer_pubkey bytes == archive publisher.pub.
   f. manifest publisher fp, if present, matches the delegated bundle-signer fp.
   g. every route's _relaypack._inner_provenance names a signed membership entry.
4. ChainStatus + memb + deleg returned to importer; TOFU prompt rendered with cell label
   (LabelStore.Get).
```

End — FRP-11 SHIPPED 2026-05-05.
