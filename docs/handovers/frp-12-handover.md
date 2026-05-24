# FRP-12 handover — Modifier framework (reserved slots)

**Status:** SHIPPED on 2026-05-05. Readiness hardening pass added the StoreAdapter preflight gate before FRP-13.
**Engine version:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI release surface:** 48 UNCHANGED.
**Spec version:** 4 UNCHANGED.
**Locked invariants:** 36 (FRP-11) → 47 (FRP-12; added 37–47).
**Supplement:** v2.3.10 → v2.3.11 (one new subsection: §17.5).
**Predecessor:** FRP-11 SHIPPED 2026-05-05.
**Successor:** FRP-13 — public directory (gated by `specs/cell-closure-v1.md`, NOT by FRP-12).

## 1. What landed

11 commits on `main`:

| # | Title | Test delta | Surface delta |
|---|---|---|---|
| 1 | `specs/modifiers/_template.md` | n/a | 1 file |
| 2 | `specs/modifiers/{client_desync,tls_fragment}.md` PENDING | n/a | 2 files |
| 3 | `publisher/deploy/modifiers` skeleton + frontmatter | +10 | 3 files |
| 4 | `cmd/genregistry` + initial `registry_gen.go` | 0 (binary) | 2 files |
| 5 | `registry.go` + tests + zero-PASS guard | +8 | 3 files |
| 6 | `platforms.go` + tests | +3 | 2 files |
| 7 | `core/internal/selection/candidate_platform.go` + tests | +9 | 2 files |
| 8 | binder wired to `AllowedModifierKinds` | +2 | 2 files |
| 9 | wizard Screen6Handoff modifier surface + i18n + Rust guard | +2 wizard | wizard 98→100 |
| 10 | Android `ModifierGuardTest` (invariant 47) | +1 | 1 file |
| 11 | relaypack-v1.md amend + process doc + supplement v2.3.11 + handover | n/a | 6 files |

**Total new tests:** ≥35 across 5 surfaces (publisher 21 + engine 9 + wizard 2 + binder 2 + android 1). Phase doc requirement was ≥15.

## 2. Locked answers honoured (eight; per supplement §17.5)

1. **Build-time codegen, not runtime parse.** `publisher/deploy/modifiers/cmd/genregistry` reads `.md` files into `registry_gen.go`. Generator refuses PASS records without `--allow-pass` (FRP-12 ship MUST NOT use the flag).
2. **No PASS records in `specs/`.** Verification grep returns empty at every commit. Test-only synthetic PASS fixture lives under `publisher/deploy/modifiers/testdata/`.
3. **Subpackage layout.** Eight files at top level + `cmd/genregistry/` + `testdata/`.
4. **Engine importer platform gate.** `StoreAdapter.SaveImport` calls `RejectByPlatform` before persistence; `RejectByPlatform` returns `ErrModifierPlatform` (wire label `IMP_MODIFIER_PLATFORM`).
5. **Validator wiring at `publisher/deploy/relaypack/binder.go`.** Validator package itself NOT modified. Binder calls `allowedModifierKindsForPhase(phase)` → `modifiers.AllowedKindsAt(rp)`.
6. **`min_phase` enum mirrors `relaypackvalidate.Phase`.** Permitted: `V1.5 | V1.6 | PostV2`.
7. **Module location.** Registry in `daal/publisher`; engine gate in `daal/core`. Asymmetric guard verified.
8. **UI strings: 11 EN + 11 FA keys.** Wizard Screen6Handoff renders "Modifiers: none active" at FRP-12 ship. Android has no modifier UI; ModifierGuardTest enforces.

## 3. Locked invariants 37–47 (per phase doc §3 + supplement §17.5)

| # | Invariant |
|---|---|
| 37 | Zero PASS records ship at FRP-12. Build-time (genregistry refuses) + runtime (registry test reads `specs/modifiers/*.md`). |
| 38 | Unknown / PENDING / REJECTED / DEPRECATED kinds stay hard-rejected. |
| 39 | `min_phase` enforced via `AllowedKindsAt(phase)` ordinal filter. |
| 40 | `platforms[]` enforced at the engine importer/store boundary with `IMP_MODIFIER_PLATFORM`; modifier-bearing routes fail before persistence unless the platform policy allows them. |
| 41 | Modifier carry is per-candidate (RP013 fires per-route, not bundle-wide). |
| 42 | Recipient UI default OFF (toggle keys present; no live opt-in surface at FRP-12). |
| 43 | Pass record reviewable; codegen rejects malformed front-matter (`Meta.validate()`). |
| 44 | No engine release symbols added. ABI count stays 48. |
| 45 | Position B preserved. No project-side modifier outcome telemetry. |
| 46 | `exposure_mode: serverless_external` NOT in scope. Lives in enum, not `modifiers[]`. |
| 47 | Android source-grep guard for modifier admin / opt-in surfaces (`ModifierGuardTest`). |

## 4. Engine-line check (run on FRP-12 head)

```bash
# Engine version + ABI
nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l                    # 48 unchanged
grep -E '^const Version' core/abi/abi.go                                # daal-core 0.9.0+v3-share unchanged

# Module-direction guards
! rg -n '^\s*"daal/core' bundle/go/bundle/                             # exits non-zero
! rg -n '^\s*"daal/publisher' core/                                    # exits non-zero
! rg -n '^\s*"daal/publisher' bundle/go/                               # exits non-zero

# Zero-PASS guard (locked invariant 37)
rg "status.*PASS" specs/modifiers/*.md | grep -v _template.md           # empty
```

## 5. Test surface deltas

| Surface | Before FRP-12 | After FRP-12 |
|---|---|---|
| `publisher/deploy/modifiers/` | 0 | **21** (10 frontmatter + 8 registry + 3 platforms) |
| `publisher/deploy/relaypack/` | baseline | **+2** (binder wiring) |
| `core/internal/selection/` | baseline | **+9** (candidate_platform) |
| `core/trust/` | baseline | **+2** (StoreAdapter modifier preflight gate) |
| `client-desktop/daal-wizard` | 98 | **100** (+2 modifiers_i18n) |
| `client-android :app:testDebugUnitTest` | 47 (post-FRP-11 + hardening) | **49** (+1 ModifierGuardTest + 1 from hardening) |

Total new test count at FRP-12 after readiness hardening: ≥37 (exceeds the phase doc §4 #9 requirement of ≥15).

## 6. Files added / modified at FRP-12

```
specs/modifiers/                                NEW directory
├── _template.md                                NEW (commit 1)
├── client_desync.md                            NEW (commit 2; PENDING)
└── tls_fragment.md                             NEW (commit 2; PENDING)

specs/relaypack-v1.md                           AMENDED (commit 11; new "Modifier framework (FRP-12 amendment)" section)
specs/frp-track-v1.md                           AMENDED (commit 11; §4.14 status SHIPPED)
phases of development/42-phase-frp-12-modifier-framework.md
                                                AMENDED (commit 11; status SHIPPED)
daal-roadmap-v3-supplement-diaspora-helper.md  AMENDED (commit 11; v2.3.10 → v2.3.11; +§17.5)

publisher/deploy/modifiers/                     NEW package
├── doc.go                                      package overview
├── frontmatter.go                              md → Meta parser + Status/Phase/Platform enums
├── frontmatter_test.go                         10 tests
├── registry.go                                 Lookup / AllKinds / AllowedKindsAt / HasPassAt
├── registry_gen.go                             generated — committed
├── registry_test.go                            8 tests (incl. zero-PASS guard)
├── platforms.go                                PlatformFromGOOS + IsKindAllowedOnPlatform
├── platforms_test.go                           3 tests
├── testdata/
│   └── synthetic_pass.md                       test-only PASS fixture
└── cmd/genregistry/main.go                     build-time codegen binary

publisher/deploy/relaypack/binder.go            AMENDED (commit 8; +allowedModifierKindsForPhase)
publisher/deploy/relaypack/binder_modifiers_test.go
                                                NEW (2 tests)

core/internal/selection/
├── candidate_platform.go                       NEW (RejectByPlatform + ErrModifierPlatform)
└── candidate_platform_test.go                  NEW (9 tests)

core/trust/state.go                             AMENDED (readiness hardening; SaveImport preflights modifier-bearing routes before persistence)
core/trust/importer_test.go                     AMENDED (+2 StoreAdapter modifier-gate tests)

client-desktop/tauri/src/wizard/i18n/wizard.en.json
                                                AMENDED (+11 keys; 293→304)
client-desktop/tauri/src/wizard/i18n/wizard.fa.json
                                                AMENDED (+11 keys; 293→304)
client-desktop/tauri/src/wizard/screens/Screen6Handoff.tsx
                                                AMENDED (modifier-surface panel)
client-desktop/daal-wizard/src/lib.rs          AMENDED (+pub mod modifiers_i18n)
client-desktop/daal-wizard/src/modifiers_i18n.rs
                                                NEW (2 tests)

client-android/app/src/test/java/ai/daal/app/publisher/ModifierGuardTest.kt
                                                NEW (1 test; invariant 47)

docs/modifier-review-process.md                 NEW
docs/handovers/frp-12-handover.md               NEW (this file)
```

## 7. Carry-overs (post-track follow-on phase)

* **First concrete modifier PASS.** `client_desync` Linux-desktop censor-lab review and PASS-record sign-off lives in a separate post-track phase. Touches `specs/modifiers/client_desync.md` only; re-runs `genregistry --allow-pass`; updates the FRP-12-ship empty-allow-list assertion in `binder_modifiers_test.go` to reflect the new non-empty allow-list.
* **`tls_fragment` semantics finalisation.** Library choice (sing-box vs Daal-side), fragmentation policy, `platforms[]` finalisation. Currently `platforms: []` (no platform yet enabled).
* **Recipient UI toggle wiring.** Per-candidate enable/disable toggle is rendered but inert at FRP-12. The post-track phase wires the toggle to `_relaypack.modifiers[].kind` selection and persists user preference.
* **FA native review for 11 new desktop strings** placeholder-tagged English ships at FRP-12; native Persian translation per the FRP-12 carry-over (mirrors FRP-11 cell-i18n pattern).
* **Multi-modifier interaction analysis.** Research-only; no FRP-12 code. Any second concrete-modifier phase MUST re-validate against every existing PASS modifier before promotion.

## 8. What FRP-12 unblocks

* **Post-track concrete modifier phase.** First `client_desync` PASS — the framework is in place; that phase is purely catalogue + censor-lab work + a single re-run of `genregistry --allow-pass`.
* **FRP-13 (public directory gate).** NOT blocked on FRP-12; gate is `specs/cell-closure-v1.md` SHIPPED + supplement §17.2's six abuse-handling-maturity conditions. FRP-12's framework + FRP-13's directory are independent layers.

## 9. Validator behaviour at FRP-12 head (per `relaypack-v1.md` test vector table)

```
Phase=V1.5  + modifiers[] non-empty  → reject RP013 (unchanged)
Phase=V1.6  + modifiers[] non-empty  → reject RP013 (unchanged)
Phase=PostV2 + modifiers[] non-empty + kind in AllowedModifierKinds → accept
Phase=PostV2 + modifiers[] non-empty + kind NOT in AllowedModifierKinds → reject RP013

At FRP-12 ship: AllowedModifierKinds is ALWAYS empty (locked invariant 37),
so PostV2 + non-empty modifiers[] → reject RP013 unconditionally.

The framework is in place; the gate is closed.
```

End — FRP-12 SHIPPED 2026-05-05.
