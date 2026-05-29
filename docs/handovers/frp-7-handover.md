# FRP-7 Handover — V1.5 Pilot Rotation + Closure Path

**Status:** SHIPPED 2026-05-03 (engineering surface).
**Closure:** HOLD (`specs/v1-5-closure-v1.md`) until live pilot
completes.
**Engine line:** `daal-core 0.9.0+v3-share` UNCHANGED.
**ABI:** **48** UNCHANGED.

This handover summarises the seven-commit FRP-7 series and what
remains for the V1.5 milestone to close.

## What FRP-7 ships

FRP-7 is the **V1.5 closure-path** phase: rotation
implementation, synthetic 6-scenario soak rig, and pilot
evidence templates. The five-FRP live pilot is the final gate
and is operations-driven, not engineering-driven.

### Commit-by-commit

| # | SHA | Title |
|---|---|---|
| 1 | `04dd0d9` | rotation/recommender.go + tests + opsec_test + soak-rig spec amend |
| 2 | `864ee49` | rotation executor + transactional history + L3 wallclock pin |
| 3 | `95d6923` | V003 signed_sbps history table + Rust operator_db ops |
| 4 | `f5ed0e0` | rotate CLI subcommand + Rust wizard ops + Tauri shims + TS bridge |
| 5 | `786aad6` | Screen 6 LIVE Rotate button + RotateModal + EN/FA i18n |
| 6 | `6207188` | 6 V1.5 soak scenarios + v1-5-superset selector + count tests |
| 7 | (this commit) | pilot templates + consent + closure spec HOLD + handover |

### New code surfaces

* `publisher/deploy/rotation/` — Go package: `recommender.go`
  (`FromExplanation`, `FromContext`, locked types
  `Level`/`Confidence`/`RotationRecommendation`/`RotationContext`),
  `executor.go` (`MockProvider`-friendly Execute path with
  transactional history insert + L3 wallclock pin), and three
  test files (`recommender_test.go`, `executor_test.go`,
  `opsec_test.go`).
* `client-desktop/daal-wizard/migrations/V003__signed_sbps_history.sql`
  — the reversible V003 migration adding the `signed_sbps`
  history table and writing the FRP-2 `operators.signed_sbp_*`
  projection columns transactionally on every insert.
* `publisher/deploy/cli/cli.go` — the `daal-deploy
  rotate-recommend`, `reprovision`, and `assign-fip` CLI surfaces
  used by the wizard rotation flow.
* `client-desktop/daal-wizard/src/commands.rs` — the Rust wizard
  command implementation for `rotate_recommend`,
  `rotate_execute`, `rotate_history`, and `rotate_revert`.
* `client-desktop/tauri/src-tauri/src/lib.rs` — the Tauri command
  shims (`wizard_rotate_recommend`, `wizard_rotate_execute`,
  `wizard_rotate_history`, `wizard_rotate_revert`) with the
  rotate-event progress channel.
* `client-desktop/tauri/src/wizard/screens/RotateModal.tsx` — the
  4-state modal (input/confirmation/executing/success).
* `test-rigs/distribution-failure/scenarios/v1-5-*.json` — the
  6 V1.5 synthetic-soak scenarios.
* `test-rigs/distribution-failure/soak-driver/cmd/soak-driver/v1_5_superset_test.go`
  — the count tests pinning the `v1-5-superset`, `v2-superset`,
  and `v3-superset` selector sizes.
* `docs/pilot/frp-7-pilot-template.md` — operational pilot
  evidence template.
* `docs/pilot/consent-template.md` — bilingual EN/FA consent
  template (FA copy: NEEDS NATIVE REVIEW).
* `specs/v1-5-closure-v1.md` — V1.5 closure spec, status HOLD.
* `specs/blackout-soak-rig-v1.md` — amended with V1.5 scenario
  list and the `v1-5-superset` selector entry.

### Locked invariants reinforced

| Invariant | Evidence |
|---|---|
| Engine `daal-core 0.9.0+v3-share` | `core/internal/version` unchanged across all 7 commits |
| ABI count = 48 | nm check unchanged |
| `v3-superset` size = 31 | `v3_superset_test.go` + new `TestV1_5SupersetIsAdditive` |
| `v2-superset` size = 26 | `v3_superset_test.go` + new `TestV1_5SupersetIsAdditive` |
| `v1-5-superset` size = 6 | new `TestV1_5SupersetCount` |
| L3 wall-clock < 15 s | `executor.ErrL3WallClockBudget` + `v1-5-l3-fast-path.json` synthetic assertion |
| Position B (no phone-home) | `opsec_test.go` (recommender) + `wizard_rotate_*` Tauri shims contain no analytics calls + RotateModal opens no sockets |

## Test matrix at ship

| Tree | Command | Result |
|---|---|---|
| `publisher/deploy/rotation/...` | `go test ./...` | PASS (≥ 18 recommender cases + executor PASS + opsec PASS) |
| `client-desktop/daal-wizard` | `cargo test -p daal-wizard` | PASS (V003 migration + reversible-revert test PASS) |
| `publisher/...` | `go test ./...` | PASS |
| `client-desktop/tauri` (TS) | `npm run build` | PASS (vite 238 kB, +9 kB from FRP-6) |
| `client-desktop/tauri` (Rust) | `cargo build` | PASS |
| `test-rigs/distribution-failure/soak-driver/...` | `go test ./...` | PASS (v1-5-superset count + ID + additivity tests green) |
| `test-rigs/distribution-failure --scenarios v1-5-superset` | rig run | PASS 6/6 |
| `test-rigs/distribution-failure --scenarios v3-superset` | rig run | PASS 31/31 (regression unchanged) |
| FRP-3 explanation goldens | as in FRP-6 handover | 7/7 OK |

## V1.5 milestone — what remains

The engineering surface for V1.5 is COMPLETE at FRP-7. What
remains for V1.5 to **close** is operational, not engineering:

1. **Run a live pilot** with five FRPs per
   `docs/pilot/frp-7-pilot-template.md`. Seven consecutive
   days. Aggregate roll-up table fills.
2. **Native FA review of the consent template** before any FRP
   signs the FA copy. The EN copy is signature-ready.
3. **Native FA review of the FRP-6 + FRP-7 i18n** (carried over
   from FRP-6 handover). FRP-6 keys: 30 per locale. FRP-7
   keys: rotate-modal keys in
   `client-desktop/tauri/src/wizard/i18n/wizard.fa.json`.
4. **Project lead transcribes** the aggregate roll-up into
   `specs/v1-5-closure-v1.md` and flips status from HOLD to
   SHIPPED.

## V1.5 → V1.6 gate

V1.6 is the **CDN milestone** line (FRP-8: cdn_fronted
candidates per supplement §11.7 + §14.4). V1.5 closure is the
production precondition. FRP-7.5 engineering may begin once FRP-7
engineering ships, and V1.6 spec work may be prepared in parallel,
but no `cdn_fronted` candidate ships in production until V1.5
closes.

V1.6 engine target: `daal-core 0.9.0+v3-share` UNCHANGED. The
mode-aware schema reservations have already shipped through
V1.5 (validator RP021 + schema E2E synthetic scenario), so V1.6
is an additive surface, not a schema bump.

## Carry-over open items

* (FRP-6) FA copy native review — 30 keys.
* (FRP-7) FA copy native review — 30 more keys (rotate modal).
* (FRP-7) FA consent text native review.
* (FRP-7) Live pilot run with 5 FRPs.
* (V1.6 spec) `phases of development/38-phase-frp-8-v1-6-cdn-fronted.md`
  is filed but not started.

## Files to read first if you're picking this up

1. `daal-roadmap-v3-supplement-diaspora-helper.md` §22.1 + §14.1
   (the V1.5 success metrics and L3 wall-clock pin).
2. `specs/v1-5-closure-v1.md` (the closure gate).
3. `publisher/deploy/rotation/recommender.go` (the policy table
   from supplement §14.1 in code).
4. `client-desktop/tauri/src/wizard/screens/RotateModal.tsx`
   (the operator-facing rotation UX).
5. `docs/pilot/frp-7-pilot-template.md` (what gets measured).

## Attestation

| Field | Value |
|---|---|
| Phase | FRP-7 |
| Engine | `daal-core 0.9.0+v3-share` |
| ABI count | 48 |
| Synthetic soak | `v1-5-superset` 6/6 PASS, `v3-superset` 31/31 PASS |
| Live pilot | NOT YET RUN — V1.5 closure HOLD |
| Project position | B (no telemetry, unchanged) |
