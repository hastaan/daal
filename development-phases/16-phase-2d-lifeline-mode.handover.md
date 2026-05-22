# Phase 2D — Lifeline-Strict + Argon2id PIN-Vault — Handover

**Status:** ✅ DONE.

**Engine version:** `daal-core 0.5.0+survivability` (held; every
addition is append-only).

**Release ABI surface:** **39** (was 37 at 2C; 2D adds two:
`engine_unlock_secrets` and `engine_set_allow_bulk_capable`).

**Soak ABI surface:** 40 (release 39 + `engine_set_now_unix`).

## What landed

### Engine

- **Lifeline-Strict mode.** `engine_set_mode("lifeline-strict")`
  flips `PostureLifeline` (same as `lifeline`) and stamps an
  hour-bucketed `lifelineStrictSince`. Cap multiplier is shared
  with lifeline at 0.33×; the deltas are behavioural.
- **Stability-biased ranker.** New
  `core/pathmanager/network_view.go` introduces a `NetworkView`
  interface with `FailureRate()` and
  `AllowsBulkCapableThisSession()`; new `RankWithView` sorts by
  failure rate ascending in `lifeline-strict`. Legacy `Rank`
  composes with a zero-view fallback.
- **Bulk-capable filter.** `lifeline-strict` excludes
  bulk-capable routes unless the per-session opt-in flag is set.
- **Refresh gate.** `core/refresh/subscription.go` and
  `core/refresh/revocation.go` thread a `userTriggered` flag.
  Scheduler-driven refreshes in `lifeline-strict` short-circuit
  with the `skipped_lifeline_strict` outcome (recorded, not a
  failure). User-triggered refreshes always run.
- **PIN-vault primitive.** `core/keyvault/` package. Argon2id v1
  parameters (t=3, m=64MiB, p=4, salt=16B, out=32B) are
  constants, regression-locked by `TestParametersLocked`.
  AES-GCM with AAD `"daal-keyvault-v1"`. Sealed blob layout:
  `version|salt|nonce|ctlen|ciphertext`. 14 unit tests.
- **Storage profiles.** `keystore` (default) vs `vault`
  (PIN-encrypted). Selected by the empty marker
  `state/.use_vault`. Behavioural names — never group-based —
  enforced by `core/opsec_test.go::TestNoGroupBasedLabels`.

### Release ABI

- `engine_set_mode` accepts `lifeline-strict` (signature
  unchanged).
- `engine_unlock_secrets(pin)` — 0 OK, -1 wrong PIN, -2 keystore
  profile (no PIN gate).
- `engine_set_allow_bulk_capable(allow)` — flips the per-session
  bulk-capable opt-in flag; returns 0; cleared by `NewSession`.
- `engine_export_diagnostics` widens additively with:
  `secrets_unlocked`, `storage_profile`, `session_allows_bulk_capable`,
  and (only when active) `lifeline_strict_active_since`.

### Soak rig

- New commands: `unlock-secrets`, `set-allow-bulk`,
  `subscription_refresh_user`.
- Driver actions: `unlock_secrets`, `set_allow_bulk`,
  `subscription_refresh_user`.
- Invariants: `ruleRefreshOutcomeMapped` accepts
  `skipped_lifeline_strict`; new `ruleNoPINLeakInDiagnostics`.
- New scenarios: `lifeline-strict-policy.json`,
  `lifeline-strict-roam.json`.
- Default whitelist now 10 scenarios (5 legacy + 3 from 2C + 2
  from 2D).

### Desktop

- `engine.rs` resolves `engine_unlock_secrets` and
  `engine_set_allow_bulk_capable`; `unlock_secrets(pin)` and
  `set_allow_bulk_capable(allow)` Rust wrappers.
- `commands.rs` exposes `unlock_secrets` returning
  `UnlockOutcome::{Unlocked, NotRequired, WrongPin}` and
  `set_allow_bulk_capable`.
- Tauri commands: `unlock_secrets`, `set_allow_bulk_capable`.
- `bridge.ts`: widened `Mode` with `'lifeline-strict'`; widened
  `DiagnosticsBlob` with 2D fields; new `unlockSecrets` and
  `setAllowBulkCapable` calls.
- New components: `LifelineStrictBanner`, `PinUnlockGate`.
  `ModePicker` widened with the strict mode (label
  "Lifeline (local-only)").
- Banner stack on Home: pointer-rotation banner above
  lifeline-strict banner (vertical stack — 2D decision lock).
- i18n keys: `mode.lifelineStrict.*`, `unlock.*` (English +
  Persian).

### Specs

- New: `specs/lifeline-mode-v1.md`, `specs/key-vault-v1.md`.
- Amended: `engine-abi-v1.md` (37→39), `mode-budgets-v1.md`,
  `posture-fsm-v1.md`, `network-memory-v1.md` (Argon2id no
  longer deferred), `route-budgets-v1.md`,
  `failure-taxonomy-v1.md` (added `skipped_lifeline_strict`).

## Verification matrix

| Check | Result |
| --- | --- |
| `go test ./...` (core) | PASS |
| `go test ./...` (soak-driver) | PASS |
| Release ABI surface (`nm` count) | **39** |
| `cargo build -p daal-desktop-core` | PASS |
| 7d soak `--mode rig` (10 scenarios) | ALL PASSED |
| 7d soak `--mode in-engine` (10 scenarios) | ALL PASSED |
| 30d soak `--mode in-engine` (10 scenarios) | ALL PASSED |

Canonical regressions:

- `core/abi/secrets_test.go::TestPINDoesNotLeakIntoDiagnostics`
- `core/keyvault/vault_test.go::TestPINNotEmbeddedInBlob`
- `core/pathmanager/rank_test.go::TestLifelineStrictDoesNotFilterRelayRouteFamilies`
- `core/abi/abi_test.go::TestSetModeLifelineStrictDoesNotResetSession`
- `core/budget/engine_test.go::TestAllowBulkCapableClearedByNewSession`
- `test-rigs/.../invariants.go::ruleNoPINLeakInDiagnostics`

## Locked decisions held through 2D

- ABI append-only.
- Argon2id v1 params LOCKED.
- HashID 8-byte truncated SHA-256 with `|` separator (2C).
- PIN never crosses any other ABI surface; never appears in
  diagnostics.
- Mode change does NOT bump session epoch; network change does
  NOT bump session epoch; unlock does NOT bump session epoch.
- Bulk-capable session opt-in cleared by `NewSession` only.
- Diagnostics widening additive only.
- Storage profile detected via `state/.use_vault` flag at Init.
- Lifeline-strict shares lifeline's 0.33× multiplier;
  behavioural deltas live in path-manager / refresher / desktop.
- No relay-route filter, ever (regression-tested).
- "Lifeline (local-only)" UI label vs `lifeline-strict` engine
  token (deliberately distinct strings).
- Storage-profile labels behavioural ("vault" / "keystore"),
  never group-based.

## Decision deviations from the spec lock

- The spec lock named **one** new release symbol
  (`engine_unlock_secrets`, surface 37→38). Implementation
  required a second (`engine_set_allow_bulk_capable`) so the
  lifeline-strict bulk-capable opt-in flag could cross FFI from
  the desktop. Resolved via AskUser:
  **two new release symbols, surface 37→39.** Recorded here and
  in `specs/engine-abi-v1.md`.

## Carry-overs to 2G

- Auto-promotion to `lifeline-strict` on burn detection.
- 1 000 synthetic clients with independent roam patterns +
  lifeline-strict toggle patterns.
- Build on the `network-roam`, `lifeline-strict-policy`, and
  `lifeline-strict-roam` scenarios as the seed set.

## Carry-overs to 2E (iOS)

- iOS NE memory budget must accommodate Argon2id 64 MiB peak
  (one-shot at unlock; flagged for measurement).
- Surface 39 must be consumed by the iOS shim.

## Files changed / added

```
core/abi/abi.go                      (modified — 2D fields, init detection, diag widening)
core/abi/abi_test.go                 (modified — set-mode tests)
core/abi/refresh.go                  (modified — userTriggered threading)
core/abi/secrets.go                  (added)
core/abi/secrets_export.go           (added — 2 cshared symbols)
core/abi/secrets_gomobile.go         (added)
core/abi/secrets_test.go             (added)
core/budget/engine.go                (modified — bulk-capable session flag)
core/budget/engine_test.go           (modified)
core/keyvault/doc.go                 (added)
core/keyvault/argon2.go              (added)
core/keyvault/argon2_test.go         (added)
core/keyvault/vault.go               (added)
core/keyvault/vault_test.go          (added)
core/pathmanager/network_view.go     (added)
core/pathmanager/rank.go             (modified — RankWithView)
core/pathmanager/rank_test.go        (modified)
core/refresh/subscription.go         (modified — gate + RefreshUser)
core/refresh/subscription_test.go    (modified)
core/refresh/revocation.go           (modified — gate + RefreshAllUser)
cmd/daal-soak-engine/main.go        (modified — 3 new commands)
test-rigs/distribution-failure/scenarios/lifeline-strict-policy.json   (added)
test-rigs/distribution-failure/scenarios/lifeline-strict-roam.json     (added)
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go     (modified — whitelist)
test-rigs/distribution-failure/soak-driver/internal/client/client.go   (modified — wrappers)
test-rigs/distribution-failure/soak-driver/internal/invariants/invariants.go  (modified — rules)
test-rigs/distribution-failure/soak-driver/internal/soak/soak.go       (modified — actions)
client-desktop/daal-desktop-core/src/engine.rs                        (modified — 2 symbols)
client-desktop/daal-desktop-core/src/commands.rs                      (modified — UnlockOutcome, set_allow_bulk)
client-desktop/tauri/src-tauri/src/lib.rs                              (modified — 2 commands)
client-desktop/tauri/src/lib/bridge.ts                                 (modified — types + wrappers)
client-desktop/tauri/src/pages/Home.tsx                                (modified — wiring)
client-desktop/tauri/src/pages/components/ModePicker.tsx               (modified)
client-desktop/tauri/src/pages/components/LifelineStrictBanner.tsx     (added)
client-desktop/tauri/src/pages/components/PinUnlockGate.tsx            (added)
client-desktop/tauri/src/i18n/en.json                                  (modified)
client-desktop/tauri/src/i18n/fa.json                                  (modified)
specs/lifeline-mode-v1.md            (added)
specs/key-vault-v1.md                (added)
specs/engine-abi-v1.md               (modified — 2D additions)
specs/mode-budgets-v1.md             (modified — lifeline-strict)
specs/posture-fsm-v1.md              (modified — lifeline-strict)
specs/network-memory-v1.md           (modified — vault profile)
specs/route-budgets-v1.md            (modified — bulk-capable filter)
specs/failure-taxonomy-v1.md         (modified — skipped_lifeline_strict)
```

## Next phase

**Phase 2G** — V2 Success-Metric Soak (1k synthetic clients,
auto-promotion to lifeline-strict, 30-day in-engine).
