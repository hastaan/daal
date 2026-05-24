# Lifeline Mode (V0.1) — V2.5 behavioural overlay

**Status:** Locked at Phase 2D.

**Related:** `mode-budgets-v1.md`, `route-budgets-v1.md`,
`network-memory-v1.md`, `posture-fsm-v1.md`, `failure-taxonomy-v1.md`,
`engine-abi-v1.md`, `key-vault-v1.md`.

## Purpose

Lifeline Mode V1 introduces a second lifeline-class mode token,
`lifeline-strict`, alongside the existing `lifeline`. The new mode
shares lifeline's 0.33× cap multiplier (no new budget arithmetic)
but layers four behavioural restrictions on top:

1. **Stability-biased ranker.** Routes are sorted by per-network
   failure rate (ascending). Stable routes win over fast routes.
2. **Bulk-capable filter.** Routes whose family is bulk-capable
   are filtered out unless the user has set the per-session
   bulk-capable opt-in flag.
3. **Refresh gate.** Scheduled subscription and revocation
   refreshes are skipped with a `skipped_lifeline_strict`
   audit row. User-triggered refreshes bypass the gate.
4. **Audit visibility.** The diagnostics blob carries
   `lifeline_strict_active_since` (hour-bucketed timestamp of
   the most recent transition into the mode) so the user can
   see at a glance that the overlay is active.

## Decision lock

Phase 2D ships a manual entry: the user toggles to
"Lifeline (local-only)" on the desktop. **Auto-promotion** to
lifeline-strict on burn detection is deferred to **Phase 2G** as
part of the V2 Success-Metric Soak.

## Mode token

The release-ABI mode token is `lifeline-strict`. The desktop
displays "Lifeline (local-only)" because the strict variant's
behavioural posture is "no scheduled fetches; only user actions
talk to the network". The two strings (engine token vs UI label)
are deliberately distinct — the engine's vocabulary is locked
by ABI, the UI's label is editorial and i18n-translatable.

## Cap arithmetic

Identical to lifeline:

| Mode             | Hourly multiplier | Session multiplier |
| ---------------- | ----------------- | ------------------ |
| `lifeline`       | 0.33×             | 0.33×              |
| `lifeline-strict`| 0.33×             | 0.33×              |
| `normal`         | 1.0×              | 1.0×               |
| `bulk`           | 1.0×              | 1.0×               |

The session-bulk-capable opt-in flag does NOT widen caps; it
only flips the bulk-capable family filter on the ranker.

## Bulk-capable session opt-in

The flag is engine-side state in `core/budget.Engine` (NOT
network-keyed; see `network-memory-v1.md` decision lock):

- Cleared on `NewSession` (engine_init or session-epoch bump).
- Survives `SetMode` and `engine_network_changed`.
- Toggled by the new release-ABI symbol
  `engine_set_allow_bulk_capable(allow int) -> int` and surfaced
  in `engine_export_diagnostics` as
  `session_allows_bulk_capable: bool`.

## Refresh gate

Both `SubscriptionRefresh` and `RevocationRefreshAll` accept a
`userTriggered bool` parameter at the Go layer. When the engine
mode is `lifeline-strict` and `userTriggered == false`, the call
returns immediately with the new outcome string
`skipped_lifeline_strict` (recorded in the audit ledger; not a
failure). User-triggered calls always run.

The release-ABI symbols `engine_subscription_refresh` and
`engine_revocation_refresh_all` always pass `userTriggered=true`
because every direct ABI call from the desktop or Android UI is,
by construction, user-initiated. The scheduler-driven path uses
`userTriggered=false`.

## Diagnostics fields (additive)

```
{
  "mode": "lifeline-strict" | "lifeline" | "normal" | "bulk",
  "secrets_unlocked": bool,
  "storage_profile": "vault" | "keystore",
  "session_allows_bulk_capable": bool,
  "lifeline_strict_active_since": "<RFC3339 hour-bucketed>"  // present iff mode == "lifeline-strict"
}
```

The `lifeline_strict_active_since` field is the only field that
appears conditionally; the others are always present after Init.
The PIN no-leak invariant
(`abi.TestPINDoesNotLeakIntoDiagnostics`,
`invariants.ruleNoPINLeakInDiagnostics`) is the canonical
regression on the V0.1 + CC.6 privacy posture.

## Forbidden labels

`lifeline-strict` is a **mode** ("the engine's networking
posture") and a **storage profile** ("vault" / "keystore"). Neither
implies anything about the user's identity, occupation, or
political category. The `core/opsec_test.go::TestNoGroupBasedLabels`
denylist forbids any string matching:

- "ordinary user", "activist", "journalist"
- "high-risk", "high risk"
- "device-seizure"

Inside the engine, in specs, in the desktop tree, and in the soak
rig. Use behavioural names ("vault" / "keystore", "lifeline" /
"lifeline-strict" / "normal" / "bulk") only.

## Soak coverage

Two scenarios under `test-rigs/distribution-failure/scenarios`:

- `lifeline-strict-policy.json` — manual toggle on day 1; bulk
  opt-in flip mid-week; toggle back to normal on day 6.
- `lifeline-strict-roam.json` — combines `network_changed` with
  `set_mode lifeline-strict` to exercise the V2.4 + 2D
  cross-product.

Both run under the default 7d soak whitelist (10 scenarios total
as of 2D) in both `--mode rig` and `--mode in-engine`.

## Phase 2G additions

Phase 2G shipped:

1. **Auto-promotion** to `lifeline-strict`. Driven by
   `core/burnpressure/` (3 distinct families × 30-min window ×
   ladder step ≥ 3 — locked v1 thresholds). The scheduler calls
   `EvaluateAutoPromotion` on every Tick; if the verdict says
   promote AND `engine_set_auto_promotion(1)` is in effect AND the
   user has not manually flipped mode in the same hour-bucket AND
   the detector has not already fired in the same hour-bucket, the
   engine flips into `lifeline-strict` via the auto-path (which
   does NOT stamp the manual-override hour). The flag defaults to
   on at `engine_init` and survives session epochs.
2. **1 000 synthetic clients × 30 days** soak in `cmd/soak-driver
   run-burn`, validated by the directory-rotation comparison
   primary metric in `specs/v2-success-metric-v1.md`.
3. Diagnostics widening: `auto_promotion_enabled` (always),
   `auto_promotion_last_fired_at` (after first fire).

The 2G ABI addition is `engine_set_auto_promotion(int enabled)`
(release surface 39 → 40). Manual mode picks ALWAYS win — auto-
promotion is a courtesy, not an override.

## Phase 2E (iOS) integration

* The 64 MiB Argon2id peak runs in the **host app** process,
  not the Network Extension (which has a ~50 MiB ceiling). The
  unsealed identity persists in the App Group secrets KV under
  iOS file protection; the extension reads the unsealed identity
  at tunnel start without ever holding the PIN. See
  `key-vault-v1.md` Phase 2E carry-over and `ios-build-v1.md`.
* Release ABI surface 41 (Phase 2E added `engine_lifecycle_event`)
  is consumed by the iOS shim. The Swift bridge fires
  `will_sleep`, `did_wake`, and `memory_pressure_warning` per the
  locked v1 token set; the engine records the events but takes no
  action by itself.
* Auto-promotion preference round-trips via a SwiftUI `Toggle`
  mirrored over `UserDefaults` (key `autoPromotionEnabled`). The
  engine is the source of truth; the mirror is a UX-side
  optimisation so the toggle shows the right state on fresh
  launch before the bridge has read diagnostics.
