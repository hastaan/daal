# Phase 2B Handover — Mode Budgets + V2.3 8-Posture FSM

**Status:** ✅ **DONE** (engine + ABI + desktop UI + specs).

**Engine version:** `daal-core 0.5.0+survivability` (held).
**Release ABI surface:** **36** (held; no new release function).
**Soak ABI surface:** **37** (release + `engine_set_now_unix`, held).

## Roadmap coverage

V2.2 (mode budget UI: lifeline / normal / bulk) + V2.3 (cooldown
state machine: 8 named postures, V2.3 family-cooldown ladder).
V2.1's 90% rate-limit prompt now lives in the desktop. V0.3 failure
taxonomy is the canonical cooldown-reason vocabulary.

## Locked decisions (decided up-front via AskUser)

1. **Posture as parallel axis** (Option C). Pre-2B
   `pathmanager.State` enum is preserved unchanged. The V2.3 8-state
   posture vocabulary lives on a **parallel** `pathmanager.Posture`
   axis, methods on `Manager` (Posture / SetPosture). Diagnostics
   surfaces both. Removal of `State` is deferred to V3 as a
   separate, scoped refactor.
2. **Hybrid family-cooldown trigger.** Family-class V0.3 categories
   (`tls_sni_or_cert_block_suspected`, `udp_unavailable`,
   `quic_unavailable` per `IsFamilyClass`) trip the family ladder
   on the FIRST occurrence (immediate step-1 = 5 min). Per-route
   classes (`tcp_reset`, `tls_handshake_failed`, `tcp_*_timeout`,
   `dns_*`) keep the legacy "3 failures in 1 h on the same family"
   trigger; both escalate up the V2.3 ladder
   (5 min → 15 min → 1 h → 4 h → 24 h, capped at 24 h).
3. **All-in-2B desktop UI.** ModePicker + RouteBudgetTable +
   RouteHealthTable + V2.1 90% RateLimitPrompt + Persian copy land
   together in 2B. No separate desktop sub-phase.

## Files touched

### Engine (Go)

Created:
- `core/budget/effective.go` — `ModeFactor`, `applyFactor`,
  `Engine.EffectiveCap`, `Engine.SetMode`, `Engine.Mode`.
- `core/budget/effective_test.go` — 9 tests (matrix over every
  tag × mode pair; lifeline-thirds; SetMode-no-epoch-bump;
  AddRespectsLifelineMultiplier).
- `core/pathmanager/posture.go` — 8 Posture constants, 12
  PostureEvents, `LegalTransitions` closed table, `IsLegal`.
- `core/pathmanager/posture_test.go` — 8 tests (uniqueness, closed
  table, every-active-can-disconnect, IsLegal yes/no, default,
  legal advance, illegal rejection, recovery cycle).
- `core/pathmanager/family.go` — `familyBackoffLadder` (5min /
  15min / 1h / 4h / 24h), `FamilyCooldownStep` (1-indexed, clamps
  at 24h), `IsFamilyClass`.
- `core/pathmanager/family_test.go` — 7 tests (ladder values,
  clamp, zero, IsFamilyClass map, immediate step-1 for family
  classes, 3-failure preamble for per-route classes, escalation
  reset on Connected, ladder escalation across consecutive
  failures).
- `core/pathmanager/rank.go` — pure `Rank(rs, mode)` filter +
  deprefer-bulk + consumed-fraction sort + tie-break-by-id. NOT
  yet wired into `engine_set_route`'s connect path; 2C wires it
  into the per-network "next route" picker.
- `core/pathmanager/rank_test.go` — 6 tests (bulk-mode filter,
  lifeline-only filter, deprefer bulk-capable in normal/lifeline,
  consumed-fraction sort, route-id tie-break, empty input).

Modified:
- `core/budget/engine.go` — added `mode` field; `SetMode`/`Mode`
  accessors; `Add` and `Snapshot` now thread
  `ModeFactor(e.mode)`. Mode change MUST NOT bump session epoch
  (asserted by `TestSetModeDoesNotBumpSessionEpoch`).
- `core/pathmanager/fsm.go` — Manager extended with `posture`,
  `routeHealth` map, `familyEscalation` counter,
  `familyLastReason` map; new `Posture()`, `SetPosture(event,
  to)`, `RouteHealth()`, `SkippedFamilies()` accessors. Rewrote
  `Failed` to honour the hybrid trigger (immediate ladder for
  family classes, 3-in-bucket for per-route classes). Updated
  `Connected()` to reset escalation on success. Legacy `State`
  axis untouched.
- `core/pathmanager/explain.go` — extended `SkippedFamily` struct
  with `Until` (time.Time) and `LadderStep` (int) fields. Existing
  `Reason` field preserved.
- `core/abi/budget.go` — added `budgetEngineIfPresent()`
  non-instantiating peek for SetMode wiring.
- `core/abi/abi.go::SetMode` — threads validated mode into the
  budget engine and into the V2.3 posture FSM. Rejects
  `lifeline-strict` at 2B; 2D widens validation. Rejects unknown
  values.
- `core/abi/abi.go::ExportDiagnostics` — additive widening with
  `posture` (string), `route_health[]`, `skipped_families[]`. The
  legacy `state` and `why` fields are unchanged. `budgets[]`
  caps reflect the *effective* (post-multiplier) ceiling.
- `core/abi/abi_test.go` — 4 new tests:
  `TestSetModeWiresToBudgetEngine`,
  `TestSetModeFlipsToPostureLifelineWhenActive`,
  `TestSetModeRejectsLifelineStrict`,
  `TestExportDiagnosticsCarriesPostureAndRouteHealth`.

### Desktop (Rust + TS + i18n)

Modified:
- `client-desktop/daal-desktop-core/src/commands.rs` — `set_mode`
  Rust shim.
- `client-desktop/tauri/src-tauri/src/lib.rs` — `set_mode`
  registered as `#[tauri::command]` and listed in the
  invoke_handler! macro.
- `client-desktop/tauri/src/lib/bridge.ts` — `setMode(mode)`,
  `Mode` type, `BudgetRow` / `RouteHealthRow` /
  `SkippedFamilyRow` / `DiagnosticsBlob` interfaces, typed
  `diagnostics()` parser.
- `client-desktop/tauri/src/pages/Home.tsx` — 5 s diagnostics
  poll, `onSetMode` handler, four new components wired in.
- `client-desktop/tauri/src/i18n/en.json` — `home.mode_*`,
  `prompt.*`, `cooldown.*` keys.
- `client-desktop/tauri/src/i18n/fa.json` — full Persian
  translations of the same keys.

Created:
- `client-desktop/tauri/src/pages/components/ModePicker.tsx` —
  segmented control with active-mode hint.
- `client-desktop/tauri/src/pages/components/RouteBudgetTable.tsx`
  — per-route hourly + session bars; V2.1 90% / exhausted colour
  rules.
- `client-desktop/tauri/src/pages/components/RouteHealthTable.tsx`
  — V0.3 cooldown reason via `cooldown.<category>` i18n keys;
  relative-time rendering of `cooldown_until`.
- `client-desktop/tauri/src/pages/components/RateLimitPrompt.tsx`
  — V2.1 90% threshold prompt with per-route session-scoped
  dismissal; verbatim roadmap copy in i18n.

### Specs

Created:
- `specs/mode-budgets-v1.md` — V2.2 modes, multipliers, V2.1
  prompt copy.
- `specs/posture-fsm-v1.md` — 8 postures, closed transition
  table, V2.3 ladder, V0.3 orthogonality, ABI widening.

Amended:
- `specs/route-budgets-v1.md` — Status section adds 2B threading
  note (Add/Snapshot honour `ModeFactor`; SetMode does NOT bump
  session epoch).
- `specs/engine-abi-v1.md` — 2B widening section appended
  (additive only; surface still 36; `set_mode` accepted set is
  `{lifeline, normal, bulk}`).

## Verification

All four gates green:

| Gate | Command | Result |
|---|---|---|
| nm count | `nm /tmp/libdaalcore.so \| grep -c '^[0-9a-f]\+ T engine_'` | **36** |
| Go tests | `cd /home/daal/core && go test -count=1 ./...` | all 13 pkgs ok |
| Bundle/lab | `bundle/go ./...` + `lab-driver/internal/...` | all ok |
| Desktop | `client-desktop && cargo test --workspace` | bundle-rs 5/5, parity 1/1, engine_load 1/1, tun-helper 3+1 |
| 7d-rig soak | `soak-driver run-7d --mode rig` | ALL SCENARIOS PASSED |
| 7d-in-engine soak | `soak-driver run-7d --mode in-engine` | ALL SCENARIOS PASSED |
| **30d-in-engine soak** | `soak-driver run-30d --mode in-engine` | **ALL SCENARIOS PASSED** (V2 entry-criterion preserved) |

## Intentional deferrals

### Soak rig scenarios (`mode-bulk-unlock`, `posture-recovery-cycle`) → 2B-Rig

The distribution-failure soak rig models *origin-server channel
blocking*; it does not yet drive `engine_set_mode` /
`engine_set_route_budget` / fault-injected route failures within a
day. Adding these scenarios requires:

1. Extending `soak-driver/internal/soak/soak.go::driveOneDay` with
   per-day mode / fault hooks parsed from a richer scenario
   schema.
2. Extending `soak-driver/internal/invariants` with assertions
   over `route_health[]` and the effective-cap `budgets[]` shape.
3. Extending `censor.Scenario` with optional engine-side action
   blocks while keeping the existing channel-blocking shape
   bit-for-bit identical (so the 30 d in-engine parity sweep
   still gives byte-identical ledgers on legacy scenarios).

That's a self-contained rig-extension phase. Until then, the 2B
engine paths are deterministically covered by Go unit tests + ABI
integration tests; the 30 d parity sweep on the existing 7
scenarios stays green and continues to gate V2 entry. No inert
scenarios were checked in.

### Rank wiring → 2C

`pathmanager.Rank` is implemented and tested but is NOT yet wired
into `engine_set_route` 's connect path. 2C wires it into the
per-network "next route" picker so that mode + per-network
preferences both apply at route-selection time. Until 2C, the
desktop manually selects `route_id`s; the budget engine still
enforces caps regardless.

## Carry-overs to subsequent phases

### 2C — Per-Network Memory

- **Wire `pathmanager.Rank`** into `engine_set_route`'s connect path
  (and into a new "best route on this network" suggester used by
  the desktop to pre-select a route after a network change).
- **Family-escalation key widening.** Today the escalation counter
  is keyed by `family` (with implicit `network_id = "global"`). 2C
  widens to `(family × network_id)` so a roam to a friendly
  network resets the ladder. This is the bridge between V2.3 and
  V2.4.
- **Surface bump 36 → 37** via `engine_network_changed` (still
  additive in semantics; new function only).

### 2D — Lifeline Mode Strict Variant

- **Widen `engine_set_mode`'s validation set** to accept
  `lifeline-strict`. The 2B `TestSetModeRejectsLifelineStrict`
  test will need to flip to `TestSetModeAcceptsLifelineStrict` (or
  be deleted in favour of a positive test).
- **Behavioural overlay.** `lifeline-strict` shares the 0.33×
  multiplier with `lifeline` but adds: stability-biased ranker,
  `bulk-capable` refused for general traffic (per-session opt-in
  needed), refresh gate, permanent banner. All of these live on
  the path-manager / desktop side; the budget engine stays
  unchanged.
- **Spec update.** `specs/lifeline-mode-v1.md` already exists for
  the V2.5 local policy; 2D extends it with the strict variant
  and amends `mode-budgets-v1.md` to flip the
  `engine_set_mode` accepted set.

### 2B-Rig (small parallel phase)

- Extend the soak driver per the deferral note above. Two new
  scenarios materialise the 2B engine paths inside the rig.
  Engine-side surfaces don't change; this is rig harness work.

## Locked invariants preserved

The following pre-existing invariants were preserved across 2B and
must remain locked through 2C / 2D / 2G:

- **ABI append-only.** No release function signature changed; no
  release function was removed. nm = 36.
- **V2.1 cap table values.** Hourly + session caps and
  `modes_allowed` strings are byte-identical to the pre-2B table.
- **`modes_allowed` enforcement.** Lives in `pathmanager.Rank`,
  NOT in the budget engine. The budget engine sees no mode tag —
  it only sees the multiplier from `Engine.SetMode`.
- **Hour bucket.** `now.Truncate(time.Hour).UTC()`.
- **`auth_failed` exemption.** Preserved by `IsFamilyClass(false)`
  + a path in `Failed` that records the route in `routeHealth`
  WITHOUT setting `InCooldown=true`.
- **Diagnostics widening additive only.** Pre-2B consumers reading
  legacy fields see identical shapes.
- **`KindBudgetReset` cadence (1 h).** V2 entry-criterion parity
  contract.
- **`lifeline-only` is a budget TAG; `lifeline-strict` is a
  MODE.** Don't conflate; `lifeline-only` lives on routes,
  `lifeline-strict` lives on the engine.
- **Mode change does NOT bump session epoch** (2A-Polish rule).
  Asserted by `TestSetModeDoesNotBumpSessionEpoch`.
- **`engine_set_mode` rejects `lifeline-strict` at 2B.** 2D
  widens.
- **iOS work waits until end of V2** (per `09-phase-2-ios-survivability.md`).

## Pointer to next action

Next phase per the V2 sub-phase order:

> ✅ 2F → ✅ 2A → ✅ 2A-Polish → **✅ 2B** → **➡ 2C Per-Network
> Memory** → 2D Lifeline-Strict → 2G 1k Soak → 2E iOS.

Begin 2C with: wire `pathmanager.Rank` into `engine_set_route`,
add `engine_network_changed` (surface 36 → 37), key the
family-escalation counter on `(family × network_id)`.
