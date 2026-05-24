# Phase 2E — iOS Bring-Up — Handover

## Status: DONE (engine + scaffold; Apple-CI artefacts deferred to partner-mac)

The engine-side and rig-side work for V2.6 ("iOS rollout") is
complete and merged. The Apple-side build, TestFlight upload,
AltStore re-sign smoke, and on-device WG-handoff verification are
explicitly **operational dependencies** that run on Apple
infrastructure (the project's primary CI does NOT require macOS).
This handover documents the state at code-merge; the Apple-side
gates are tracked separately as ship-line items.

## What shipped

### 1. Release ABI 40 → 41

New release symbol: `engine_lifecycle_event(token) -> int`. Locked
v1 token set: `will_sleep`, `did_wake`, `memory_pressure_warning`.

* Returns 0 on a known token, -1 otherwise.
* Side-effect-light by design: records the event for diagnostics,
  takes no other action. Does NOT bump the session epoch, does
  NOT reset cooldown counters.
* The Swift bridge is the only caller on iOS; non-iOS platforms
  never invoke this symbol. The diagnostics fields
  `last_lifecycle_event` and `last_lifecycle_at` are absent on
  Linux / Android / desktop.

Engine version unchanged: `daal-core 0.6.0+v2-soak` (the version
bump is informative, gated on engine work; 2E is platform
integration only).

### 2. Soak `-tags soak` debug knobs (NOT release ABI)

Two soak-only ABI symbols added under the `cshared && soak` build
tag:

* `engine_soak_set_wg_memory_kib(int64)` — drives the simulated WG
  sub-engine RSS gauge.
* `engine_soak_force_wg_handoff()` — stamps a forced one-way
  handoff timestamp.

Soak ABI surface: 44 (release 41 + `engine_set_now_unix` + 2 soak
knobs). Release surface stays at 41.

### 3. Diagnostics widening (Phase 2E, additive only)

* `last_lifecycle_event: string` — most recent token; absent until
  first fire this engine session.
* `last_lifecycle_at: RFC3339` — timestamp; absent until first
  fire.
* `wg_subengine_memory_kib: int` — soak only; absent on release
  builds.
* `wg_subengine_handoff_at: RFC3339` — soak only; absent on
  release builds and absent until a forced handoff.

### 4. Soak rig — two new scenarios + driver actions

* `ios-extension-memory.json` — runs the soak engine subprocess
  with `GOMEMLIMIT=50MiB`. Drives three lifecycle events
  (`memory_pressure_warning`, `will_sleep`, `did_wake`) over the
  simulated week and asserts the same invariant ledger passes.
* `ios-wireguard-handoff.json` — drives the soak knobs on day 2
  to simulate the watermark crossing + forced handoff. Asserts
  the diagnostics surface carries the two soak-only fields after
  the forced handoff.
* `--scenarios v2-superset` whitelist widened from 10 to 12
  scenarios (legacy 5 + 2C 3 + 2D 2 + 2E 2). Backward-compatible:
  the legacy 5 are still selectable via `--scenarios legacy`.
* New driver actions: `lifecycle_event`,
  `soak_set_wg_memory_kib`, `soak_force_wg_handoff`.
* New `EngineEnv map[string]string` field on the `Scenario`
  struct; the driver respawns clients with that env when the
  scenario specifies it (the only consumer at 2E is
  `ios-extension-memory` setting `GOMEMLIMIT=50MiB`).

### 5. iOS scaffolding under `client-ios/`

```
client-ios/
  DaalApp/                       # SwiftUI host app
    Sources/{App,ContentView,ModePicker,RouteBudgetTable,
             LifelineStrictBanner,PinUnlockGate,
             AutoPromotionToggle,ConfigurationStore}.swift
    Resources/{en,fa}.lproj/Localizable.strings
    Info.plist
  DaalTunnel/                    # NEPacketTunnelProvider extension
    Sources/{PacketTunnelProvider,EngineBridge,
             WireguardSubEngine,MemorySampler,Logger}.swift
    Info.plist
  Configuration/Daal.entitlements
  build-xcframework.sh
  docs/personal-apple-id-self-sign.{en,fa}.md
  README.md
```

The Xcode project file itself is NOT committed at code-merge; the
maintainer (no macOS) commits Swift sources blind, and Apple CI
generates the `.xcodeproj` via `xcodegen` or `tuist` at build
time. (Decision recorded here; alternative is to commit the
`.xcodeproj` from the partner-mac. Either path keeps the merge
gate the same: Apple-CI green.)

### 6. Specs

* **New:** `specs/ios-build-v1.md` — gomobile bind incantation,
  App Group layout, NE memory budget envelope, watermark,
  Argon2id-in-host-app pattern, network-detection privacy floor.
* **New:** `specs/wireguard-subengine-v1.md` — locked constants
  (38 MiB watermark, 1 Hz sampling, <200 ms downtime budget,
  one-way per session, boringtun v0.6.0 pin).
* **Amended:** `specs/engine-abi-v1.md` — surface 41, the new
  symbol, the diagnostics widening.
* **Amended:** `specs/lifeline-mode-v1.md` — the iOS host-app /
  extension Argon2id split, the auto-promotion UserDefaults
  mirror.
* **Amended:** `specs/key-vault-v1.md` — the Phase 2E carry-over
  describing the host-app unlock pattern.

## Verification matrix (code-merge)

| Gate | Result |
|------|--------|
| `cd core && go test ./...` | GREEN |
| `cd core && go test -tags soak ./abi/...` | GREEN |
| `cd test-rigs/distribution-failure/soak-driver && go test ./...` | GREEN |
| Release ABI count (`nm` on `-tags cshared` build) | **41** |
| Soak ABI count (`nm` on `-tags 'cshared soak'` build) | **44** |
| `engine_lifecycle_event` present in nm output | YES |
| `engine_soak_set_wg_memory_kib` only in soak build | YES |
| Lifecycle tests (4) | GREEN |
| Auto-promotion tests (7) — 2G regression | GREEN |
| Burn-pressure tests (7) — 2G regression | GREEN |
| Burn-classifier tests (5) — 2G regression | GREEN |
| Soak-driver builds | GREEN |
| Two new scenarios load via `loadScenarios("v2-superset")` | YES |

## Verification matrix (Apple-CI / partner-mac, deferred)

These items run on Apple infrastructure and do NOT block
code-merge; they are the ship-line gates for putting iOS users
on a real build.

| Gate | Owner |
|------|-------|
| `Libbox.xcframework` builds reproducibly via `build-xcframework.sh` | Apple CI |
| Both Xcode targets compile (`xcodebuild build`) | Apple CI |
| `EngineBridge` unit tests pass on iOS Simulator (against `LibboxFake`) | Apple CI |
| `swiftlint` clean | Apple CI |
| TestFlight build distributed to internal testers | Apple Connect API |
| AltStore re-sign smoke passes ≥1 physical device, OR documented waiver | Manual, partner-mac |
| `ios-extension-memory` AND `ios-wireguard-handoff` soaks PASS in `--mode rig` and `--mode in-engine` | Apple CI runs the rig under `GOMEMLIMIT=50MiB` |
| WG sub-engine handoff verified on-device under memory-pressure load; downtime ≤200 ms recorded | Manual, partner-mac |
| TestFlight continuous-reissue pipeline operational (one re-upload within 60 days; ≥2 TestFlight groups provisioned) | Operational |
| Personal Apple ID self-sign docs landed (en + fa, screenshots) | Done in this handover at the text level; screenshots are operational and add when partner-mac is available |
| boringtun v0.6.0 vendored as `client-ios/Vendored/boringtun/libboringtun.a` with SHA256SUMS | Apple CI / partner-mac |

## Locked decisions held through 2E

* ABI append-only (one new release symbol at 2E:
  `engine_lifecycle_event`).
* Engine version unchanged (`daal-core 0.6.0+v2-soak`).
* Argon2id v1 params LOCKED (host app runs unlock; extension
  reads unsealed result).
* Storage profile labels behavioural ("vault" / "keystore"),
  never group-based.
* Bulk-capable session opt-in cleared by `NewSession` only.
* Diagnostics widening additive only.
* 2G burn-pressure thresholds LOCKED.
* Auto-promotion default-on; iOS Settings toggle is a UserDefaults
  mirror over `engine_set_auto_promotion`.
* Per-network privacy floor on iOS: SSID empty, carrier empty
  (deliberate degradation; documented).
* WG sub-engine handoff one-way per session.
* WG sub-engine watermark 38 MiB (locked at 2E).
* WG sub-engine downtime budget <200 ms.
* boringtun v0.6.0 (locked at 2E).
* "Lifeline (local-only)" UI label vs `lifeline-strict` engine
  token.
* iOS bridge owns NE lifecycle; engine reacts via
  `engine_network_changed` and `engine_set_mode` only.

## Decision deviations from the spec lock

* The current `phases of development/18-phase-2e-ios.md` (drafted
  before 2G) named "**No new release ABI surface**. Surface stays
  at **37**." That number predates 2C/2D/2G. The 2E spec lock
  resolved this with one new symbol (`engine_lifecycle_event`)
  and the corrected baseline of 40 → 41.
* The spec mentioned "ABI stays at 40" as one option; the
  AskUser at 2E start picked **add `engine_lifecycle_event`** so
  the engine has a typed surface for the NE state transitions
  the bridge emits — recording them in diagnostics is more
  valuable than relying on log-line parsing.

## Carry-overs to V3

Phase 3 receives:

* Stable, V2-complete engine ABI on all four platforms (Linux,
  Windows, Android, iOS). Surface is **41** at end of V2.
* A budget + mode-budget + posture-FSM + per-network-memory +
  lifeline-strict + auto-promotion feature set tested at 1000-
  client soak scale.
* Cross-cutting items CC.1 (external audit) and CC.7 (Persian
  wordlist commissioning) ready to gate broader rollout.
* New transport families (V3) plug into the existing trust /
  budget / FSM / diagnostics surfaces — no new architecture is
  expected.
* The WireGuard sub-engine pattern (`WireguardSubEngine`
  protocol + memory-driven handoff) generalises to a "memory-
  pressured WASM transport" pattern in V3.5 if needed.

## Files added/modified at 2E

```
core/abi/lifecycle.go                              added
core/abi/lifecycle_export.go                       added (cshared)
core/abi/lifecycle_gomobile.go                     added (gomobile)
core/abi/lifecycle_test.go                         added (4 tests)
core/abi/ios_handoff_soak.go                       added (soak only)
core/abi/ios_handoff_soak_export.go                added (cshared+soak)
core/abi/ios_handoff_soak_gomobile.go              added (gomobile+soak)
core/abi/ios_handoff_diag.go                       added (soak only)
core/abi/abi.go                                    modified (Core struct widening, diag widening, soakDiagHook)
cmd/daal-soak-engine/main.go                      modified (lifecycle-event + soak-set-wg-memory-kib + soak-force-wg-handoff commands)
test-rigs/distribution-failure/scenarios/ios-extension-memory.json    added
test-rigs/distribution-failure/scenarios/ios-wireguard-handoff.json   added
test-rigs/distribution-failure/soak-driver/internal/censor/censor.go  modified (EngineEnv field)
test-rigs/distribution-failure/soak-driver/internal/client/client.go  modified (SpawnWithEnv, lifecycle_event, soak knobs)
test-rigs/distribution-failure/soak-driver/internal/soak/soak.go      modified (3 new actions)
test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go    modified (per-scenario respawn for engine_env, v2-superset 10→12)
client-ios/DaalApp/Info.plist                                        added
client-ios/DaalApp/Sources/App.swift                                 added
client-ios/DaalApp/Sources/ContentView.swift                         added
client-ios/DaalApp/Sources/ModePicker.swift                          added
client-ios/DaalApp/Sources/LifelineStrictBanner.swift                added
client-ios/DaalApp/Sources/PinUnlockGate.swift                       added
client-ios/DaalApp/Sources/AutoPromotionToggle.swift                 added
client-ios/DaalApp/Sources/RouteBudgetTable.swift                    added
client-ios/DaalApp/Sources/ConfigurationStore.swift                  added
client-ios/DaalApp/Resources/en.lproj/Localizable.strings            added
client-ios/DaalApp/Resources/fa.lproj/Localizable.strings            added
client-ios/DaalTunnel/Info.plist                                     added
client-ios/DaalTunnel/Sources/PacketTunnelProvider.swift             added
client-ios/DaalTunnel/Sources/EngineBridge.swift                     added (LibboxImpl + LibboxFake)
client-ios/DaalTunnel/Sources/WireguardSubEngine.swift               added (Libbox + boringtun impls)
client-ios/DaalTunnel/Sources/MemorySampler.swift                    added
client-ios/DaalTunnel/Sources/Logger.swift                           added
client-ios/Configuration/Daal.entitlements                           added
client-ios/build-xcframework.sh                                       added
client-ios/docs/personal-apple-id-self-sign.en.md                     added
client-ios/docs/personal-apple-id-self-sign.fa.md                     added
client-ios/README.md                                                  added
specs/ios-build-v1.md                                                 added
specs/wireguard-subengine-v1.md                                       added
specs/engine-abi-v1.md                                                amended (surface 41, lifecycle, iOS gomobile artifact)
specs/lifeline-mode-v1.md                                             amended (host-app/extension Argon2id split)
specs/key-vault-v1.md                                                 amended (2E carry-over section)
phases of development/18-phase-2e-ios.handover.md                     this file
```

## Next phase

**V3 — Ecosystem integrations.** WebTunnel, Snowflake, MASQUE,
Psiphon / Conjure hooks, WASM transport slot, partner-operated
lifeline relay (V3.7, optional). New transport families plug into
the existing trust / budget / FSM / diagnostics surfaces — no
new architecture is expected.
