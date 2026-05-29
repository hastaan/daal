# Phase 2C — Per-Network Memory: HANDOVER

## Status: COMPLETE

Phase 2C lands V2.4 from the V2 roadmap, plus the rig-side
infrastructure that was originally scoped as 2B-Rig and was folded
into 2C per the Option A spec approval (single mid-V2 jump in
release ABI surface, single coordinated soak-rig extension, single
ABI-version bump rather than two).

## Deliverable summary

| Layer | What lands | Files |
|---|---|---|
| **Engine** | `core/netmem` package; `(family, networkID)`-keyed family escalation; per-network budget capture/restore; `engine_network_changed` ABI; `current_network_id` in diagnostics | `core/netmem/*`, `core/budget/engine.go`, `core/pathmanager/fsm.go`, `core/abi/network*.go`, `core/abi/abi.go`, `core/routestore/secrets.go` |
| **Soak rig** | `set-mode` and `network-changed` engine commands; `EngineAction` schema in scenarios; `runEngineActions` dispatcher; `ExportDiagnostics` capture; `no_ssid_leak_in_diagnostics` invariant; 3 new scenarios | `cmd/daal-soak-engine/main.go`, `test-rigs/distribution-failure/soak-driver/internal/{client,censor,soak,invariants}/*`, `test-rigs/distribution-failure/scenarios/{network-roam,mode-bulk-unlock,posture-recovery-cycle}.json`, `test-rigs/distribution-failure/soak-driver/cmd/soak-driver/main.go` |
| **Desktop** | Rust shim (`engine.rs`, `commands.rs`); Tauri command; `bridge.ts` typings + `networkChanged()`; `NetworkLine` component (hashed prefix only); `home.network` / `home.forget_network` keys (en + fa) | `client-desktop/daal-desktop-core/src/{engine.rs,commands.rs}`, `client-desktop/tauri/src-tauri/src/lib.rs`, `client-desktop/tauri/src/lib/bridge.ts`, `client-desktop/tauri/src/pages/components/NetworkLine.tsx`, `client-desktop/tauri/src/pages/Home.tsx`, `client-desktop/tauri/src/i18n/{en,fa}.json` |
| **Specs** | New `network-memory-v1.md`; ABI v1 bumped 36→37 with 2C section; `route-budgets-v1.md` + `posture-fsm-v1.md` cross-refs | `specs/network-memory-v1.md`, `specs/engine-abi-v1.md`, `specs/route-budgets-v1.md`, `specs/posture-fsm-v1.md` |

## Surface count

- **Release ABI: 37** (was 36 at end of 2A/2B). The single
  addition is `engine_network_changed`. CI assertion in
  `specs/engine-abi-v1.md` is updated.
- **Soak ABI: 38** (release + `engine_set_now_unix`).
- **`engine_version`: `daal-core 0.5.0+survivability`** (held
  through all of V2; every 2C addition is append-only).

## Decisions locked at 2C (do NOT change downstream)

1. **HashID = 8-byte truncated SHA-256(kind | "|" | carrier | "|" | ssid)**.
   Lowercase hex, 16 chars. Locked at v1; bumping any of the four
   axes invalidates every saved blob.
2. **`SentinelUnset = "0000000000000000"`** is the network ID
   between `engine_init` and the first `engine_network_changed`.
   Treated as a real-but-empty network.
3. **Raw SSID/BSSID/carrier strings are discarded inside
   `core/abi.NetworkChanged` before the hash propagates.** The
   regression test `TestSSIDDoesNotLeakIntoDiagnostics` is the
   canonical V0.1 + CC.6 invariant. The soak rig adds a
   day-level invariant `no_ssid_leak_in_diagnostics` keyed by
   each scenario's `engine_actions`.
4. **Persisted hourly counters stay device-wide on the storage
   axis** (preserves byte-for-byte 30d soak parity from 2A/2B).
   Per-network restore rides on top via Capture/Restore.
5. **Family-escalation key widened to (family, networkID)**.
   Empty active-network collapses to legacy single-key behaviour
   (so 2B's family tests stay byte-stable).
6. **Mode change does NOT bump session epoch; network change does
   NOT bump session epoch.** Both are 2A-Polish carry-overs.
7. **Diagnostics widening additive only**. `current_network_id`
   added at root.
8. **High-risk Argon2id PIN-vault interface stable** in
   `SecretsKV`; actual high-risk wiring DEFERRED to 2D.
9. **`ForgetNetwork` is package-internal at 2C**; no new release
   ABI symbol. The desktop UI does not yet wire the
   "Forget this network" button (i18n key reserved for 2D).
10. **`engine_set_mode("lifeline-strict")` still rejected at 2C**.
    Widens at 2D. The 2B test
    `TestSetModeRejectsLifelineStrict` flips to positive at 2D.

## Verification matrix (re-run on 2026-04-27)

| Check | Result |
|---|---|
| `nm libdaalcore.so \| grep -c '^[0-9a-f]\+ T engine_'` | **37** ✅ |
| `engine_network_changed` symbol present at 0x5a2db0 | ✅ |
| `engine_version_str()` starts with `daal-core 0.5` | ✅ (cargo `engine_loads_and_sets_tunnel_socks` validates) |
| Core packages green (14, incl. new `core/netmem`) | ✅ |
| Cargo workspace tests | ✅ bundle-rs 5/5, parity 1/1, engine_load 1/1, tun-helper 4/4 |
| `TestSSIDDoesNotLeakIntoDiagnostics` (CC.6) | ✅ |
| 7d-rig soak, 8 scenarios | ✅ ALL PASS |
| 7d-in-engine soak, 8 scenarios | ✅ ALL PASS |
| **30d-in-engine soak (V2 entry-criterion)** | ✅ **ALL 8 PASS** |

## Open follow-ups (carry to 2D)

- Widen `engine_set_mode` to accept `lifeline-strict`.
- Wire Argon2id PIN-vault into the netmem key-derivation path
  (the interface is stable at 2C; only the high-risk-class
  derivation is deferred).
- Persist `lifeline-strict` flag in `Snapshot.Mode` so a
  hostile-network flag survives roams.
- 2D behavioural overlay: stability-biased ranker, bulk-capable
  refused, refresh gate, permanent banner.

## Open follow-ups (carry to 2G)

- The `network-roam` scenario added at 2C is the seed for 2G's
  multi-network simulation. 2G adds 1k synthetic clients each
  with their own roam pattern.

## V2 sub-phase order (locked)

1. ✅ 2F Scheduler
2. ✅ 2A Route Budget Engine + 2A-Polish
3. ✅ 2B Mode Budgets + V2.3 8-Posture FSM
4. ✅ **2C Per-Network Memory (FOLDED 2B-Rig in per Option A)**
5. ☐ 2D Lifeline Mode Strict Variant
6. ☐ 2G V2 Success-Metric Soak (1k synthetic clients)
7. ☐ 2E iOS

End of 2C handover.
