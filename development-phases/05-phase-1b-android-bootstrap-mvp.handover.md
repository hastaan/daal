# Phase 1B — Android Bootstrap MVP: Handover

**Status:** Implementation complete (Go core, engine ABI, importer, route store, CLI, Android Gradle project). Some pieces are deliberately staged (real sing-box driver wiring, real local probes, AAR build on a host with the Android NDK).

**Roadmap coverage:** V1.1, V1.2, V1.3, V1.4 entrypoints, V1.5 Tier 1/Tier 2 trust pins (Tier 3 directory fetch is Phase 1D), Modules 1/2/3/4/5 minimal slices, CC.6 (zero telemetry), CC.4 panic-wipe.

---

## What was built

### Go core (`/home/daal/core/`, module `daal/core`)

- `routestore/` — sqlite (pure-Go `modernc.org/sqlite`) schema, CRUD, age-encrypted KV for sing-box profile bytes, `HourBucket()` timestamps, panic-wipe.
- `trust/` — pin lookup, first-seen, rotation acceptance, revocation, plus the `StoreAdapter` that wires `routestore.Store` to `bundle-go/importer.State`.
- `engine/`
  - `config.go` — `RouteRow + profile bytes → SingBoxConfig` translator with UDP-gating mark.
  - `engine.go` — `Driver` interface plus a deterministic `Stub` driver. The real sing-box driver lands behind `//go:build singbox` in Phase 1B-Polish.
- `diagnostics/classify.go` — locked V0.3 mapping table; `IsCensorshipClass(AuthFailed) == false` is the explicit hard rule.
- `pathmanager/fsm.go` — `NoRoute → Connecting → Connected | Cooldown | Failed`, per-route exponential cooldown (5 m → … → 24 h), per-family cooldown after 3 same-hour failures, `auth_failed` exempt.
- `abi/` — the singleton facade. 14 functions exactly, matching `specs/engine-abi-v1.md`. Two build-tag variants:
  - `//go:build cshared` exports `engine_*` C symbols for `go build -buildmode=c-shared` (Tauri sidecar / desktop).
  - `//go:build gomobile` exposes a `DaalCore` struct gomobile bind serializes to Java/Kotlin.

### Bundle library additions (`/home/daal/bundle/go/importer/`)

- `importer.go` + `util.go` — pure `bundle-go` policy logic for TOFU, rotation chains, in-archive revocation, and the Verdict union (`Imported`, `TrustPromptNeeded`, `RotationAccepted`, `Rejected`). The store interface is `State` (kept narrow so the importer never touches sqlite directly).

### Daal-core CLI (`/home/daal/cmd/daal-core/`)

- Linux/Windows test harness exercising the same ABI the gomobile binding will. Subcommands: `version`, `import`, `resolve`, `connect`, `disconnect`, `mode`, `probe`, `diag`, `list`. Pending trust prompts persist to `state_dir/pending/` so a multi-process workflow (`import` then `resolve`) works.

### Android Gradle project (`/home/daal/client-android/`)

- `settings.gradle.kts` + `build.gradle.kts` + `app/build.gradle.kts` — Kotlin 2.0, AGP 8.5, Compose BOM `2024.06.00`, ABI splits `arm64-v8a` + `armeabi-v7a`, `minSdk 24`, Compose enabled, R8 on release.
- `AndroidManifest.xml` — VpnService with `foregroundServiceType="specialUse"` and `PROPERTY_SPECIAL_USE_FGS_SUBTYPE = vpn`, `.sbp` content/file intent filters, no backup.
- Kotlin sources:
  - `data/DaalCoreBridge.kt` — direct delegate to the gomobile `DaalCore` binding.
  - `vpn/DaalVpnService.kt` — foreground service that owns the Go core lifecycle.
  - `vm/DaalViewModel.kt` — Compose-side state holder; UI is a redacted projection of the Go core's truth.
  - `ui/MainActivity.kt` — single-Activity host with Home + modal trust-prompt dialog.
- Resources: `values/strings.xml` (EN), `values-fa/strings.xml` (FA), launcher vector drawable, data-extraction-rules excluding everything from cloud backup.
- `app/libs/README.md` — documents how to produce `daal-core.aar` from the `/core` Go module on a host with the Android NDK.

### Specs (frozen)

- `specs/engine-abi-v1.md` — 14-function ABI surface, stability rules, privacy invariants.
- `specs/android-client-v1.md` — screens, security-level defaults, VpnService configuration, privacy invariants.
- `specs/trust-ui-v1.md` — copy in EN + FA, dialog invariants, anti-pattern register.
- `specs/routestore-v1.md` — schema, encryption, hour-bucket rule, migration policy.

### Tests

```
daal/bundle-go/bundle      ok
daal/bundle-go/publisher   ok
daal/core                  ok  (TestNoNetworkCallSitesInCore, TestNoGroupBasedLabels)
daal/core/abi              ok  (end-to-end import + resolve + connect)
daal/core/diagnostics      ok  (V0.3 mapping table)
daal/core/engine           ok  (config build + Stub driver round-trip)
daal/core/pathmanager      ok  (auth_failed exemption + cooldown timers + family escalation)
daal/core/routestore       ok  (CRUD + secret round-trip + plaintext-not-in-DB + panic-wipe)
daal/core/trust            ok  (TOFU + rotation accepted + rotation rejected + revocation)
```

CLI smoke (against the Phase 1A sample bundles, in `/home/daal/specs/test-vectors/bundles/samples/`):

| Step | Result |
|---|---|
| `import signed-A.sbp` | `Kind=1` (TrustPromptNeeded), EN+FA fingerprints rendered |
| `resolve <fp> trust` | `Kind=0` (Imported) |
| `connect sample-route-1` | success against the stub engine |
| `disconnect` | success |
| `import unknown-publisher-B.sbp` | `Kind=1` (different fp; new prompt) |
| `import valid-rotation-B.sbp` | **`Kind=2` (RotationAccepted)** without re-prompt |
| `import revoked-A.sbp` | `Kind=0` (silent), in-archive revocation revokes `sample-route-1` |
| `connect sample-route-1` | refused: `route is revoked and cannot be activated` |

---

## Decisions worth carrying forward

1. **Sing-box is staged behind a build tag.** The default core build ships an in-process `engine.Stub` driver that satisfies the entire ABI but does not establish a real tunnel. Phase 1B-Polish (next session) lands the real driver under `//go:build singbox`. The reasons:
   - The stub keeps all unit and integration tests deterministic on a Linux/WSL2 host with no NDK.
   - The ABI surface is *already* frozen against the stub, so swapping in sing-box is a drop-in.
   - The CLI and tests prove the bundle-import + trust + revocation paths end-to-end without depending on a tunnel actually establishing.
2. **Pure-Go sqlite.** `modernc.org/sqlite` keeps the Go core cgo-free for the `c-shared` and `gomobile` builds. The cost is 2-3× slower writes vs cgo sqlite, which is irrelevant for V1's working set (a few hundred routes max).
3. **age-encrypted secret KV.** Sing-box outbound JSON never sits in cleartext on disk. The age identity file is the device-bound key; Android-side wrapping with `EncryptedSharedPreferences` is a Phase 1B-Polish hardening.
4. **Pending trust prompts persist to disk.** This is what makes the CLI flow `import` → `resolve` work across two processes. The Android app keeps the state in-process anyway, but the persistent path is the right primitive — it also covers the case where the app is killed mid-prompt.
5. **Path manager is intentionally minimal.** Per-route + per-family cooldown only. Per-network memory, route budgets, modes-as-policy, shortlist racing are V2 work and explicitly absent here. The FSM is named exactly the way `pathmanager/fsm.go` documents it; the diagnostics screen will quote `LastReason()` directly.
6. **No telemetry, anywhere.** Source-grep enforced in `core/opsec_test.go`. The Android Gradle project does not link any analytics SDK. The `INTERNET` permission is held by the VpnService process, not the UI process.
7. **No group-based labels.** Same source-grep test. The four security levels (Standard / Elevated / Strict / Maximum Protection) are the only sanctioned tier strings.

---

## Known follow-ups (Phase 1B-Polish, the next session)

- **Real sing-box driver** behind `//go:build singbox`. Pulls in the `sing-box` Go module, builds with build-tag trim to V1's transport set, wires Go events to the engine `Subscribe` channel. APK size impact lands here.
- **Real local probes**. `core/engine/probe.go` should perform: a UDP echo to a test host, a DNS resolution, a TCP/443 connect — all to **operator-supplied** target lists, never to a hardcoded project endpoint.
- **`gomobile bind` AAR build script** in `tools/build-aar.sh` (or `client-android/build-aar.ps1` for Windows) that runs gomobile against `/core` and drops the AAR into `client-android/app/libs/daal-core.aar`. Documented in `client-android/app/libs/README.md` already.
- **bundle-go cert chain for sub-keys**. Today the bundle's manifest signature is verified against `publisher.pub` directly. Phase 1A's sub-key issuance code already exists; Phase 1B-Polish should teach `bundle.VerifyBundle` to follow `trust/subkey-cert.json` so journalists can rotate sub-keys without a root touch.
- **Strict rotation-chain signature verification**. Today `importer.verifyRotation` accepts a chain when the OLD fingerprint matches a pinned publisher and the embedded NEW pub matches the bundle's publisher.pub. The Ed25519 signature on the chain is parsed but not verified because the .sbp does not embed the OLD pub bytes; this is documented inline. The fix is to embed `trust/old-root.pub` in any rotation-shipping bundle and verify the chain signature here.
- **Compose screens still to fill in.** Routes screen, Add Route tabs, Diagnostics screen, Settings screen, Onboarding flow. The MainActivity.kt skeleton holds the trust prompt and HomeScreen; everything else is a TODO bound to the same `DaalViewModel`.
- **ProGuard rules tightening** once the gomobile artifact is real (the `keep abi.**` rule will need refinement).
- **Privacy review document** at `docs/security/no-telemetry-review-phase-1b.md`, mirroring the Phase 0C review.

---

## Phase 1C / 1D handoff

Phase 1C (offline sharing) consumes:
- `bundle-go/importer` + `core/trust.StoreAdapter` — the same import path used by file import is what the LAN/QR/clipboard receivers will call. There is exactly one trust path on the device.
- The pending-prompt persistence — the LAN receiver hands a bundle to the importer, then the existing prompt UI handles it.
- The `Add Route` tabs UI scaffolding — the LAN/QR receivers slot in here.

Phase 1D (bootstrap directory) consumes:
- `core/abi.ImportSBP` — fetched directories are signed `.sbp` bundles; the same code path validates and stores them.
- `core/trust` — the official directory's signing keys are pinned in advance (Tier 1 keys); `LookupPublisher` returns the pinned trust level so directory bundles import silently.
- The `secrets_kv` KV — directory pointer rotation can write a new pointer set under a reserved key like `bootstrap-pointers:v1`.

---

## Validation snapshot

```
$ /usr/local/go/bin/go version
go version go1.27-devel ...

$ cd /home/daal/core && go test ./...
ok  daal/core
ok  daal/core/abi
ok  daal/core/diagnostics
ok  daal/core/engine
ok  daal/core/pathmanager
ok  daal/core/routestore
ok  daal/core/trust

$ cd /home/daal/bundle/go && go test ./...
ok  daal/bundle-go/bundle
ok  daal/bundle-go/publisher

$ /tmp/daal-core version
daal-core 0.2.0+stub-engine

$ /tmp/daal-core --state-dir /tmp/x import signed-A.sbp     # → Kind=1 prompt
$ /tmp/daal-core --state-dir /tmp/x resolve <fp> trust       # → Kind=0 imported
$ /tmp/daal-core --state-dir /tmp/x connect sample-route-1   # → connected
$ /tmp/daal-core --state-dir /tmp/x import valid-rotation-B  # → Kind=2 rotation accepted
$ /tmp/daal-core --state-dir /tmp/x import revoked-A         # → Kind=0; route revoked
$ /tmp/daal-core --state-dir /tmp/x connect sample-route-1   # → refused (revoked)
```

OPSEC source-grep clean: no `net/http`, `http.Get`, `http.Client`, `http.NewRequest` outside test denylists; no group-based labels in code, Kotlin sources, manifests, strings, or specs.

---

## Files added or changed

```
core/                                                  NEW Go module daal/core
core/go.mod
core/abi/{abi.go,abi_export.go,abi_gomobile.go,pending.go,abi_test.go}
core/diagnostics/{classify.go,classify_test.go}
core/engine/{config.go,config_test.go,engine.go,engine_test.go}
core/pathmanager/{fsm.go,fsm_test.go}
core/routestore/{schema.go,store.go,secrets.go,store_test.go}
core/trust/{pin.go,sha.go,state.go,helpers_test.go,importer_test.go,rotation_test.go}
core/opsec_test.go

bundle/go/importer/{importer.go,util.go}              NEW package

cmd/daal-core/{go.mod,main.go}                       NEW Linux/Windows CLI

client-android/                                       NEW Android Gradle project
client-android/{settings.gradle.kts,build.gradle.kts,gradle.properties}
client-android/app/{build.gradle.kts,proguard-rules.pro}
client-android/app/libs/README.md
client-android/app/src/main/AndroidManifest.xml
client-android/app/src/main/java/ai/daal/app/data/DaalCoreBridge.kt
client-android/app/src/main/java/ai/daal/app/vpn/DaalVpnService.kt
client-android/app/src/main/java/ai/daal/app/vm/DaalViewModel.kt
client-android/app/src/main/java/ai/daal/app/ui/MainActivity.kt
client-android/app/src/main/res/values/strings.xml
client-android/app/src/main/res/values-fa/strings.xml
client-android/app/src/main/res/xml/data_extraction_rules.xml
client-android/app/src/main/res/drawable/ic_launcher.xml

specs/engine-abi-v1.md                                NEW
specs/android-client-v1.md                            NEW
specs/trust-ui-v1.md                                  NEW
specs/routestore-v1.md                                NEW

phases of development/05-phase-1b-android-bootstrap-mvp.handover.md   THIS FILE
```

Phase 1B is ready for the Phase 1B-Polish session (real sing-box wiring + AAR build) and for Phase 1C (offline sharing) to start consuming the trust path.
