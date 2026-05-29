# Phase 45 — Data-plane & delivery: design spec for Gaps 2, 3, 4-publisher

**Status:** design spec; implementation deferred to a dedicated session whose **exit gate is real tunneled traffic on Android and desktop Linux**.
**Branch (when implementation begins):** `gap-dataplane-and-delivery`.
**Position:** slots after Phase FRP-14 (`44-phase-frp-14-pack-to-person.md`).

## Why this is a separate phase

The "tractable" gaps (5, 1, 4-recipient) were implemented in the v0.1.0 follow-up to FRP-14 and are validated by webview flow checks on device. They produce no tunneled traffic by nature.

Real tunneled traffic requires three large, interdependent pieces:

1. **Gap 2** — A real in-process sing-box `engine.Driver` behind `//go:build singbox`.
2. **Gap 3** — Android `VpnService` + a new `engine_set_tun_fd(int)` ABI so the Go engine receives the TUN fd from Kotlin.
3. **Gap 4-publisher** — A canonical Daal subscription hosting path (live `Put` on R2 / GH-Pages, a `publish-subscription` CLI subcommand, and a wizard step that emits the recipient-pasteable URL).

Each is small in isolation but their dependency graph is real: Gap 3 cannot tunnel without Gap 2's real driver consuming the fd; Gap 4-publisher cannot be validated against a live recipient until Gap 2 is feeding routes through a tunnel. Doing them as one phase with a single "traffic actually flows" exit gate is the cheapest way to ship them correctly.

## Invariants locked at the end of this phase

1. **`engine.NewDefaultDriver()` is the only constructor call site in `core/abi/abi.go`.** Build tag `singbox` selects the real driver; absent tag keeps the stub for unit tests + ABI-stability soak. Pinned by `TestDriverSelectionByBuildTag` (Go test guarded by `//go:build singbox` and its inverse twin).
2. **Append-only ABI growth.** The cshared release surface grows by exactly two symbols: `engine_set_tun_fd(int) → int` and `engine_clear_tun_fd() → int`. Total release ABI count moves from 33 → 35 (or whatever the locked baseline is at the time). Pinned by the `nm libdaalcore.so | grep -c '^[0-9a-f]\+ T engine_'` CI gate.
3. **`engine_set_tun_fd` takes ownership of the fd.** After a successful call the caller MUST NOT `close(fd)`. The engine closes it on `engine_clear_tun_fd` or `engine_shutdown`. Pinned by `TestSetTunFdOwnershipSemantics` (mock Driver + sentinel close).
4. **Android `VpnService.protect()` is reachable from Go.** A C callback registered via a new `engine_register_protect_callback(extern "C" fn(int)→int)` (one additional symbol if needed; otherwise routed through the existing JNI bridge) excludes the engine's own upstream sockets from the TUN. Pinned by integration test (Android instrumented).
5. **`libsing_box.so` is removed.** The 58 MB dead artifact at `client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libsing_box.so` is deleted; only `libdaalcore.so` + `libdaal_desktop_tauri_lib.so` ship in jniLibs after this phase. Pinned by APK-bom assertion in CI (or a `find ... | grep -v allowlist` shell guard).
6. **Desktop traffic actually flows through sing-box.** The route → outbound translation in `daal-desktop-core/src/commands.rs::connect` (the TODO at the existing line ~94) is finished: on `connect(route_id)`, the GUI does `Engine::set_route(route_id)` AND PUTs the resolved outbound block to the sidecar via Clash REST. Pinned by `TestDesktopConnectTunnelsThroughSingbox` (real outbound, real TCP probe).
7. **Per-recipient subscription hosting is live.** `daal-deploy publish-subscription` performs an actual R2 / GH-Pages PUT, returns a recipient-pasteable URL, and the recipient app's paste flow refreshes against that URL on its scheduler tick. Pinned by `mission/gap-dataplane-publish-subscription.sh`.

## Architecture

```mermaid
flowchart TD
  UI[client-ui React<br/>paste URL / connect] --> Bridge[Tauri Rust shell]
  Bridge -->|dlopen| Core[libdaalcore.so]
  Core --> Sel{NewDefaultDriver<br/>build tag?}
  Sel -- "stub<br/>(unit tests)" --> Stub[engine.Stub]
  Sel -- "singbox<br/>(release)" --> SBLib[engine.SingBox<br/>libbox in-proc]
  SBLib -.TUN fd.-> AVPN[Android VpnService<br/>Builder.establish→fd<br/>engine_set_tun_fd]
  SBLib -.Linux tun-helper.-> LXTUN[/dev/net/tun via SCM_RIGHTS<br/>daal-tun-helper]
  SBLib --> Net((Internet))

  Pub[Publisher Wizard] --> CLI[daal-deploy<br/>publish-subscription]
  CLI -->|R2 / GH-Pages PUT| Host[(hosted subscription body<br/>URI-list / SIP008 / Clash)]
  Recipient[Recipient AddSheet] --> Engine2[engine_subscription_add]
  Engine2 -.scheduler tick.-> Host
```

## Deliverables

### Spec docs (this file is one of them)

- THIS doc — `development-phases/45-gap-dataplane-and-delivery.md`.
- NEW `specs/engine-driver-v1.md` — locks the `engine.Driver` interface contract for real-driver implementers (Events, hour-buckets, UDP gating, Stats redaction).
- NEW `specs/tun-fd-handoff-v1.md` — locks `engine_set_tun_fd` semantics + ownership + `protect()` callback.
- UPDATE `specs/android-client-v1.md` — replaces the gomobile-AAR section with the in-process `libdaalcore.so` + VpnService + Tauri mobile plugin model.
- UPDATE `specs/tunnel-dialer-v1.md` — close out the §"Future work (1.5C)" item: Android now uses the engine driver directly, not a SOCKS5 inlet.
- NEW `specs/subscription-host-v1.md` — canonical wire format Daal hosts (URI-list); rotation rules; signing requirement (TBD).

### Code packages

- NEW `core/engine/engine_default.go` (`//go:build !singbox`) and `core/engine/engine_singbox.go` (`//go:build singbox`). Each defines `NewDefaultDriver()`; the singbox file additionally defines the real `SingBox` struct implementing `engine.Driver`.
- UPDATE `core/abi/abi.go:214` — one-line change: `engine.NewStub()` → `engine.NewDefaultDriver()`.
- NEW `core/abi/tun_fd.go` + `core/abi/tun_fd_export.go` (cshared) + `core/abi/tun_fd_gomobile.go` (parity) — `SetTunFD(int) error`, `ClearTunFD() error`.
- UPDATE `core/go.mod` — add `github.com/sagernet/sing-box` (trimmed via per-family tags); `core/go.sum` regenerated.
- UPDATE `tools/build-engine-android.sh` — append `,singbox` to `-tags`; the unit-test build script stays at `cshared` only.
- UPDATE `tools/build-engine-ios.sh` — same `-tags cshared,singbox`.
- NEW `tools/build-aar.sh` — `gomobile bind -target=android -tags gomobile,singbox ./abi` (optional; only if a non-Tauri Android host is ever needed).
- NEW Tauri mobile plugin `client-shell/tauri/plugins/daal-platform/`:
  - `Cargo.toml` (depends on `tauri`, mobile features).
  - `src/lib.rs` — plugin init + `#[tauri::command] connect_vpn(route_id)` and `disconnect_vpn()` (Android branch starts/stops `DaalVpnService`; desktop branch is a no-op since data plane is already in-process).
  - `android/build.gradle.kts`.
  - `android/src/main/AndroidManifest.xml` — `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` (SDK 34+), `POST_NOTIFICATIONS` (SDK 33+ runtime); `<service android:name="org.daal.desktop.vpn.DaalVpnService" android:permission="android.permission.BIND_VPN_SERVICE" android:foregroundServiceType="specialUse" android:exported="false"><property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="vpn"/><intent-filter><action android:name="android.net.VpnService"/></intent-filter></service>`.
  - `android/src/main/kotlin/org/daal/desktop/vpn/DaalVpnService.kt` — rewritten from the legacy stub. `connect(routeId)`: `Builder.establish()` → `pfd.detachFd()` → JNI into the Tauri plugin Rust → `engine_set_tun_fd(fd)` → `engine_set_route(routeId)`.
- UPDATE `client-shell/tauri/src-tauri/src/lib.rs` — register the plugin; route the Tauri `connect` command's Android branch through `connect_vpn`.
- UPDATE `client-shell/tauri/daal-desktop-core/src/commands.rs::connect` — finish the route→outbound translation: read the route's outbound profile (already in `core/abi`), PUT it to sing-box via Clash REST API.
- DELETE `client-shell/tauri/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libsing_box.so` (and its build/intermediates copies). It is a dead 58 MB artifact (only `main.main`, zero references).
- UPDATE `client-shell/tauri/plugins/daal-platform/README.md` — flip "Source preservation only" to "Active plugin".
- NEW publisher subcommand `cmd/daal-deploy publish-subscription` — wraps the FRP-14 per-recipient creds into a URI-list body and PUTs to R2 / GH-Pages via the existing `publisher/deploy/freshness/backends/{r2,ghpages}/` clients (currently stubbed for freshness; the implementations are real, only the freshness CLI's wiring is missing).
- UPDATE `publisher/deploy/cli/cli.go` — close out the `freshness.ErrBackendNotImplemented` stubs at lines ~1015-1019 and ~1119-1124 so `publish-freshness` and `publish-subscription` both PUT live.
- UPDATE `client-shell/tauri/daal-wizard/src/cli_bridge.rs` — add `run_publish_subscription(args)`; the wizard's Step 7 (or the new Recipients page) gets a "Publish to URL" button per recipient.

### CI gates

- `mission/gap-dataplane-driver-selection.sh` — builds with and without `-tags singbox`, verifies the right driver was linked (sentinel symbol + smoke run).
- `mission/gap-dataplane-android-tunnel.sh` — Android instrumented test: install APK, accept VpnService prompt, import a real `.sbpx` for a sandbox relay, connect, curl `https://api.daal.test/echo` through the tunnel, assert the response carries the relay's egress IP.
- `mission/gap-dataplane-desktop-tunnel.sh` — Linux desktop equivalent: launch GUI headless, connect, probe egress.
- `mission/gap-dataplane-publish-subscription.sh` — publisher publishes a subscription URL via R2, recipient pastes it, scheduler tick imports routes, end-to-end works.

## Carry-overs / risks

- **APK size.** sing-box's transitive graph (sing-quic, sing-mux, sing-shadowtls, sing-tun, quic-go, gvisor, cloudflare/circl) can easily push libdaalcore.so past 50 MB per ABI. Mitigation: trim sing-box itself with its per-family tags (`with_wireguard`, `with_quic`, `with_acme`, etc.); strip release `.so`s; gzip the `.aab` upload. APK size budget: ≤ 60 MB per-ABI; ≤ 200 MB universal.
- **CGO cross-compile.** sing-box's TUN code (sing-tun) uses gvisor for userspace netstack and needs cgo for several transports. Already on cgo on Android; budget +30s build time per ABI.
- **`protect()` semantics.** If sing-box opens upstream sockets in-engine, Android needs each socket excluded from the TUN. The cleanest path is a registered JNI callback (`engine_register_protect_callback`); the alternative is the engine refuses to open sockets and demands the host pre-create them, which is the Tailscale approach and harder to retrofit.
- **In-process vs sidecar on Android.** This phase commits to **in-process** (Gap 2 chosen "In-process Go library behind `//go:build singbox`"). Sidecar option (mirror desktop) explicitly rejected to avoid the extra IPC layer on mobile.
- **Subscription signing.** Open question for `specs/subscription-host-v1.md`: should the hosted body be signed by the publisher root key (so the recipient verifies before importing) or stay unsigned (current engine wraps with a local synthetic .sbp signed by the device delegate key). Decision deferred to the spec doc; the engine-side wrap path works either way.

## Phase exit checklist

- [ ] All spec docs landed and locked.
- [ ] `libdaalcore.so` built with `-tags singbox` for all 4 Android ABIs + desktop targets.
- [ ] `nm libdaalcore.so | grep ' T engine_' | wc -l` = 35 (or the new baseline).
- [ ] APK installs cleanly on the test device (192.168.0.172:46529 or successor).
- [ ] VpnService prompt appears on first connect; user accepts; the persistent foreground notification renders.
- [ ] `curl --interface tun0 https://api.daal.test/echo` returns the relay's egress IP (Android instrumented test).
- [ ] Linux desktop equivalent passes.
- [ ] Publisher publishes a subscription URL via R2; recipient pastes it; routes appear in the routestore; scheduler tick rotates the body 24 h later (or whatever `profile_update_min` is set to).
- [ ] `libsing_box.so` deleted; APK shrinks by ~58 MB.
- [ ] Handover doc written.
