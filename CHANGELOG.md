# Changelog

All notable changes to Daal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions in this file refer to the user-visible app version recorded in
`VERSION`. The engine ABI version (`daal-core 0.9.0+v3-share`), SBP
spec version (`4`), and ABI symbol count (`58`) are independent — see
`docs/build-and-release.md` for the versioning matrix.

## [0.2.0] — unreleased

Everything since the v0.1.0 tag (2026-05-29). Phase 45 and the FRP-14
publisher track shipped under the `[0.1.0] — unreleased` heading for three
months; this section exists so the smart-route-selection work lands somewhere
that is already true.

### Engine / data plane

- In-process sing-box driver (`-tags singbox`) replaces the spawned sidecar on
  Android; the engine now runs inside the app process behind `VpnService` with
  a gvisor TUN. Desktop still uses the sidecar — see phase 45 Part 4.
- All four transports verified end to end on device against a live relay:
  vless-reality, websocket-tls, naive (Cronet) and hysteria2.
- `addDisallowedApplication(self)` keeps the engine's own sockets out of the
  tunnel, fixing "no available network interface" on every outbound dial.
- ABI grew 48 → 58 exported `engine_` symbols (append-only; see
  `specs/engine-abi-v1.md`).

### Relay

- Canonical `relayports` family→port map, shared by the box config, the
  firewall and the client, replacing three separate hardcodings of 443.
- One shared `ws-in` inbound for all recipients. Per-user WS inbounds all bound
  the same port, so a relay crashed the moment it had a second recipient.
- Real teardown: "delete the server too" removes the server, its ephemeral SSH
  key and its firewall, and provisioning now rolls back on failure. A failed
  provision used to leave a billing server and an SSH key that permanently
  wedged every retry.
- `/whoami` on the mgmt plane (endpoint only; no client leg yet).

### Publisher

- The 6-digit PIN is gone. The signing key and cloud token move to
  hardware-backed device custody (AndroidKeyStore / OS keystore), which on
  Android is strictly stronger than what it replaced.
- Setup collapsed from 7 steps to 3, and the "distribute" step and the
  SETUP/RECIPIENTS tab split were removed in favour of a relay list whose
  detail view lists that relay's artifacts.
- Per-recipient credentials (FRP-14 Tier-2): `.sbp`/`.sbpx` now carry real,
  connectable client outbounds instead of metadata stubs.

### Fixed

- `core/scheduler` raced on `Stop()`; `cmd/daal-core` and `cmd/daal-soak-engine`
  could not build at all; `go vet` was red in four modules.
- `tools/check-hardcoded-strings.sh` reported OK while never running.
- The engine library, the soak binaries and `daal-core` are no longer tracked
  in git — see `client-shell/tauri/src-tauri/resources/README.md`.

## [0.1.0] — 2026-05-29

Development phase. **Unified-client architecture** plus **Tauri Mobile
Android + iOS bundles** rolled together. The same React/TS UI and
Rust+Go engine that ship to desktop also build into a signed Android
APK and an iOS .ipa, with no separate native UI codebase.

### Unified client

- One UI: `client-ui/` is a Vite + React app, browser-first, with a
  full dev harness (every screen reachable via `?harness=<scenario>`)
  and an ImageMagick montage capture pipeline for visual review.
- One shell: `client-shell/tauri/` hosts the Tauri 2 binary for
  desktop and is the build target for Tauri Mobile Android / iOS.
  Native VPN / NetworkExtension sources are preserved under
  `client-shell/tauri/plugins/daal-platform/` for the mobile binary.
- Backend-agnostic contract: every screen reads its data through a
  `D2Contract` interface with two backends (`tauri`, `harness`); the
  legacy `lib/bridge.ts` is now an implementation detail.
- Mobile-first redesign across the React app: density-aware shell
  router (Desktop / Tablet / Mobile), 27 design-system primitives in
  `client-ui/src/design/primitives/`, oklch token system in
  `tokens.css`, and screen-by-screen clarity passes for Connection,
  Network, Status, Settings, Publisher, and Onboarding. (The shipped
  nav is 5 sections — Connection / Network / Status / Publisher /
  Settings, per `shell/TabletShell.tsx:33-52`, Publisher being
  opt-in. "Routes" became the Network page; "Sources" is not a screen
  at all — it is the Subscriptions panel, and the user-facing label
  reverted from "Sources" to "Subscriptions".)
- Settings is one centred column with a sticky chip rail that jumps
  to grouped cards; all `<select>` controls are replaced by the
  `Segmented` primitive; About lives in a brand card with the
  locale-aware `Daal / دال` mark.

### Mobile bundles

- Android: signed `.apk` for arm64-v8a, armeabi-v7a, x86_64
  (per-ABI splits). Each APK is **~14 MB** thanks to R8 shrink +
  `assets/resources/libdaalcore.so` strip (Tauri's `bundle.resources`
  duplicates the engine on Android, wasted ~15 MB) + native-lib ZIP
  compression. The universal APK is no longer shipped — at 100 MB
  with all ABIs it was 7× the per-ABI size for no benefit.
- iOS: unsigned `.ipa` distributed as `Daal_<version>_unsigned.ipa`.
  Install by dragging the IPA into [Sideloadly](https://sideloadly.io/)
  (free, macOS or Windows) and signing it locally with your own free
  Apple ID. Sideloadly handles the 7-day Personal Team cert refresh.
  Signed App Store / Ad-Hoc distribution will follow once an Apple
  Developer account is provisioned.
- New `tools/build-engine-android.sh` cross-compiles `libdaalcore.so`
  against the Android NDK for all three target ABIs (API 24 = Android 7.0).
- New `tools/build-engine-ios.sh` cross-compiles `libdaalcore.dylib`
  for iOS via Go `c-archive` → `clang -shared -all_load` (Go forbids
  `-buildmode=c-shared` on iOS).
- `tauri::mobile_entry_point` annotation on `daal-desktop-tauri::run`
  gives Tauri the JNI / Swift bridge entry without affecting desktop.
- Engine library is loaded by short name on mobile (Android's `dlopen`
  resolves against the auto-extracted nativeLibraryDir; iOS uses
  `@rpath` → `@executable_path/Frameworks`).

### Full plumbing pass

- Every `engine_*` ABI export (58 release symbols) now reaches the
  React UI through a typed three-layer path:
  `Engine ABI → daal-desktop-core/{engine.rs,commands.rs} → #[tauri::command] → D2Contract → screen`.
- 113 Tauri commands declared, registered, and invoked from the
  client — including `apply_cooldown`, `lifecycle_event`,
  `probe_udp/dns/tcp443`, `scheduler_status`, `stats_redacted`,
  `redistribute_route`, `set_route_budget`,
  `set_{rendezvous_priority,push_rendezvous_enabled,auto_promotion,masque_submode_override,experimental_families_enabled}`,
  `bootstrap_{install_seeds,refresh,status}`, `uri_detect`,
  `uri_import`, `loaded_wasm_modules`, `wasm_kill_switch_pubkey`,
  plus 22 `wizard_*` commands and 5 `recipient_qr_*` commands.
- New UI surfaces: the **Network** page lists live routes with per-row
  Connect / Cooldown / Data-cap / Redistribute actions (it was called
  "Routes" during the redesign; the shipped page is
  `client-ui/src/d2pages/NetworkPage.tsx`); Diagnostics
  exposes a 6-tile dashboard with sparkline plus Network test,
  Scheduler, Stats (redacted), and Bootstrap accordions; Settings
  exposes auto-promotion / push rendezvous / experimental families /
  MASQUE submode toggles + loaded WASM module list + WASM kill-switch
  pubkey; Connection page shows live throughput when connected.
- Vault-locked PIN entry screen wired to `engine_unlock_secrets`.
- Lifecycle + network change emitters wired to the engine via the
  browser's `visibilitychange` + `online`/`offline` events.
- Publisher (FRP-5) full rebuild — `PublisherWizard` runs all 22
  `wizard_*` Tauri commands across 7 named steps with a status side
  rail, cloud-provider grid (Hetzner / Vultr / DigitalOcean / Linode /
  custom), live pricing card, fingerprint card, and harness-mode
  fake-progress flows; streams `wizard://*` event channels.
- Recipient (FRP-6) QR fountain — `RecipientImport` runs all 5
  `recipient_qr_*` commands with three input modes (camera /
  clipboard / file).
- `tools/check-plumbing.mjs` enforces three-layer coverage and runs
  in CI; the plumbing pass reports zero gaps.

### Internationalisation

- Persian translations cover every reachable client surface —
  Settings, Status/Diagnostics, Connection, Network, Subscriptions,
  Publisher wizard, and onboarding — with 408 keys per locale in
  `client-ui/src/i18n/{en,fa}.json`. Only 22 entries are
  deliberately identical across locales (brand names, protocol
  IDs, region slugs, EN: / FA: line prefixes).
- `tools/check-hardcoded-strings.sh` reports zero hard-coded
  user-visible strings on the D-2 surfaces. **It is not run by any
  CI**: `appveyor.yml` is packaging-only and contains no test or gate
  step, and there is no `.github/workflows/`. Run it by hand (it needs
  ripgrep installed, and now exits 2 rather than passing silently if
  ripgrep is missing).

### Brand

- Canonical brand assets reduced to **3 files** under
  `client-shared/branding/sources/`: the SVG master, a transparent
  PNG, and an on-white PNG. `tools/gen-assets.sh` derives every
  platform target (Windows `.ico`, macOS `.icns`, iOS AppIcon set,
  Android adaptive + legacy mipmaps, web favicons) from those three.
- Android adaptive icon: background is now white (was teal), and
  foreground is padded to the 66% safe zone so launcher masks
  (squircle, circle, teardrop) never clip the eagle.
- Connection page: the placeholder shield SVG was removed; the
  Connect button is now a single eagle PNG that fades and pulses
  via CSS for the disconnected / connecting / connected / error
  states. Respects `prefers-reduced-motion`.

### CI

- AppVeyor free OSS plan handles Windows / macOS / iOS bundles
  (one concurrent vCPU job, ~25 min per platform). Linux + Android
  build locally on the dev workstation. GitHub Actions is no longer
  used — the account was rate-throttled by earlier runs.
- `tools/preflight-appveyor.py` runs 26 static checks against
  `appveyor.yml` before every push.

### Landing

- `landing/` is a Vite + React site published to
  https://hastaan.github.io/daal/ via the `gh-pages` branch.
- Download-card sizes are now resolved at **build time** by
  `vite.config.ts`: it reads from the local `dist-release/v<X>/`
  folder first (Linux + Android), then falls back to
  `gh release view v<X>` (Windows + macOS + iOS). The page itself
  never reaches a GitHub API at runtime — important because those
  endpoints are blocked in some of the network environments Daal
  targets.
