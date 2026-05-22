# Changelog

All notable changes to Daal will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions in this file refer to the user-visible app version recorded in
`VERSION`. The engine ABI version (`daal-core 0.9.0+v3-share`), SBP
spec version (`4`), and ABI symbol count (`52`) are independent — see
`docs/build-and-release.md` for the versioning matrix.

## [0.1.0] — unreleased

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
  Routes, Sources, Diagnostics, Settings, Publisher, and Onboarding.
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

- Every `engine_*` ABI export (55 release symbols) now reaches the
  React UI through a typed three-layer path:
  `Engine ABI → daal-desktop-core/{engine.rs,commands.rs} → #[tauri::command] → D2Contract → screen`.
- 73 Tauri commands declared, registered, and invoked from the
  client — including `apply_cooldown`, `lifecycle_event`,
  `probe_udp/dns/tcp443`, `scheduler_status`, `stats_redacted`,
  `redistribute_route`, `set_route_budget`,
  `set_{rendezvous_priority,push_rendezvous_enabled,auto_promotion,masque_submode_override,experimental_families_enabled}`,
  `bootstrap_{install_seeds,refresh,status}`, `uri_detect`,
  `uri_import`, `loaded_wasm_modules`, `wasm_kill_switch_pubkey`,
  plus 22 `wizard_*` commands and 5 `recipient_qr_*` commands.
- New UI surfaces: Routes page lists live routes with per-row
  Connect / Cooldown / Data-cap / Redistribute actions; Diagnostics
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
  Settings, Diagnostics, Connection, Routes, Sources, Publisher
  wizard, and onboarding — with 370 keys per locale in
  `client-ui/src/i18n/{en,fa}.json`. Only 22 entries are
  deliberately identical across locales (brand names, protocol
  IDs, region slugs, EN: / FA: line prefixes).
- `tools/check-hardcoded-strings.sh` runs in CI; the D-2 surfaces
  report zero hard-coded user-visible strings.

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
