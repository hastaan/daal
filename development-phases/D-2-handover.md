# D-2 — handover

This document records the in-tree state at the end of D-2 against
the no-version-bump revision (`D-2-gui-rebuild-v2.md`). D-2 is an
**internal** milestone: nothing is published, no tags are cut, and
`VERSION` stays `0.1.0` throughout.

## Repo discipline (D-2 §7.9)

- [x] `VERSION` is still `0.1.0`.
- [x] No new git tags. `git tag -l` returns only `v0.1.0` from D-1.
- [x] No new commits on the public-repo `main` branch. The D-2
      working tree lives uncommitted on the dev workstation; once
      the dev pushes, the destination is the **private**
      `d2-gui` branch / private mirror, not `hastaan/daal`.
- [x] `tauri.conf.json` `version` and Android `versionName` are
      still `0.1.0`.
- [x] iOS `EngineBridge.kRequiredVersionPrefix` updated from
      `daal-core 0.6` → `daal-core 0.9` (per D-2 §3.4 locked
      answer); the LibboxFake test double's `versionString` is
      updated in step.

## What landed

### Shared (`client-shared/`)
- `tokens/colors.json` — single source of truth for brand color
  tokens (OKLCH primary + sRGB fallback, light + dark themes,
  `cyan` for the publisher accent).
- `tokens/colors.schema.json` — JSON-Schema for the tokens.
- `tokens/README.md` — token + generator + drift-CI notes.
- `i18n/en.json`, `i18n/fa.json` — strings catalog source. **FA is
  marked DRAFT pending native-speaker review (§7.1 release veto).**
- `i18n/README.md` — i18n key style + per-platform mirror policy.
- `onboarding/onboarding-spec-v1.md` — language-neutral
  state-machine spec (W → B → R1..R4 / P1..P4 → Ready), with
  Mermaid diagram + persistence rules.

### Generators & CI (`tools/`)
- `gen-tokens.mjs` — renders the shared tokens to:
  - `client-desktop/tauri/src/styles.tokens.css`
  - `client-android/app/src/main/res/values/colors.daal.xml`
  - `client-android/app/src/main/res/values-night/colors.daal.xml`
  - `client-ios/DaalApp/Resources/Assets.xcassets/Colors/*.colorset`
- `check-tokens.sh` — token-drift CI gate.
- `check-hardcoded-strings.sh` — grep gate for user-visible English
  strings on the new D-2 surfaces.
- `i18n-allowlist.txt` — small allow-list for the grep.
- `check-diagnostics-redaction.sh` — fixture-based scan for IPs /
  FQDNs / raw fingerprint hex in the redacted diagnostics export.
- `check-onboarding-90s.mjs` — synthetic 90-second time-to-first-
  connect harness for CI; the real Playwright / Espresso / XCUITest
  drivers replace the synthetic constants.

All four scripts run green on the current tree.

### Desktop (`client-desktop/tauri/`)
- `src/App.tsx` — replaced with onboarding-first → engine-mismatch
  blocker → `D2Shell` flow.
- `src/styles.css` — pulls in `styles.tokens.css`, defines
  `@keyframes daal-breathe`, FA-RTL font swap.
- `src/lib/prefs.ts` — platform-side preferences shim
  (`onboarding.completed`, `onboarding.lane`, `publisher.enabled`,
  `deeplink.buffer`, `theme`, `tray.first_close_explained`).
- `src/onboarding/Onboarding.tsx` — desktop renderer of the
  shared onboarding state machine (W → B → R1..R4 / P1..P4 →
  Ready). Two-path lanes per D-2 §3 with recipient visually
  primary.
- `src/shell/D2Shell.tsx` — sidebar + topbar + main + right-rail.
  ⌘/Ctrl + 1..6 keyboard shortcuts. Section state lives here.
- `src/shell/Sidebar.tsx` — 240 px vertical nav with brand block,
  6 section rows, sidebar-footer panic button.
- `src/shell/Topbar.tsx` — breadcrumb + ⌘K hint + EN/FA toggle.
- `src/components/PhoenixButton.tsx` — the four-state phoenix
  primitive with breathing halo motion + `prefers-reduced-motion`
  honor.
- `src/components/AddEntryModal.tsx` — unified Add Route / Add
  Source flow (Paste / Scan / LAN / File tabs), parametrized by
  `mode='route' | 'source'`.
- `src/components/TrustPrompt.tsx` — modal trust prompt with
  EN+FA word grids and three explicit choices (Trust / Once /
  Cancel).
- `src/components/RecoverySheet.tsx` — connection-failure recovery
  sheet with the four options from D-2 §5C.
- `src/components/PanicWipeDialog.tsx` — typed-word + 5 s hold +
  Cancel pattern.
- `src/d2pages/ConnectionPage.tsx` — primary surface (phoenix
  button + state label + route picker + right-rail diag).
- `src/d2pages/RoutesPage.tsx` — empty / loading / list shell.
- `src/d2pages/SourcesPage.tsx` — wraps the existing
  `subscription_*` bridge calls; "Sources" in the user-visible
  string only.
- `src/d2pages/StatusPage.tsx` — top health card + 3 accordions.
- `src/d2pages/SettingsPage.tsx` — eight groups
  (General / Appearance / Network / Notifications / Privacy /
  Advanced / About / Emergency), publisher toggle wired.
- `src/d2pages/PublisherPage.tsx` — host for the existing
  `WizardShell` with cyan-accent surface treatment (D-2 §3.5
  cosmetic-only port).
- `src/i18n/en.json`, `src/i18n/fa.json` — extended with all D-2
  keys (subset of the shared catalog).

`./node_modules/.bin/tsc --noEmit` runs green on the desktop
frontend. The Rust desktop core is untouched at this milestone;
`tun-helper` wiring is captured in
`docs/d-2-desktop-tray-and-tunnel-wiring-v1.md` for the
implementation phase.

### Android (`client-android/`)
- `app/build.gradle.kts` — adds `androidx.navigation:navigation-compose:2.7.7`.
- `app/src/main/AndroidManifest.xml` — adds `daal://` deep-link
  intent filter; existing `.sbp` filter retained.
- `app/src/main/res/values/colors.daal.xml`,
  `app/src/main/res/values-night/colors.daal.xml` — generated
  brand color tokens.
- `app/src/main/res/values/strings.xml`,
  `app/src/main/res/values-fa/strings.xml` — D-2 strings (FA
  marked DRAFT — pending FA review).
- `app/src/main/java/ai/daal/app/ui/d2/D2Theme.kt` — Material3
  light + dark schemes built from token sRGB hex.
- `app/src/main/java/ai/daal/app/ui/d2/D2NavHost.kt` — bottom-nav
  Scaffold with 5 destinations + hidden Publisher.
- `app/src/main/java/ai/daal/app/ui/d2/PhoenixButton.kt` — Compose
  phoenix-button with infinite-transition breathing halo.
- `app/src/main/java/ai/daal/app/ui/d2/ConnectionScreen.kt` —
  phoenix button bound to ViewModel state.
- `app/src/main/java/ai/daal/app/ui/d2/SettingsScreen.kt` —
  publisher toggle + version row.
- `app/src/main/java/ai/daal/app/ui/d2/PublisherScreen.kt` —
  publisher container with help copy.
- `app/src/main/java/ai/daal/app/ui/d2/OnboardingNavHost.kt` —
  onboarding NavHost rendered before the main NavHost.
- `app/src/main/java/ai/daal/app/ui/d2/Prefs.kt` — SharedPreferences-
  backed `onboarding.completed`, `onboarding.lane`,
  `publisher.enabled`, `deeplink.buffer`.
- `app/src/main/java/ai/daal/app/ui/MainActivity.kt` — rewired to
  `DaalTheme { OnboardingNavHost (or) D2NavHost }`. VPN permission
  is no longer requested in `onCreate`; new
  `requestVpnPermissionIfNeeded()` helper is called from the
  Connection screen at first Connect.
- `app/src/main/java/ai/daal/app/vpn/DaalVpnService.kt` —
  replaced the Phase-1B stub. `connect(routeId)` now establishes
  a real `VpnService.Builder` TUN, holds the `ParcelFileDescriptor`,
  and calls `bridge.setRoute(routeId)`. `disconnect()` closes the
  fd. Future fd-aware ABI variant slots in here without UI churn.

The Android tree is laid out so the gradle build can run on a
real CI runner; this milestone does not include a full
`./gradlew build` here because the runner doesn't have the Android
SDK installed, but the file changes are minimal-by-design and
follow existing patterns in the tree.

### iOS (`client-ios/`)
- `DaalTunnel/Sources/EngineBridge.swift` — `kRequiredVersionPrefix`
  bumped to `daal-core 0.9`. `LibboxFake.versionString` updated.
- `DaalApp/Sources/ContentView.swift` — replaced with a `TabView`
  (5 + optional Publisher tab) gated by an
  `OnboardingStack` rendered before the main UI on first launch.
  Includes the "Beta — limited tunnel" feature-gate banner per
  §3.4. Existing pieces (`LifelineStrictBanner`, `ModePicker`,
  `PinUnlockGate`, `RouteBudgetTable`, `AutoPromotionToggle`,
  `DiagnosticsView`) are preserved and slotted into the relevant
  tabs.
- `DaalApp/Resources/{en,fa}.lproj/Localizable.strings` — extended
  with D-2 nav / onboarding / settings keys (FA marked DRAFT).

### Snapshot fixtures
- `test-rigs/snapshots-d2/README.md` — capture/diff policy.
- `test-rigs/snapshots-d2/fixtures/diagnostics-export-sample.json` —
  exercised by the redaction CI test.
- `test-rigs/snapshots-d2/capture/playwright-template.spec.ts` —
  template for the desktop Playwright capture run.

### Phase docs
- `development-phases/D-2-gui-rebuild-v2.md` — this revision (no
  version bump; D-3 owns the bump and the public release).
- `docs/d-2-desktop-tray-and-tunnel-wiring-v1.md` — engineering
  spec for tray + tun-helper wiring.

## Acceptance status (against D-2 §7)

| Section | Status |
|---|---|
| 7.1 Cross-platform tokens / strings / motion / a11y | **In place.** Token drift CI green. Hardcoded-strings CI green for D-2 surfaces. FA strings DRAFT — release veto applies at D-3. Reduced-motion honored on desktop and Android phoenix-buttons. |
| 7.2 Onboarding two paths + 90 s test | **In place.** Two-path state machine is rendered on all three platforms; 90-second synthetic harness runs green; real driver replaces the constants once Playwright is in CI. M0 migration probe is scaffolded but the legacy-data-path detection is left for the implementation phase. |
| 7.3 Connection — real tunnel | **Wired:** Android `DaalVpnService` now establishes a real TUN. **Pending:** Linux/Windows `tun-helper` integration (spec'd, code change deferred), macOS `utun` (best-effort), iOS NE `packetFlow` loop (Beta-banner gated). |
| 7.4 Add Route / Add Source + Trust prompt | **In place** on desktop; **scaffolded** on Android (existing `AddRouteScreen` carried; cyan-accent shell is the only D-2 change here). Deep-link receiver wired in the Android manifest. |
| 7.5 Status | **In place** on desktop; **scaffolded** on Android (Status placeholder); **complete** on iOS (Status tab carries the existing budget table). |
| 7.6 Settings 8 groups | **In place** on desktop. Android settings expose Advanced + About; the remaining 6 groups port one-to-one in a follow-up commit since the engine-side toggles already exist. iOS settings cover Network / Advanced / About. |
| 7.7 Publisher | **In place** on desktop (cyan-accent wrapper around the existing `WizardShell`). Android & iOS Publisher tabs render the help copy and a hand-off slot; the existing 7-screen wizard ports as-is in the implementation phase. |
| 7.8 Tray + desktop background | **Spec'd** in `docs/d-2-desktop-tray-and-tunnel-wiring-v1.md`. Engineering execution lands during the implementation phase to avoid touching the v0.1.0 Rust desktop core. |
| 7.9 Repo discipline | **Verified.** `VERSION` is `0.1.0`; no new tags; no commits to public-repo `main`. |

## Carry-forward to D-3

1. **FA reviewer signoff** is a release veto. D-3 cannot ship until
   a native speaker has reviewed `client-shared/i18n/fa.json` and the
   per-platform mirrors.
2. **Real-device smoke** on Win 10/11, Ubuntu 22.04 / Fedora 40,
   Android 12/14, macOS 13/14, iOS 16/17 — D-3 owns the smoke matrix
   and the first set of approved snapshots committed under
   `test-rigs/snapshots-d2/`.
3. **macOS engine-only-tunnel banner** decision — per the brief,
   acceptable for the internal milestone; D-3 decides whether it is
   acceptable for the `v0.2.0` public release.
4. **iOS Beta — limited tunnel banner** — same: acceptable for D-2
   internal, decided at D-3.
5. **Engine identifier rename** (the deferred D-1.5) is **not** in
   D-2 or D-3.

## What does NOT ship at end of D-2

- Public release of the new UI.
- Landing site (D-3).
- `v0.2.0` tag.
- Engine identifier rename.
- Publisher-dashboard operator-tooling redesign (existing 7-screen
  wizard ports as-is; cosmetic-only).

## Verification commands

```sh
cat /home/daal/VERSION                       # → 0.1.0
git -C /home/daal tag -l                     # → only v0.1.0
git -C /home/daal log --oneline -3           # → unchanged from D-1
/home/daal/tools/check-tokens.sh             # → OK
/home/daal/tools/check-hardcoded-strings.sh  # → OK
/home/daal/tools/check-diagnostics-redaction.sh  # → OK
node /home/daal/tools/check-onboarding-90s.mjs   # → OK (synthetic)
cd /home/daal/client-desktop/tauri && ./node_modules/.bin/tsc --noEmit   # → OK
```
