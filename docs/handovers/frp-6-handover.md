# FRP-6 — Recipient UX + Product Readiness — Handover

**Status: SHIPPED 2026-05-03**

FRP-6 makes the recipient client (Android + Desktop) a thin renderer of
the FRP-3 `Explanation` struct. The 7 deterministic goldens at
`specs/test-vectors/explanation/` are the cross-language reference
fixtures both Kotlin and TypeScript renderers bind against. iOS
receives a single-line placeholder per supplement §21.5.

## Position B preserved

Two new OPSEC test files (Android `OPSecTest.kt` + Tauri
`recipient_opsec_test.rs`) sweep the new sources for analytics-vendor
symbols (`firebase|crashlytics|sentry|amplitude|mixpanel|google-analytics|datadog|newrelic`)
and outbound-network symbols (`std::net::TcpStream`, `reqwest::`,
`hyper::client`, `surf::`, `ureq::`, `tokio::net::TcpStream`,
`okhttp3`, `retrofit2`, `io.ktor.client`). Both stay green.

## Engine ABI

Untouched at 48. FRP-6 is a UI-side phase; the engine / daal-core has
no new FRP-6 release symbols. The existing `engine_diagnostics_explain`
payload now includes the FRP-3 `Explanation` keys (`pick`, `shortlist`,
`active_cooldowns`, etc.) while preserving the legacy `WhyExplain`
fields for older renderers.

## Commits

| # | SHA | Subject |
|---|-----|---------|
| 1 | 7e6f915 | spec amend + Kotlin Explanation + 7-golden round-trip |
| 2 | 570a7c3 | RouteHealthBanner + lifecycle-scoped polling |
| 3 | ffc867b | WhyThisRouteScreen v2 + RelayPackInfoSheet + EN/FA copy |
| 4 | 86328ab | AddRouteScreen QR tab live + OPSecTest analytics grep |
| 5 | 0ae73fe | Tauri recipient_* command set + opsec + TS Explanation |
| 6 | e7db5ad | desktop recipient screens + i18n + goldens fixture |
| 7 | (this commit) | iOS placeholder + handover + status flips |

## Android screens enumerated

1. **HomeScreen** (`ui/MainActivity.kt`) — mounts `RouteHealthBanner`
   above the existing Connect/Disconnect controls. Lifecycle-scoped
   `Explanation` polling at 500 ms; pauses on `ON_PAUSE` for zero
   background CPU.
2. **WhyThisRouteScreen v2** (`ui/WhyThisRouteScreen.kt`) — renders
   the full FRP-3 `Explanation` per phase doc §5.2: Picked / Race
   order / Failures / Active cooldowns / Recent network signals /
   Memory hint / Reason. Falls back to the FRP-1.5A `WhyExplainUi`
   shape when the diagnostics blob lacks a `pick` field. "About this
   connection" link surfaces the `RelayPackInfoSheet`.
3. **RelayPackInfoSheet** (`ui/RelayPackInfoSheet.kt`) — Material 3
   `ModalBottomSheet` with the 3 locked paragraphs (`relaypack_h1`/
   `_p1`, `_h2`/`_p2`, `_h3`/`_p3`). EN copy verbatim from phase doc
   §5.3; FA first-pass shipped.
4. **AddRouteScreen** tab 2 (`ui/AddRouteScreen.kt`) — `AnimatedQrTab`
   composable with Session ID + Frame (base64) inputs and a "Feed
   frame" button calling the existing `core.fountainFeedFrame` ABI.
   Camera capture is host-driven (CameraX/MLKit integration is host
   wiring, not bundled at FRP-6 to keep the AAR thin); the manual
   paste field is the documented fallback.

## Desktop screens enumerated

1. **Home.tsx** — mounts `RouteHealthBanner` above the existing Home
   content. Polls `diagnosticsExplain` every 1 s.
2. **AddRoute.tsx** — gains a `QRImport` section under the existing
   .sbp file picker.
3. **`recipient/RouteHealthBanner.tsx`** — `● Connected via REALITY ·
   direct VPS` shape; falls back to "Not connected" placeholder.
4. **`recipient/ExplanationView.tsx`** — same sectioning as Android.
5. **`recipient/RelayPackInfoSheet.tsx`** — fixed-inset overlay with
   the 3 locked paragraphs read from `i18n/{en,fa}.json`.
6. **`recipient/QRImport.tsx`** — wires the 5 new
   `recipient_qr_*` Tauri commands; each frame is fed to the existing
   core `engine_fountain_feed_frame` decoder. On `complete`, the core
   has already decoded, verified, and imported the `.sbp`; finalize
   returns the importer verdict for the UI.

## iOS placeholder confirmed

- File: `client-ios/DaalApp/Sources/ContentView.swift`, Settings
  section, immediately after the `settings.diagnostics` NavigationLink.
- Strings: `frp6.placeholder` defined in
  `DaalApp/Resources/en.lproj/Localizable.strings` and
  `DaalApp/Resources/fa.lproj/Localizable.strings`.
- EN text: "iOS support for FRP-published routes is post-V3 per the
  project roadmap. iOS clients connect to existing trust-pinned
  publishers normally."
- Verification: `rg -n "iOS support for FRP-published routes" client-ios/`
  returns 1 match (en.lproj only — by design; FA is a translation, not a
  literal copy of the EN sentinel string).

## EN/FA copy review note

- **EN copy is locked.** Three paragraphs of the RelayPack modal are
  verbatim from phase doc §5.3 in both `client-android/.../strings.xml`
  and `client-desktop/tauri/src/i18n/en.json`. The
  `RelayPackInfoSheetStringsTest.kt` pin asserts every
  phase-doc-locked phrase is present in the EN strings file.
- **FA copy is first-pass.** The Persian translations are paragraph-
  by-paragraph mirrors of the EN source, written with FA grammar
  conventions (RTL, native vocabulary, soft kerning). They have not
  yet had a native-speaker review pass. Native-speaker review is the
  **FRP-7 readiness gate** — the pilot soak runs against this UX, so
  the FA copy must be reviewed before the soak begins.
- The FRP-7 gate verdict (below) reflects this.

## Real-time banner update test result

- **Android default cadence: 500 ms.** Pinned by
  `ExplanationPollingTest.default_poll_interval_is_under_one_second`.
- **Desktop default cadence: 1000 ms.** Set in
  `recipient/RouteHealthBanner.tsx` via `setInterval(tick, 1000)`.
- Both satisfy invariant 23 (banner update ≤ 1 s of an
  `Explanation` change).
- Full Compose-recomposition timing requires an emulator + the
  shipped libdaalcore.so AAR, which is built on a Windows-side host;
  the JVM unit-test layer pins the cadence and the parser correctness
  per `ExplanationPollingTest.parser_picks_up_family_within_one_blob`.

## OPSEC grep results

```
$ rg -nE 'firebase|crashlytics|sentry|amplitude|mixpanel|google-analytics|datadog|newrelic' \
        client-android/app/src/main/java client-android/app/build.gradle.kts \
        client-desktop/tauri/src client-desktop/tauri/src-tauri/src \
        client-desktop/tauri/src-tauri/Cargo.toml
(no matches)
```

Verified at the unit-test level by:

- `client-android/app/src/test/java/ai/daal/app/OPSecTest.kt`
  (3 test methods: build files, Kotlin source, no direct network in
  UI/VM).
- `client-desktop/tauri/src-tauri/tests/recipient_opsec_test.rs`
  (4 test methods: Cargo.toml, src/, recipient.rs sockets, command
  names polarity).

## ABI count

```
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l
48
```

Untouched. FRP-6 uses only existing ABI symbols; the diagnostics
payload shape was widened internally without changing the release
surface.

## Test inventory

| Layer | Tests | Where |
|-------|-------|-------|
| Kotlin Explanation parser | 8 (7 goldens + 1 legacy null) | `client-android/app/src/test/.../data/ExplanationParseTest.kt` |
| Kotlin polling cadence    | 2 | `client-android/app/src/test/.../vm/ExplanationPollingTest.kt` |
| Kotlin EN/FA strings pin  | 5 | `client-android/app/src/test/.../ui/RelayPackInfoSheetStringsTest.kt` |
| Kotlin OPSEC              | 3 | `client-android/app/src/test/.../OPSecTest.kt` |
| Rust recipient session    | 4 | `client-desktop/tauri/src-tauri/src/recipient.rs` (mod tests) |
| Rust recipient OPSEC      | 4 | `client-desktop/tauri/src-tauri/tests/recipient_opsec_test.rs` |
| Node fixture cross-check  | 1 (7-of-7 batch) | `client-desktop/tauri/src/recipient/__tests__/explanation.fixture.test.mjs` |

Total FRP-6 additions across commits 1-7: **27 test cases**.

## Android JVM test environment

- `client-android/gradlew` is pinned to Gradle 8.7.
- Android local tests run with SDK 34 (`ANDROID_HOME=/opt/android-sdk`
  in the current dev environment).
- When `app/libs/daal-core.aar` is absent, JVM unit tests compile
  against the generated `app/src/testStubs/java/abi/` jar only. Release
  builds still require the real gomobile AAR; the stub is not a release
  dependency and is not packaged as production core.

## Build matrix at ship

```
cd client-android && ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk \
  GRADLE_USER_HOME=/tmp/daal-gradle-home ./gradlew --no-daemon testDebugUnitTest  PASS (18 tests)
cd client-desktop/tauri/src-tauri && cargo build --tests        PASS
cd client-desktop/tauri/src-tauri && cargo test                 PASS (8 tests across 2 binaries)
cd client-desktop/tauri && npx tsc --noEmit                     PASS
cd client-desktop/tauri && npm run build                        PASS
node client-desktop/tauri/src/recipient/__tests__/explanation.fixture.test.mjs   7/7 OK
rg -n "iOS support for FRP-published routes" client-ios/        ≥1 match
```

Android release/instrumented builds require the AAR (built on a
Windows-side host with the NDK). Local JVM tests run without the AAR via
the generated compile-time test stub described above.

## FRP-7 gate verdict

**PASS conditional on FA copy native-speaker review.**

- Engine ABI: 48 (untouched). ✅
- `Explanation` struct binding: Kotlin + TS bind verbatim against
  `core/internal/selection/explain.go`. ✅
- 7-golden cross-language fixtures: Kotlin round-trips all 7; Node
  cross-checks structural shape. ✅
- iOS placeholder: confirmed at `ContentView.swift` Settings section
  + en.lproj/fa.lproj. ✅
- Position B: enforced by 7 OPSEC test methods across Android + Tauri. ✅
- ≤1 s banner latency: 500 ms Android cadence + 1000 ms desktop. ✅
- EN copy locked verbatim from phase doc §5.3. ✅
- **FA copy first-pass shipped; native-speaker review remains.** This is
  the only outstanding readiness item; FRP-7's pilot soak runs against
  the UX a real user will see, so FA review must complete before the
  soak begins. Recommended path: hand `values-fa/strings.xml` and
  `i18n/fa.json` to a native speaker for a one-pass review of the
  recipient surface (banner.*, why.*, qr.*, relaypack.* keys);
  iterate text-only (no Kotlin or TS edits).

## Surface left for FRP-7+

- **Android emulator banner-latency instrumented test.** The JVM unit
  layer pins the cadence and the parser; the Compose-recomposition
  timing test lives at `gradle connectedAndroidTest` and is gated on
  the AAR being available locally. This is a CI-side wiring item, not
  a code change.
- **Camera capture path on Android** (CameraX + MLKit barcode). The
  manual paste fallback ships at FRP-6; live camera integration is a
  host-shell feature that depends on per-build target SDK choices.
- **Desktop browser-side QR scanner.** Same pattern — the recipient
  receives base64 frames from the publisher's `qr-fountain` CLI as
  text via Signal/in-person; native QR scanning is V2 territory.
- **Sub-key rotation prompts** (FRP-7.5). FRP-6 surfaces the publisher
  fingerprint via the existing `TrustPromptDialog`; live rotation
  prompts arrive at FRP-7.5.
- **Freshness-endpoint update notifications** (FRP-8).
- **Push notifications about route switches** (V2 recipient mobile UX).

Co-authored-by: factory-droid[bot] <138933559+factory-droid[bot]@users.noreply.github.com>
