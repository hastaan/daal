# Android Client v1

## Status

Phase 1B deliverable. The Compose tree, `VpnService`, and Daal-core
integration are described here; the source of truth for behavior is the
Go core (engine ABI).

## Stack

- Kotlin 2.0.x
- Jetpack Compose (BOM `2024.06.00`)
- `androidx.security.crypto` for the device key
- `gomobile bind` AAR (`daal-core.aar`) imported as a flat-dir dependency
- ABI splits: `arm64-v8a`, `armeabi-v7a`; `minSdk 24`

## Screens

1. **Onboarding** — three steps: pick security level (Standard / Elevated / Strict / Maximum Protection), optional PIN (mandatory for Maximum), grant `VpnService` permission.
2. **Home** — Connect / Disconnect, current route name, trust badge, redacted byte counter.
3. **Routes** — grouped by trust class.
4. **Add Route** — five tabs: Paste link, Static QR, Animated QR (Phase 1C), LAN receive (Phase 1C), Import file.
5. **Diagnostics** — DNS / TCP-443 / UDP probe results, last refresh, hour-bucketed counts.
6. **Settings** — emergency-pool toggle, language (EN/FA), panic wipe.

## Trust UI invariants

- Friend-shared bundle from a previously unseen publisher MUST surface a confirmation dialog **before** the bundle's routes become usable.
- Dialog shows: hex fingerprint (truncated by default; "details" reveals full), 4-word English fingerprint, 4-word Persian fingerprint.
- Three buttons: **Trust this publisher** / **Just for this one bundle** / **Cancel**.
- A route from a known publisher imports silently; an audit row is appended to `trust_audit`.
- Rotation chains accepted from a previously pinned publisher do NOT re-prompt; a banner informs the user.

## Security-level defaults

| Level | PIN | Emergency pool | Bulk allowed | UDP probe before UDP routes | Stronger trust warnings |
|---|---|---|---|---|---|
| Standard | optional | enabled | yes | yes | normal |
| Elevated | optional | enabled | no by default | yes | normal |
| Strict | optional | disabled | no | yes | yes |
| Maximum | required | disabled | no | yes | yes |

No app-facing label MAY refer to identity, occupation, politics, or social group. The four labels above are the only sanctioned strings.

## VpnService

- Foreground service, `foregroundServiceType="specialUse"` with PROPERTY_SPECIAL_USE_FGS_SUBTYPE = `vpn`.
- Persistent low-importance notification.
- Daal-core runs in the service process so the UI process stays lean.
- Phase 1B's engine driver is the Go stub; Phase 1B-Polish wires the real sing-box driver and TUN file descriptor handoff.

## Privacy invariants

- `android:allowBackup="false"` and full-backup excludes everything (`data_extraction_rules.xml`).
- No analytics SDK is linked.
- `INTERNET` is granted to the engine; the UI process never opens its own sockets.
- `POST_NOTIFICATIONS` is requested only for the foreground notification.

## RelayPack recipient UI (FRP-6)

FRP-6 makes the recipient client a thin renderer of the FRP-3
`Explanation` struct (`core/internal/selection/explain.go`). The
`engine_export_diagnostics` ABI symbol is the carrier — no new release
symbol is added (ABI count remains 48).

### Surfaces

1. **Persistent route-health banner.** Mounted in `HomeScreen`. Renders
   `Explanation.pick.family` and the locked exposure-mode label
   ("Connected via REALITY · Hetzner Frankfurt"). Updates within ≤1 s of
   an `Explanation` change via a lifecycle-scoped `kotlinx.coroutines.flow.Flow`
   that polls every 500 ms while the screen is visible and pauses on
   `onPause`. Tap to expand.
2. **Expanded "Why this route" view.** `WhyThisRouteScreen` (existing
   surface, FRP-6 extends) renders the full `Explanation`: pick,
   shortlist (race order + outcome chips), failures (classification
   chips), active cooldowns (chips with countdown), network signals,
   memory hint, plain-language reason. The legacy FRP-1.5A
   `WhyExplainUi` shape is rendered as a fallback only when the
   diagnostics blob does not carry a `pick` field.
3. **RelayPack explanation modal.** A bottom-sheet (`RelayPackInfoSheet`)
   reachable from the expanded view. Three paragraphs in EN and FA
   ("What is a RelayPack?", "What did your relative do?", "What does
   your Daal app do?"); copy locked verbatim in
   `phases of development/35-phase-frp-6-recipient-ux.md` §5.3.
4. **Animated-QR import.** `AddRouteScreen` tab 2 wires the camera
   preview through `DaalCoreBridge.fountainFeedFrame`; on completion
   the bundle goes through the existing `importSbp` → trust-prompt →
   pin path. No new ABI calls beyond what FRP-1C already exposes.

### Cross-language fixture pin

The Kotlin `Explanation` data class at `app/src/main/java/.../data/Explanation.kt`
binds to FRP-3's locked JSON shape. The 7 deterministic goldens at
`specs/test-vectors/explanation/` are the cross-language reference
fixtures; `ExplanationParseTest.kt` round-trips every golden and
asserts every field. The same goldens drive the Tauri TS renderer.

### Privacy & lifecycle invariants (FRP-6 specific)

- No analytics SDK on top of the existing FRP-1B prohibition;
  `OPSecTest.kt` greps `app/build.gradle*` and the Kotlin source tree
  for `firebase|crashlytics|sentry|amplitude|mixpanel|google-analytics`.
- The 500 ms diagnostics polling Flow is `viewModelScope`-bound and
  cancels on `onPause` — no wake-lock, no background pull.
- `AddRouteScreen` requests `CAMERA` only when the user opens the
  animated-QR tab; permission dismissal returns to a paste-fallback
  state rather than a crash.
