# Phase D-2 — Daal GUI rebuild (per design brief v2)

**Status:** PROPOSED — depends on Phase D-1 complete (rename + new
repo + signed `Daal v0.1.0` shipping the legacy UI under the new
name).
**Maturity target:** **first user-shippable Daal release** with the
new IA, two-path onboarding, real Connect flow, and complete
section coverage on Desktop + Android. iOS reaches feature parity
in scope but ships behind a feature gate if the Apple-CI side has
not caught up.
**Engine `Version` target:** **unchanged** at `daal-core 0.9.x`;
all UI changes are above the ABI.
**ABI release surface target:** **unchanged**.
**Predecessor:** Phase D-1 — rename + asset wiring shipped.
**Successor:** Phase D-3 — landing site / GitHub Pages.

---

## 1. Strategic frame

The engine boots and works. The current UI does not. D-2 rebuilds the
client surfaces so that:

1. A first-time user can finish onboarding in ≤ 90 s and either
   connect or know exactly what to do next.
2. **Recipient** users (inside Iran, just want to connect) are the
   primary path — visually weighted as the default at the
   "Who are you?" branch.
3. **Publisher** users (diaspora helpers running a VPS for family)
   have a real, named onboarding lane — not buried in advanced.
4. Five top-level sections (Connection / Routes / **Sources** /
   Status / Settings) are present on **every** platform with the
   same names, icons, and order. Publisher is a sixth advanced
   module, hidden until enabled.
5. Every primary flow has empty / loading / error states designed
   and built — not just happy path.

The single source of truth for visual + interaction direction is
`docs/daal-gui-design-brief-v2.md` plus the three reference HTMLs in
`/home/daal/src/`. Engineering follows the designer's Figma output;
the brief and HTMLs anchor scope when Figma is ambiguous.

---

## 2. Locked answers

| Question | Locked answer |
|---|---|
| User-facing rename "Subscriptions → Sources" | Ships **here**, with the new IA. Engine ABI / `subscription_*` calls are unchanged. **Visible** UI labels, headings, accessibility strings, and copy all say "Sources". **i18n keys themselves stay legacy** (`subs.title`, `subscription_card_*`, etc.) so engine code, comments, and developer docs remain readable; only the localized **values** change. |
| Publisher path on first run | Two-path onboarding ("I want to connect" / "I want to help others"); recipient is the visually primary option; publisher is clear but secondary; "I'm not sure yet" → recipient with a banner offering to switch. |
| Publisher mode visibility for users who started as recipient | Settings → Advanced → "I am a publisher" toggle, reversible. |
| Cross-platform parity at end of D-2 | Desktop (Win/Linux/macOS) and Android: full IA, all five sections, onboarding, trust prompt, recovery sheet, panic wipe — ALL primary flows from brief §7a. iOS: full IA target, but ships gated if Apple-CI lags; minimum-viable iOS is same five sections rendered (Connection + Routes/Add + Sources + Status + Settings) over the existing NE skeleton. |
| Real packet tunnel | Desktop: wires `tun-helper/` to a real system VPN on connect. Android: replaces the stubbed `DaalVpnService.connect` with a real sing-box driver handing the TUN fd to Go. iOS: NE remains scaffold; if `packetFlow.readPackets/writePackets` plumbing is not done by D-2 ship, iOS ships with a "Beta — limited tunnel" banner and a feature flag. |
| Sources section title | **"Sources"** in user-visible text everywhere. Engine surfaces, diagnostics JSON, code, comments stay `subscription`. |
| Default theme | Follows OS; default-on-first-launch is **dark** (matches reference HTMLs and target audience usage context). |
| Default language | Detect from OS; fall back to English. RTL flips on FA. |
| What ships at the end of D-2 | A `Daal v0.2.0` release where Desktop and Android pass every acceptance criterion in §6. iOS ships best-effort with feature gate. |
| What does NOT ship at end of D-2 | The landing site (D-3). The publisher dashboard's full operator-tooling redesign (existing 7-screen wizard ports as-is into the Publisher section with cosmetic-only changes). The engine identifier rename (D-1.5). |

---

## 3. Scope

### 3.1 Shared (cross-platform)

- Implement the brand token system from brief §10:
  - OKLCH primary tokens **plus** sRGB fallbacks for every token.
  - Light + Dark themes for every token.
  - Same names across React/CSS, Compose Material3, and SwiftUI.
- Lift the canonical assets (`/home/daal/src/`) into a
  `client-shared/branding/` source-of-truth (already created in
  D-1) and reference from each platform's asset pipeline.
- Build a shared **strings catalog** (EN + FA) covering every
  primary flow. Use ICU MessageFormat or platform equivalent. The
  EN catalog is the source; FA is reviewed by a native speaker
  before release.
- Define the **route auto-naming rules** (brief §5.1) once, in the
  engine layer or a thin adapter, so every platform renders the
  same human-friendly names without re-deriving them.
- Implement **deep-link / share-sheet / file-open intent
  routing** to Add Route / Add Source per brief §4.8 on every
  platform.

### 3.2 Desktop (Win / Linux / macOS — Tauri + React)

Replace the current 5-tab top nav with the **sidebar + breadcrumb +
right-rail** layout from `daal-desktop.html`.

**Build:**

- Sidebar nav (vertical, 6 entries; Publisher dimmed off until
  enabled). Keyboard shortcuts ⌘/Ctrl+1..6. Search ⌘/Ctrl+K opens
  a command palette. Esc closes modals.
- Onboarding flow as a separate router stack rendered before the
  main app on first run (Welcome / Who are you? / branch / R or P
  paths / Ready). Persists "completed onboarding" flag in
  Tauri-side state.
- Connection screen with the **phoenix-button motion** primitive
  (brief §10.5) — the 3-D phoenix asset only when connected.
- Add Route + Add Source flows (paste / drop image for QR / LAN /
  file) — desktop replaces mobile's camera scan with a paste-or-
  drop-image flow.
- Trust prompt modal (centered, dismiss-blocked).
- Connection failure recovery sheet.
- Status accordion screen.
- Settings page with all 8 groups.
- Tray menu, close-to-tray, quit-while-connected, sleep/wake
  reconnect, autostart toggle.
- Wire `tun-helper/` (existing Rust crate) into the Connect flow
  so a desktop "Connect" actually establishes a system-level tunnel
  (or, if the platform integration is incomplete on macOS, ship
  Win+Linux real-tunnel and macOS engine-only-tunnel with a
  documented banner — same pattern as iOS feature gate).

**Removed surfaces:**

- `App.tsx`'s top tabs.
- The bare `route_id` text input on Home.
- The single-page-stack-of-banners Home layout.
- `RotateModal.tsx`'s confused 800-line state machine — replaced
  by the publisher flow's well-defined screens (existing FRP-5
  wizard ports as-is into the Publisher section).

### 3.3 Mobile — Android (Compose)

The Android codebase has the screens (`AddRouteScreen`,
`SubscriptionsScreen`, `BootstrapScreen`, `ShareRouteScreen`,
`WhyThisRouteScreen`, etc.) but no navigation. D-2 wires them.

**Build:**

- Replace the single-screen `MainActivity` with a Material3
  bottom-nav `Scaffold` hosting a `NavHost` with five top-level
  destinations (Connection / Routes / Sources / Status / Settings)
  + a hidden Publisher destination revealed by the toggle.
- Onboarding `NavHost` rendered before the main `NavHost` on first
  launch.
- Connection screen with the phoenix-button motion primitive
  (rendered as a Compose `Canvas` with a `prefers-reduced-motion`
  equivalent via `LocalConfiguration` accessibility settings).
- Real Route picker on Connection (no more disabled Connect
  button).
- Wire `DaalVpnService.connect()` to a real sing-box driver that
  hands the TUN fd to Go core. Replace the stubbed comment.
- VPN permission asked on first Connect (not on
  `MainActivity.onCreate` — current behavior is wrong).
- File-open intent (`.sbp`), share-sheet text (`daal://` URLs),
  share-sheet image (QR PNG) wired to Add Route deep-link routing.
- Trust prompt as a full-screen sheet (current dialog is too
  cramped for the 6-word grids).
- Recovery sheet on connect failure.
- Panic wipe with the typed-word + delay confirm pattern; floating
  duress shield button per brief.

**Renames at UI layer (engine unchanged):**

- All `R.string` keys for "Subscription*" stay; their **values**
  change to "Source"/"Sources".
- New i18n keys for onboarding, recovery sheet, trust prompt copy
  that didn't exist before.

### 3.4 Mobile — iOS (SwiftUI)

iOS is the most behind. Goal at D-2 is **structural parity** even
if some screens render minimal first cuts.

**Build:**

- Update `EngineBridge.swift` REQUIRED_VERSION_PREFIX to
  `daal-core 0.9` (today says `0.6`). Rebuild
  `Libbox.xcframework` from the current `core/abi`.
- Replace the single `Form` `ContentView` with a `TabView`
  (5 tabs: Connection, Routes, Sources, Status, Settings). Match
  the IA exactly.
- Implement onboarding as a full-screen `NavigationStack`
  preceding the `TabView` on first launch.
- Wire the `NETunnelProviderManager` so a Connection screen
  Connect action installs the VPN profile, asks permission, and
  starts the tunnel. The NE side already has the EngineBridge
  scaffold; finish `packetFlow.readPackets/writePackets` plumbing
  if engineering bandwidth allows.
- If the NE plumbing is incomplete by ship: ship iOS with a
  "Beta — limited tunnel" banner and a feature flag in Settings →
  Advanced; do not block D-2 on it.

### 3.5 Publisher mode (cross-platform, advanced)

- Existing FRP-5 7-screen wizard ports into the Publisher section
  on Desktop and Android with **cosmetic-only changes** (cyan
  accent, new typography, no functional reshuffling).
- Toggle in Settings → Advanced reveals/hides the section.
- Cyan-accent surface treatment (brief §10.1 `--cyan` token) for
  every Publisher screen so users always know they're in the
  advanced surface.
- "Publisher handoff / bundle distribution" sub-screen produces
  the QR + PIN + 6-word fingerprint grid (publisher's own
  fingerprint, in EN + FA) so the publisher can read it aloud on
  a phone call to the recipient.

---

## 4. Workstreams (parallelizable)

### 4A. Brand tokens & shared assets

1. Author `client-shared/tokens/colors.json` (light + dark, OKLCH
   + sRGB fallback per brief §10.1).
2. Generate platform-specific token outputs:
   - Tauri/React: emit a CSS file consumed by the Tauri shell.
   - Android: emit `colors.xml` (light) + `colors-night.xml`
     (dark), Material3 theme `daal_theme.xml`.
   - iOS: emit `Colors.xcassets` color sets with light/dark
     appearances.
3. Bundle Iowan Old Style fallback (designer must verify license
   for redistribution; if unlicensable, the designer picks a
   close substitute — Charter and Newsreader are open-source
   alternatives in the existing fallback stack).
4. Bundle Vazirmatn (open-source) for FA.
5. Bundle one humanist sans for body and one mono — system fonts
   are acceptable per platform.

### 4B. Onboarding flow

1. Build the two-path onboarding in `client-shared/onboarding/`
   spec: a state machine with screens W (welcome), B (branch),
   R1..R4 (recipient), P1..P4 (publisher), M0 (migration check),
   plus deep-link hold buffer.
2. Render the spec on each platform using its native idioms
   (NavController on Android, NavigationStack on iOS, simple
   router on Tauri).
3. Persist the "completed" flag in engine state via a new ABI
   call OR (cheaper) in platform-side preferences keyed by
   install id. (Decision: platform-side preferences. The engine
   should not own UI state.)

### 4C. Connection + phoenix-button motion

1. Implement the four phoenix-button states (brief §10.5) as a
   reusable component on each platform.
2. Wire the four states to engine signals:
   - Disconnected: `engine_state == NoRoute || cleared`
   - Connecting: from `set_route` call until first heartbeat
     success
   - Connected: heartbeat success + ≥1 successful packet round
     trip recorded in route health
   - Error: any failure surfaced from `set_route` or a sustained
     heartbeat-loss state.
3. Implement the recovery sheet (brief §4.1) bound to the same
   error signal.

### 4D. Add Route / Add Source unified entry point

1. One sheet/modal component, four tabs (Paste / Scan or Drop /
   LAN / File). Reused by both "+ Add route" (Routes section) and
   "+ Add Source" (Sources section), parametrized by URI scheme.
2. Trust-prompt modal shared. Inputs: visual fingerprint URI,
   EN words, FA words, publisher display name, spec version.
   Outputs: 0 (Trust) / 1 (Once) / 2 (Cancel).
3. Deep-link receiver per platform (Android intent filter on
   `daal://` + `*.sbp`, iOS Universal Links + `UIDocumentPicker`
   intent, Tauri custom protocol + `tauri://` URL handler).

### 4E. Status, Settings, Publisher

1. Status screen: top health card + three accordions, on every
   platform.
2. Settings screen: 8 groups. Engine-driven toggles bind to the
   relevant ABI calls; UI-only toggles persist in platform
   preferences. Panic wipe is wired to the existing engine-side
   wipe call but adds the typed-word + delay UI pattern.
3. Publisher: port the FRP-5 wizard 1:1 into the new section
   chrome with cyan accent. No functional changes.

### 4F. Real packet tunnel

1. Desktop:
   - Linux: `tun-helper` already exists; finish wiring it to
     `engine_set_route` so the engine asks the helper to bring up
     a TUN with the relevant route's transport descriptor. Use
     the existing `polkit` privilege-escalation path.
   - Windows: integrate WinTUN; `tun-helper` is the existing
     abstraction layer.
   - macOS: `utun` device + system extension privilege ask. May
     ship best-effort; document a fallback to engine-only tunnel
     with a banner if the system extension flow is not finished.
2. Android: real sing-box driver in `DaalVpnService`. The
   previous `// Phase 1B intentionally does NOT establish a real
   TUN` comment goes away.
3. iOS: Network Extension `packetFlow.readPackets/writePackets`
   loop bound to `Libbox.xcframework`. If incomplete, gate iOS as
   noted in §3.4.

### 4G. Localization sweep

1. Extract every existing English string + every new D-2 string
   into `en.json` (or platform equivalent).
2. FA translation pass by a native speaker.
3. Add ICU plural support (`{n, plural, one {...} other {...}}`)
   for any count-bearing string. There aren't many — last
   refresh "n minutes ago" / "n routes" are the obvious ones.
4. Wire RTL flip on every screen body. Keep the editorial chrome
   LTR (matches reference HTML behavior).

---

## 5. Hard-state inventory (designer-and-engineering work)

Every flow must have these states designed AND built:

| State | Notes |
|---|---|
| Empty | Connection with no routes, Routes empty, Sources empty, Status when no diagnostics yet, Add Route preview empty, Publisher with no server |
| Loading | All > 200 ms operations; > 3 s loading gets explainer copy; > 15 s gets Cancel |
| Error | Connect failure, source refresh failure, route import error, file format invalid, deep-link malformed, engine version mismatch (full-screen blocker), permission denied (with re-ask flow) |
| Locked | Vault-locked PIN gate before Connection / Routes / Sources / Status / Settings (Settings except Emergency stays reachable from the duress shield) |
| Pre-permission | One-screen explainers before VPN / Camera / Notifications / Local network (brief §1.9) |
| Migration | private codename -> Daal import success; import failure; "do this later" path |
| Mid-onboarding intent hold | A `daal://` URL clicked while onboarding is in progress; show breadcrumb on resume |
| Quit while connected (desktop only) | Confirm modal |
| Sleep/wake | Brief "Reconnecting…" banner |

---

## 6. Acceptance criteria

D-2 ships when **all** of the following hold:

### 6.1 Cross-platform

- [ ] Brand tokens (light + dark) generated for all three
      platforms from `client-shared/tokens/colors.json`. CI emits
      drift warnings if the per-platform outputs go out of sync
      with the source JSON.
- [ ] Strings catalog: zero hard-coded user-visible strings on any
      platform. CI grep proves it.
- [ ] FA pass: every English string has an FA counterpart;
      reviewed by a native speaker; live-flip works on every
      screen.
- [ ] Phoenix-button motion respects `prefers-reduced-motion` /
      OS reduced-motion settings on all platforms.

### 6.2 Onboarding (every primary flow per brief §7a)

- [ ] Two-path onboarding shipped: recipient (R0..R4) and
      publisher (P1..P4) paths complete end-to-end.
- [ ] Migration prompt (M0) detects an existing Daal install on
      the same platform-specific data path (Win / Linux / Android
      paths from D-1 §6 risk table); imports routes, sources,
      mode, lifeline preference. Failure-mode falls through to
      normal onboarding.
- [ ] Time-to-first-connect from a clean install ≤ 90 s on a
      smoke device, recipient path, with one well-formed test
      Source URL pasted.

### 6.3 Connection

- [ ] Connect button on every platform actually connects via a
      real packet tunnel (Desktop Win+Linux must; macOS may ship
      with engine-only tunnel + banner; Android must; iOS may
      ship with banner).
- [ ] Route picker exposes routes by human name only (brief §5.1).
- [ ] Connection failure shows the recovery sheet with all four
      options live.
- [ ] Connected state on Desktop and Android shows the 3-D
      phoenix breathing.

### 6.4 Routes / Sources

- [ ] Add Route flow complete: Paste, Scan/Drop, LAN, File.
- [ ] Add Source flow complete (same four sub-flows scoped to
      `daal://sub/...`).
- [ ] Trust prompt full-screen on mobile, modal on desktop, with
      the EN+FA word grid; cannot be dismissed except via three
      explicit choices.
- [ ] Deep-link entry: opening `daal://sub/...` from outside the
      app routes to Add Source with URL pre-filled, even when
      vault is locked or onboarding is mid-flight.

### 6.5 Status

- [ ] Health card top + three accordions render correct data from
      `engine_diagnostics` and `engine_diagnostics_explain`.
- [ ] "Export diagnostics" produces a redacted JSON; the redaction
      is verified by a CI test that scans the export for known
      destinations / IPs / fingerprint hex.

### 6.6 Settings

- [ ] All 8 groups render and the toggles bind to the right ABI
      calls.
- [ ] Panic wipe three-step confirm with typed word + delay
      window with Cancel works as specified. Wipes data on a
      smoke device and returns to Welcome.
- [ ] Detailed-notifications toggle behaves correctly: lock-screen
      previews always use generic copy.
- [ ] Language switch is live (no app restart).

### 6.7 Publisher (advanced)

- [ ] Toggle reveals/hides the Publisher section.
- [ ] All seven existing wizard screens render with cyan accent
      treatment; functionally unchanged.
- [ ] Publisher handoff screen produces the QR + PIN + 6-word
      fingerprint grid (EN + FA) for the publisher's own key.

### 6.8 Tray + desktop background behavior

- [ ] Tray menu present on Win/Linux/macOS with status indicator,
      quick connect/disconnect, current route name, mode submenu.
- [ ] Close-to-tray default with the one-time first-close
      explainer.
- [ ] Quit-while-connected confirm modal.
- [ ] Autostart toggle works (Win: registry / startup folder;
      Linux: `.desktop` autostart entry; macOS: launch agent).

### 6.9 Acceptance against brief §7a

- [ ] Every primary flow from the brief has been designed by the
      designer AND built to the per-flow checklist (Wireframe,
      hi-fi light/dark/EN/FA, empty/loading/error states,
      prototype frame, hard-constraint review, WCAG AA contrast
      check).
- [ ] iOS gets a partial pass with explicit feature gates noted in
      release notes.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Designer ships Figma after engineering starts; engineering builds against the brief HTMLs and then has to redo. | The brief explicitly authorizes the reference HTMLs as anchor when Figma is ambiguous. Engineering builds against HTMLs first; visual polish is final-pass cosmetic work that can absorb later Figma updates. |
| Tunnel integration on macOS is non-trivial (system extension provisioning). | Pre-decided fallback: ship "engine-only tunnel" on macOS with a banner. macOS-real-tunnel becomes a D-2.5. |
| iOS engineering bandwidth lags. | Pre-decided fallback: iOS ships with feature gate, banner, and a "Beta" build channel separate from the App Store / TestFlight primary release. |
| FA review slips and we accidentally ship machine-translated strings. | Hold release on a hard "FA reviewer signoff" gate. FA-blocking is a release veto. |
| The "Sources" rename surfaces dozens of legacy strings we missed. | Add a CI grep that fails on user-visible "Subscription" / "subscription" inside i18n catalogs. Allow-listed paths: engine call sites, comments, code identifiers. |
| New onboarding "completed" flag interacts badly with the migration import flow. | The migration prompt M0 short-circuits the rest of onboarding to the "Ready" screen; the flag is set to `completed` on import success. On import failure, the flag stays unset and onboarding proceeds normally. |
| sRGB-fallback colors drift from the OKLCH source as designers tweak the OKLCH values. | The token JSON is the single source; the platform output files are generated. CI fails the build if generated files are committed without re-running the generator. |
| Phoenix-button motion conflicts with reduced-motion settings or appears to crash on low-end Android devices. | Component falls back to static phoenix on any of: `prefers-reduced-motion`, low-RAM device flag, frame-rate < 30 fps measured for 1 s after start. |

---

## 8. Test plan

1. **Per-flow E2E:** at least one happy-path E2E test per primary
   flow on Desktop and Android. Tools: Playwright for Tauri,
   Espresso/Compose UI test for Android, XCUITest if iOS bandwidth
   permits.
2. **Onboarding 90-second test:** a CI-driven scripted run from
   first launch to "Connected" using a stubbed Source. Fails the
   build if it takes > 90 s end-to-end on the reference VM.
3. **Localization snapshot test:** every screen rendered in
   EN-light, EN-dark, FA-light, FA-dark. Diff against approved
   snapshots.
4. **Reduced-motion test:** every animated component verified to
   stop animating under reduced-motion.
5. **A11y audit:** automated WCAG AA contrast check on every
   approved snapshot. TalkBack / VoiceOver / NVDA spot-checks for
   the trust prompt, panic wipe, and Connect button.
6. **Real-device smoke:** install the new release on:
   - Windows 10 + Windows 11
   - Ubuntu 22.04 + Fedora 40 (AppImage + deb)
   - Android 12 + Android 14 (low-end + flagship)
   - macOS 13 + 14 (best-effort)
   - iOS 16 + 17 (best-effort, behind feature gate)
7. **Migration smoke:** install the legacy Daal release on the
   same device, configure with a route + Source + PIN, then
   install Daal D-2; verify M0 detects, imports, and routes
   straight to "Ready."

---

## 9. Roll-out

1. Cut `Daal v0.2.0-alpha` to internal testers once Desktop +
   Android pass §6.
2. Two-week alpha soak. **No automatic crash reports, no opt-in
   crash uploads, no network telemetry of any kind** — the
   brief's hard rule (§1.2) is absolute. Alpha feedback is
   collected out-of-band: testers manually attach the redacted
   `Settings → Status → Export diagnostics` JSON to a bug report
   if they choose to. The export is what the user already sees;
   it never leaves the device unless the user explicitly attaches
   it to a message.
3. Beta `v0.2.0-beta` with FA reviewer signoff and any alpha
   bugs fixed.
4. `v0.2.0` to the new repo's Releases page. Landing site goes
   live in parallel from D-3.

---

## 10. Handover artefacts (produced at end of D-2)

- `Daal v0.2.0` release on the new repo with signed artefacts for
  all platforms.
- Per-flow snapshot library committed to
  `test-rigs/snapshots-d2/`.
- Updated `docs/build-and-release.md` with the new artefact
  shapes.
- A `D-2.handover.md` summarizing acceptance status, any feature
  gates (iOS NE, macOS tunnel) carried forward, and the next-
  phase entry point (D-3 landing site).
- Designer's Figma file linked from `docs/` with read-only access
  for the team.
