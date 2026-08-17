# Phase D-2 — Daal GUI rebuild (no-version-bump revision)

**Status:** **SHIPPED.** Handover: `development-phases/D-2-handover.md`.
Supersedes the version-bump variant (`D-2-gui-rebuild.md`), which is kept
on disk as the design-level reference only.

**VERSION pin:** **`0.1.0` throughout D-2 *and* D-3.** No bump until
the very end of D-3 (landing site + downloads). All D-2 builds are
local/private dev builds tagged with the git SHA only and **never**
pushed to the public release repo.

**Engine `Version` target:** unchanged at `daal-core 0.9.x`.
**ABI release surface target:** unchanged.
**Predecessor:** D-1 — rename + asset wiring shipped as signed
`v0.1.0` on the new repo.
**Successor:** D-3 — landing site / GitHub Pages / single signed
snapshot bump to `v0.2.0`.

---

## 1. Strategic frame

The engine boots and works. The current UI does not. D-2 rebuilds the
client surfaces against the brief and the three reference HTMLs in
`/home/daal/src/`, while keeping the public repo on `v0.1.0` (legacy
UI) untouched. When D-2 is "done", the work sits on a private branch;
nothing is published until D-3 wraps and a single clean signed
snapshot is cut as `v0.2.0`.

**Hard rule on publishing:** no incremental D-2 history reaches the
public repo. The public repo continues to show only `v0.1.0` until
D-3.

The single source of truth for visual + interaction direction is
`docs/daal-gui-design-brief-v2.md` plus the three reference HTMLs in
`/home/daal/src/`. Engineering follows the designer's Figma output;
the brief and HTMLs anchor scope when Figma is ambiguous.

---

## 2. Versioning + repo discipline (the only structural change)

This is the one thing that differs from the previous D-2 draft.

- `VERSION` file stays `0.1.0` for the entire D-2 phase **and** D-3
  *until D-3 cuts its release tag*.
- `tauri.conf.json`, Android `versionName`, iOS
  `CFBundleShortVersionString` all stay `0.1.0`.
- D-2 development happens on a long-lived **private branch**
  (`d2-gui` or similar) on the dev workstation. Optional: push to a
  private mirror for backup; **never** push to `hastaan/daal`.
- No tags are cut during D-2. No GitHub Release is published. CI is
  allowed to run on the private branch but `release.yml`'s tag
  trigger is not invoked.
- `CHANGELOG.md` may accumulate `[Unreleased]` notes locally, but no
  `[0.2.0]` heading is written until D-3.
- The "Initial public release: Daal v0.1.0" commit on `main` of
  `hastaan/daal` remains the only thing the public sees during D-2
  and D-3.
- Internal smoke builds may be hand-named e.g.
  `Daal-0.1.0-d2-<shortsha>-<arch>.{apk,exe,…}` so testers can tell
  them apart from the public `v0.1.0`. These are **never** uploaded
  to GitHub Releases.

---

## 3. Locked answers

| Question | Locked answer |
|---|---|
| User-facing rename "Subscriptions → Sources" | Ships here. Engine ABI, code identifiers, comments, dev docs, and **i18n keys** (`subs.title`, `subscription_card_*`) stay legacy. Only the localized **values** change. |
| Publisher path on first run | Two-path onboarding: Recipient (visually primary) / Publisher (named secondary lane) / "I'm not sure yet" → recipient with a banner offering a switch. |
| Publisher visibility for users who started as recipient | Settings → Advanced → "I am a publisher" toggle, reversible. |
| Cross-platform parity at end of D-2 | Desktop (Win/Linux/macOS) + Android: full IA, all 5 sections, onboarding, trust prompt, recovery sheet, panic wipe. iOS: structural parity but ships gated if Apple-CI lags. |
| Real packet tunnel | Desktop: `tun-helper/` wired on Connect. Android: real sing-box driver in `DaalVpnService` replaces the stub. iOS: NE remains scaffold; "Beta — limited tunnel" banner + feature gate if `packetFlow` plumbing lags. |
| Sources section title | "Sources" in user-visible text everywhere. Engine surfaces, diagnostics JSON, code, comments stay `subscription`. |
| Default theme | Follows OS; first-launch default = **dark**. RTL flips on FA. |
| What ships at end of D-2 | A **private** internal milestone — Desktop+Android pass §6, iOS feature-gated. **Nothing is published.** `VERSION` stays `0.1.0`. |
| What does NOT ship at end of D-2 | Public release of the new UI; landing site (D-3); engine identifier rename (deferred); publisher-dashboard operator-tooling redesign (existing 7-screen wizard ports as-is). |

---

## 4. Scope (per platform)

### 4.1 Shared (cross-platform)

- Brand token system from brief §10:
  - OKLCH primary tokens **plus** sRGB fallbacks for every token
  - Light + Dark themes
  - Same names across React/CSS, Compose Material3, SwiftUI
- Lift canonical assets in `/home/daal/src/` into
  `client-shared/branding/` (already created in D-1) and reference
  from each platform's asset pipeline.
- Shared **strings catalog** (EN + FA) covering every primary flow.
  ICU MessageFormat. EN is source; FA reviewed by a native speaker
  before any release.
- Define **route auto-naming rules** (brief §5.1) once in the engine
  layer or a thin adapter so every platform renders the same
  human-friendly names.
- **Deep-link / share-sheet / file-open** intent routing → Add
  Route / Add Source per brief §4.8.

### 4.2 Desktop (Win / Linux / macOS — Tauri + React)

Replace the current 5-tab top nav with the **sidebar + breadcrumb +
right-rail** layout from `daal-desktop.html`.

- Sidebar nav (vertical, 6 entries; Publisher dimmed off until
  enabled). ⌘/Ctrl+1..6, ⌘/Ctrl+K command palette, Esc closes
  modals.
- Onboarding flow as a separate router stack rendered before the
  main app on first run.
- Connection screen with the **phoenix-button motion** primitive
  (3-D phoenix asset only when connected).
- Add Route + Add Source flows (paste / drop image for QR / LAN /
  file).
- Trust prompt modal (centered, dismiss-blocked).
- Connection failure recovery sheet.
- Status accordion screen.
- Settings page with all 8 groups.
- Tray menu, close-to-tray, quit-while-connected, sleep/wake
  reconnect, autostart toggle.
- Wire `tun-helper/` into the Connect flow. macOS may ship
  engine-only-tunnel + banner if system-extension flow lags.

**Removed:** `App.tsx` top tabs; bare `route_id` text input on Home;
single-page-stack-of-banners Home; `RotateModal.tsx` 800-line state
machine (replaced by FRP-5 wizard ports).

### 4.3 Android (Compose)

- Replace single-screen `MainActivity` with a Material3 bottom-nav
  `Scaffold` hosting a `NavHost` (5 destinations + hidden
  Publisher).
- Onboarding `NavHost` rendered before the main `NavHost` on first
  launch.
- Connection screen with the phoenix-button motion (Compose
  `Canvas`, respects accessibility reduced-motion).
- Real Route picker on Connection (no more disabled Connect).
- Wire `DaalVpnService.connect()` → real sing-box driver hands the
  TUN fd to Go core. Replace the stubbed comment.
- VPN permission asked on first Connect (not on
  `MainActivity.onCreate`).
- File-open intent (`.sbp`), share-sheet text (`daal://`), share-
  sheet image (QR PNG) → Add Route deep-link routing.
- Trust prompt as a full-screen sheet.
- Recovery sheet on connect failure.
- Panic wipe with typed-word + delay confirm; floating duress
  shield button per brief.

### 4.4 iOS (SwiftUI)

- `EngineBridge.swift` `REQUIRED_VERSION_PREFIX` → `daal-core 0.9`
  (currently `0.6`). Rebuild `Libbox.xcframework` from `core/abi`.
- Replace single `Form` `ContentView` with a `TabView` (5 tabs).
- Onboarding as a full-screen `NavigationStack` preceding `TabView`
  on first launch.
- Wire `NETunnelProviderManager` so Connect installs profile, asks
  permission, starts tunnel.
- Finish `packetFlow.readPackets/writePackets` plumbing if
  bandwidth allows; otherwise ship behind "Beta — limited tunnel"
  banner + Settings → Advanced flag.

### 4.5 Publisher mode (cross-platform, advanced)

- Existing FRP-5 7-screen wizard ports into the Publisher section
  on Desktop and Android with **cosmetic-only changes** (cyan
  accent, new typography, no functional reshuffling).
- Toggle in Settings → Advanced reveals/hides the section.
- Cyan-accent surface treatment everywhere in Publisher.
- Publisher handoff sub-screen produces QR + PIN + 6-word
  fingerprint grid (publisher's own fingerprint, EN + FA) for
  read-aloud over a phone call.

---

## 5. Workstreams (parallelizable)

### 5A. Brand tokens & shared assets
1. Author `client-shared/tokens/colors.json` (light + dark, OKLCH
   + sRGB fallback per brief §10.1).
2. Generate platform-specific token outputs:
   - Tauri/React: emit a CSS file consumed by the Tauri shell.
   - Android: emit `colors.xml` (light) + `colors-night.xml`
     (dark), Material3 theme `daal_theme.xml`.
   - iOS: emit `Colors.xcassets` color sets with light/dark
     appearances.
3. Bundle Iowan Old Style fallback (verify license; fall back to
   Charter / Newsreader otherwise).
4. Bundle Vazirmatn for FA; humanist sans for body; mono = system
   per platform.

### 5B. Onboarding flow
1. State machine in `client-shared/onboarding/`: W (welcome), B
   (branch), R1..R4 (recipient), P1..P4 (publisher), M0
   (migration check), deep-link hold buffer.
2. Render on each platform via native idioms.
3. Persist "completed" flag in **platform-side preferences**.

### 5C. Connection + phoenix-button motion
1. Reusable component, four states.
2. Wire to engine signals:
   - Disconnected: `engine_state == NoRoute || cleared`
   - Connecting: from `set_route` until first heartbeat success
   - Connected: heartbeat success + ≥1 successful packet round
     trip
   - Error: any failure from `set_route` or sustained
     heartbeat-loss
3. Recovery sheet (brief §4.1) bound to the same error signal.

### 5D. Add Route / Add Source unified entry point
1. One sheet/modal, four tabs (Paste / Scan-or-Drop / LAN / File).
   Reused for both flows; parametrized by URI scheme.
2. Trust-prompt modal shared.
3. Deep-link receiver per platform.

### 5E. Status, Settings, Publisher
1. Status: top health card + three accordions on every platform.
2. Settings: 8 groups. Engine-driven toggles bind to ABI; UI-only
   toggles persist in platform prefs. Panic wipe wired to existing
   engine wipe + typed-word + delay UI.
3. Publisher: port FRP-5 wizard 1:1 into the new section chrome
   with cyan accent.

### 5F. Real packet tunnel
1. Desktop: `tun-helper` wired to `engine_set_route` (Linux
   `polkit`, Windows `WinTUN`, macOS `utun`).
2. Android: real sing-box driver in `DaalVpnService`.
3. iOS: NE `packetFlow.readPackets/writePackets` loop bound to
   `Libbox.xcframework`. Feature-gate if incomplete.

### 5G. Localization sweep
1. Extract every English string + every new D-2 string into
   `en.json`.
2. FA pass.
3. ICU plurals.
4. RTL flip on every screen body. Editorial chrome stays LTR.

---

## 6. Hard-state inventory

Every flow must have these states designed AND built:

| State | Notes |
|---|---|
| Empty | Connection (no routes), Routes empty, Sources empty, Status (no diag yet), Add Route preview empty, Publisher (no server) |
| Loading | All > 200 ms; > 3 s explainer; > 15 s Cancel |
| Error | Connect failure, source refresh, route import, file-format invalid, malformed deep-link, engine version mismatch (full-screen blocker), permission denied (with re-ask) |
| Locked | Vault-locked PIN gate before Connection / Routes / Sources / Status / Settings |
| Pre-permission | One-screen explainers before VPN / Camera / Notifications / Local network |
| Migration | private codename → Daal import success / failure / "do this later" |
| Mid-onboarding intent hold | `daal://` clicked while onboarding is in progress; breadcrumb on resume |
| Quit while connected (desktop) | Confirm modal |
| Sleep/wake | "Reconnecting…" banner |

---

## 7. Acceptance criteria

D-2 is internally "done" when **all** of the following hold. **No
publishing happens at this milestone** — that is D-3.

### 7.1 Cross-platform
- [ ] Brand tokens generated for all three platforms from
      `client-shared/tokens/colors.json`. CI emits drift warnings if
      outputs diverge from the source JSON.
- [ ] Strings catalog: zero hard-coded user-visible strings on any
      platform. CI grep proves it.
- [ ] FA pass: every English string has an FA counterpart;
      reviewed by a native speaker; live-flip works on every
      screen.
- [ ] Phoenix-button motion respects `prefers-reduced-motion` /
      OS reduced-motion on all platforms.

### 7.2 Onboarding
- [ ] Two-path onboarding shipped: recipient (R0..R4) and
      publisher (P1..P4) paths complete end-to-end.
- [ ] Migration prompt (M0) detects an existing legacy install on
      the platform-specific data path; imports routes, sources,
      mode, lifeline preference. Failure falls through to normal
      onboarding.
- [ ] Time-to-first-connect from clean install ≤ **90 s** on a
      smoke device, recipient path, with one well-formed test
      Source URL pasted.

### 7.3 Connection
- [ ] Connect actually connects via real packet tunnel on Desktop
      Win+Linux + Android; macOS may ship engine-only-tunnel with
      banner; iOS may ship feature-gated.
- [ ] Route picker exposes routes by human name only.
- [ ] Connection failure shows the recovery sheet with all four
      options live.
- [ ] Connected state on Desktop and Android shows the 3-D
      phoenix breathing.

### 7.4 Routes / Sources
- [ ] Add Route flow complete: Paste, Scan/Drop, LAN, File.
- [ ] Add Source flow complete (same four sub-flows scoped to
      `daal://sub/...`).
- [ ] Trust prompt full-screen on mobile, modal on desktop, with
      EN+FA word grid; only three explicit choices.
- [ ] Deep-link entry: `daal://sub/...` from outside the app
      routes to Add Source with URL pre-filled, even when vault
      is locked or onboarding is mid-flight.

### 7.5 Status
- [ ] Health card top + three accordions render correct data from
      `engine_diagnostics` and `engine_diagnostics_explain`.
- [ ] "Export diagnostics" produces redacted JSON; CI test scans
      the export for known destinations / IPs / fingerprint hex.

### 7.6 Settings
- [ ] All 8 groups render; toggles bind to the right ABI calls.
- [ ] Panic wipe three-step confirm with typed word + delay
      window with Cancel works as specified.
- [ ] Detailed-notifications toggle: lock-screen previews always
      use generic copy.
- [ ] Language switch is live (no app restart).

### 7.7 Publisher (advanced)
- [ ] Toggle reveals/hides the Publisher section.
- [ ] All seven existing wizard screens render with cyan accent
      treatment; functionally unchanged.
- [ ] Publisher handoff screen produces the QR + PIN + 6-word
      fingerprint grid (EN + FA) for the publisher's own key.

### 7.8 Tray + desktop background behavior
- [ ] Tray menu present on Win/Linux/macOS with status indicator,
      quick connect/disconnect, current route name, mode submenu.
- [ ] Close-to-tray default with the one-time first-close
      explainer.
- [ ] Quit-while-connected confirm modal.
- [ ] Autostart toggle works (Win: registry / startup folder;
      Linux: `.desktop` autostart; macOS: launch agent).

### 7.9 Repo discipline (new)
- [ ] `VERSION` is **still `0.1.0`** at end of D-2.
- [ ] No tags, no release artifacts, no public-repo commits added
      during D-2.
- [ ] `hastaan/daal` `main` is unchanged from the D-1 snapshot.
- [ ] D-2 work lives on a private branch / private mirror only.

---

## 8. Differences from the previous D-2 draft

| Area | Previous draft | This revision |
|---|---|---|
| `VERSION` during D-2 | bumped to `0.2.0` | **stays `0.1.0`** until D-3 |
| Release at end of D-2 | `Daal v0.2.0` published | **internal-only milestone**, no publishing |
| Tag cut | `v0.2.0-alpha` → `-beta` → `v0.2.0` during D-2 | none until D-3 |
| Public repo | receives D-2 commits + tags | unchanged from D-1 |
| Acceptance §7.9 | n/a | new "repo discipline" section |
| Roll-out plan | alpha → beta → release inside D-2 | internal alpha soak only; release is part of D-3 |

Everything else from the previous D-2 draft (scope, workstreams,
hard-state inventory, design DNA anchors in `/home/daal/src/`, brand
tokens, phoenix-button motion, FA review veto) is preserved.
