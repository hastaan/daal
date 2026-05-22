# Phase 35 (FRP-6) — Recipient UX + Product Readiness

**Status:** SHIPPED 2026-05-03 across 7 commits. Handover at `docs/handovers/frp-6-handover.md`.
**Roadmap line:** *"Tauri wizard screens 0–6, with a 'CDN-fronted candidates: coming in V1.6' line on the toolbox screen instead of a broken option."* (recipient-side surfaces) — `daal-roadmap-v3-supplement-diaspora-helper.md` §21.1; *"Used REALITY because UDP is blocked on this network."* — supplement §13.1 step 8.
**Supplement target:** v2.3.7.
**Engine version target:** `daal-core 0.9.0+v3-share` **(UNCHANGED — UI-side phase).**
**ABI release surface target:** **48** **(UNCHANGED — UI consumes existing diagnostics surface).**
**Maturity:** UI phase. Lands the recipient-side UX bound to FRP-3's `Explanation` struct.
**Predecessor:** Phase 31 (FRP-3) — `Explanation` struct locked; Phase 34 (FRP-4b) — signed RelayPacks producible.
**Successor:** Phase 36 (FRP-7) — V1.5 pilot soak runs against this UX.

## 1. Strategic frame

The recipient UX is the place RelayPack breadth becomes visible to the family member in Iran. It must do four things:

1. **Import** — accept the QR scan from the FRP-side wizard; verify the bundle; surface a TOFU prompt the first time a publisher is seen.
2. **Show route health** — render the current decision in plain language, bound to FRP-3's `Explanation` struct.
3. **"Why this route"** — same surface, expanded view: shortlist, failures, active cooldowns, network signals.
4. **RelayPack explanation** — surface what a RelayPack is to a non-technical user in EN and FA.

FRP-6 is **product readiness** for V1.5: by the end of this phase, a non-technical Iranian family member can scan the QR their diaspora relative sent them, see "Connected via REALITY" on screen, and (when something fails) see a one-sentence explanation of what changed.

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Platforms in scope | Android (full happy path), desktop (full happy path), iOS (placeholder confirming nothing owed at V1.5; reaffirmed post-V3 per supplement §21.5). |
| `Explanation` struct binding | UI consumes the JSON shape locked in FRP-3 §5. No reshaping at the UI layer. |
| Diagnostics export source | The engine's `engine_export_diagnostics` ABI (already shipped at 3-Soak; no new release symbol). UI parses the existing JSON. |
| TOFU prompt | Shows publisher fingerprint EN/FA wordlists + hex; user confirms once; pinned thereafter. Reuses `bundle/go/publisher/keystore.go` fingerprint format. |
| Languages | EN + FA. FA copy reviewed by native speaker. |
| Route health surface | Persistent banner: "Connected via X" (route family + EN/FA-localized). Tap to expand. |
| Expanded view | Renders `Explanation`: pick (route family, exposure mode), shortlist (race order + outcome), failures (classification + cooled tag), active cooldowns (tag + reason + remaining time), network signals, memory hint, plain-language reason. |
| RelayPack explanation surface | Modal accessible from "About this connection" link. EN and FA copy locked: 3 paragraphs, ~150 words each. |
| Notifications | None at V1.5. The recipient client does not push notifications about route switches; the persistent banner is enough. |
| Mobile-vs-desktop UI parity | Both platforms render the same `Explanation` shape; visual treatment differs (mobile compact, desktop more detailed). |
| Telemetry | Zero. UI never reports user actions. Verified by Android `OPSecTest.kt` + Tauri allowlist. |
| iOS V1.5 placeholder | A short text on the "Settings → About" screen: "iOS support for FRP-published routes is post-V3 per the project roadmap. iOS clients connect to existing trust-pinned publishers normally." |

## 3. Locked invariants

Tracks invariants 1–16 inherited. Phase-specific:

17. **No engine release symbols added.** ABI count stays 48; UI consumes existing diagnostics.
18. **`Explanation` struct shape unchanged.** FRP-6 binds to FRP-3's locked struct verbatim.
19. **TOFU is one-tap.** First time only; pinned thereafter; surfaces fingerprint in EN, FA, and hex.
20. **No background analytics.** No wake-lock for telemetry; no probe scheduler beyond the selector's normal pipeline.
21. **EN/FA parity.** Every user-facing string has both translations; missing translation is a compile-time error in the build.
22. **Position B preserved.** No third-party crash reporter; no analytics SDK; no opt-in tracker. Verified by `OPSecTest.kt` and Tauri allowlist.
23. **Route health banner is real-time.** Updates within ≤1 s of a `engine_export_diagnostics` change. Verified by integration test.
24. **iOS V1.5 surface is a placeholder.** No iOS-specific recipient UX work shipped at V1.5; the placeholder is the only user-facing iOS change at FRP-6.
25. **No selector logic in UI.** UI is a thin renderer of `Explanation`; never makes shortlist / cooldown decisions itself.

## 4. Sub-task breakdown

| #  | Task |
|----|------|
| 0  | Replace any prior FRP-6 stub with this locked spec at `phases of development/35-phase-frp-6-recipient-ux.md`. |
| 1  | Read inputs end-to-end: FRP-3 handover (`Explanation` struct golden files); supplement §13.1 step 8, §14.5; existing `client-android/` import surface; existing `client-desktop/` UI; `specs/qr-fountain-v1.md`; `bundle/go/publisher/keystore.go` (for fingerprint format). |
| 2  | **Android — Import flow.** Author Compose screens at `client-android/app/src/main/java/.../wizard/recipient/`. Screens: QR scan (camera permission); fragment-collection progress (per `qr-fountain-v1.md`); bundle parse + signature verify; TOFU prompt (first time); pinning confirmation. |
| 3  | **Android — Route health banner.** Persistent foreground banner in the main screen. Renders `Explanation.pick`. Tap expands to full `Explanation` view. Updates via the `engine_export_diagnostics` flow already in place. |
| 4  | **Android — Expanded "Why this route" view.** Renders the full `Explanation`: pick, shortlist (race order + outcome chips), failures (classification chips), active cooldowns (chips with countdown), network signals, memory hint, plain-language reason. EN + FA. |
| 5  | **Android — RelayPack explanation modal.** Bottom-sheet modal accessible from the expanded view. 3 paragraphs in EN, 3 in FA; explains "what a RelayPack is", "what your diaspora relative did", "what the selector does for you". |
| 6  | **Desktop — Import flow.** Tauri commands at `client-desktop/tauri/src-tauri/src/recipient/` + frontend screens at `client-desktop/tauri/src/recipient/`. Mirrors Android steps but adapted for desktop input (QR scan via webcam OR paste from file). |
| 7  | **Desktop — Route health banner.** Status bar item; click expands. Same `Explanation` data. |
| 8  | **Desktop — Expanded view + RelayPack explanation modal.** Mirrors Android. |
| 9  | **EN/FA copy.** Locked at `client-android/app/src/main/res/values/strings.xml`, `values-fa/strings.xml`; `client-desktop/tauri/src/i18n/{en,fa}/recipient.json`. Native-speaker FA review. |
| 10 | **iOS placeholder.** One-line edit to `client-ios/.../about.swift` (or wherever the about screen lives) adding the placeholder text from §2 above. |
| 11 | **OPSEC tests.** `client-android/app/src/test/.../OPSecTest.kt` extended; `client-desktop/tauri/src-tauri/tests/recipient_opsec_test.rs` added. Forbid: any analytics SDK, any crash reporter, any `http.client.Get` to non-publisher endpoints. |
| 12 | Final regression sweep: Android `./gradlew test connectedAndroidTest`; Desktop `cargo test`, `pnpm test`; `nm` returns 48; FRP-7 gate verdict; handover. |

## 5. UI shapes (locked)

### 5.1. Android persistent banner

```
┌──────────────────────────────────────┐
│ ● Connected via REALITY              │ ← tap to expand
│ Hetzner Frankfurt                    │
└──────────────────────────────────────┘
```

FA equivalent: `متصل از طریق REALITY` (right-to-left layout enforced).

### 5.2. Expanded "Why this route" view (Android)

```
Picked: REALITY (vless-reality)
  exposure mode: direct VPS
  family class: VPS-native
  probing risk: low

Race order:
  1. vless-reality       success (12 ms)
  2. websocket-tls       not started

Recent network signals:
  • UDP appears blocked on this network

Memory hint:
  REALITY worked here within last 24h

Reason:
  Used REALITY because UDP is blocked on this network.
```

FA equivalent localized; visual elements preserved.

### 5.3. RelayPack explanation modal — EN copy (locked)

> **What is a RelayPack?**
> A RelayPack is a small set of internet routes your diaspora family member set up for you on a server outside Iran. Your Daal app picks the route that works best on your network right now. If one route stops working, Daal switches to another automatically.
>
> **What did your relative do?**
> They rented a small server (about €5/month) and ran a one-time wizard that sets the server up safely. The server is yours; nothing leaves their machine; nobody else uses your routes.
>
> **What does your Daal app do?**
> When your network changes — new Wi-Fi, mobile data, café — Daal runs five small probes to see what works on this network. It picks the best route from your RelayPack and explains its choice in one sentence. If a route fails, it cools down and tries another. No information leaves your phone.

FA copy locked separately; reviewed by native speaker.

## 6. Build matrix at FRP-6 exit

```
$ cd client-android && ./gradlew test                           # green
$ cd client-android && ./gradlew connectedAndroidTest            # green (with emulator)
$ cd client-android && ./gradlew lint                            # green
$ cd client-desktop && cargo fmt --check
$ cd client-desktop/tauri/src-tauri && cargo test
$ cd client-desktop/tauri && pnpm test
$ cd client-desktop/tauri && pnpm build
$ # iOS placeholder check
$ rg -n "iOS support for FRP-published routes" client-ios/        # ≥1 match
$ nm /tmp/libdaalcore.so | grep ' T engine_' | wc -l            # 48 (UNCHANGED)
$ # OPSEC: no analytics SDKs
$ rg -nE 'firebase|crashlytics|sentry|amplitude|mixpanel' client-android/app/build.gradle*
$ rg -nE 'firebase|crashlytics|sentry|amplitude|mixpanel' client-desktop/tauri/package.json
$ # both: no matches
```

## 7. Spec deliverables

**0 NEW.** All work is implementation against existing `Explanation` struct (FRP-3) + diagnostics ABI (3-Soak).

**1 AMENDED:**
- `specs/android-client-v1.md` — gains a §"RelayPack recipient UI" section describing the import flow + banner + expanded view shapes.

## 8. Out of scope (deferred)

- iOS recipient UX — post-V3 per supplement §21.5.
- Push notifications about route switches — V2 (recipient mobile UX).
- Cell-aware UI (peer recommendations) — **FRP-11.**
- Sub-key rotation prompts — **FRP-7.5** (FRP-6 surfaces sub-key fingerprints in TOFU; live rotation prompts come at FRP-7.5).
- Freshness-endpoint update notifications — **FRP-8.**
- Modifier opt-in toggles — **FRP-12.**

## 9. Handover requirements

The FRP-6 handover must contain:

1. Status: SHIPPED. Date.
2. Android screens enumerated with screenshots.
3. Desktop screens enumerated with screenshots.
4. iOS placeholder confirmed (file path + line).
5. EN/FA copy review note.
6. Real-time banner update test result (≤1 s latency).
7. OPSEC grep results.
8. `nm` count = 48 unchanged.
9. FRP-7 gate verdict.

## 10. Track ordering rationale

FRP-6 is the last "code-only" V1.5 phase before the soak (FRP-7). It binds to FRP-3's `Explanation` struct (locked) and consumes FRP-4b's signed RelayPacks (producible). Putting it before FRP-7 means the pilot soak runs against the actual UX a real user will see, not a developer test harness — which is the only honest way to test "does the family member understand what's happening when REALITY switches to WebSocket-TLS at 11pm Tehran time".

End — locked at FRP-track planning. Next: FRP-7 (rotation + V1.5 pilot soak).
