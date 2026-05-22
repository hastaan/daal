# Daal — GUI Design Brief, v2

> **Supersedes** `daal-gui-design-brief.md`. This version folds in the
> three reference HTMLs in `/home/daal/src/` as canonical visual DNA,
> renames the product to Daal end-to-end, renames
> "Subscriptions" to "Sources" for users, and adds the missing hard
> states (failure, locked, migration, panic, errors) plus
> implementation-side notes (sRGB fallbacks, asset wiring).
>
> **Reference HTMLs (visual + interaction DNA — read these first):**
> - `/home/daal/src/on-boarding.html` — two-path onboarding
> - `/home/daal/src/daal-mobile-app.html` — main app, 5 sections
> - `/home/daal/src/daal-desktop.html` — desktop, sidebar + rail
>
> **Brand assets (use as-is, do not redraw):**
> - `/home/daal/src/daal-flat-no-bg.svg` — primary mark, vector
> - `/home/daal/src/daal-flat-no-bg.png` — same, raster
> - `/home/daal/src/daal-3d-no-bg.png` — 3-D bevel variant for the
>   connect-button hero state
> - `/home/daal/src/daal-flat-bg-033E51.png` — flat on brand teal
> - `/home/daal/src/daal-3d-flat-bg.png` — 3-D on brand teal
> - `/home/daal/src/favicon-512x512.png` — favicon source

---

## 0. Project at a glance

- **Product name:** **Daal** (Persian: "دال"). Successor to the
  retired private codename. Every user-visible string says *Daal*; no
  retired-codename string ships in v1.
- **What it is:** an anti-censorship client. The user installs it,
  gets routes from a publisher (or imports/receives them), and turns
  on the connection. Underneath: a tunnel + smart route picker. To
  the user it should feel like *"I press one button and the internet
  works again."*
- **Users:** non-technical people in censored regions (primarily
  Iran), and diaspora helpers running a server abroad for family
  back home. **Persian (RTL)** and **English (LTR)** are first-class
  from day one.
- **Form factors:**
  - **Desktop** (Windows, Linux, macOS) — Tauri shell, React UI
  - **Mobile** (Android, iOS) — native (Compose / SwiftUI)
- **Brand:** see §10. Short version: **deep teal + warm gold**, gold
  phoenix shield with "دال" calligraphy, editorial serif headings,
  calm dignified tone, never "VPN bro."

### Design north star

A first-time user, with no instructions, opens the app and within
**60 seconds** is either (a) connected, or (b) on a screen that tells
them *exactly* what to do next. Every screen should be obvious by
looking. Normal screens should not need more than two sentences of
explanatory copy; **security disclosures** (trust prompt, panic wipe,
PIN setup, key rotation) may use expandable "Tell me more" details
when the user actively asks for them.

---

## 1. Hard product constraints (do not violate)

These come from the engine's threat model and security spec. They
constrain the UI even when they look unfriendly.

1. **Source URLs are never displayed once added.** A "Source" is the
   user-facing name for a Subscription. Once added, the user manages
   it by display name and refresh history. URLs are write-only.
2. **No analytics. No telemetry. Daal does not send analytics or
   usage data to a Daal server.** *(Note the careful wording — we do
   not say "Daal cannot see your traffic," because the local engine
   handles your traffic. We promise no remote analytics, no remote
   server.)* Everything in the UI must work offline, end-to-end, with
   the engine alone. No Google Fonts, no CDN, no external network
   calls of any kind from the UI layer.
3. **Trust prompts are mandatory and modal.** When the engine returns
   `VerdictTrustPromptNeeded`, the UI MUST present it with the EN
   BIP-39 words and the FA Persian words side-by-side. The user must
   be able to read the words out loud to a friend on the phone.
4. **No "remember me" / "auto-trust" shortcut on the trust prompt.**
5. **Diagnostics are redacted.** Route IDs, fingerprints, mode,
   state, timestamps — yes. Destinations, IP addresses, content of
   any kind — no.
6. **Panic / emergency wipe must always be reachable in ≤ 2 taps from
   anywhere in the app**, including from a locked-vault state.
7. **PIN unlock has no biometric fallback** (Argon2id is the gate).
   Biometrics may be added later as an *additional* factor, never as
   a replacement.
8. **RTL is not a translation, it's a mirror.** Every layout must
   work visually in RTL. Test FA before shipping any screen. The
   reference HTMLs already model this correctly: `setLang('fa')`
   flips `dir="rtl"`, swaps the font stack to Vazirmatn, swaps
   Western digits for Persian-Indic, mirrors arrows.
9. **Permissions are requested only when needed**, never at app
   launch.
   - VPN permission: on first **Connect** tap.
   - Camera permission: on first tap of **Scan QR**.
   - Notifications permission: on first toggle of any notification.
   - Local network / mDNS: on first tap of **Receive from a friend
     (LAN)**.
   Each permission ask is preceded by a one-screen explainer in
   plain language. Sample copy:
   *"Daal needs the VPN permission to route your traffic through the
   engine. This lets Daal create a local tunnel. Daal does not use
   analytics or send usage data to a Daal server."*
10. **Routes always have human-readable names.** The raw `route_id`
    is never the primary label anywhere. See §5.1.
11. **Cross-platform parity is a target, not a snapshot.** This brief
    describes the destination state. The current code has gaps
    (notably iOS, stale against `daal-core 0.9`). Designer designs
    for the target IA on every platform; engineering catches up.
12. **LAN URL exposed only during active sharing.** A LAN URL may
    include a local IP. Show it only on the active share screen,
    never persist, never export, never mention in diagnostics.

---

## 2. Information architecture (shared across all platforms)

**Five primary sections everywhere, plus Publisher as an advanced
module.** Same five names, icons, and order on every platform.
Publisher is hidden until the user opts in via Settings → Advanced
(see §4.6).

| # | Section | Engine surface it covers | What the user thinks it's for |
|---|---|---|---|
| 1 | **Connection** | engine_set_route / engine_clear_route (the user-facing "connect" / "disconnect" is an app-level concept on top of these) | "Turn it on. See the green light." |
| 2 | **Routes** | route list + import + share-with-friend | "My routes. Add a new one. Send one to a friend." |
| 3 | **Sources** | subscription_list / add / refresh / remove (engine-internal name remains `subscription`; **user-facing name is "Sources"**) | "The publishers I follow." |
| 4 | **Status** | diagnostics + why-this-route + budgets + health | "Is it working? Why this route?" |
| 5 | **Settings** | mode, lifeline, PIN, language, panic, about | "Configure & emergency tools." |
| 6 | **Publisher** *(advanced; off by default)* | wizard, key rotation, publisher handoff / bundle distribution | "I publish routes for others." |

**Naming note:** "Sources" is the user-visible label everywhere
(navigation, headings, copy, accessibility labels). The engine ABI,
diagnostics JSON, code comments, and developer docs continue to use
"subscription" / `subscription_id`. The brief is the only place the
mapping is explicit; everywhere else in the UI it is "Sources."

### Navigation pattern per platform

- **Mobile:** bottom nav bar with 5 icons (Connection / Routes /
  Sources / Status / Settings). Publisher is hidden behind a Settings
  → Advanced toggle. Trust prompt is always a full-screen sheet.
- **Desktop:** vertical sidebar (collapsible) with the same six
  entries (Publisher dimmed with an "Off" badge until enabled).
  Sidebar collapses to icon-only on narrow windows. Each item has a
  keyboard shortcut shown inline (⌘/Ctrl+1..6). The reference desktop
  HTML demonstrates this verbatim.
- **System tray (desktop only):** quick connect/disconnect, current
  route name, mode picker. Click tray → focuses Connection screen.
  Tray icon color reflects state.

---

## 3. Onboarding (first-launch flow)

This is a **two-path onboarding**: the second screen branches the
user into the **recipient** flow ("I want to connect") or the
**publisher** flow ("I want to help others"). Both paths converge on
the main app. The branch is reversible from Settings → Advanced.

The reference is `/home/daal/src/on-boarding.html`. The designer
should treat that HTML as the canonical interaction blueprint and
refine the visual layer on top of it.

**Goal:** a brand-new user with no routes can finish onboarding in
**under 90 seconds** and end up either (a) connected (recipient) or
(b) sharing a subscription with their family (publisher).

### Onboarding sequence

**Shared start (everyone):**

0. **Migration check** *(only if applicable)* — the installer detects
   an existing Daal install on the same device. If found, show:

   > *"Welcome back. We found your existing Daal setup. Daal is the
   > new name and a refreshed app. Would you like to import your
   > routes, sources, and settings?"*
   >
   > **Import everything** *(primary)* · **Start fresh**
   > *(secondary, with a small "Your old data will not be deleted"
   > reassurance)*

   On import success: skip directly to a "You're ready" screen. On
   import failure: fall through to the normal onboarding with a small
   toast and a Settings → Advanced → Migration retry entry.

1. **Welcome** — logo at full scale, one-line tagline, "Get started"
   button, language picker (EN / فا) prominently. RTL flips at this
   step.

2. **Who are you?** — the branch.
   - **"I want to connect"** *(primary, visually weighted as the
     default for the typical user inside a censored region)*
   - **"I want to help others"** *(clear and well-designed but
     visually secondary)*
   - **"I'm not sure yet"** as a small text link → routes to
     recipient with a banner that lets them switch.

   *Design note (correcting v1 brief):* the original brief framed
   recipient and publisher as equally weighted. Real-world usage will
   be heavily skewed toward recipient; making "I want to connect"
   visually primary cuts onboarding friction for the majority while
   keeping publisher discoverable for diaspora helpers.

**Recipient path (4 screens):**

R1. **What is Daal?** — three short claim cards (no jargon):
- *"A way to reach. Daal helps you reach the open internet when your
  country blocks it."*
- *"Routes are how it connects. A route is the path your traffic
  takes. You can get them from a publisher, a friend, or a file."*
- *"Your routes stay yours. They live on this device. Daal does not
  send analytics or usage data to a Daal server."*

R2. **Set a PIN** *(optional)* — Argon2id vault vs OS keystore
choice. Honest copy on the trade-off: *"A PIN protects your routes
if someone takes your phone. You'll enter it each time you open
Daal."* "Skip — use device keystore instead" is not buried.

R3. **Add your first route** — four equal-weight tiles:
- **Subscribe to a Source** *(recommended; flagged with a small
  "Recommended" pill)* — paste a `daal://` link or scan a QR.
- **Receive from a friend** — LAN handoff or 6-digit PIN.
- **Import a file** — open a `.sbp` from this device.
- **Skip for now** — empty home, with the same four tiles inline as
  the empty state.

R4. **Ready when you are.** — the phoenix shield breathing a soft
gold halo, tappable. Below it: a route chip showing the selected
route as `<Source name> · <route nickname>` (never the raw ID), and
one helper line: *"First connect asks for VPN permission once."*

**Publisher path (4 screens):**

P1. **Welcome, publisher.** — pub-tag accent (cyan, not gold) is
introduced here and stays through every publisher surface. Two
claim cards:
- *"You sign each route. Subscribers verify your fingerprint once.
  They trust the publisher, not the network."*
- *"You stay anonymous to Daal. There is no Daal server. Your
  subscription URL goes peer-to-peer, or through whatever channel
  you choose."*

P2. **Name your publisher.** — a real human name, not a domain or
ID. Example chips below the input: *"Family", "Maman & Baba",
"Tehran group", "Class of 2018"*. *"You can change this later. Keep
it personal — your people will recognise it."*

P3. **Where will routes run from?** — paste a VPS endpoint, or
auto-detect when the user has the Daal CLI running on a reachable
VPS. List shows `name · location · provider · last-seen` with a
"Detected" tag. *"I'll set up later — show me the dashboard"* link
never blocks onboarding.

P4. **Share with your people.** — a QR (encoding the subscription
URL), a 6-digit PIN, and the publisher's own 6-word fingerprint
shown side-by-side in EN BIP-39 + FA Persian (so the publisher can
read them aloud on a phone call so the recipient can verify the
trust prompt later). One primary CTA: *"Send subscription link"*
(opens system share sheet).

### Empty-state policy

If the user skipped step R3, every subsequent screen that requires a
route shows a **helpful empty state** with the same four "add a
route" options inline — never a dead end, never a generic "no data."

---

## 4. Section-by-section spec

For each section: **purpose**, **primary action**, **what's on the
screen**, **secondary actions**, **edge cases**.

The reference for the main app is
`/home/daal/src/daal-mobile-app.html` (mobile) and
`/home/daal/src/daal-desktop.html` (desktop). They model the
finished IA. The text below adds detail and the missing hard states.

---

### 4.1 Connection (the "on/off" screen)

**Purpose:** the daily-driver screen. 95 % of users will only ever
see this one.

**Primary action:** one **giant phoenix-shield button** in the
center. State-driven (states defined in §10.5):

| Engine state | Button label | Phoenix visual |
|---|---|---|
| Disconnected | "Connect" | Flat phoenix shield, neutral palette |
| Connecting | "Connecting…" | Phoenix shield, soft pulse |
| Connected | "Connected" | 3-D phoenix shield, gold halo breathing |
| Error | "Try again" | Shield with subtle red ring |

**On the screen, in priority order:**

1. The big button.
2. **Currently selected route** — small chip below the button,
   tappable to change. Format: `<Source name> · <route nickname>`.
3. **Route picker** when tapped: a sheet/list showing imported
   routes grouped by trust class (Trusted / Prompted / New /
   Emergency). Each row: Source name + nickname + trust badge.
4. **Mode chip** — small, bottom-right of the button area. Shows
   current mode (Normal / Bulk / Lifeline / Lifeline-strict).
5. **One-line status** below the button: e.g. *"On Wi-Fi · network
   seen before · pointers rotated · valid 14 days"* — one line,
   redacted, plain language.

**Pull-down / scroll-up reveals (mobile)** OR **expandable card
(desktop):**

- Why this route? (link to Status → Why this route)
- Pointer-rotation banner (only when expiring/expired)
- Lifeline-strict banner (only when active)
- Rate-limit prompt (only when threshold crossed)

**Do NOT put on this screen:** route budgets table, route health
table, source list, diagnostics export, PIN unlock, network-id line.
Those go to Status / Settings.

**Edge cases / hard states:**

- **No route imported** → giant button replaced by an empty state
  with the four "add a route" tiles from R3.
- **Vault locked** → giant button replaced by a PIN unlock card.
  After unlock the button renders.
- **Engine version mismatch** → full-screen blocker until app is
  updated. (The current "yellow header banner" is too subtle.)

**Connection failure recovery:** *(critical — design carefully)*

If a connect attempt fails, show a recovery sheet with a clear
primary path and three fallbacks, in this order:

1. **Try again** *(primary, large)* — retries the same route.
2. **Try a different route** — opens a compact route picker
   pre-sorted by health (best first), excluding the failing route.
3. **Refresh Sources** — runs subscription_refresh on all sources,
   then offers the picker again.
4. **Switch to Lifeline mode** — last resort; degrades capability
   but maximizes reach. Confirm modal explains the trade-off in one
   sentence.

A small *"Why did this fail?"* link opens Status → Why this route
pre-scrolled to the last failure. Never show raw engine error codes
on this sheet — they go behind a "Show details" disclosure.

---

### 4.2 Routes

**Purpose:** the user's library of routes. Manage them; import new
ones; share them with friends.

**Layout:** title + search + "+ Add route" button. List grouped by
trust class. Each row: Source name + nickname + trust badge +
last-used relative time.

**Empty state:** the four "add a route" tiles inline.

**Route detail screen:** publisher info card with the visual
fingerprint (the abstract image, deterministic from the fingerprint
hash); editable nickname; trust badge with "View fingerprint words"
sheet (EN BIP-39 + FA Persian, monospace, side-by-side); source
provenance ("from Source X" / "imported from file" / "received from
friend on YYYY-MM-DD"); actions: **Use this route** · **Share** ·
**Remove** (Tier 2 destructive — see §5).

**Add route flow** (the "+ Add route" button) — single sheet/modal,
four large tabs:

1. **Paste a link** — text input for `daal://...` URIs; auto-detect
   from clipboard with a one-tap "Use clipboard" affordance.
2. **Scan QR** *(mobile only)* — camera viewfinder for static and
   animated QR. Fountain decoder progress: *"Reading frame 14 of
   ~22"* with an animated arc.
   - **Desktop replaces this tab with "Paste / Drop QR image"**:
     drop an image file, paste from clipboard, paste raw frame data.
3. **Receive from a friend (LAN)** — mDNS browse list + 6-digit PIN
   entry. Shows nearby devices by display name, never IPs.
4. **Import file** — system file picker (`.sbp`).

After any of these, if the engine returns trust-prompt-needed, route
to the **Trust Prompt** modal (§4.7).

**Route import errors:** show a plain-language sentence with at
least one suggested next action ("Try a different file" / "Re-paste
the link" / "Refresh the Source it came from") and a "Show details"
disclosure for the engine error code.

**Share route flow** (from a route detail) — generates a session,
shows: a 6-digit PIN in big font; a static QR; an animated QR option
for routes too large for static; a LAN URL in plain text for
read-aloud (§1.12: only shown during the active session, never
stored, never exported); an "End sharing" button that wipes the
bundle bytes.

---

### 4.3 Sources

**Purpose:** manage the user's "I follow this publisher" relationships.

**Layout:** title + "+ Add Source" button. List rows: publisher
display name (bold) + visual fingerprint thumbnail + last refresh
relative time + route count + outcome icon + chevron.

**Source detail:** publisher info (same fingerprint widget as route
detail); **the URL is never displayed** (hard rule §1.1); last
refresh timeline (last 7 outcomes as colored dots); routes from this
Source (list); actions: **Refresh now** · **Pause** · **Unsubscribe**.

**+ Add Source flow:** the same four-option sheet as Add Route,
scoped to subscription URLs (`daal://sub/...`).

---

### 4.4 Status (the "is it working? why?" screen)

**Purpose:** the diagnostic surface. Most users never visit it; when
they do, they're usually upset and need to know what's wrong.

**Top:** big visual health card — Green ("All systems normal."),
Amber ("Some routes are limited.", expandable), Red ("Daal cannot
reach the open internet.", expandable, with next-step suggestions
that mirror the recovery sheet).

**Below, three collapsed accordions:**

1. **Why this route?** *(expanded by default when connected)* —
   active route, one-sentence reason, skipped routes (`family →
   reason`), last failure if any.
2. **Network** — current network id (small hash like `wifi-a3f2`
   plus the human label "Wi-Fi" / "Cellular"); per-network memory
   ("seen 3 times"); pointer-rotation banner (5-state).
3. **Routes & budgets** — compact table: route nickname,
   mode-eligibility, budget tag, used/total bytes; route health
   (success rate over last hour).

**Bottom:** **"Export diagnostics"** button → confirm modal
explaining what's in the export ("redacted; no destinations, no
content, no IPs") → save `.json` or copy to clipboard.

---

### 4.5 Settings

Sections (one group per heading):

1. **Connection mode** — picker (Normal · Bulk · Lifeline ·
   Lifeline-strict, segmented mobile / radio cards desktop), each
   with a one-line plain-language description; auto-promotion
   toggle; allow-bulk-capable-session toggle.

2. **Security** — PIN: Set / Change / Remove; storage profile read-
   only display + Convert; Lock now (vault profile only).

3. **Language & region** — EN / فا live-flip; "Use system language"
   toggle; date/time format follows OS.

4. **Notifications** *(desktop & Android; iOS lives in OS
   Settings)* — toggles for: route burned, source refresh failure,
   rate-limit threshold, pointer rotation needed; **Detailed
   notifications** toggle (default OFF) — when OFF, all
   notifications use generic copy ("Daal needs your attention"),
   when ON they may include Source / route names. **Lock-screen
   previews always use generic copy regardless of this toggle.**
   Master "Quiet mode" toggle.

5. **Startup** *(desktop only)* — "Start Daal when I sign in" (off
   by default); "Start minimized to tray" (only enabled when
   autostart is on).

6. **Advanced** — "I am a publisher" toggle (reveals the Publisher
   section in the nav); engine log level (warn / info / debug);
   reset onboarding (re-runs §3 next launch); **Migration** entry
   (visible only if a previous Daal install is detected and import
   is incomplete).

7. **Emergency** — always last, always visible, always red.
   - **Panic wipe** — three-step confirm (typed word + final
     confirm + short delay window with a Cancel still available
     during the delay). Wipes all routes, sources, secrets, logs.
     Returns to Welcome.
   - Reachable in ≤ 2 taps from any screen via a small floating
     shield-icon at the bottom-right (the duress button). Designer
     decides how to make it accessible without being scary or
     accidentally tappable.

8. **About** — app version, engine version, build date, license
   (GPL-3.0), link to source.

---

### 4.6 Publisher *(advanced, hidden by default)*

For users who run their own publisher. Hidden until "I am a
publisher" is toggled in Settings → Advanced. Visually marked with
the cyan accent introduced on the publisher onboarding path so users
always know they're in advanced surface.

Includes: Wizard (the existing 7-screen FRP-5 flow), Key rotation,
Subkey lifetime, **Publisher handoff / bundle distribution**
(operator tooling for getting a signed bundle to subscribers,
distinct from the consumer share-a-route flow in §4.2), Cell join.

May eventually split into a separate "Daal Publisher" app —
designer should treat it as a self-contained module to make that
split easy.

---

### 4.7 Trust Prompt (modal, cross-cutting)

Appears whenever the engine returns `VerdictTrustPromptNeeded`.
Always full-screen on mobile, always a centered modal on desktop.
Cannot be dismissed except via one of three explicit choices.

- **Title:** *"Verify this publisher"*
- **Subtitle:** *"Read the words below out loud to the person who
  sent you this. They should match exactly."*
- **Visual fingerprint:** the abstract image (deterministic from the
  fingerprint hash). Large, central.
- **Word grids, side by side:**
  - **English (BIP-39):** monospace, 6 words on a 2×3 grid, large.
  - **Persian:** RTL, monospace, 6 words on a 2×3 grid, large.
- **Below the words:** publisher display name (bold) + spec version.
- **Three buttons:**
  - **Trust this publisher** *(primary, gold)* — adds to Trusted.
  - **Use this route once** *(secondary)* — one-shot.
  - **Cancel** *(tertiary, ghost)*.
- A subtle *"Why am I seeing this?"* link → half-sheet with a
  one-paragraph plain-language explanation.

**Anti-patterns:** no auto-select; no color-coded "safe choice"
(Trust and Cancel must look equally weighted in safety — the user
must read the words); raw fingerprint hex only inside an "Advanced"
disclosure.

This screen is **missing from all three reference HTMLs** — it's
the single highest-priority new screen for the designer.

---

### 4.8 Incoming links, files, and shared text

| Source | Behavior |
|---|---|
| `daal://sub/...` URL clicked from a browser, messenger, or email | Open Daal → **Add Source → Paste a link**, URL pre-filled, preview running. Trust prompt as needed. |
| `daal://route/...` or any other `daal://` schemes | Same: deep-link into the matching Add Route sub-flow with the input pre-filled. |
| `.sbp` file opened from the OS | Open Daal → **Add Route → Import file**, file already loaded, preview running. |
| Text shared into Daal via the OS share sheet (mobile) | Open Daal → **Add Route → Paste a link**, text pre-filled. |
| QR image shared/dropped into Daal | Open Daal → **Add Route → Scan QR** *(mobile)* or **Paste / Drop QR image** *(desktop)*, image pre-loaded, decode running. |

**Rules:**
- Locked vault: hold the intent in memory, show PIN unlock, resume
  on success.
- Mid-onboarding: hold the intent until onboarding finishes, then
  route to its target on the "You're ready" step.
- Never silently auto-import — always preview + trust prompt.
- Show a small breadcrumb on the destination screen
  (*"Opened from a link"* / *"Opened from a file"*).

---

## 5. Cross-cutting UX rules

### 5.1 Route naming (the rule of "no raw IDs")

Every route, Source, and publisher in the UI is shown by a **human
display name**, never by its raw ID. The raw ID lives only in
Status → "Show details" disclosures and exported diagnostics.

**Auto-naming rules** (applied at import time):

- **Routes from a Source:** `<Source name> · <route nickname from
  publisher metadata>` — e.g. *"Pars Relays · Rescue 03"*. If
  publisher metadata has no nickname: *"Pars Relays · route 1"*,
  *"… route 2"*, etc.
- **Routes received from a friend:** `Friend route · <weekday>
  <month> <day>` — e.g. *"Friend route · Mon May 6"*. Multiple from
  the same day get a numeric suffix.
- **Routes imported from a file:** `<filename without extension>`.
  Multiple imports of the same filename get a numeric suffix.
- **Emergency-pool routes:** *"Emergency · <short code>"*, badged
  with the emergency icon.

The user can rename any route at any time from the Route detail
screen. The new name is what shows up everywhere afterward; the raw
ID never changes. Sources follow the same rule: the publisher's
self-declared display name is the default, fully editable.

### Empty / Loading / Error states

- **Empty:** every list screen has a meaningful empty state with a
  clear next action. No "Nothing here" dead ends.
- **Loading:** > 200 ms gets a skeleton or spinner. > 3 s gets
  explanatory copy. > 15 s gets a Cancel button.
- **Error:** plain-language sentence; **at least one** suggested
  next action; raw codes only inside a "Show details" disclosure.

### Destructive & dangerous actions

| Tier | Examples | Pattern |
|---|---|---|
| **1 — Reversible** | Pause Source, disable a notification, log out of share session | Single-step toggle/button. No confirm. Toast on success with **Undo** action visible for 5 s. |
| **2 — Locally destructive** | Remove route, unsubscribe from a Source, end share session, lock vault now, reset onboarding | Confirm modal with the consequence in plain language; **Cancel** as the default-focused button; destructive button labeled with the verb (*"Remove route"*, never *"OK"*). |
| **3 — Irreversible / security-critical** | Panic wipe, delete publisher key, revoke publisher key, rotate publisher key, change PIN with no fallback | Two-step: (a) modal with consequence + a typed confirmation word (*"Type WIPE to continue"*); (b) final destructive button. Always a "How does this work?" link to a longer explanation. Color: red. The action button is never auto-focused. Panic adds a short delay window with a Cancel during the delay. |

Specific call-outs:

- **Remove route** (Tier 2) — if the route came from a Source,
  warn the next refresh will re-add it.
- **Unsubscribe from a Source** (Tier 2) — warn that all routes
  from this Source will be removed too; offer "Keep routes" toggle.
- **Rotate publisher key** (Tier 3) — explain that subscribers
  will see a trust prompt on next refresh and need to re-verify.
- **Revoke publisher key** (Tier 3) — explicit: subscribers who
  don't get the revocation cannot use new routes. Longer "Tell me
  more" disclosure.

### Notifications & banners

- Maximum **one** banner visible at a time.
- Stacking by priority: Engine mismatch > Vault locked > Pointer
  expired > Pointer expiring > Lifeline-strict active > Rate-limit.
- Lower-priority banners are queued, not simultaneous.

### Animation

- Subtle. The phoenix lights up on connect, soft pulse during
  connecting, gentle settle on connected. Never spinning forever.
- Respect `prefers-reduced-motion` on every platform.

### Typography

- Headings: Iowan Old Style (display serif) — established in the
  reference HTMLs. Falls back through Charter / Newsreader /
  Palatino Linotype / Book Antiqua / Palatino / Georgia / serif.
- Body: system humanist sans (-apple-system / BlinkMacSystemFont /
  Segoe UI / system-ui / sans-serif).
- Mono: ui-monospace / SF Mono / JetBrains Mono / Menlo /
  monospace.
- FA: Vazirmatn / IRANSans / Geeza Pro / SF Arabic / Tahoma.
- **All fonts must be bundled locally with the app.** No remote
  font loading, no Google Fonts, no CDN — fonts ship inside the
  binary / app bundle.
- All text must work at 200% zoom (desktop) and "Largest" dynamic
  type (mobile).

### Iconography

- One icon family across all platforms (Lucide / Phosphor / custom).
- Custom icons only for: the phoenix shield (brand mark), the
  publisher cyan badge, the trust-class chips, the visual
  fingerprint generator (already produced by the engine — UI
  consumes the data URI).

### Localization

- Every string in a `.json` / `.strings` / `.xml` resource. Zero
  hard-coded copy.
- FA strings ship in the same release as EN — never lag behind.
- Plurals via ICU MessageFormat or platform equivalent.
- Times shown as relative ("2 hours ago") with absolute on tooltip.

### Accessibility (non-negotiable)

- WCAG AA contrast on every screen, light and dark.
- Every interactive element labelled for VoiceOver / TalkBack /
  NVDA.
- Keyboard navigation on desktop covers every action; visible focus
  rings.
- Touch targets ≥ 44 × 44 pt on mobile.
- Trust-prompt words must be selectable so users can paste them
  into a translator if needed.

---

## 6. Platform conventions to honor

- **Android:** Material 3 motion + back-button handling. Bottom
  nav. Foreground service notification when connected.
- **iOS:** SF Symbols where they fit; Dynamic Type; Form/List
  idioms in Settings; Network Extension permission ask.
- **Desktop:**
  - Tray menu (Win/Linux/macOS) with status indicator (color +
    label), Connect/Disconnect, current route name, mode picker
    submenu, Open Daal, Quit. Tray icon color reflects state.
  - Native title bar on macOS, custom on Windows/Linux (designer
    call, but pick one and apply consistently).
  - Keyboard shortcuts: ⌘/Ctrl+1..6 for nav sections, ⌘/Ctrl+K for
    command palette, Esc closes modals.
  - Window minimum size: 720 × 480 (sidebar collapses below 900).
  - **Background behavior:**
    - **Close button** defaults to **minimize to tray**, not quit.
      First time the user clicks close, show a one-time sheet:
      *"Daal will keep running in the background so your
      connection stays active. You can change this in Settings."*
      with **Keep running in background** (primary) and **Quit
      Daal** (secondary). Remember the choice.
    - **Quit while connected** confirm modal: *"Daal is currently
      protecting your connection. Quitting will disconnect you."*
      Buttons: **Stay connected** (primary) / **Quit anyway**
      (destructive).
    - **Autostart** in Settings → Startup. Default OFF.
    - **Sleep / wake** — engine reconnects automatically if it was
      connected before. UI shows brief "Reconnecting…", never a
      hard error.

---

## 7. Deliverables we want from the designer

1. **Brand system doc** — color tokens (light + dark, sRGB
   fallbacks alongside OKLCH), type scale, spacing scale,
   elevation, motion, iconography rules.
2. **Wireframes** for all six sections + onboarding + trust prompt
   + recovery sheet, per platform (mobile portrait, desktop).
3. **High-fidelity mockups** for the same screens, light + dark,
   EN + FA (FA mockups must be true RTL mirrors).
4. **Interactive prototype** (Figma) covering the primary flows
   from §7a.
5. **Component library** in Figma (Buttons, Inputs, Cards, Lists,
   Modals, Banners, Empty states, Toasts, Phoenix-button states,
   visual-fingerprint frame, QR scanner viewfinder, trust-prompt
   word grid, route-chip, source-row, status-card, recovery-sheet).
6. **Asset export bundle** — all icons as SVG, the phoenix in the
   states needed (idle / connecting / connected / error), favicons
   / app icons per platform spec (raw logos in `/home/daal/src/`).
7. **Empty / error / loading inventory** — every variant designed
   and specced.

We do **not** want: a bespoke marketing site beyond the GitHub
Pages landing page (separate scope), animations beyond the
phoenix's four states + the connecting pulse + the QR-fountain
progress, illustration sets beyond the three onboarding cards.

---

## 7a. Acceptance criteria

Design work is accepted only when **every primary flow** is
designed and prototyped across the full product matrix:

| Axis | Variants |
|---|---|
| Platform | Mobile (portrait), Desktop |
| Language / direction | English (LTR), Persian (RTL) |
| Theme | Light, Dark |
| Screen state | Empty, Loading, Success, Error |

**Primary flows that must be covered:**

1. First-launch onboarding (recipient path)
2. First-launch onboarding (publisher path)
3. Migration: private codename -> Daal import success and import failure
4. Add route — all four sub-flows
5. Add Source (subscribe) — all four sub-flows
6. Connect to a route (success path)
7. Connect failure → recovery sheet → success
8. Trust prompt (incoming + resolution paths)
9. Share a route (sender side, all three sub-flows)
10. Status → Why this route → diagnostics export
11. Settings → change PIN
12. Settings → Panic wipe (full three-step)
13. Settings → Language switch (live RTL flip)
14. Publisher wizard end-to-end (publisher mode only)
15. Desktop: close-to-tray + quit-while-connected
16. Incoming-link handling: open `daal://sub/...` from outside the
    app while locked / mid-onboarding / on Connection screen
17. Permission pre-explainer screens (VPN / Camera / Notifications
    / Local network) — one each, before the OS dialog

**Per-flow checklist:**

- [ ] Wireframe (lo-fi)
- [ ] Hi-fi mockup, light EN
- [ ] Hi-fi mockup, dark EN
- [ ] Hi-fi mockup, light FA (RTL)
- [ ] Hi-fi mockup, dark FA (RTL)
- [ ] Empty state designed
- [ ] Loading state designed
- [ ] Error state designed
- [ ] Interactive prototype frame linked
- [ ] Reviewed against §1 hard constraints
- [ ] WCAG AA contrast verified

If a flow is platform-specific (e.g. desktop-only tray, mobile-only
camera scan), only the applicable platform variants are required;
**all language × theme × state variants are still required.**

---

## 8. Out of scope

- Browser extension
- Server / publisher backend admin panel
- Payment / billing screens (Daal has no billing)
- Account creation (Daal has no accounts)
- Cloud sync UI (there is no cloud)
- Social features

The marketing/landing site is its own scoped phase
(`development-phases/D-3-...`); the designer may be asked to
contribute hero artwork there but the IA / build is separate.

---

## 9. Open questions for the designer

1. Default theme: light or dark? Recommendation: follow OS, default
   to dark on first launch given the audience and context.
2. Is the trust-prompt word grid better as 2×3 or as a single
   column of 6? Test with FA at small sizes.
3. On desktop, should the system tray icon change color by state,
   or only by a small badge?
4. Should the route picker on Connection live as a sheet, a
   popover, or a dedicated mini-screen?
5. Empty-state illustration vocabulary — phoenix in different
   poses, or abstract shield-only motifs?
6. How aggressive should the panic-wipe affordance be? Reachable
   but not accidentally pressable.
7. Should the migration check (private codename -> Daal) prompt include a
   visual "before / after" comparison, or stay text-only?

---

## 10. Brand system (canonical)

This section consolidates the brand tokens that appear across the
three reference HTMLs. The designer should refine, not invent.

### 10.1 Color tokens (OKLCH primary, sRGB fallback required)

The reference HTMLs use OKLCH and `color-mix()`. These work in
modern browsers but **must have sRGB fallbacks** in shipped tokens:
Android `colors.xml`, iOS `Asset Catalog` colors, and Tauri WebView
on older Windows builds need straightforward hex / RGB. Provide
both for every token.

| Token | OKLCH (reference) | sRGB fallback (provide alongside) | Use |
|---|---|---|---|
| `--bg` | `oklch(28% 0.04 215)` | (designer to derive — approx `#163844`) | Primary screen background, dark theme |
| `--bg-deep` | `oklch(22% 0.045 215)` | approx `#0E2C39` | Page bg outside screens |
| `--surface` | `oklch(33% 0.04 215)` | approx `#1B4658` | Cards, sidebar, sheets |
| `--surface-2` | `oklch(38% 0.04 215)` | approx `#22556B` | Hover / active raised |
| `--line` | `oklch(45% 0.025 215)` | approx `#386371` | Hairlines on dark |
| `--line-soft` | `oklch(40% 0.03 215)` | approx `#2D5867` | Softer hairlines |
| `--fg` | `oklch(96% 0.012 80)` | approx `#F2EBD9` | Primary text |
| `--muted` | `oklch(72% 0.012 215)` | approx `#A6B5BB` | Secondary text |
| `--dim` | `oklch(58% 0.015 215)` | approx `#7B8E97` | Tertiary text |
| `--gold` | n/a (canonical sRGB) | `#C9A23A` | Brand mark, CTA |
| `--gold-warm` | `oklch(78% 0.12 80)` | approx `#D9B86E` | Recipient accent on dark |
| `--gold-deep` | `oklch(60% 0.12 75)` | approx `#9C7C2B` | Pressed / depressed gold |
| `--cyan` | `oklch(70% 0.10 195)` | approx `#5FA1B0` | Publisher accent |
| `--green` | `oklch(72% 0.14 150)` | approx `#5FA85A` | Success |
| `--amber` | `oklch(76% 0.14 80)` | approx `#E0A93B` | Warning |
| `--red` | `oklch(64% 0.18 25)` | approx `#C8553D` | Danger / Tier-3 destructive |

**Light theme** is not modeled in the HTMLs and must be added.
Recommendation: invert the lightness axis only — keep hue/chroma
the same, derive background ≈ `oklch(96% 0.012 80)` (paper) and
foreground ≈ `oklch(28% 0.04 215)` (deep teal). The gold token
stays put at `#C9A23A` and reads acceptably on paper background.

### 10.2 Typography stack

| Use | Stack |
|---|---|
| Display (headings) | Iowan Old Style, Charter, Newsreader, Palatino Linotype, Book Antiqua, Palatino, Georgia, serif |
| Body | -apple-system, BlinkMacSystemFont, Segoe UI, system-ui, sans-serif |
| Mono | ui-monospace, SF Mono, JetBrains Mono, Menlo, monospace |
| Persian (FA) | Vazirmatn, IRANSans, Geeza Pro, SF Arabic, Tahoma, sans-serif |

Bundled locally on every platform (§5 Typography).

### 10.3 Radii & spacing

- `--r-phone: 44px`, `--r-card: 16px`, `--r-tile: 12px`,
  `--r-pill: 999px` (per the reference HTMLs).
- Spacing scale: 4 / 8 / 12 / 16 / 22 / 32 / 48 / 64 px.

### 10.4 Logo & favicon usage

| Asset | File in `/home/daal/src/` | Use |
|---|---|---|
| Flat phoenix mark, vector | `daal-flat-no-bg.svg` | App nav header, share-link previews, anywhere ≥ 64px |
| Flat phoenix mark, raster | `daal-flat-no-bg.png` | Fallback for surfaces that can't render SVG |
| 3-D phoenix bevel | `daal-3d-no-bg.png` | **Connect button "Connected" state only** — the only place the bevelled variant appears |
| Flat on brand teal | `daal-flat-bg-033E51.png` | Splash screen, store assets |
| 3-D on brand teal | `daal-3d-flat-bg.png` | Marketing / landing page hero |
| Favicon | `favicon-512x512.png` | GitHub Pages, web installer |

### 10.5 Phoenix-button motion (the brand primitive)

The phoenix is the app's emotional center. Four states:

| State | Visual | Motion |
|---|---|---|
| Disconnected | Flat phoenix on neutral teal disc | Static |
| Connecting | Flat phoenix; subtle radial gold pulse | 1.6 s ease-in-out, opacity 0.4 → 0.8 |
| Connected | 3-D phoenix; gold halo radial gradient | 2.6 s ease-in-out breathing, opacity 0.55 → 1.0, scale 1.0 → 1.07 |
| Error | Flat phoenix with subtle red ring; halo dimmed to grey | Static |

All states must respect `prefers-reduced-motion` (animation off,
opacity stays at the upper bound).

---

## 11. Reference HTML map

The three HTMLs in `/home/daal/src/` serve different purposes for
the designer:

| File | Authority for |
|---|---|
| `on-boarding.html` | Two-path onboarding flow + the publisher cyan accent |
| `daal-mobile-app.html` | Mobile IA + bottom nav + section eyebrows + connection state copy |
| `daal-desktop.html` | Desktop sidebar + breadcrumb + right rail + tray + ⌘ shortcuts |

**Known issues in the HTMLs that the designer should NOT replicate:**

- Asset references use hashed names (`mouenlj9-daal-flat-no-bg.svg`,
  `mouenlnv-daal-3d-no-bg.png`). The actual files are
  `daal-flat-no-bg.svg` and `daal-3d-no-bg.png` in
  `/home/daal/src/`. Use the clean names.
- All three HTMLs are dark-only. The light theme must be added.
- The QR generator in `on-boarding.html` is a fake deterministic
  pattern, not a scannable QR. Real QRs come from the engine.
- The mobile app HTML names section 3 "Sources" but related copy
  sometimes uses "Subscriptions." The user-visible label is
  **"Sources"** everywhere; reconcile.
- The trust prompt, recovery sheet, panic wipe, permission
  pre-explainers, vault-locked, migration prompt, and route-import
  errors are **not yet drawn**. They are the designer's primary new
  output.
