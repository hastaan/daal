# Daal — GUI Design Brief

> Document for the frontend designer. Covers what the app does, who it's
> for, what each screen needs to do, what the user flows look like, and
> the cross-platform constraints. **No visual mockups inside** — the
> visual language is yours to design.

---

## 0. Project at a glance

- **Product name:** Daal (Persian: "دال")
- **What it is:** an anti-censorship client. The user installs it, gets
  routes from a publisher (or imports them), and turns on the connection.
  Underneath it's a tunnel + smart route picker; to the user it should
  feel like "I press one button and the internet works again."
- **Users:** non-technical people in censored regions. Many will be
  scared, on shaky networks, on cheap Android phones, occasionally on
  Windows laptops. **Persian (RTL)** and English (LTR) are first-class
  from day one.
- **Form factors:**
  - **Desktop** (Windows, Linux, macOS) — Tauri shell, React UI
  - **Mobile** (Android, iOS) — native (Compose / SwiftUI)
- **Brand:**
  - Logo: gold phoenix on shield with "دال" calligraphy
  - Colors: gold `#C9A23A`, deep teal `#033E51`, black, off-white
  - Tone: dignified, calm, protective. NOT flashy "hacker" aesthetic.
    Think "trusted civic utility," not "VPN bro."

### Design north star

**A first-time user, with no instructions, should be able to open the
app and within 60 seconds either (a) be connected, or (b) understand
exactly what they need to do next.** Every screen should be obvious by
looking. Normal screens should not need more than two sentences of
explanatory copy; **security disclosures** (trust prompt, panic wipe,
PIN setup, key rotation) may use expandable "Tell me more" details
when the user actively asks for them.

---

## 1. Hard product constraints (do not violate)

These come from the engine's threat model and security spec. They
constrain the UI even when they look unfriendly.

1. **Subscription URLs are never displayed once added.** The user
   manages a subscription by its display name and refresh history. URLs
   are write-only.
2. **No analytics. No telemetry. No "did you mean…?" suggestions
   that hit the network.** Everything in the UI must work offline,
   end-to-end, with the engine alone. No Google Fonts, no CDN.
3. **Trust prompts are mandatory and modal.** When the engine says
   "this publisher's fingerprint changed, confirm Trust / Once /
   Cancel," the UI MUST present that, with the EN BIP-39 words and the
   FA Persian words side-by-side. The user must be able to read the
   words out loud to a friend on the phone.
4. **No "remember me" / "auto-trust" shortcut on the trust prompt.**
5. **Diagnostics are redacted.** Route IDs, fingerprints, mode, state,
   timestamps — yes. Destinations, IP addresses, content of any kind —
   no.
6. **Panic / emergency wipe must always be reachable in ≤ 2 taps from
   anywhere in the app.** Including from a locked-vault state.
7. **PIN unlock screen has no biometric fallback** (Argon2id is the
   gate). Biometrics may be added later as an *additional* factor, but
   not as a replacement.
8. **RTL is not a translation, it's a mirror.** Every layout must work
   visually in RTL. Test FA before shipping any screen.
9. **Permissions are requested only when needed**, never at app launch.
   - VPN permission: on first **Connect** tap (not on first run, not on
     onboarding).
   - Camera permission: on first tap of **Scan QR**.
   - Notifications permission: on first toggle of any notification in
     Settings.
   - Local network / mDNS: on first tap of **Receive from a friend
     (LAN)**.
   Each permission ask must be preceded by a one-screen explainer in
   plain language so the OS dialog isn't the first the user hears of
   it. Sample copy: *"Daal needs the VPN permission to route your
   traffic through the engine. This lets Daal create a local tunnel.
   Daal does not use analytics or send usage data to a Daal server."*
10. **Routes always have human-readable names.** The raw `route_id` is
    never the primary label anywhere in the UI. See §5.1 for the naming
    rules.
11. **Cross-platform parity is a target, not a snapshot.** This brief
    describes the destination state for every platform. The current
    code has gaps (notably iOS, which is stale against the current
    engine version). The designer should design for the target IA on
    every platform — engineering will catch up.

---

## 2. Information architecture (shared across all platforms)

**Five primary sections everywhere, plus Publisher as an advanced
module.** Same five names, icons, and order on every platform.
Publisher is hidden until the user opts in via Settings → Advanced
(see §4.6). This is the single most important rule in this brief —
please don't deviate per platform unless a platform convention forces
it.

| # | Section | Engine surface it covers | What the user thinks it's for |
|---|---|---|---|
| 1 | **Connection** | engine_set_route / engine_clear_route (the user-facing "connect" / "disconnect" is an app-level concept on top of these) | "Turn it on. See the green light." |
| 2 | **Routes** | route list + import + share-with-friend | "My routes. Add a new one. Send one to a friend." |
| 3 | **Subscriptions** | subscription_list / add / refresh / remove | "The publishers I follow." |
| 4 | **Status** | diagnostics + why-this-route + budgets + health | "Is it working? Why this route?" |
| 5 | **Settings** | mode, lifeline, PIN, language, panic, about | "Configure & emergency tools." |
| 6 | **Publisher** *(advanced; off by default)* | wizard, key rotation, publisher handoff / bundle distribution | "I publish routes for others." |

### Navigation pattern per platform

- **Mobile:** bottom nav bar with 5 icons (Connection / Routes /
  Subscriptions / Status / Settings). Publisher is hidden behind a
  Settings → Advanced toggle. Trust prompt is always a full-screen
  sheet.
- **Desktop:** vertical sidebar (collapsible) with the same 6 entries.
  Sidebar collapses to icon-only on narrow windows. Resizable; the
  current top-tab pattern is going away.
- **System tray (desktop only):** quick connect/disconnect, current
  route, mode picker. Click tray → focuses Connection screen.

---

## 3. Onboarding (first-launch flow)

This is new — the current apps drop the user straight onto a broken
home screen. We need a real first-run experience.

**Goal:** a brand-new user with no routes can finish onboarding in
**under 90 seconds** and end up either (a) connected or (b) on a screen
that tells them *exactly* what to do next.

### Onboarding screens (in order)

0. **Migration check** *(only if applicable, before Welcome)* —
   Daal is the successor to a previous app called Daal. If the
   installer detects an existing Daal install on the same machine /
   account / device, show a single screen:

   > "Welcome back. We found your existing Daal setup. Daal is the
   > new name and a refreshed app. Would you like to import your
   > routes, subscriptions, and settings?"
   >
   > **Import everything** *(primary)* · **Start fresh** *(secondary,
   > with a small "Your old data will not be deleted" reassurance)*

   On import success, skip directly to a "You're ready" screen instead
   of the full onboarding. On import failure, fall through to the
   normal onboarding with a small toast "Couldn't import old data —
   you can try again from Settings → Migration."

1. **Welcome** — logo, one-line tagline, "Get started" button, language
   picker (EN / فا) prominently. RTL flips at this step.
2. **What is Daal?** — three short illustrated cards swipable
   horizontally (or three steps on desktop):
   - "Daal helps you reach the open internet."
   - "Routes are how Daal connects. You can get them from a publisher,
     a friend, or a file."
   - "Your routes stay on your device. Daal does not see your traffic."
3. **Set a PIN** — optional but recommended. Two states:
   - **Skip PIN** → uses keystore profile (Android KeyStore / iOS
     Keychain / OS keyring). Default for casual users.
   - **Set PIN** → vault profile, Argon2id. For users who want a
     re-lock barrier on shared devices.
   Copy must be honest about the trade-off: "A PIN protects your routes
   if someone takes your phone. You'll need it every time you open
   Daal."
4. **Add your first route** — four equal-weight choices, large icons,
   one tap each:
   - **Subscribe to a publisher** (paste a `daal://sub/...` URL or scan
     a QR — recommended path)
   - **Receive from a friend** (LAN handoff or QR)
   - **Import a file** (`.sbp`)
   - **Skip for now** (lands on an empty state with a friendly nudge)
5. **You're ready.** — short success screen with one large "Connect"
   button that takes them to the Connection screen and pre-selects the
   first route.

### Empty-state policy

If the user skipped step 4, every subsequent screen that requires a
route must show a **helpful empty state** with the same four "add a
route" options inline — never a dead end, never a generic "no data."

---

## 4. Section-by-section spec

For each section: **purpose**, **primary action**, **what's on the
screen**, **secondary actions**, **edge cases**.

---

### 4.1 Connection (the "on/off" screen)

**Purpose:** the daily-driver screen. 95 % of users will only ever see
this one.

**Primary action:** one **giant connect/disconnect button** in the
center. State-driven:

| Engine state | Button label | Visual |
|---|---|---|
| Disconnected | "Connect" | Phoenix shield, neutral |
| Connecting | "Connecting…" | Phoenix shield, spinner / pulse |
| Connected | "Connected" | Phoenix shield, gold glow / check |
| Error | "Try again" | Shield with subtle red ring |

**On the screen, in priority order:**

1. The big button.
2. **Currently selected route** — small chip below the button,
   tappable to change. Format: `<publisher_display_name> · <route nickname>`. Never the raw `route_id`.
3. **Route picker** when tapped: a sheet/list showing the user's
   imported routes grouped by trust class (Trusted / Prompted / New).
   No raw IDs visible. Each row shows publisher name + nickname + a
   trust badge (Trusted / Once / New).
4. **Mode chip** — small, bottom-right of the button area: shows
   current mode (Normal / Bulk / Lifeline / Lifeline-strict). Tappable
   → opens mode sheet.
5. **Tiny status line** below the button: e.g. "Using rotated pointers
   · valid 14 days" OR "On Wi-Fi · network seen before" — one line,
   redacted, dimmed. Plain language, never engine jargon.

**Pull-down / scroll-up reveals (mobile)** OR **expandable card
(desktop):**

- Why this route? (link to Status → Why this route)
- Pointer rotation banner (only when expiring/expired)
- Lifeline-strict banner (only when active)
- Rate-limit prompt (only when threshold crossed; offers "switch to
  Bulk" inline)

**Do NOT put on this screen:** route budgets table, route health
table, subscription list, diagnostics export, PIN unlock,
network-id line. Those go to Status / Settings.

**Edge cases:**
- No route imported → giant button is replaced by an empty state
  with the four onboarding "add a route" tiles.
- Vault locked → giant button is replaced by a PIN unlock card; only
  after unlock does the button render.
- Engine version mismatch → full-screen blocker until app is
  updated. Today's "yellow header banner" is too subtle.

**Connection failure recovery** *(critical flow — design carefully)*

If a connect attempt fails, do **not** drop the user back to a generic
error. Show a recovery sheet with a clear primary path and three
fallbacks, in this order:

1. **Try again** *(primary, large)* — retries the same route. Most
   transient failures resolve on retry.
2. **Try a different route** — opens a compact route picker
   pre-sorted by health (best first), excluding the failing route.
   One tap = retry with the new route.
3. **Refresh subscriptions** — runs subscription_refresh on all
   subscriptions, then offers the picker again. Use this when routes
   look stale or burned.
4. **Switch to Lifeline mode** — last resort; degrades capability but
   maximizes reach. Confirm modal explains the trade-off in one
   sentence.

A small "Why did this fail?" link opens the Status → Why this route
section pre-scrolled to the last failure. Never show raw engine error
codes on this sheet — they go behind a "Show details" disclosure.

---

### 4.2 Routes

**Purpose:** the user's library of routes. Manage them; import new
ones; share them with friends.

**Layout:**

- **Top bar:** "Routes" title, search input, "+ Add route" button.
- **List:** grouped by trust class (Trusted / Prompted / New /
  Emergency). Each row:
  - Publisher display name (bold)
  - Route nickname (regular)
  - Trust badge
  - Last-used relative time ("2 days ago")
  - Subtle right-chevron → route detail
- **Empty state:** the four onboarding tiles inline.

**Route detail screen:**

- Header: publisher name + visual fingerprint (the abstract image,
  same one shown at import time)
- Trust badge with a "View fingerprint words" button → opens a sheet
  with EN BIP-39 + FA Persian words side-by-side, monospaced
- Nickname (editable)
- Subscription source ("from publisher X" or "imported from file" or
  "received from friend on YYYY-MM-DD")
- Actions: **Use this route** · **Share** · **Remove**
- A small "Why might this route fail?" section pointing to Status

**Add route flow** (the "+ Add route" button):

A single bottom sheet / modal with four large tabs/options:

1. **Paste a link** — text input for `daal://...` URIs; auto-detect
   from clipboard with a one-tap "Use clipboard" affordance
2. **Scan QR** *(mobile only — camera viewfinder for both static and
   animated QR)*. The fountain decoder shows progress: "Reading frame
   14 of ~22" with an animated arc. **Desktop replaces this tab with a
   "Paste / Drop QR image" flow:** drop an image file, paste from
   clipboard, or paste raw frame data. Desktop can *display* QR codes
   when sharing routes (§4.2 Share flow), it just cannot scan with a
   webcam in V1.
3. **Receive from a friend (LAN)** — mDNS browse list + 6-digit PIN
   entry. Shows nearby devices by display name, never IPs.
4. **Import file** — system file picker (`.sbp`)

After any of these, if the engine returns trust-prompt-needed, route
the user to the **Trust Prompt** modal (see §4.7).

**Share route flow** (from a route detail):

Mirror of "Receive from a friend." Generates a session, shows:

- A **6-digit PIN** in big font
- A **static QR** for the recipient to scan (same room)
- An **animated QR** option for routes too large for a static QR
- A **LAN URL** shown in plain text for read-aloud. **The LAN URL is
  only shown during the active user-initiated sharing session. It is
  never stored, never exported, never shown in diagnostics, and is
  removed from the screen the moment the session ends.**
- An **End sharing** button — wipes the bundle bytes per the V1.4
  invariant

---

### 4.3 Subscriptions

**Purpose:** manage the user's "I follow this publisher" relationships.

**Layout:**

- **Top bar:** "Subscriptions" title, "+ Subscribe" button.
- **List:** each row shows
  - Publisher display name (bold) + visual fingerprint thumbnail
  - "Last refreshed: 2h ago · 47 routes"
  - Refresh outcome icon (success / warning / error)
  - Right-chevron → subscription detail

**Subscription detail:**

- Publisher info (same fingerprint widget as route detail)
- **The URL is never displayed.** This is a hard product rule (§1.1).
  The user manages a subscription by display name and refresh history
  only.
- Last refresh timeline (last 7 outcomes as colored dots)
- Routes from this publisher (list)
- Actions: **Refresh now** · **Pause** · **Unsubscribe**

**+ Subscribe flow:** same four-option sheet as Add route, scoped to
publisher subscription URLs.

---

### 4.4 Status (the "is it working? why?" screen)

**Purpose:** the diagnostic surface. Most users never visit it; when
they do, they're usually upset and need to know what's wrong.

**Top of screen:** big visual health card.

- Green: "All systems normal."
- Amber: "Some routes are limited." → expandable
- Red: "Daal cannot reach the open internet." → expandable, with
  next-step suggestions (refresh subscriptions, try another route,
  switch to lifeline mode)

**Below, three collapsed accordions:**

1. **Why this route?** *(expanded by default when connected)*
   - Active route name
   - "Daal chose this route because: …" (one sentence)
   - "Skipped routes:" small list of `family → reason` pairs
   - Last failure (if any)

2. **Network**
   - Current network id (a small hash, like `wifi-a3f2`, plus the
     human label "Wi-Fi" / "Cellular" / "Ethernet")
   - "Daal has seen this network N times" (per-network memory feature)
   - Pointer rotation banner (5-state: ok / rotated / expiring /
     expired / unknown)

3. **Routes & budgets**
   - Compact table: route nickname, mode-eligibility, budget tag, used
     bytes / total
   - Route health (per-route success rate over last hour)

**At the bottom:** **"Export diagnostics"** button → opens a confirm
modal explaining what's in the export (and what's NOT — crucially,
"no destinations, no content, no IPs"). Saves a `.json` to disk
or copies to clipboard.

---

### 4.5 Settings

**Purpose:** configuration and emergency tools.

Sections (one per group):

1. **Connection mode**
   - Picker: Normal · Bulk · Lifeline · Lifeline-strict (segmented
     control on mobile, radio cards on desktop)
   - One-line description per mode in plain language (no jargon)
   - "Auto-promotion" toggle: "Switch to lifeline-strict automatically
     when traffic patterns show pressure." (with a caveat link)
   - "Allow bulk-capable session" toggle (with explanation)

2. **Security**
   - PIN: Set / Change / Remove (with appropriate warnings)
   - Storage profile: Vault vs Keystore (read-only display + "Convert"
     action)
   - Lock now (manually re-locks the vault; only visible when vault
     profile)

3. **Language & region**
   - Language: EN / فا (immediate apply, RTL flip)
   - "Use system language" toggle
   - Date/time format follows OS

4. **Notifications** *(desktop & Android; iOS lives in OS Settings)*
   - Toggles for: route burned, subscription refresh failure,
     rate-limit threshold, pointer rotation needed
   - **Detailed notifications** toggle (default OFF). When OFF,
     all notifications use generic copy ("Daal needs your
     attention", "A subscription needs refresh"). When ON,
     notifications may include the publisher display name /
     route nickname. **Lock-screen previews must always use the
     generic copy regardless of this toggle** — detailed copy
     appears only after the device is unlocked.
   - Master "Quiet mode" toggle

5. **Startup** *(desktop only)*
   - "Start Daal when I sign in" — autostart toggle (default OFF)
   - "Start minimized to tray" — only enabled when autostart is ON
     (default OFF)
   - One-line copy explaining that autostart keeps the connection
     ready when the computer wakes up

6. **Advanced**
   - "I am a publisher" toggle — reveals the Publisher section in the
     nav
   - Engine log level (warn / info / debug)
   - Reset onboarding (re-runs §3 next launch)
   - **Migration** — re-run the private codename -> Daal import (visible only if
     a previous Daal install is detected and import is incomplete)

7. **Emergency**  ← **always last, always visible, always red**
   - **Panic wipe** — three-step confirm, types a word, then wipes
     all routes, subscriptions, secrets, logs. Returns to Welcome.
   - The button must be reachable in ≤ 2 taps from any screen via a
     small floating shield-icon at the bottom-right of every screen
     (a "duress button"). Designer call: how to make it accessible
     without being scary or accidentally tappable.

8. **About**
   - App version, engine version, build date, license (GPL-3.0), link
     to source

---

### 4.6 Publisher *(advanced, hidden by default)*

**Purpose:** for the small fraction of users who run their own
publisher. Hidden until "I am a publisher" is toggled in Settings →
Advanced.

This is where the existing 7-screen wizard lives. The designer can
mostly leave it alone except:

- It deserves its own section in the nav (don't bury it in Settings)
- Visually mark it as "advanced mode" — slightly different color
  accent so users know they're in a power-user surface
- Includes: Wizard, Key rotation, Subkey lifetime, **Publisher
  handoff / bundle distribution** (operator tooling for getting a
  signed bundle to subscribers — distinct from the consumer
  "share a route with a friend" flow in §4.2), Cell join (publisher
  cell)

We may eventually split this into a separate "Daal Publisher" app —
designer should treat it as a self-contained module to make that
split easy.

---

### 4.7 Trust Prompt (modal, cross-cutting)

This appears whenever the engine returns
`VerdictTrustPromptNeeded`. Always full-screen on mobile, always a
centered modal on desktop. Cannot be dismissed except via one of three
explicit choices.

**Layout:**

- **Title:** "Verify this publisher"
- **Subtitle:** "Read the words below out loud to the person who sent
  you this. They should match exactly."
- **Visual fingerprint:** the abstract image (deterministic from the
  fingerprint hash). Large, central.
- **Word grids, side by side:**
  - **English (BIP-39):** monospace, 6 words on a 2x3 grid, large
  - **Persian:** RTL, monospace, 6 words on a 2x3 grid, large
- **Below words:** publisher display name (bold) + spec version
- **Three buttons:**
  - **Trust this publisher** (primary, gold) — adds to Trusted
  - **Use this route once** (secondary) — one-shot
  - **Cancel** (tertiary, ghost)
- A subtle "Why am I seeing this?" link → opens a half-sheet with a
  one-paragraph explanation in plain language.

**Anti-patterns to avoid:**
- Do not auto-select any button.
- Do not use color for "the safe choice" — Trust and Cancel must look
  equally weighted in safety; the user must read the words.
- Do not show the raw fingerprint hex unless the user expands an
  "Advanced" disclosure.

---

### 4.8 Incoming links, files, and shared text

Daal must accept content from outside the app and route it directly
into the right flow — never dump the user on Welcome or Home and make
them figure out where to paste.

**Triggers and routing:**

| Source | Behavior |
|---|---|
| `daal://sub/...` URL clicked from a browser, messenger, or email | Open Daal → **Add Route → Paste a link tab**, with the URL pre-filled and the import preview already running. If trust prompt is needed, route straight to it. |
| `daal://route/...` or any other `daal://` schemes | Same: deep-link into the matching Add Route sub-flow with the input pre-filled. |
| `.sbp` file opened from the OS file browser, email attachment, or messenger | Open Daal → **Add Route → Import file**, file already loaded, preview running. Trust prompt routing as above. |
| Text shared into Daal via the OS share sheet (mobile) | Open Daal → **Add Route → Paste a link**, text pre-filled. |
| Image (QR) shared into Daal (mobile share sheet, desktop drop/paste) | Open Daal → **Add Route → Scan QR** *(mobile)* or **Paste / Drop QR image** *(desktop)*, image pre-loaded, decode running. |

**Rules:**

- If Daal is **locked** (vault profile, secrets locked) when an
  incoming intent arrives, hold the intent in memory, show the PIN
  unlock gate, and resume the deep-link target immediately after
  unlock.
- If Daal is in the middle of **onboarding**, hold the intent until
  onboarding finishes, then route directly to its target on the
  "You're ready" step instead of the default Connection screen.
- Never silently auto-import. The user must always see the preview
  + trust prompt before anything is added to their device.
- Show a small breadcrumb on the destination screen
  (*"Opened from a link"* / *"Opened from a file"*) so the user
  understands why they're suddenly in Add Route.

---

## 5. Cross-cutting UX rules

### 5.1 Route naming (the rule of "no raw IDs")

Every route, every subscription, every publisher in the UI is shown by
a **human display name**, never by its raw ID. The raw ID is available
only in Status → "Show details" disclosures and in exported
diagnostics.

**Auto-naming rules** (applied at import time):

- **Routes from a subscribed publisher:** `<Publisher display name>
  · <route nickname from publisher metadata>` — e.g. *"Pars Relays ·
  Rescue 03"*. If the publisher metadata has no nickname, fall back
  to *"Pars Relays · route 1"*, *"… route 2"*, etc.
- **Routes received from a friend (LAN/QR):** `Friend route ·
  <weekday> <month> <day>` — e.g. *"Friend route · Mon May 6"*.
  Multiple from the same day get a numeric suffix.
- **Routes imported from a file:** `<filename without extension>` —
  e.g. *"my-backup-routes"*. Multiple imports of the same filename
  get a numeric suffix.
- **Emergency-pool routes** (the engine's bootstrap fallback): always
  *"Emergency · <short code>"*, badged with the emergency icon.

**The user can rename any route at any time** from the Route detail
screen. The new name is what shows up everywhere afterward. The raw
ID never changes.

Subscriptions follow the same rule: the publisher's self-declared
display name is the default, fully editable.

### Empty states
Every list screen has a meaningful empty state with a clear next
action. No "Nothing here" dead ends.

### Loading states
- Anything > 200 ms gets a skeleton or spinner.
- Anything > 3 s gets explanatory copy ("Refreshing… this can take a
  moment on slow networks.")
- Anything > 15 s gets a cancel button.

### Error states
- Errors get a plain-language sentence, never a raw stack/JSON.
- Errors offer **at least one** suggested next action.
- Engine-level errors with codes have a "Show details" disclosure for
  troubleshooting.

### Destructive & dangerous actions

A consistent confirmation pattern for everything that deletes,
revokes, or wipes. Three tiers, designer to standardize the visual
language for each:

| Tier | Examples | Pattern |
|---|---|---|
| **Tier 1 — Reversible** | Pause subscription, disable notification, log out of share session | Single-step toggle/button. No confirm. Toast on success with **Undo** action visible for 5 s. |
| **Tier 2 — Locally destructive** | Remove route, unsubscribe, end share session, lock vault now, reset onboarding | Confirm modal with the consequence in plain language ("This route will be removed from your device. You can re-import it later if you have the original."), **Cancel** as the default-focused button, destructive button labeled with the verb (*"Remove route"*, not *"OK"*). |
| **Tier 3 — Irreversible / security-critical** | Panic wipe, delete publisher key, revoke publisher key, rotate publisher key, change PIN with no fallback | Two-step confirm: (a) modal with consequence + a **typed** confirmation word (*"Type WIPE to continue"*, *"Type ROTATE to continue"*), (b) final destructive button. Always a "How does this work?" link to a longer explanation. Color: red. The action button is never auto-focused. |

Specific call-outs:

- **Remove route** (Tier 2) — explicitly mention if the route came
  from a subscription, the next refresh will re-add it.
- **Unsubscribe** (Tier 2) — warn that all routes from this publisher
  will be removed too; offer "Keep routes" toggle.
- **Rotate publisher key** (Tier 3, publishers only) — must explain
  that subscribers will see a trust prompt on next refresh and need
  to re-verify.
- **Revoke publisher key** (Tier 3) — even more explicit: subscribers
  who don't get the revocation cannot use new routes. This needs a
  longer "Tell me more" disclosure.
- **Panic wipe** (Tier 3) — three-step (typed word + final confirm +
  short delay before the action runs, with a "Cancel" still available
  during the delay).

### Notifications & banners
- Maximum **one** banner visible at a time.
- Banners stack by priority: Engine mismatch > Vault locked > Pointer
  expired > Pointer expiring > Lifeline-strict active > Rate-limit.
- Lower-priority banners are queued, not shown simultaneously.

### Animation
- Subtle. The phoenix lights up on connect, a soft pulse during
  connecting, a gentle settle on connected. Never spinning forever.
- No skeleton-shimmer for items that load in < 100 ms.
- Respect `prefers-reduced-motion` on every platform.

### Typography
- Headings: a humanist serif or a high-contrast sans (designer's
  call) that pairs with the calligraphic "دال" in the logo.
- Body: a system-friendly humanist sans with full Persian support.
  Vazirmatn is a strong default for FA; pair with Inter / Plus Jakarta
  / similar for EN.
- **All fonts must be bundled locally with the app.** No remote font
  loading, no Google Fonts, no CDN — fonts ship inside the binary /
  app bundle. This is a hard rule (see §1.2 — no telemetry, no
  network calls outside the engine).
- All text must work at 200% zoom (desktop) and "Largest" dynamic
  type (mobile).

### Color tokens (designer to extend)
- `--color-gold-primary`: `#C9A23A` — main brand, primary buttons
  in connected state
- `--color-teal-deep`: `#033E51` — surfaces / dark mode background
- `--color-ink`: near-black for light mode text
- `--color-paper`: off-white for light mode background
- `--color-success`: a calm green (NOT highlighter)
- `--color-warning`: an amber that meets contrast on both bg colors
- `--color-danger`: a deep red — for Panic and irreversible actions
  only
- All tokens defined for **both light and dark themes** from day one.
- The phoenix gold should remain readable in both themes; designer
  may need a slightly desaturated variant for dark mode.

### Iconography
- One icon family across all platforms (Lucide / Phosphor / custom).
- Custom icons only for: the phoenix shield (brand mark), the
  "publisher" badge, the trust-class chips, the visual fingerprint
  generator (already in engine — we just consume the data URI).

### Localization
- Every string in a `.json` / `.strings` / `.xml` resource. Zero
  hard-coded copy.
- FA strings always shipped same release as EN — never lag behind.
- Plurals handled with ICU MessageFormat (or platform equivalent).
- All times shown as relative ("2 hours ago") with absolute as a
  tooltip.

### Accessibility (non-negotiable)
- WCAG AA contrast on every screen, light and dark.
- Every interactive element has a label readable by VoiceOver /
  TalkBack / NVDA.
- Keyboard navigation on desktop covers every action; visible focus
  rings.
- Touch targets ≥ 44 × 44 pt on mobile.
- The trust-prompt words must be selectable so users can paste them
  into a translator if needed.

---

## 6. Platform conventions to honor

- **Android:** Material 3 motion + back-button handling. Bottom nav.
  Foreground service notification when connected (we already have
  this; designer to spec the icon + copy).
- **iOS:** SF Symbols where they fit; respect Dynamic Type; use
  Form/List idioms for Settings; Network Extension permission ask
  copy.
- **Desktop:**
  - Tray menu (Win/Linux/macOS) with: status indicator (color +
    label), Connect/Disconnect, current route name, mode picker
    submenu, Open Daal, Quit. Tray icon color reflects state
    (neutral / connecting / connected / error).
  - Native title bar on macOS, custom on Windows/Linux (designer call,
    but pick one and apply consistently)
  - Keyboard shortcuts: ⌘/Ctrl+1..6 for nav sections, ⌘/Ctrl+K for
    search, Esc closes modals
  - Window minimum size: 720 × 480 (sidebar collapses below 900 wide)
  - **Background behavior** (designer to standardize the copy):
    - **Close button** — defaults to **minimize to tray**, not quit.
      First time the user clicks close, show a one-time sheet:
      *"Daal will keep running in the background so your connection
      stays active. You can change this in Settings."* with options
      **Keep running in background** (primary, default) and **Quit
      Daal** (secondary). Remember the choice.
    - **Quit while connected** — confirm modal:
      *"Daal is currently protecting your connection. Quitting will
      disconnect you."* Buttons: **Stay connected** (primary) /
      **Quit anyway** (destructive).
    - **Autostart** — Settings → Notifications gets a sibling
      "Startup" group with *"Start Daal when I sign in"* and
      *"Start minimized to tray"* toggles. Default both off; user
      opts in.
    - **Sleep / wake** — when the OS resumes from sleep, the engine
      reconnects automatically if it was connected before. UI shows
      a brief "Reconnecting…" state, never a hard error.

---

## 7. Deliverables we want from the designer

In rough order:

1. **Brand system doc** — color tokens (light + dark), type scale,
   spacing scale, elevation, motion, iconography rules.
2. **Wireframes** for all six sections + onboarding + trust prompt,
   per platform (mobile portrait, desktop). Lo-fi is fine.
3. **High-fidelity mockups** for the same screens, light + dark,
   EN + FA (the FA mockups must show the RTL mirror, not just
   translated copy).
4. **Interactive prototype** (Figma) covering: first-launch onboarding
   → add subscription → connect → trust prompt → connected → status
   → settings → panic wipe.
5. **Component library** in Figma (Buttons, Inputs, Cards, Lists,
   Modals, Banners, Empty states, Toasts, the Phoenix-button states,
   the visual-fingerprint frame, the QR scanner viewfinder, the trust
   prompt word grid).
6. **Asset export bundle** — all icons as SVG, the phoenix in the
   states needed (idle / connecting / connected / error), favicons /
   app icons per platform spec (we have raw logos in `src/`).
7. **Empty-state, error, and loading inventory** — every variant
   listed above, designed and specced.

We do **not** want: a bespoke landing-page website (separate scope),
animations beyond the phoenix's three states, illustration sets beyond
the three onboarding cards (and even those can be simple).

---

## 7a. Acceptance criteria for design deliverables

Design work is considered complete and accepted only when **every
primary flow** has been designed and prototyped across the full
product matrix:

| Axis | Variants |
|---|---|
| Platform | Mobile (portrait), Desktop |
| Language / direction | English (LTR), Persian (RTL) |
| Theme | Light, Dark |
| Screen state | Empty, Loading, Success, Error |

**Primary flows** that must be covered:

1. First-launch onboarding (including migration screen)
2. Add route (all four sub-flows: paste, scan/paste-image, LAN,
   file)
3. Subscribe to a publisher
4. Connect to a route (success path)
5. Connect failure → recovery sheet → success
6. Trust prompt (incoming + resolution paths)
7. Share a route (sender side, all three sub-flows)
8. Status → Why this route → diagnostics export
9. Settings → change PIN
10. Settings → Panic wipe (full three-step)
11. Settings → Language switch (live RTL flip)
12. Publisher wizard end-to-end (publisher mode only)
13. Desktop: close-to-tray + quit-while-connected
14. Migration: private codename -> Daal import success and import failure
15. Incoming-link handling: open `daal://sub/...` from outside the app
    while locked / mid-onboarding / on Connection screen

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
camera scan), only the applicable platform variants are required, but
**all language × theme × state variants are still required.**

The brief is satisfied when this checklist is green for every flow.

---

## 8. Out of scope (call out so we don't drift)

- Marketing site
- Browser extension
- Server / publisher backend admin panel
- Payment / billing screens (Daal does not have any)
- Account creation (Daal has no accounts)
- Cloud sync UI (there is no cloud)
- Social features

If the designer proposes any of the above, decline politely and point
to this section.

---

## 9. Open questions for the designer to surface back

1. Should "Publisher" be a separate top-level section visible only
   when toggled, or always there but greyed out for non-publishers?
2. How aggressive should the panic-wipe affordance be? We want it
   reachable but not accidentally pressable.
3. Is the trust-prompt word grid better as 2x3 or as a single column
   of 6? Test with FA at small sizes.
4. On desktop, should the system tray icon change color by state, or
   only by a small badge?
5. Should the route picker on Connection live as a sheet, a popover,
   or a dedicated mini-screen?
6. What's the right empty-state illustration vocabulary — the phoenix
   in different poses, or abstract shield-only motifs?
7. Default theme: light or dark? (Recommendation: follow OS, default
   to dark on first launch in regions where the app is most used at
   night.)
