# Phase D-3 — Daal landing site (GitHub Pages) + downloads + docs

**Status:** PROPOSED — depends on Phase D-2 shipping `Daal v0.2.0`.
**Maturity target:** **public-facing landing site** at the project's
GitHub Pages domain that (1) explains what Daal is, (2) provides
one-click downloads pointing at the latest signed release on the
new repo, (3) documents every section of the app in detail, and
(4) does so in EN + FA (RTL) — all while honoring the design DNA
established in `docs/daal-gui-design-brief-v2.md` and the three
reference HTMLs in `/home/daal/src/`.
**Engine `Version` target:** unchanged.
**ABI release surface target:** unchanged.
**Predecessor:** Phase D-2 — shipped UI on Desktop + Android.
**Successor:** none on the rename track. The track ends here.

---

## 1. Strategic frame

D-3 is about discovery and trust. A user hears "Daal" from a
friend, types it into a browser, and within seconds:

1. **Sees the phoenix shield**, reads one calm sentence about what
   the app does, and trusts the page enough to click "Download".
2. Lands on a download that is **signed**, **versioned**, and from
   the **GitHub release** of the official `daal` repo — not a CDN
   we control, not a mirror, not a third party.
3. Can read **the full app's section-by-section docs in their
   language** before installing if they want to understand what
   they are about to run.

The site is **static**, hosted by **GitHub Pages**, and uses **no
external runtime services** (no analytics, no hosted fonts, no
CDN-hosted JS). It is the same hard rule as the app: no telemetry,
no remote calls. Everything ships in the static bundle.

The site is **the same brand DNA** as the app — same color tokens,
same typography stack, same phoenix asset set, same calm editorial
voice. A user who arrives from the site and installs the app
should feel they're in the same world.

---

## 2. Locked answers

| Question | Locked answer |
|---|---|
| Hosting | **GitHub Pages**, deployed from a `/website/` directory in the new `daal` repo, via a workflow on push to `main`. |
| Public URL | The org's existing GitHub Pages domain (e.g. `https://<org>.github.io/daal/`); a custom domain can be added later but is not required at D-3 ship. |
| Build tool | **None**, ideally — pure static HTML/CSS/JS authored hand-in-hand with the design brief. If a generator is used, it must be one that emits fully static output with no runtime JS dependencies (Astro, Eleventy, or hand-rolled). Default: hand-rolled, modeled on the three reference HTMLs. |
| Languages | **EN + FA**, RTL flip handled by toggling `dir="rtl"`, swapping the FA font stack, swapping numerals to Persian-Indic. Same rules as the app. |
| Themes | Light + Dark, OS-following with a manual override. Defaults to Dark on first visit. |
| Download links | Point at the **specific tag** of the latest signed release of the `daal` repo, baked at site build time (`https://github.com/<org>/daal/releases/download/<tag>/<asset>`). Never `releases/latest/download/...` — that path can race with a new release between site builds and serve a 404 for a versioned filename that hasn't propagated yet. No mirroring; no caching. |
| Telemetry | None. No Plausible, no Google Analytics, no Cloudflare Insights, no fingerprinting. |
| Fonts | Bundled in `/website/assets/fonts/`. Same stack as the app: Iowan Old Style (or open-source equivalent), Vazirmatn, system humanist sans, system mono. |
| Out-of-scope | A full marketing redesign with bespoke illustration. The site is **documentation + downloads**, not a sales pitch. |

---

## 3. Site architecture

A 6-page static site. Same six destinations in EN and FA = 12
total pages, but `/fa/` is structurally a mirror generated from
the same content with localized strings.

```
/                       Landing (hero + what is Daal + download CTA + 5 sections preview)
/download                Download page (per-platform tiles, latest release auto-picked)
/how-it-works            What Daal does, in 3 minutes; recipient + publisher paths
/sections                Full app walkthrough — Connection / Routes / Sources / Status / Settings / Publisher
/faq                     Plain-language Q&A — privacy, threat model, what it is and isn't
/about                   Project provenance, GPL-3.0, contributors, source link
```

FA mirror at `/fa/`, `/fa/download`, `/fa/how-it-works`, etc.
Language toggle in the header swaps the user to the same page in
the other locale. Toggle persists in `localStorage`; first-visit
respects `Accept-Language`.

---

## 4. Page-by-page spec

### 4.1 `/` — Landing

The "I just heard about Daal, what is it?" page. ≤ 3 screens of
scrolling.

**Above the fold:**

- **Hero**: 3-D phoenix on brand teal (`daal-3d-flat-bg.png` or
  the unbgged variant on a deep-teal CSS background), the
  "DAAL · دال" wordmark in the editorial serif, one-sentence
  tagline:
  - EN: *"Reach the open internet. Together."*
  - FA: *"به اینترنت آزاد برسید. در کنار هم."*
- **Primary CTA:** "Download for your device" → `/download`. The
  CTA detects the user's OS via `navigator.userAgent` and
  pre-selects the correct platform on the destination page (no
  network call).
- **Secondary link:** "How it works" → `/how-it-works`.
- **Language toggle** in the top-right (mirroring the reference
  HTMLs).

**Mid-page:**

- **What is Daal? (3 cards, same DNA as onboarding R1):**
  1. *"A way to reach. Daal helps you reach the open internet
     when your country blocks it."*
  2. *"Routes are how it connects. A route is the path your
     traffic takes. You can get them from a publisher, a friend,
     or a file."*
  3. *"Your routes stay yours. They live on this device. Daal
     does not send analytics or usage data to a Daal server."*
  Each card uses the italic-roman-numeral marker pattern from
  the on-boarding HTML (i. ii. iii.).

- **Two-path strip:** a horizontal layout mirroring the
  onboarding's "Who are you?" branch but as marketing copy:
  - *"I want to connect."* (gold accent)
  - *"I want to help others."* (cyan accent)
  Each links to the relevant section of `/how-it-works`.

**Footer of the landing:**

- Source code link (GitHub repo).
- License (GPL-3.0).
- Build version of the latest signed release (auto-injected at
  build time from the `releases/latest` API call done at site
  build, not at site load — see §6).
- Footer language toggle.

### 4.2 `/download`

**Goal:** any user gets the right file in two clicks.

**Layout:**

- A row of platform tiles. Each tile has the platform icon, the
  artefact name, the file size (rounded), the architecture, the
  signature attestation note ("Signed with the Daal release key,
  fingerprint AB:CD:…"), and a primary download button.
- The user's detected platform is highlighted; the others are
  visible but visually secondary.
- Below: "Verify your download" disclosure with the SHA-256 hash
  of each artefact (auto-injected at build time) and a one-line
  command to verify (`sha256sum Daal-Setup-x64.exe`).

**Tiles link to tag-specific URLs baked at site build time:**
`https://github.com/<org>/daal/releases/download/<tag>/<asset>`,
where `<tag>` and `<asset>` are both resolved at build from the
GitHub `releases/latest` snapshot. This pins page-and-asset
together so a release that ships between site builds cannot leave
the page pointing at a missing or mismatched filename.

| Tile | Artefact name (per D-1 §4E) |
|---|---|
| Windows | `Daal-Setup-<ver>-x64.exe` |
| Linux (AppImage) | `Daal-<ver>-x64.AppImage` |
| Linux (deb) | `daal_<ver>_amd64.deb` |
| macOS | `Daal-<ver>.dmg` |
| Android (Play / direct) | `Daal-<ver>-arm64.apk` |
| iOS | "TestFlight" link or App Store badge — gated as in D-2 §3.4 |

The site rebuilds on `release: published` events (see §6) so the
lag between a new release going live and the site updating is
typically minutes — never long enough for a user to land on a
tile pointing at a missing file. If the build workflow itself is
down, the previously baked tag URL still resolves.

**Footnote:** "iOS support is in beta. Read the iOS notes." link
to the FAQ entry.

### 4.3 `/how-it-works`

A short narrative — 3 minutes of reading — explaining how Daal
operates without dropping the reader into protocol detail.

**Sections:**

- **The problem.** Two paragraphs. State censorship is the
  problem; centralized VPN services are blocked too quickly; the
  approach Daal takes is decentralized routes signed by trusted
  publishers.
- **The recipient flow.** Four steps with screenshots from the
  app: "Open Daal" → "Add a Source from a publisher you trust"
  → "Pick a route" → "Connect."
- **The publisher flow.** Three steps: "Set up a server abroad"
  → "Generate signed routes" → "Share a subscription with the
  people you trust."
- **What stays on your device.** Bullet list of what never leaves
  the device (matches §1.5 of the app brief — diagnostics are
  redacted, no destinations, no IPs).
- **What does not happen.** Bullet list. No accounts. No cloud
  sync. No remote analytics. No "phone home." No tracking.
- **Read more:** links to `/sections`, `/faq`, `/about`.

Each step includes a small inline illustration — at minimum a
captioned screenshot from the app. We can supply screenshots from
the snapshot test corpus produced in D-2 §8.3.

### 4.4 `/sections`

This is the **detailed app walkthrough** the user asked for. One
section per top-level section of the app, each with:

- Section name + Persian subtitle.
- A screenshot from the app (light + dark).
- 3-5 paragraphs explaining what it does, in plain language, no
  jargon. Pulls heavily from the design brief but rewritten as
  prose for the reader, not as a spec.
- Anchor links so the page can be navigated by section
  (`#connection`, `#routes`, `#sources`, `#status`, `#settings`,
  `#publisher`).

The `Publisher` section is rendered with the cyan accent and
labeled "Advanced — for users who run a server." A note at the
top: "Most users will never need this section. It's for people
who set up a VPS to make routes for friends and family."

### 4.5 `/faq`

**Audience-driven Q&A**, organized into three groups:

1. **Trust & privacy:**
   - "Who runs Daal?"
   - "Can Daal see what I do online?"
   - "Why does Daal need a VPN permission?"
   - "What happens if my phone is taken?"
   - "Why are PIN unlocks so strict (no biometrics)?"
2. **Using the app:**
   - "I have a route from a friend. How do I add it?"
   - "What's a Source?"
   - "What does Lifeline mode do?"
   - "Why did the app pick this route?"
   - "What's the trust prompt?"
3. **Publishing:**
   - "What does it mean to be a publisher?"
   - "How do I set up a server?"
   - "What if my publisher key is compromised?"

Answers are 2-5 sentences each. Where the brief has explicit
hard rules (§1), they get a short, plain-language summary.

### 4.6 `/about`

- **What this is:** project provenance — Daal grew out of an
  internal prototype called Daal. The rename happened when the
  project went public.
- **License:** GPL-3.0; full text linked.
- **Source code:** GitHub repo link, with an instruction on how
  to build from source.
- **Contributors:** auto-injected from the repo's
  `git shortlog`-style aggregation at site build (no GitHub API
  call at runtime — the list is baked in by the build).
- **Security disclosure:** an email or Signal address for
  responsible disclosure of vulnerabilities.
- **Acknowledgements:** other projects we depend on (sing-box,
  WireGuard, Tauri, Compose, SwiftUI, BoringTun, etc.) with one
  line each and a link.

---

## 5. Visual language

The site **inherits the app's design DNA verbatim** so a user
arriving from the site feels continuity when they install the app.

- Same color tokens (light + dark) from the brief §10.1, with
  sRGB fallbacks. The web is fine with OKLCH; the fallback
  matters for older browsers (Safari < 15.4, Firefox < 113,
  Chrome < 111). Token JSON in `client-shared/tokens/colors.json`
  is the source; CI emits a `website/assets/tokens.css` file.
- Same typography stack. Iowan Old Style for display, system
  humanist body, Vazirmatn for FA, system mono. **Bundled
  locally** in `website/assets/fonts/`.
- Same iconography family.
- The phoenix shield is the only "illustration" anywhere on the
  site. No stock illustrations, no isometric bros, no figmoji.
- The publisher cyan accent shows up only in the publisher
  marketing strip and the `/sections#publisher` anchor.
- Generous white space. Editorial column widths
  (max-width ~64ch for body text). Text-wrap balanced.
- Animation budget: a slow phoenix breathe on the landing hero
  (`prefers-reduced-motion: reduce` falls back to static), a soft
  fade-in on first paint, no scroll-tied parallax, no
  intersection-observer reveals beyond the first paint.

The three reference HTMLs in `/home/daal/src/` already model the
visual language at production fidelity — the website should look
like a marketing-copy variant of those, not a different look.

---

## 6. Build pipeline

The site is rebuilt on every push to `main` of the `daal` repo
when `/website/**` or `/CHANGELOG.md` changes, and **also on every
release publish event** so the download links and version stamp
auto-refresh.

```
on:
  push:
    branches: [main]
    paths: ['website/**', 'CHANGELOG.md']
  release:
    types: [published]
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./website/build.sh
      - uses: actions/upload-pages-artifact@v3
        with: { path: website/dist }

  deploy:
    needs: build
    permissions: { pages: write, id-token: write }
    environment: { name: github-pages }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/deploy-pages@v4
```

`./website/build.sh` does:

1. Read `client-shared/tokens/colors.json` → emit `tokens.css`.
2. Read the latest signed release from the `daal` repo's
   `releases/latest` (via the GitHub REST API, **at build time**
   — never at site visitor's runtime). Extract the **tag name**,
   the artefact filenames, sizes, SHA-256 hashes (computed
   locally over the downloaded assets in CI), and version
   string. Bake the **tag-specific** download URLs
   (`releases/download/<tag>/<asset>`) into the rendered HTML —
   never `releases/latest/download/...`. This pins the page to
   the exact release it was built for and removes any window
   where a freshly-published release could leave the live page
   linking to a missing file.
3. Read EN and FA strings from `website/i18n/en.json`,
   `website/i18n/fa.json`.
4. Render the six pages × 2 locales = 12 HTML files, with the
   download links and version stamps baked in.
5. Copy `website/assets/` (fonts, phoenix images, favicon, CSS,
   one small i18n JS) into `website/dist/`.
6. Emit a strict CSP via `<meta http-equiv="Content-Security-
   Policy" content="default-src 'self'; img-src 'self' data:;
   style-src 'self' 'unsafe-inline'; font-src 'self'; script-src
   'self';">` injected into the `<head>` of every rendered page.
   GitHub Pages does not honor `_headers` files, so the meta-tag
   form is the default; the gate is **browser verification**
   (network panel + automated headless-browser test in CI) that
   no request escapes the host origin. If the project later
   moves off GitHub Pages to a host that supports response
   headers, the same CSP can be served as a real header in
   addition.

**The site does no runtime API calls.** The download links are
hardcoded **tag-specific** URLs of the form
`https://github.com/<org>/daal/releases/download/<tag>/<asset>`,
baked at site build time. The version stamp shown on the site is
also from build time. Both lag a release by the time the workflow
takes to re-build (typically minutes); the workflow re-runs on
`release: published` so this lag is bounded.

---

## 7. Acceptance criteria

D-3 ships when **all** of the following hold:

- [ ] The site is reachable at the project's GitHub Pages URL.
- [ ] Both EN (`/`) and FA (`/fa/`) renders are complete; the FA
      pages are true RTL mirrors with FA fonts and Persian-Indic
      numerals where they appear.
- [ ] All six pages are present (landing, download, how-it-works,
      sections, FAQ, about) in both locales.
- [ ] Download tiles point at the latest release of the `daal`
      repo and resolve to a real signed artefact for each
      platform listed in §4.2.
- [ ] Each download tile shows the SHA-256 of the artefact and
      includes a one-line verify command. The hash is auto-
      injected at build, not hand-edited.
- [ ] The CSP `default-src 'self'` is in place and the page loads
      with **zero** outbound network requests beyond the host
      origin (verify with browser network panel).
- [ ] All fonts are served from `/assets/fonts/`. No
      `fonts.googleapis.com`, no third-party CDN, no remote font
      loading anywhere.
- [ ] No analytics. No telemetry. No tracking pixel. No service
      worker that pings home.
- [ ] Light + Dark themes both present and OS-following; manual
      override toggle persists in `localStorage`.
- [ ] Lighthouse audit ≥ 95 on Performance, Accessibility, Best
      Practices, SEO; ≥ 90 on PWA (or PWA disabled if it conflicts
      with §1.2's no-service-worker-pinging-home rule).
- [ ] WCAG AA contrast verified on every color pairing.
- [ ] Pages deploy reproducibly: a `git checkout <commit>` on the
      build host produces byte-identical `website/dist` output for
      the same `releases/latest` snapshot.
- [ ] FA reviewer signoff on every FA string.
- [ ] On a screen reader (NVDA / VoiceOver / TalkBack), the site
      navigation, download buttons, and section anchors are all
      labelled and reachable.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| GitHub Pages goes down or starts injecting tracking. | Static output is reproducible; switching to a different static host (Cloudflare Pages, Codeberg Pages, self-hosted Caddy) is a copy-of-files operation. The site has no GitHub-Pages-specific config beyond the workflow. |
| The download links break when the artefact naming convention changes (e.g. an extra build dimension is added). | Asset names are read from the actual `releases/latest` snapshot at build time, not hard-coded. A naming change therefore propagates automatically to the site on the next build (which fires on `release: published`). The asset names are also fixed by D-1 §4E and verified by D-2 acceptance §6. |
| FA translation lags behind EN. | Hard rule: no FA page may render with English fallback strings. CI fails the build if any `data-i18n` key has no FA value. |
| Lighthouse score regression. | CI runs Lighthouse on the built site as a non-blocking check; PRs that drop the score below the floor surface a warning in review. |
| A user copy-pastes the SHA-256 verify command and it fails because they're on Windows without `sha256sum`. | The download page shows the OS-appropriate command for the user's detected OS (PowerShell `Get-FileHash`, macOS `shasum -a 256`, Linux `sha256sum`). |
| Dependency drift if a static-site generator is adopted later. | Default of "hand-rolled HTML" minimizes deps. If a generator is later adopted, it must produce reproducible output and not introduce runtime JS. |

---

## 9. Test plan

1. **Build reproducibility:** run the build twice on the same
   commit + the same `releases/latest` snapshot; diff the output;
   expect zero diffs.
2. **CSP enforcement:** browser visit with the network panel open;
   confirm zero requests to non-`self` origins. CI runs a
   headless browser test that asserts the same.
3. **Download integrity:** for each artefact tile, fetch the
   target URL, compute SHA-256, compare against the hash printed
   on the page. Run as a CI step.
4. **i18n parity:** every `data-i18n` key in any rendered HTML
   must have entries in both `en.json` and `fa.json`. CI grep.
5. **a11y:** axe-core or Lighthouse a11y on every page; fail the
   build on any error-level finding.
6. **Cross-browser smoke:** load the site in Chrome / Firefox /
   Safari (latest two majors each) + iOS Safari + Android
   Chrome. Visual diffs against approved snapshots.
7. **Manual UX test:** a fresh user follows the landing → download
   → install → first connect path on Windows, Linux, Android.
   Time-to-installed-app target ≤ 3 minutes including download.

---

## 10. Roll-out

1. Branch the site work into `/website/` on the `daal` repo.
2. Wire the GitHub Pages action; first deploy points at a
   `staging.<org>.github.io/daal/` path or a draft branch so the
   site is reviewable before going live.
3. Soft-launch the site one week before announcing publicly; use
   the soak time to catch FA string issues and broken links.
4. Public launch coincides with a tweet/Mastodon/Telegram
   announcement of `Daal v0.2.0` from D-2.
5. Update the README on the `daal` repo to point at the new
   landing URL as the primary install path.

---

## 11. Handover artefacts (produced at end of D-3)

- The site live at the project's Pages URL.
- `website/` directory in the repo, fully reproducible.
- A `D-3.handover.md` summarizing acceptance status, the live URL,
  the EN/FA reviewer signoff log, and the next-track entry point
  (post-rename track is closed; engine-side roadmap continues
  from FRP-13 / public-directory gate).
- Lighthouse + a11y audit reports archived in `docs/audits/`.
- Snapshot library for visual regression archived in
  `test-rigs/website-snapshots/`.

---

## 12. Sequencing summary across D-1, D-2, D-3

| | D-1 | D-2 | D-3 |
|---|---|---|---|
| Renames | Repo + working dir + user-visible product name | UI label "Sources" | Site copy "Daal" everywhere |
| Engine | Untouched | Untouched | Untouched |
| ABI | Untouched | Untouched | Untouched |
| User-visible UI | Old UI, new name | New UI per brief v2 | Site that mirrors the new UI |
| Ships as | `Daal v0.1.0` | `Daal v0.2.0` | Site live at GitHub Pages |
| Risk profile | Identifier-only; lowest | Largest scope | Pure documentation/marketing |

The three phases together replace the engineering-shaped Daal
front of house with a user-shaped Daal front of house, without
touching the engine that took the previous year to harden.
