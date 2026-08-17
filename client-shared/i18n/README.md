# `client-shared/i18n/` — strings catalog source of truth (D-2 §5G)

EN is the source of truth. FA is reviewed by a native speaker before
any release. Both are valid ICU MessageFormat.

## Files

| File | Locale |
|---|---|
| `en.json` | English (source) |
| `fa.json` | Persian / Farsi (RTL) |

## Per-platform mirrors

Each platform also keeps its own mirror in the platform's native
format. Those mirrors are loaded into the platform's i18n stack;
they're allowed to extend (platform-only keys) but **must not
contradict** keys from the shared catalog.

There is now **one** mirror, not three. Desktop and Android render the
same React UI, and there is no iOS app shell.

| Source | Mirror | Copied by |
|---|---|---|
| `client-shared/i18n/{desktop,onboarding,mobile,d2-extra}.{en,fa}.json` | `client-ui/src/i18n/d2/` | `tools/sync-i18n.mjs` (run by `npm run build`) |

The three per-platform paths documented here until 2026-08-17
(`client-desktop/tauri/src/i18n/`, `client-android/.../strings.xml`,
`client-ios/.../Localizable.strings`) never existed in this repo.

Two things to know before editing:

- **`client-shared/i18n/en.json` and `fa.json` are NOT synced.**
  `tools/sync-i18n.mjs:15-24` copies only the eight files listed above.
  The app's base catalog is `client-ui/src/i18n/{en,fa}.json`, which is
  edited directly. The two `client-shared` files are a stale fork and
  their contents disagree with what ships.
- There is no `tools/check-i18n.sh` and no CI lint. Nothing verifies
  that the mirror is in sync or that en/fa are at parity.

## Naming rules

- Keys are dot-separated lower-case identifiers.
- "Subscription" → "Sources" rename ships only as **values**. Keys
  stay legacy (`subs.title`, `subscription_card_*`). This keeps
  engine call sites, comments, and dev docs readable.
- ICU placeholders use `{name}` syntax. Plurals use ICU
  `{n, plural, one {…} other {…}}`.

## Allow-listed strings

User-visible strings in code (without an i18n key) are forbidden by
`tools/check-hardcoded-strings.sh` — which you must run **by hand**;
no CI runs it (see `docs/build-and-release.md`). It needs ripgrep
installed and exits 2 if ripgrep is absent. The grep allow-lists:

- code identifiers, comments, log lines
- engine surfaces (diagnostics JSON keys, ABI call names)
- developer docs and READMEs
- fixture data in `specs/test-vectors/` and `test-rigs/`

## RTL

- Body content flips to RTL when the active locale is FA (`dir="rtl"`
  on the document / `LayoutDirection.RTL` on Compose / `.environment(\.layoutDirection, .rightToLeft)` on SwiftUI).
- Editorial chrome stays LTR (matches reference HTMLs).
