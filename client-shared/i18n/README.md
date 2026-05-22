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

| Platform | Mirror |
|---|---|
| Desktop | `client-desktop/tauri/src/i18n/{en,fa}.json` |
| Android | `client-android/app/src/main/res/values{,-fa}/strings.xml` |
| iOS | `client-ios/DaalApp/Resources/{en,fa}.lproj/Localizable.strings` |

A future CI lint (`tools/check-i18n.sh`) parses all four sources and
fails the build if a shared-catalog key is missing or its value
diverges from the platform mirror.

## Naming rules

- Keys are dot-separated lower-case identifiers.
- "Subscription" → "Sources" rename ships only as **values**. Keys
  stay legacy (`subs.title`, `subscription_card_*`). This keeps
  engine call sites, comments, and dev docs readable.
- ICU placeholders use `{name}` syntax. Plurals use ICU
  `{n, plural, one {…} other {…}}`.

## Allow-listed strings

User-visible strings in code (without an i18n key) are forbidden by
CI grep (`tools/check-hardcoded-strings.sh`). The grep allow-lists:

- code identifiers, comments, log lines
- engine surfaces (diagnostics JSON keys, ABI call names)
- developer docs and READMEs
- fixture data in `specs/test-vectors/` and `test-rigs/`

## RTL

- Body content flips to RTL when the active locale is FA (`dir="rtl"`
  on the document / `LayoutDirection.RTL` on Compose / `.environment(\.layoutDirection, .rightToLeft)` on SwiftUI).
- Editorial chrome stays LTR (matches reference HTMLs).
