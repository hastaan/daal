# `client-shared/tokens/` — design-token source of truth

This directory is the single source of truth for Daal brand
**colors**, typography, shape, and motion tokens. Per design brief
v2 §10 and D-2 §5A, every per-platform color file (Tauri CSS,
Android `colors*.xml`, iOS `Colors.xcassets`) is **generated** from
`colors.json` by `tools/gen-tokens.mjs`.

## Files

| File | Role |
|---|---|
| `colors.json` | Source of truth. Every token has OKLCH primary + sRGB fallback, light + dark variants. |
| `colors.schema.json` | JSON-Schema for `colors.json`; CI validates the source against it. |

## Generated outputs

There is exactly **one** target.

| Path | Generator |
|---|---|
| `client-ui/src/styles.tokens.css` | `tools/gen-tokens.mjs --target=tauri` |

The `android-light`, `android-dark` and `ios` targets documented here
until 2026-08-17 **no longer exist** — running any of them prints
`[tokens] unknown target: <name>` and exits 2. They were retired in the
v0.2 unified-client move (`tools/gen-tokens.mjs:84-89`); the native
Compose / SwiftUI trees they wrote into are gone, and Android now renders
the same React UI through `client-ui/src/styles.tokens.css`.

## CI drift check

`tools/check-tokens.sh` re-runs the generator and `git diff --exit-code`
on the outputs. Any drift fails the build.

## Editing rules

1. Edit `colors.json` only.
2. Run `node tools/gen-tokens.mjs` (or `./daal tokens` if available)
   and commit both the source change and the regenerated outputs in
   the same commit.
3. CI will reject a commit that touches a generated file without
   touching the source.

## Token naming

- Token names are identical across platforms: `bg`, `teal-deep`,
  `teal-surface`, …, `gold`, …, `success`, `warn`, `danger`, `cyan`.
- Platforms map them to native conventions:
  - CSS: `--bg`, `--teal-deep`, …
  - Android XML: `daal_bg`, `daal_teal_deep`, …
  - iOS xcassets: each token is one `.colorset` with light/dark
    appearances.

## Why both OKLCH and sRGB?

OKLCH is perceptually uniform (better for ramps and accessibility
contrast tuning). It is supported in modern Tauri (Webview2 / WebKit)
and SwiftUI 17+. Older Android Compose / Material3 still wants sRGB.
The JSON carries both; the generator picks the right one per target.
