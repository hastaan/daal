# `test-rigs/snapshots-d2/` — D-2 visual snapshot library

This directory holds approved per-flow visual snapshots used by the
D-2 acceptance gate (D-2 §7.9). Each primary flow has four
snapshots:

- `EN-light.png` — English, light theme
- `EN-dark.png` — English, dark theme
- `FA-light.png` — Persian, light theme, RTL
- `FA-dark.png` — Persian, dark theme, RTL

Snapshots live under per-platform subdirectories:

```
test-rigs/snapshots-d2/
├── README.md
├── fixtures/
│   └── diagnostics-export-sample.json   # exported diag for CI redaction test
├── desktop/
│   ├── connection/
│   │   ├── EN-light.png
│   │   ├── EN-dark.png
│   │   ├── FA-light.png
│   │   └── FA-dark.png
│   ├── onboarding-W/
│   ├── onboarding-B/
│   ├── routes-empty/
│   ├── sources-empty/
│   ├── status/
│   ├── settings/
│   └── trust-prompt/
├── android/
│   └── ... (same flow names)
└── ios/
    └── ... (same flow names)
```

## Capture

Captured by:

- **Desktop (Tauri):** Playwright drives the dev server via
  `npm run dev` then `playwright snap`.
- **Android:** Compose UI test rig with `captureToImage()` per
  destination.
- **iOS:** XCUITest with `XCUIScreenshot`.

A capture script template lives at
`test-rigs/snapshots-d2/capture/playwright-template.spec.ts`.

## Diff threshold

CI uses 0.2% per-pixel tolerance with a hard 1% area-affected cap.
Approved snapshots live in this directory; a PR that changes a
snapshot must include the new approved PNG and a brief justification
in the PR description.

## License

Snapshots are part of the test fixture corpus and ship under the
same license as the rest of the repo (GPL-3.0). They are
intentionally excluded from end-user APK / DMG / NSIS bundles by the
release packaging pipeline.
