# client-ui — single Daal GUI (React + Vite + TS)

The one and only Daal client UI. Browser-first development; rendered
inside a Tauri 2 shell (`../client-shell/tauri/`) for desktop **and
Android**, which both ship today and render these same screens. iOS has
no app shell yet.

## Architecture

```
client-ui/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── d2pages/             # the 5 main screens (Connection, Network,
│   │                        #   Publisher, Settings, Status)
│   ├── shell/               # nav chrome (TabletShell, sidebar/rail)
│   ├── onboarding/          # first-run flow
│   ├── publisher/           # publisher wizard + relay screens
│   ├── recipient/           # recipient identity / import screens
│   ├── components/          # cross-screen atoms + composites
│   ├── design/              # primitives + icons
│   ├── contract/            # typed D2Contract interface
│   ├── backends/            # tauri.ts (real) + harness.ts (mock)
│   ├── harness/             # scenario catalog + dev picker
│   ├── lib/                 # i18n, prefs, platform helpers
│   ├── types/
│   ├── styles.css, styles.d2.css, styles.tokens.css
│   └── i18n/                # base catalogs + d2/ (mirrored at build)
├── public/                  # static assets served verbatim
├── index.html
├── vite.config.ts           # @branding, @contract, @designs aliases
├── package.json
└── tsconfig.json
```

The Tauri Rust shell lives entirely under `../client-shell/tauri/`.
This directory contains zero Rust, zero native code, zero
platform-specific logic.

## Dev loops

```sh
# Pure browser (fastest, no native runtime):
npm install
npm run dev:browser
# Open http://localhost:1420/?harness=connection-connected

# Full desktop app (slower, exercises Rust shell):
cd ../client-shell/tauri
npm install
npm run dev
```

## Brand assets

Canonical sources live in `client-shared/branding/` and are imported
via the `@branding/*` Vite alias:

```ts
import daal3d from '@branding/generated/daal-3d/daal-3d-desktop.png';
```

The TS bundler resolves the alias to `../client-shared/branding/*`.
No assets are duplicated under `client-ui/`.

## i18n

`npm run build` runs `node ../tools/sync-i18n.mjs` first, mirroring the
eight `client-shared/i18n/{desktop,onboarding,mobile,d2-extra}.{en,fa}.json`
catalogs into `src/i18n/d2/` for static bundling. **Edit those in
`client-shared/`** — anything you write directly into `src/i18n/d2/` is
overwritten on the next build.

The base catalog `src/i18n/{en,fa}.json` is **not** mirrored from
anywhere; edit it in place. (`client-shared/i18n/{en,fa}.json` exists but
is a stale fork that nothing copies.)

`npm run dev` is bare `vite` — it does **not** sync. Run the build, or
`node ../tools/sync-i18n.mjs` by hand, after changing a shared catalog.

## Backends

`src/backends/index.ts` picks the active backend at boot:

- `?harness=<scenario>` → `HarnessContract` (canned data, no native)
- otherwise → `TauriContract` (real, invoke('connect', …))

Screens only consume `D2Contract` via React context. They never
import `invoke` or `bridge.ts` directly.

## Telemetry

None. CC.6 unchanged: no analytics, no telemetry, no error beacon.
The frontend never imports a third-party SDK that phones home.
