# client-ui — single Daal GUI (React + Vite + TS)

The one and only Daal client UI. Browser-first development; rendered
inside a Tauri 2 shell (`../client-shell/tauri/`) for desktop today
and Android/iOS via Tauri Mobile next.

## Architecture

```
client-ui/
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── routes/              # top-level screens
│   ├── components/          # cross-screen atoms + composites
│   ├── contract/            # typed D2Contract interface
│   ├── backends/            # tauri.ts (real) + harness.ts (mock)
│   ├── harness/             # scenario catalog + dev picker
│   ├── lib/                 # i18n, prefs, platform helpers
│   ├── styles/              # tokens + d2 component styles
│   └── i18n/                # generated catalogs (mirrored at build)
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
import phoenix3d from '@branding/phoenix-3d/phoenix-3d-desktop.png';
```

The TS bundler resolves the alias to `../client-shared/branding/*`.
No assets are duplicated under `client-ui/`.

## i18n

Canonical catalogs live in `client-shared/i18n/`. `npm run build`
invokes `../tools/sync-i18n.sh` to mirror them into
`src/i18n/d2/` for static bundling.

## Backends

`src/backends/index.ts` picks the active backend at boot:

- `?harness=<scenario>` → `HarnessContract` (canned data, no native)
- otherwise → `TauriContract` (real, invoke('connect', …))

Screens only consume `D2Contract` via React context. They never
import `invoke` or `bridge.ts` directly.

## Telemetry

None. CC.6 unchanged: no analytics, no telemetry, no error beacon.
The frontend never imports a third-party SDK that phones home.
