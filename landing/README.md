# landing/

Standalone Vite + React build for `https://hastaan.github.io/daal/`.

## Why a separate project (not part of `client-ui/`)?

`client-ui/` is the in-app shell that ships inside the Tauri / Android / iOS
binary. It assumes Tauri's IPC bridge, the connection state machine, and the
i18n harness. The landing/download page needs **none** of that — it's a static
brochure with download links.

Mixing them would force every visitor to hastaan.github.io/daal to pull the
full in-app bundle (~344 KB + Tauri stubs). Splitting keeps the landing page
under 80 KB gzipped while sharing the same design tokens and brand assets via
the `@branding` alias (`../client-shared/branding/`).

## Layout

```
landing/
  index.html              # entry; <title>, OG tags, favicon links
  public/                 # static files (favicon.svg)
  src/
    main.tsx              # createRoot
    App.tsx               # one-page layout
    downloads.ts          # platform / file catalog (single source of truth for download URLs)
    styles.css            # tokens copied from client-ui/src/design/tokens.css
    vite-env.d.ts         # module declarations for `@branding/...?url`
  vite.config.ts          # base = '/daal/' (set VITE_BASE='/' for dev/preview)
  tsconfig.json
  package.json
```

## Build / preview

```bash
cd landing
npm install
npm run build      # → dist/
npm run preview    # serves dist/ on http://localhost:4173
```

For local dev with hot reload:

```bash
VITE_BASE=/ npm run dev
# opens at http://127.0.0.1:1421/
```

## Updating the download catalog

Edit `src/downloads.ts`:

1. Bump `RELEASE_VERSION`.
2. Adjust each platform's `files` array (filenames must match what's uploaded
   to the GitHub Release).
3. Flip `unavailable: true` to `false` (or remove it) as builds for the new
   version land on the Release page.
4. Re-run `npm run build` and redeploy.

## Deploying to GitHub Pages

We use the **`gh-pages` branch** method (not `/docs` on main) because
`docs/` already contains markdown documentation that must not collide
with the static landing site.

The helper `tools/deploy-landing.sh` does the whole dance via a
temporary git worktree, so the working tree of `main` is never touched:

```bash
bash tools/deploy-landing.sh           # build + commit + push gh-pages
bash tools/deploy-landing.sh --dry-run # build only, skip git work
```

First-time setup on github.com (only once per repo):

```
Settings → Pages → Source: "Deploy from a branch"
                → Branch: gh-pages / (root) → Save
```

After the first push the site goes live at
`https://hastaan.github.io/daal/` in about a minute.

This deploy path does **not** depend on GitHub Actions, so it works even
while the Actions queue is throttled.
