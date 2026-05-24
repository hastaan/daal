import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { execSync } from 'node:child_process';
import { readFileSync, statSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

// GitHub Pages serves the project at <user>.github.io/<repo>/, so we
// build with a base of `/daal/`. Override via env for `npm run dev`
// (root /) or for forks under different repo names.
const BASE = process.env.VITE_BASE ?? '/daal/';

// ---- Build-time release manifest -----------------------------------
// We want the landing page's "12.8 MB" / "14 MB" sizes to come from
// the actual artifact files, not be hand-maintained strings. To keep
// the runtime page API-free (it must work in censorship contexts) we
// resolve sizes ONCE at build time and inject them as a virtual
// constant the page reads synchronously.
//
// Resolution order per filename:
//   1. local `dist-release/v<VERSION>/<filename>` — Linux/Android
//      artifacts built on the dev machine before upload.
//   2. `gh release view <tag>` JSON — Win/Mac/iOS artifacts built by
//      AppVeyor and uploaded straight to the release.
//   3. empty string — UI hides the size pill if missing.

const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));
const VERSION = readFileSync(join(REPO_ROOT, 'VERSION'), 'utf8').trim();
const DIST_DIR = join(REPO_ROOT, 'dist-release', `v${VERSION}`);
const TAG = `v${VERSION}`;

function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '';
  const kb = n / 1024;
  if (kb < 1024) return `${Math.round(kb)} KB`;
  const mb = kb / 1024;
  if (mb >= 100) return `${Math.round(mb)} MB`;
  if (mb >= 10) return `${mb.toFixed(1)} MB`;
  return `${mb.toFixed(2)} MB`;
}

function localSizes(): Record<string, number> {
  const out: Record<string, number> = {};
  if (!existsSync(DIST_DIR)) return out;
  for (const name of readdirSync(DIST_DIR)) {
    try {
      out[name] = statSync(join(DIST_DIR, name)).size;
    } catch {
      /* ignore */
    }
  }
  return out;
}

function ghSizes(): Record<string, number> {
  // Best-effort. If `gh` is missing or unauthenticated we skip — the
  // missing artifacts will simply render without a size pill.
  try {
    const json = execSync(
      `gh release view ${TAG} --json assets 2>/dev/null`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    );
    const parsed = JSON.parse(json) as {
      assets: { name: string; size: number }[];
    };
    return Object.fromEntries(parsed.assets.map((a) => [a.name, a.size]));
  } catch {
    return {};
  }
}

const sizes = { ...ghSizes(), ...localSizes() }; // local takes priority
const SIZES: Record<string, string> = Object.fromEntries(
  Object.entries(sizes).map(([k, v]) => [k, fmtBytes(v)]),
);

export default defineConfig({
  base: BASE,
  define: {
    // Injected at build time, read by downloads.ts. Map of filename →
    // formatted size string (e.g. "12.8 MB"). Empty for unbuilt assets.
    __RELEASE_SIZES__: JSON.stringify(SIZES),
    __APP_VERSION__: JSON.stringify(VERSION),
  },
  plugins: [react()],
  resolve: {
    alias: {
      '@branding': fileURLToPath(new URL('../client-shared/branding', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 1421,
    strictPort: true,
    fs: { allow: ['..', '../client-shared'] },
  },
  build: {
    target: ['es2022'],
    sourcemap: false,
    minify: 'esbuild',
    outDir: 'dist',
  },
});
