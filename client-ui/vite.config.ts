import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { readFileSync } from 'node:fs';

// Tauri exposes the dev server URL via env vars; default to 1420.
const host = process.env.TAURI_DEV_HOST;

// Read the single source-of-truth VERSION at the repo root and inject
// it as a compile-time constant. Keeps Settings → Version perfectly in
// sync with the file the release scripts read.
const APP_VERSION = readFileSync(
    fileURLToPath(new URL('../VERSION', import.meta.url)),
    'utf8',
).trim();

export default defineConfig({
    plugins: [react()],
    clearScreen: false,
    define: {
        __APP_VERSION__: JSON.stringify(APP_VERSION),
    },
    resolve: {
        alias: {
            // Canonical brand assets live in client-shared/branding/.
            '@branding': fileURLToPath(new URL('../client-shared/branding', import.meta.url)),
            // Canonical contract types live in client-shared/contract/.
            '@contract': fileURLToPath(new URL('../client-shared/contract', import.meta.url)),
            // Canonical design source HTMLs (used by tooling & visual diffs).
            '@designs': fileURLToPath(new URL('../client-shared/designs', import.meta.url)),
            // Shared design tokens.
            '@tokens': fileURLToPath(new URL('../client-shared/tokens', import.meta.url)),
        },
    },
    server: {
        host: host || '127.0.0.1',
        port: 1420,
        strictPort: true,
        watch: { ignored: ['**/src-tauri/**'] },
        // Allow Vite to read files outside the project root (client-shared/).
        fs: { allow: ['..', '../client-shared'] },
    },
    build: {
        target: ['es2022'],
        sourcemap: false,
        // Strip console in release; CC.6 — no telemetry, but be tidy.
        minify: 'esbuild',
    },
});
