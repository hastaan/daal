#!/usr/bin/env node
// gen-tokens.mjs — emit per-platform color tokens from
// client-shared/tokens/colors.json. CI re-runs this and `git diff
// --exit-code`s the outputs to detect drift.
//
// Usage:
//   node tools/gen-tokens.mjs                    # all targets
//   node tools/gen-tokens.mjs --target=tauri

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const SOURCE = resolve(root, 'client-shared/tokens/colors.json');

const args = process.argv.slice(2);
const opt = (k) => {
    const a = args.find((x) => x.startsWith(`--${k}=`));
    return a ? a.slice(k.length + 3) : null;
};

const target = opt('target'); // null = all

const tokens = JSON.parse(readFileSync(SOURCE, 'utf8'));

const banner = `/* GENERATED FROM client-shared/tokens/colors.json — DO NOT EDIT.
 * Re-run: node tools/gen-tokens.mjs
 * Source version: ${tokens.version}
 */`;

const targets = {};

// ---- Tauri / React (CSS custom properties + light/dark blocks) ----

targets['tauri'] = {
    out: 'client-ui/src/styles.tokens.css',
    render() {
        const lines = [];
        lines.push(banner);
        lines.push(':root {');
        for (const [k, v] of Object.entries(tokens.themes.dark.tokens)) {
            lines.push(`    --${k}: ${v.srgb};`);
            lines.push(`    --${k}-oklch: ${v.oklch};`);
        }
        lines.push(`    --font-display: ${tokens.typography.font_display};`);
        lines.push(`    --font-body: ${tokens.typography.font_body};`);
        lines.push(`    --font-mono: ${tokens.typography.font_mono};`);
        lines.push(`    --font-fa: ${tokens.typography.font_fa};`);
        for (const [k, v] of Object.entries(tokens.shape)) {
            lines.push(`    --${k.replace(/_/g, '-')}: ${v}px;`);
        }
        lines.push(`    --motion-phoenix-breathe: ${tokens.motion.phoenix_breathe_seconds}s;`);
        lines.push(`    --motion-phoenix-breathe-delay-outer: ${tokens.motion.phoenix_breathe_delay_outer_seconds}s;`);
        lines.push(`    --motion-fast: ${tokens.motion.transition_fast_ms}ms;`);
        lines.push(`    --motion-default: ${tokens.motion.transition_default_ms}ms;`);
        lines.push(`    --motion-slow: ${tokens.motion.transition_slow_ms}ms;`);
        lines.push('}');
        lines.push('');
        lines.push('@media (prefers-color-scheme: light) {');
        lines.push('    :root {');
        for (const [k, v] of Object.entries(tokens.themes.light.tokens)) {
            lines.push(`        --${k}: ${v.srgb};`);
            lines.push(`        --${k}-oklch: ${v.oklch};`);
        }
        lines.push('    }');
        lines.push('}');
        lines.push('');
        lines.push('html[data-theme="light"] {');
        for (const [k, v] of Object.entries(tokens.themes.light.tokens)) {
            lines.push(`    --${k}: ${v.srgb};`);
            lines.push(`    --${k}-oklch: ${v.oklch};`);
        }
        lines.push('}');
        lines.push('html[data-theme="dark"] {');
        for (const [k, v] of Object.entries(tokens.themes.dark.tokens)) {
            lines.push(`    --${k}: ${v.srgb};`);
            lines.push(`    --${k}-oklch: ${v.oklch};`);
        }
        lines.push('}');
        return lines.join('\n') + '\n';
    },
};

// The legacy Compose Android and SwiftUI iOS targets used to live
// here. They were retired in the v0.2 unified-client move (see
// CHANGELOG.md and `client-shell/tauri/plugins/daal-platform/`). The
// native trees have no source of truth, so this generator now only
// emits Tauri tokens.

// ---- write outputs ----------------------------------------------

function writeOne(t) {
    const outPath = resolve(root, t.out);
    const body = t.render();
    if (!existsSync(dirname(outPath))) mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, body);
    console.log(`[tokens] wrote ${t.out}`);
}

const wantedKeys = target ? [target] : Object.keys(targets);
for (const k of wantedKeys) {
    if (!targets[k]) {
        console.error(`[tokens] unknown target: ${k}`);
        process.exit(2);
    }
    writeOne(targets[k]);
}
console.log('[tokens] done.');
