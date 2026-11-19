/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest';
import { mix, PALETTE } from './mix';
// The test runner hands CSS imports back empty, so the stylesheet is
// read from disk. The UI package carries no Node typings.
// @ts-expect-error node built-in, untyped here
import { readFileSync } from 'node:fs';
// @ts-expect-error node built-in, untyped here
import { fileURLToPath } from 'node:url';

const cssPath = (rel: string): string => fileURLToPath(new URL(rel, import.meta.url));
const tokens: string = readFileSync(cssPath('./tokens.css'), 'utf8');

describe('colours every web view understands', () => {
    it('mixing with transparent keeps the colour and sets the opacity', () => {
        expect(mix('var(--red)', 50, 'transparent')).toBe('rgba(229, 85, 81, 0.5)');
        expect(mix('#ffffff', 0, 'transparent')).toBe('rgba(0, 0, 0, 0)');
    });
    it('mixing two colours lands between them', () => {
        expect(mix('#ffffff', 50, '#000000')).toBe('rgba(128, 128, 128, 1)');
        expect(mix('var(--gold)', 100, 'var(--surface-2)')).toBe('rgba(201, 162, 58, 1)');
    });
    it('an unknown colour comes back as it was', () => {
        expect(mix('var(--no-such)', 50, 'transparent')).toBe('var(--no-such)');
    });
    it('the palette is the one in tokens.css', () => {
        for (const [name, hex] of Object.entries(PALETTE)) {
            const m = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`).exec(tokens);
            expect(m?.[1].toLowerCase(), name).toBe(hex);
        }
    });
    it('no source file uses a colour function old web views drop', async () => {
        const files = import.meta.glob(['../**/*.{ts,tsx,css}', '!../**/*.test.*'], {
            query: '?raw',
            import: 'default',
            eager: true,
        }) as Record<string, string>;
        // CSS comes back empty through the glob: read the stylesheets from disk.
        // styles.tokens.css is generated (tools/gen-tokens.mjs) and carries
        // `--*-oklch` twins of its hex values that nothing reads; it is
        // checked for that instead, below.
        for (const rel of ['./tokens.css', '../styles.css', '../styles.d2.css']) files[rel] = readFileSync(cssPath(rel), 'utf8');
        const bad: string[] = [];
        for (const [path, text] of Object.entries(files)) {
            text.split('\n').forEach((line, i) => {
                const code = line.replace(/\/\*.*?\*\//g, '').trim();
                if (code.startsWith('//') || code.startsWith('*') || code.startsWith('/*')) return;
                if (/color-mix\(|oklch\(|oklab\(/.test(code)) bad.push(`${path}:${i + 1}`);
            });
        }
        expect(bad).toEqual([]);
        const used = Object.entries(files)
            .filter(([, text]) => /var\(--[a-z0-9-]+-oklch\b/.test(text))
            .map(([path]) => path);
        expect(used).toEqual([]);
    });
    it('Persian text is never letter-spaced', () => {
        const css: string = readFileSync(cssPath('../styles.css'), 'utf8');
        expect(css).toMatch(/:root\[dir="rtl"\] \*\s*\{\s*letter-spacing:\s*0\s*!important;/);
    });
});
