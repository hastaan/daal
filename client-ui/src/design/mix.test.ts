/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest';
import { blend, LIGHT, mix, mixRules, mixVarName, PALETTE } from './mix';
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
        expect(blend('var(--red)', 50, 'transparent')).toBe('rgba(229, 85, 81, 0.5)');
        expect(mix('#ffffff', 0, 'transparent')).toBe('rgba(0, 0, 0, 0)');
    });
    it('mixing two colours lands between them', () => {
        expect(mix('#ffffff', 50, '#000000')).toBe('rgba(128, 128, 128, 1)');
        expect(blend('var(--gold)', 100, 'var(--surface-2)')).toBe('rgba(201, 162, 58, 1)');
    });
    it('a token defined as another token blends like that token', () => {
        expect(mix('var(--info)', 16, 'transparent')).toBe(mix('var(--cyan)', 16, 'transparent').replace('-cyan-', '-info-'));
        expect(tokens).toMatch(/--info:\s*var\(--cyan\)/);
    });
    it('a blend of theme colours follows the theme, with the dark value as fallback', () => {
        const v = mix('var(--red)', 16, 'transparent');
        expect(v).toBe(`var(--mix-red-16-t, ${blend('var(--red)', 16, 'transparent')})`);
        expect(mixVarName('var(--gold)', 12, 'var(--surface-2)')).toBe('--mix-gold-12-surface-2');
        const rules = mixRules('--mix-red-16-t', 'rgba(1, 2, 3, 0.16)', 'rgba(4, 5, 6, 0.16)');
        expect(rules).toContain(':root{--mix-red-16-t:rgba(1, 2, 3, 0.16)}');
        expect(rules).toContain(':root[data-theme="light"]{--mix-red-16-t:rgba(4, 5, 6, 0.16)}');
        expect(rules).toContain(':root:not([data-theme="dark"]){--mix-red-16-t:rgba(4, 5, 6, 0.16)}');
        // With a document, the stylesheet that defines it is in it.
        if (typeof document !== 'undefined') {
            expect(document.getElementById('daal-mix')?.textContent).toContain('--mix-red-16-t');
        }
    });
    it('the light palette is the one in tokens.css, under both light selectors', () => {
        const forced = /:root\[data-theme="light"\]\s*\{([^}]*)\}/.exec(tokens)?.[1] ?? '';
        const system = /@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme="dark"\]\)\s*\{([^}]*)\}/.exec(tokens)?.[1] ?? '';
        expect(forced.trim()).toBe(system.trim().replace(/\n {4}/g, '\n  '));
        for (const [name, hex] of Object.entries(LIGHT)) {
            const m = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`).exec(forced);
            expect(m?.[1].toLowerCase(), name).toBe(hex);
        }
        expect(Object.keys(LIGHT).sort()).toEqual(Object.keys(PALETTE).sort());
    });
    it('light text colours reach WCAG AA on every light surface', () => {
        const lum = (hex: string) => {
            const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
            const l = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
            return 0.2126 * l[0] + 0.7152 * l[1] + 0.0722 * l[2];
        };
        const ratio = (a: string, b: string) => {
            const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
            return (x + 0.05) / (y + 0.05);
        };
        for (const text of ['fg', 'muted', 'dim', 'gold', 'gold-warm', 'gold-deep', 'green', 'green-dim', 'amber', 'red', 'cyan']) {
            for (const surface of ['bg', 'bg-deep', 'surface', 'surface-2']) {
                expect(ratio(LIGHT[text], LIGHT[surface]), `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5);
            }
        }
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
