// mix — a blend of two palette colours as a plain rgba() string.
//
// The app used CSS `color-mix()` (and `oklch()`), which web views older
// than Chromium 111 do not understand: the declaration is dropped, so
// borders and tinted backgrounds vanished on a phone whose web view was
// never updated (seen on an Xperia with WebView 103, 2026-11-19). In
// Iran a phone often cannot update it. Every colour the app uses is
// therefore a plain sRGB value, and blends are worked out here.
//
// `PALETTE` mirrors design/tokens.css; a test holds the two together.
//
// The light theme has its own palette (`LIGHT`), and the theme can change
// while a screen is open. So a blend that differs between the themes is
// not returned as a fixed colour: it gets a custom property of its own
// (`--mix-red-16-t`), defined once in a small stylesheet with the dark
// value on :root and the light value under the same selectors tokens.css
// uses. The returned `var(--mix-…, <dark value>)` keeps the dark colour as
// its fallback, so with no document (tests, a refused stylesheet) the
// dark result still shows.

export const PALETTE: Record<string, string> = {
    bg: '#0d2e35',
    'bg-deep': '#001f28',
    surface: '#1a3b42',
    'surface-2': '#284850',
    'surface-3': '#39555c',
    line: '#46595e',
    'line-soft': '#354c52',
    fg: '#f6f1e9',
    muted: '#9da7a9',
    dim: '#717d80',
    gold: '#c9a23a',
    'gold-warm': '#e0ae57',
    'gold-deep': '#a97416',
    green: '#5bbd74',
    'green-dim': '#397949',
    amber: '#dfa635',
    red: '#e55551',
    cyan: '#48b7bd',
};

/** The light theme's values, mirroring the light block of tokens.css. */
export const LIGHT: Record<string, string> = {
    bg: '#f6f2ea',
    'bg-deep': '#efe9de',
    surface: '#fffdf9',
    'surface-2': '#f2ede4',
    'surface-3': '#ddd6ca',
    line: '#d9d1c3',
    'line-soft': '#e7e0d4',
    fg: '#14353c',
    muted: '#4c5f64',
    dim: '#5a6b70',
    gold: '#7a580b',
    'gold-warm': '#7c5509',
    'gold-deep': '#6a4b09',
    green: '#1b6a3c',
    'green-dim': '#336a47',
    amber: '#a64b00',
    red: '#ac2820',
    cyan: '#19656e',
};

/** Tokens defined as another token in tokens.css (`--info: var(--cyan)`). */
export const ALIASES: Record<string, string> = {
    info: 'cyan',
};

type Rgba = [number, number, number, number];

function parse(c: string, palette: Record<string, string>): Rgba | null {
    const s = c.trim();
    if (s === 'transparent') return [0, 0, 0, 0];
    const v = /^var\(--([a-z0-9-]+)\)$/.exec(s);
    const hex = v ? palette[ALIASES[v[1]] ?? v[1]] : s;
    const m = hex ? /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex) : null;
    if (!m) return null;
    return [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16), 1];
}

/**
 * The blend as one plain colour, worked out with one palette: `percent`
 * of `a` mixed into `b`, or null when either side is unknown.
 */
export function blend(
    a: string,
    percent: number,
    b: string,
    palette: Record<string, string> = PALETTE,
): string | null {
    const x = parse(a, palette);
    const y = parse(b, palette);
    if (!x || !y) return null;
    const p = Math.max(0, Math.min(100, percent)) / 100;
    const alpha = x[3] * p + y[3] * (1 - p);
    if (alpha === 0) return 'rgba(0, 0, 0, 0)';
    // Premultiplied, so mixing with `transparent` keeps the hue.
    const ch = (i: 0 | 1 | 2) => Math.round((x[i] * x[3] * p + y[i] * y[3] * (1 - p)) / alpha);
    return `rgba(${ch(0)}, ${ch(1)}, ${ch(2)}, ${Math.round(alpha * 1000) / 1000})`;
}

/** `--mix-red-16-t` for mix('var(--red)', 16, 'transparent'). */
export function mixVarName(a: string, percent: number, b: string): string {
    const part = (c: string) => {
        const s = c.trim();
        if (s === 'transparent') return 't';
        const v = /^var\(--([a-z0-9-]+)\)$/.exec(s);
        return v ? v[1] : s.replace(/[^a-z0-9]/gi, '').toLowerCase();
    };
    return `--mix-${part(a)}-${String(percent).replace(/[^0-9]/g, '_')}-${part(b)}`;
}

const defined = new Set<string>();

/** The stylesheet rules that give one blend its value in each theme. */
export function mixRules(name: string, dark: string, light: string): string {
    return (
        `:root{${name}:${dark}}\n` +
        `:root[data-theme="light"]{${name}:${light}}\n` +
        `@media (prefers-color-scheme: light){:root:not([data-theme="dark"]){${name}:${light}}}\n`
    );
}

function define(name: string, dark: string, light: string): void {
    if (defined.has(name) || typeof document === 'undefined') return;
    defined.add(name);
    try {
        let el = document.getElementById('daal-mix');
        if (!el) {
            el = document.createElement('style');
            el.id = 'daal-mix';
            document.head.appendChild(el);
        }
        el.appendChild(document.createTextNode(mixRules(name, dark, light)));
    } catch {
        /* no stylesheet: the dark value in the fallback shows */
    }
}

/**
 * `percent` of `a` mixed into `b`. Each side is `var(--token)`, a
 * `#rrggbb` value or `transparent`. An unknown colour gives `a` back
 * unchanged, so a mistake shows a solid colour rather than nothing.
 * A blend that is the same in both themes comes back as a plain colour;
 * one that differs comes back as `var(--mix-…, <dark>)` (see the top).
 */
export function mix(a: string, percent: number, b: string): string {
    const dark = blend(a, percent, b, PALETTE);
    if (dark === null) return a;
    const light = blend(a, percent, b, LIGHT) ?? dark;
    if (light === dark) return dark;
    const name = mixVarName(a, percent, b);
    define(name, dark, light);
    return `var(${name}, ${dark})`;
}
