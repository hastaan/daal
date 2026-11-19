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

type Rgba = [number, number, number, number];

function parse(c: string): Rgba | null {
    const s = c.trim();
    if (s === 'transparent') return [0, 0, 0, 0];
    const v = /^var\(--([a-z0-9-]+)\)$/.exec(s);
    const hex = v ? PALETTE[v[1]] : s;
    const m = hex ? /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex) : null;
    if (!m) return null;
    return [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16), 1];
}

/**
 * `percent` of `a` mixed into `b`. Each side is `var(--token)`, a
 * `#rrggbb` value or `transparent`. An unknown colour gives `a` back
 * unchanged, so a mistake shows a solid colour rather than nothing.
 */
export function mix(a: string, percent: number, b: string): string {
    const x = parse(a);
    const y = parse(b);
    if (!x || !y) return a;
    const p = Math.max(0, Math.min(100, percent)) / 100;
    const alpha = x[3] * p + y[3] * (1 - p);
    if (alpha === 0) return 'rgba(0, 0, 0, 0)';
    // Premultiplied, so mixing with `transparent` keeps the hue.
    const ch = (i: 0 | 1 | 2) => Math.round((x[i] * x[3] * p + y[i] * y[3] * (1 - p)) / alpha);
    return `rgba(${ch(0)}, ${ch(1)}, ${ch(2)}, ${Math.round(alpha * 1000) / 1000})`;
}
