// StateIcon — a small state disc for checklists, list rows and summaries:
// ok ✓ green, warn ! amber, bad × red, off – muted, none = a hollow ring,
// busy = a spinning arc.

interface StateIconProps {
    state: 'ok' | 'warn' | 'bad' | 'busy' | 'off' | 'none';
    size?: number;
    /** Gives it a name (role="img"); without it, it is decoration. */
    label?: string;
    /** 'outline': a coloured ring and glyph on no disc — the quieter
     *  form, for "works" beside a filled "in use". */
    variant?: 'filled' | 'outline';
}

const FILL: Record<'ok' | 'warn' | 'bad' | 'off', string> = {
    ok: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    off: 'var(--muted)',
};

// Glyphs drawn on the disc in --on-accent (dark; white in the light theme), on a 24-unit grid.
const GLYPH: Record<'ok' | 'warn' | 'bad' | 'off', JSX.Element> = {
    ok: <path d="M7 12.5l3.3 3.3L17 9" />,
    warn: (
        <>
            <path d="M12 7v6" />
            <path d="M12 16.8v.2" />
        </>
    ),
    bad: <path d="M8.5 8.5l7 7M15.5 8.5l-7 7" />,
    off: <path d="M8 12h8" />,
};

export function StateIcon({ state, size = 20, label, variant = 'filled' }: StateIconProps) {
    const a11y = label
        ? { role: 'img' as const, 'aria-label': label }
        : { 'aria-hidden': true as const };
    const box = {
        width: size,
        height: size,
        display: 'inline-flex',
        flexShrink: 0,
        verticalAlign: 'middle',
    } as const;
    if (state === 'busy') {
        return (
            <span {...a11y} data-state="busy" style={box}>
                <svg
                    viewBox="0 0 24 24"
                    width={size}
                    height={size}
                    className="daal-spin"
                    style={{ display: 'block', animation: 'daal-spin 0.9s linear infinite' }}
                >
                    <circle cx="12" cy="12" r="9" fill="none" stroke="var(--line)" strokeWidth={2} />
                    <path d="M12 3a9 9 0 0 1 9 9" fill="none" stroke="var(--gold-warm)" strokeWidth={2} strokeLinecap="round" />
                </svg>
            </span>
        );
    }
    if (state === 'none') {
        return (
            <span {...a11y} data-state="none" style={box}>
                <svg viewBox="0 0 24 24" width={size} height={size} style={{ display: 'block' }}>
                    <circle cx="12" cy="12" r="9" fill="none" stroke="var(--muted)" strokeWidth={1.7} />
                </svg>
            </span>
        );
    }
    if (variant === 'outline') {
        return (
            <span {...a11y} data-state={state} data-variant="outline" style={box}>
                <svg viewBox="0 0 24 24" width={size} height={size} style={{ display: 'block' }}>
                    <circle cx="12" cy="12" r="10" fill="none" stroke={FILL[state]} strokeWidth={1.8} />
                    <g fill="none" stroke={FILL[state]} strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
                        {GLYPH[state]}
                    </g>
                </svg>
            </span>
        );
    }
    return (
        <span {...a11y} data-state={state} style={box}>
            <svg viewBox="0 0 24 24" width={size} height={size} style={{ display: 'block' }}>
                <circle cx="12" cy="12" r="11" fill={FILL[state]} />
                <g fill="none" stroke="var(--on-accent)" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round">
                    {GLYPH[state]}
                </g>
            </svg>
        </span>
    );
}
