// StatusPill — mono-letterspacing badge with a colored dot. Used for
// connection state, trust badges, route health.

import type { ReactNode } from 'react';

type Tone = 'good' | 'warn' | 'bad' | 'neutral' | 'gold';

interface Props {
    tone: Tone;
    children: ReactNode;
    glow?: boolean;
    dotless?: boolean;
}

const TONE_COLOR: Record<Tone, string> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    neutral: 'var(--muted)',
    gold: 'var(--gold-warm)',
};

export function StatusPill({ tone, children, glow, dotless }: Props) {
    const color = TONE_COLOR[tone];
    return (
        <span
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 7,
                fontFamily: 'var(--font-mono)',
                fontSize: 9.5,
                fontWeight: 600,
                letterSpacing: '0.18em',
                textTransform: 'uppercase',
                color,
            }}
        >
            {!dotless && (
                <span
                    aria-hidden
                    style={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        background: color,
                        boxShadow: glow ? `0 0 8px ${color}` : 'none',
                    }}
                />
            )}
            {children}
        </span>
    );
}
