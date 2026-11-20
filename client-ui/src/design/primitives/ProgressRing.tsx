// ProgressRing — a circular progress mark, with optional content in its
// centre. With no `value` it spins (indeterminate).

import type { ReactNode } from 'react';

interface ProgressRingProps {
    /** 0..1; undefined = indeterminate. */
    value?: number;
    size?: number;
    stroke?: number;
    /** Centre content (a percentage, an icon, the bird). */
    children?: ReactNode;
    tone?: 'gold' | 'good' | 'bad';
    /** Accessible name of the progress bar. */
    label?: string;
}

const TONE: Record<NonNullable<ProgressRingProps['tone']>, string> = {
    gold: 'var(--gold-warm)',
    good: 'var(--green)',
    bad: 'var(--red)',
};

export function ProgressRing({
    value,
    size = 56,
    stroke = 4,
    children,
    tone = 'gold',
    label,
}: ProgressRingProps) {
    const known = typeof value === 'number' && Number.isFinite(value);
    const v = known ? Math.max(0, Math.min(1, value as number)) : 0.25;
    const r = (size - stroke) / 2;
    const c = 2 * Math.PI * r;
    const pct = Math.round(v * 100);
    return (
        <span
            role="progressbar"
            aria-label={label}
            aria-valuemin={known ? 0 : undefined}
            aria-valuemax={known ? 100 : undefined}
            aria-valuenow={known ? pct : undefined}
            data-progress={known ? pct : 'busy'}
            style={{
                position: 'relative',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: size,
                height: size,
                flexShrink: 0,
            }}
        >
            <svg
                width={size}
                height={size}
                viewBox={`0 0 ${size} ${size}`}
                aria-hidden
                className={known ? undefined : 'daal-spin'}
                style={{
                    position: 'absolute',
                    insetBlockStart: 0,
                    insetInlineStart: 0,
                    display: 'block',
                    // Start at twelve o'clock; spin when indeterminate.
                    transform: known ? 'rotate(-90deg)' : undefined,
                    animation: known ? undefined : 'daal-spin 1.1s linear infinite',
                }}
            >
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={r}
                    fill="none"
                    stroke="var(--line)"
                    strokeWidth={stroke}
                />
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={r}
                    fill="none"
                    stroke={TONE[tone]}
                    strokeWidth={stroke}
                    strokeLinecap="round"
                    strokeDasharray={`${c * v} ${c}`}
                    style={{ transition: known ? 'stroke-dasharray var(--t-slow)' : undefined }}
                />
            </svg>
            {children != null && (
                <span
                    style={{
                        position: 'relative',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'var(--fg)',
                        fontSize: Math.max(11, Math.round(size * 0.24)),
                        fontWeight: 600,
                    }}
                >
                    {children}
                </span>
            )}
        </span>
    );
}
