// MetricTile — dashboard tile: small label, big value, optional
// trend or accent. Used inside the Status page. Sentence case, body font;
// the value stays on one line (ellipsis), so it never breaks mid-word.

import type { ReactNode } from 'react';
import { StatusLight } from './StatusLight';

interface Props {
    label: ReactNode;
    value: ReactNode;
    unit?: ReactNode;
    tone?: 'good' | 'warn' | 'bad' | 'neutral';
    pulse?: boolean;
    sub?: ReactNode;
}

export function MetricTile({
    label,
    value,
    unit,
    tone,
    pulse,
    sub,
}: Props) {
    return (
        <div
            style={{
                background: 'var(--surface)',
                border: '1px solid var(--line-soft)',
                borderRadius: 'var(--r-card)',
                padding: '14px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
                minWidth: 0,
            }}
        >
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontFamily: 'var(--font-body)',
                    fontSize: 12,
                    fontWeight: 600,
                    color: 'var(--muted)',
                }}
            >
                {tone && <StatusLight tone={tone} pulse={pulse} />}
                <span>{label}</span>
            </div>
            <div
                style={{
                    // One line, never broken inside a word: a value too
                    // long for the tile ends in an ellipsis instead.
                    fontFamily: 'var(--font-body)',
                    fontSize: 22,
                    fontWeight: 600,
                    color: 'var(--fg)',
                    lineHeight: 1.3,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    minWidth: 0,
                }}
            >
                {value}
                {unit && (
                    <span
                        style={{
                            fontFamily: 'var(--font-body)',
                            fontSize: 13,
                            fontWeight: 400,
                            color: 'var(--muted)',
                            marginInlineStart: 6,
                        }}
                    >
                        {unit}
                    </span>
                )}
            </div>
            {sub && (
                <div
                    style={{
                        fontFamily: 'var(--font-body)',
                        fontSize: 12,
                        color: 'var(--muted)',
                    }}
                >
                    {sub}
                </div>
            )}
        </div>
    );
}
