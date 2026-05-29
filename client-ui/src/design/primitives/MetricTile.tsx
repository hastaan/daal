// MetricTile — dashboard tile: small label, big value, optional
// trend or accent. Used inside Diagnostics page.

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
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    letterSpacing: '0.18em',
                    textTransform: 'uppercase',
                    color: 'var(--dim)',
                }}
            >
                {tone && <StatusLight tone={tone} pulse={pulse} />}
                <span>{label}</span>
            </div>
            <div
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 26,
                    fontWeight: 500,
                    color: 'var(--fg)',
                    lineHeight: 1.1,
                    overflowWrap: 'anywhere',
                }}
            >
                {value}
                {unit && (
                    <span
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 13,
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
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: 'var(--muted)',
                        letterSpacing: '0.04em',
                    }}
                >
                    {sub}
                </div>
            )}
        </div>
    );
}
