// TitleBar — the always-visible top strip on Desktop. Mirrors macOS-
// style window chrome with a small status pill on the right.

import type { ReactNode } from 'react';

interface Props {
    left?: ReactNode;
    right?: ReactNode;
}

export function TitleBar({ left, right }: Props) {
    return (
        <div
            style={{
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
                padding: '6px 14px',
                height: 32,
                background: 'var(--bg-deep)',
                borderBottom: '1px solid var(--line-soft)',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                color: 'var(--muted)',
                letterSpacing: '0.04em',
            }}
        >
            <div>{left}</div>
            <div>{right}</div>
        </div>
    );
}
