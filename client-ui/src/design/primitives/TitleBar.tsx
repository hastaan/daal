// TitleBar — the always-visible top strip on Desktop: one status badge
// on the inline-start side, and (only when something is wrong) one on
// the inline-end side. Tall enough for a clickable Badge.

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
                padding: '2px 14px',
                minHeight: 36,
                background: 'var(--bg-deep)',
                borderBottom: '1px solid var(--line-soft)',
                fontFamily: 'var(--font-body)',
                fontSize: 12,
                color: 'var(--muted)',
            }}
        >
            <div style={{ display: 'flex', alignItems: 'center', minWidth: 0 }}>{left}</div>
            <div style={{ display: 'flex', alignItems: 'center', minWidth: 0 }}>{right}</div>
        </div>
    );
}
