// GroupLabel — a small label that groups a list of cards or rows.
// Sentence case, body font, readable grey (no mono capitals).

import type { ReactNode } from 'react';

export function GroupLabel({ children }: { children: ReactNode }) {
    return (
        <div
            style={{
                fontFamily: 'var(--font-body)',
                fontSize: 12,
                fontWeight: 600,
                color: 'var(--muted)',
                margin: '14px 0 8px',
            }}
        >
            {children}
        </div>
    );
}
