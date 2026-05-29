// GroupLabel — small mono label that visually groups a list-of-cards
// (or rows). Matches .group-label in daal-mobile-app.html.

import type { ReactNode } from 'react';

export function GroupLabel({ children }: { children: ReactNode }) {
    return (
        <div
            style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 9,
                letterSpacing: '0.18em',
                textTransform: 'uppercase',
                color: 'var(--dim)',
                margin: '14px 0 8px',
            }}
        >
            {children}
        </div>
    );
}
