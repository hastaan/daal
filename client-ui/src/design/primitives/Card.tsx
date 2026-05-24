// Card — base surface block used across all densities. Wraps content
// in the standard --surface fill, --line-soft border, --r-card radius.

import type { CSSProperties, ReactNode } from 'react';

interface Props {
    children: ReactNode;
    /** When set, the card adopts the deeper --surface-2 fill (used for
     * "raised" cards on cards). */
    raised?: boolean;
    style?: CSSProperties;
    onClick?: () => void;
    role?: string;
    'aria-label'?: string;
}

export function Card({
    children,
    raised,
    style,
    onClick,
    role,
    'aria-label': ariaLabel,
}: Props) {
    return (
        <div
            role={role}
            aria-label={ariaLabel}
            onClick={onClick}
            style={{
                background: raised ? 'var(--surface-2)' : 'var(--surface)',
                border: '1px solid var(--line-soft)',
                borderRadius: 'var(--r-card)',
                padding: '14px 16px',
                cursor: onClick ? 'pointer' : 'default',
                ...style,
            }}
        >
            {children}
        </div>
    );
}
