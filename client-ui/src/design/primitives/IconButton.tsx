// IconButton — square button used in nav bars, tabbars, toolbars.

import type { ButtonHTMLAttributes, ReactNode } from 'react';

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
    children: ReactNode;
    size?: number;
    active?: boolean;
    label?: string;
}

export function IconButton({
    children,
    size = 40,
    active,
    label,
    style,
    ...rest
}: Props) {
    return (
        <button
            {...rest}
            aria-label={label ?? rest['aria-label']}
            style={{
                width: size,
                height: size,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: active
                    ? 'rgba(201,162,58,0.10)'
                    : 'transparent',
                border: 0,
                borderRadius: 12,
                color: active ? 'var(--gold-warm)' : 'var(--muted)',
                cursor: rest.disabled ? 'not-allowed' : 'pointer',
                transition: 'background var(--t-fast), color var(--t-fast)',
                ...style,
            }}
        >
            {children}
        </button>
    );
}
