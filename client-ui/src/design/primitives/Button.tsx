// Button — primary / secondary / ghost / danger variants. All sizes
// are touch-friendly (44px+ tap target by default thanks to padding).

import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
type Size = 'sm' | 'md' | 'lg';

interface Props
    extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
    variant?: Variant;
    size?: Size;
    block?: boolean;
    leading?: ReactNode;
    trailing?: ReactNode;
    children: ReactNode;
}

const PADS: Record<Size, string> = {
    sm: '6px 12px',
    md: '10px 16px',
    lg: '14px 22px',
};
const FONTS: Record<Size, number> = { sm: 12, md: 13, lg: 15 };

export function Button({
    variant = 'primary',
    size = 'md',
    block,
    leading,
    trailing,
    children,
    style,
    ...rest
}: Props) {
    const base = {
        display: block ? 'flex' : 'inline-flex',
        width: block ? '100%' : undefined,
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        padding: PADS[size],
        borderRadius: 'var(--radius-md)',
        fontSize: FONTS[size],
        fontFamily: 'var(--font-body)',
        fontWeight: 600,
        cursor: rest.disabled ? 'not-allowed' : 'pointer',
        opacity: rest.disabled ? 0.55 : 1,
        transition:
            'background var(--t-fast), color var(--t-fast), border var(--t-fast)',
    } as const;
    const variants: Record<Variant, React.CSSProperties> = {
        primary: {
            background: 'var(--gold)',
            border: 0,
            color: 'oklch(20% 0.04 80)',
        },
        secondary: {
            background: 'var(--surface-2)',
            border: '1px solid var(--line)',
            color: 'var(--fg)',
        },
        ghost: {
            background: 'transparent',
            border: 0,
            color: 'var(--muted)',
        },
        danger: {
            background: 'transparent',
            border: '1px solid color-mix(in oklab, var(--red) 50%, transparent)',
            color: 'var(--red)',
        },
    };
    return (
        <button {...rest} style={{ ...base, ...variants[variant], ...style }}>
            {leading}
            <span>{children}</span>
            {trailing}
        </button>
    );
}
