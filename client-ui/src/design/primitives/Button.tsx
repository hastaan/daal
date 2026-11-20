// Button — primary / secondary / ghost / danger / link variants. Every
// variant is at least 44 px high (the smallest comfortable tap target).
//
// One primary (gold) button per screen state (spec A.1); everything else
// is secondary, a link or in the overflow.

import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { mix } from '../mix';
import { Icon, isIconName } from './icons';
import type { IconName } from './icons';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'link';
/** `compact` is the same as `sm`: a small button inside a header row. */
type Size = 'sm' | 'compact' | 'md' | 'lg';

interface Props
    extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
    variant?: Variant;
    size?: Size;
    block?: boolean;
    /** A node, or an icon name (`leading="plus"`). */
    leading?: ReactNode | IconName;
    trailing?: ReactNode;
    /** Written as `data-button`; the harness driver finds controls by it. */
    dataButton?: string;
    children: ReactNode;
}

const PADS: Record<Size, string> = {
    sm: '6px 12px',
    compact: '6px 12px',
    md: '10px 16px',
    lg: '14px 22px',
};
const FONTS: Record<Size, number> = { sm: 13, compact: 13, md: 14, lg: 15 };
const ICONS: Record<Size, number> = { sm: 16, compact: 16, md: 18, lg: 20 };

export function Button({
    variant = 'primary',
    size = 'md',
    block,
    leading,
    trailing,
    dataButton,
    children,
    style,
    type,
    ...rest
}: Props) {
    const base = {
        display: block ? 'flex' : 'inline-flex',
        width: block ? '100%' : undefined,
        minHeight: 44,
        alignItems: 'center',
        justifyContent: 'center',
        gap: 8,
        padding: PADS[size],
        borderRadius: 'var(--radius-md)',
        fontSize: FONTS[size],
        fontFamily: 'var(--font-body)',
        fontWeight: 600,
        lineHeight: 1.25,
        textAlign: 'center',
        cursor: rest.disabled ? 'not-allowed' : 'pointer',
        opacity: rest.disabled ? 0.55 : 1,
        transition:
            'background var(--t-fast), color var(--t-fast), border var(--t-fast)',
    } as const;
    const variants: Record<Variant, React.CSSProperties> = {
        primary: {
            background: 'var(--gold)',
            border: 0,
            color: '#1f1401',
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
            border: `1px solid ${mix('var(--red)', 50, 'transparent')}`,
            color: 'var(--red)',
        },
        link: {
            background: 'transparent',
            border: 0,
            color: 'var(--gold-warm)',
            padding: '10px 4px',
        },
    };
    const lead = isIconName(leading) ? <Icon name={leading} size={ICONS[size]} /> : leading;
    return (
        <button
            type={type ?? 'button'}
            data-button={dataButton}
            // What kind of button this is, for the harness's screen checks
            // (build/ux/capture-all.mjs counts buttons by it).
            data-variant={variant}
            {...rest}
            style={{ ...base, ...variants[variant], ...style }}
        >
            {lead}
            <span>{children}</span>
            {trailing}
        </button>
    );
}
