// Disclosure — a fold: a summary that opens to show more. A real
// <button aria-expanded> rather than <details>, so it looks and behaves
// the same in every web view. The children are mounted only while open.
//
//   inline: a 44 px gold text link with a chevron (for "Details", help).
//   card:   a full-width card whose header is the summary.

import { useState } from 'react';
import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { Icon } from './icons';
import type { IconName } from './icons';

interface DisclosureProps {
    summary: ReactNode;
    children: ReactNode;
    variant?: 'inline' | 'card';
    /** Leading icon, e.g. 'help' or 'shieldAlert'. */
    icon?: IconName;
    /** Shown at the end of the header (card variant only), e.g. a Badge. */
    trailing?: ReactNode;
    /** danger: icon and summary in red. */
    tone?: 'default' | 'danger';
    defaultOpen?: boolean;
    /** Controlled form: pass both. */
    open?: boolean;
    onToggle?: (open: boolean) => void;
    dataButton?: string;
}

export function Disclosure({
    summary,
    children,
    variant = 'inline',
    icon,
    trailing,
    tone = 'default',
    defaultOpen = false,
    open: openProp,
    onToggle,
    dataButton,
}: DisclosureProps) {
    const { density } = useDensity();
    const [inner, setInner] = useState(defaultOpen);
    const controlled = openProp !== undefined;
    const open = controlled ? !!openProp : inner;
    const toggle = () => {
        const next = !open;
        if (!controlled) setInner(next);
        onToggle?.(next);
    };
    const danger = tone === 'danger';
    const chevron = (
        <span
            aria-hidden
            style={{
                display: 'inline-flex',
                flexShrink: 0,
                transition: 'transform var(--t-fast)',
                transform: open ? 'rotate(180deg)' : 'none',
            }}
        >
            <Icon name="chevronDown" size={variant === 'card' ? 20 : 16} />
        </span>
    );

    if (variant === 'card') {
        return (
            <div
                data-disclosure="card"
                style={{
                    width: '100%',
                    background: 'var(--surface)',
                    border: '1px solid var(--line-soft)',
                    borderRadius: 'var(--r-card)',
                }}
            >
                <button
                    type="button"
                    aria-expanded={open}
                    data-button={dataButton}
                    onClick={toggle}
                    style={{
                        appearance: 'none',
                        width: '100%',
                        minHeight: 56,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 12,
                        padding: '14px 16px',
                        background: 'transparent',
                        border: 0,
                        borderRadius: 'var(--r-card)',
                        color: danger ? 'var(--red)' : 'var(--fg)',
                        cursor: 'pointer',
                        textAlign: 'start',
                    }}
                >
                    {icon && <Icon name={icon} size={20} />}
                    <span
                        style={{
                            flex: 1,
                            minWidth: 0,
                            fontFamily: 'var(--font-display)',
                            fontSize: 16,
                            fontWeight: 500,
                            lineHeight: 1.3,
                        }}
                    >
                        {summary}
                    </span>
                    {trailing}
                    <span style={{ color: 'var(--muted)', display: 'inline-flex' }}>{chevron}</span>
                </button>
                {open && <div style={{ padding: density === 'phone' ? '0 16px 16px' : '0 16px 18px' }}>{children}</div>}
            </div>
        );
    }

    return (
        <div data-disclosure="inline">
            <button
                type="button"
                aria-expanded={open}
                data-button={dataButton}
                onClick={toggle}
                style={{
                    appearance: 'none',
                    minHeight: 44,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '0 2px',
                    background: 'transparent',
                    border: 0,
                    color: danger ? 'var(--red)' : 'var(--gold-warm)',
                    fontFamily: 'var(--font-body)',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: 'pointer',
                    textAlign: 'start',
                }}
            >
                {icon && <Icon name={icon} size={16} />}
                <span>{summary}</span>
                {chevron}
            </button>
            {open && <div style={{ paddingBlock: '4px 8px' }}>{children}</div>}
        </div>
    );
}
