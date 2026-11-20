// Disclosure — where the long explanations went.
//
// The relay page used to print every explanation it had, all the time.
// The owner's verdict after one real session: "there is a lot of text
// on page too". The rule now is one short sentence per section; anything
// longer sits behind one of these two.
//
//   WhatIsThis  — an explanation the person may ask for.
//   Collapsible — a whole section that is one summary line until tapped.
//
// Both use glyphs that do not point sideways and logical CSS only, so
// they lay out the same in a right-to-left language.

import type { ReactNode } from 'react';
import { useState } from 'react';
import { Icon } from '../design/primitives';

const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--muted)',
    lineHeight: 1.55,
};

export function WhatIsThis({
    label,
    children,
    defaultOpen,
    dataButton,
}: {
    /** "What is this?" — or a more specific question. */
    label: string;
    children: ReactNode;
    defaultOpen?: boolean;
    dataButton?: string;
}) {
    // Still a <details> (the content is in the page, folded, so the raw
    // text a helper needs is there and tests can see it is inside the
    // fold), but drawn like the app's Disclosure (spec B.5): no sideways
    // triangle, which points the wrong way in Persian, and a chevron that
    // turns when it opens.
    const [open, setOpen] = useState(!!defaultOpen);
    return (
        <details
            open={defaultOpen}
            onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}
        >
            <summary
                className="daal-fold"
                data-button={dataButton}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    listStyle: 'none',
                    fontSize: 13,
                    fontWeight: 600,
                    color: 'var(--gold-warm)',
                    cursor: 'pointer',
                    // A 44 px tap target (E.1.5).
                    minHeight: 44,
                    lineHeight: 1.5,
                }}
            >
                <span>{label}</span>
                <span
                    aria-hidden
                    style={{
                        display: 'inline-flex',
                        flexShrink: 0,
                        transition: 'transform var(--t-fast)',
                        transform: open ? 'rotate(180deg)' : 'none',
                    }}
                >
                    <Icon name="chevronDown" size={16} />
                </span>
            </summary>
            <div style={{ ...BODY, display: 'grid', gap: 8, paddingBottom: 6 }}>
                {children}
            </div>
        </details>
    );
}

export function Collapsible({
    title,
    summary,
    trailing,
    open,
    onToggle,
    children,
}: {
    title: ReactNode;
    /** The one line that stays visible while closed. */
    summary?: ReactNode;
    /** A status pill, typically. */
    trailing?: ReactNode;
    open: boolean;
    onToggle: () => void;
    children: ReactNode;
}) {
    return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <button
                type="button"
                aria-expanded={open}
                onClick={onToggle}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    width: '100%',
                    textAlign: 'start',
                    font: 'inherit',
                    color: 'var(--fg)',
                    background: 'var(--surface)',
                    border: '1px solid var(--line-soft)',
                    borderRadius: 'var(--r-card)',
                    padding: '12px 16px',
                    cursor: 'pointer',
                }}
            >
                <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 3 }}>
                    <span
                        style={{
                            fontFamily: 'var(--font-display)',
                            fontSize: 18,
                            fontWeight: 500,
                            lineHeight: 1.2,
                        }}
                    >
                        {title}
                    </span>
                    {summary && <span style={BODY}>{summary}</span>}
                </span>
                {trailing}
                <span
                    aria-hidden
                    style={{
                        color: 'var(--muted)',
                        display: 'inline-flex',
                        transition: 'transform var(--t-fast)',
                        transform: open ? 'rotate(180deg)' : 'none',
                    }}
                >
                    <Icon name="chevronDown" size={18} />
                </span>
            </button>
            {open && <div style={{ display: 'grid', gap: 8 }}>{children}</div>}
        </section>
    );
}
