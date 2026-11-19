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

const BODY: React.CSSProperties = {
    fontSize: 12,
    color: 'var(--muted)',
    lineHeight: 1.55,
};

export function WhatIsThis({
    label,
    children,
    defaultOpen,
}: {
    /** "What is this?" — or a more specific question. */
    label: string;
    children: ReactNode;
    defaultOpen?: boolean;
}) {
    return (
        <details open={defaultOpen}>
            <summary
                style={{
                    fontSize: 12,
                    color: 'var(--gold-warm)',
                    cursor: 'pointer',
                    padding: '6px 0',
                }}
            >
                {label}
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
                <span aria-hidden style={{ color: 'var(--dim)', fontSize: 14 }}>
                    {open ? '▴' : '▾'}
                </span>
            </button>
            {open && <div style={{ display: 'grid', gap: 8 }}>{children}</div>}
        </section>
    );
}
