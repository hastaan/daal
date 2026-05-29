// SidebarFull — labelled vertical nav for DesktopShell.

import type { ReactNode } from 'react';
import type { SectionId } from './icons';
import { SECTION_ICONS } from './icons';

interface Item {
    id: SectionId;
    label: string;
    shortcut?: string;
    badge?: string;
    disabled?: boolean;
}

interface Props {
    active: SectionId;
    sections: Array<{ label: string; items: Item[] }>;
    onChange: (id: SectionId) => void;
    footer?: ReactNode;
    width?: number;
}

export function SidebarFull({
    active,
    sections,
    onChange,
    footer,
    width = 240,
}: Props) {
    return (
        <aside
            style={{
                width,
                background: 'var(--bg-deep)',
                borderInlineEnd: '1px solid var(--line-soft)',
                display: 'flex',
                flexDirection: 'column',
                padding: '18px 0',
                minHeight: 0,
            }}
        >
            {/* Sidebar header intentionally empty — no logo at the
                top of the desktop sidebar. The brand mark lives on the
                Connection page; repeating it permanently in the rail
                read as visual noise / a stray empty box. */}

            {sections.map((sec, si) => (
                <div key={si}>
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            textTransform: 'uppercase',
                            letterSpacing: '0.16em',
                            color: 'var(--dim)',
                            padding: '12px 18px 6px',
                        }}
                    >
                        {sec.label}
                    </div>
                    {sec.items.map((it) => {
                        const on = active === it.id;
                        return (
                            <button
                                key={it.id}
                                disabled={it.disabled}
                                onClick={() => onChange(it.id)}
                                style={{
                                    width: '100%',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 12,
                                    padding: '10px 18px',
                                    color: it.disabled
                                        ? 'var(--dim)'
                                        : on
                                            ? 'var(--fg)'
                                            : 'var(--muted)',
                                    background: on
                                        ? 'rgba(201,162,58,0.08)'
                                        : 'transparent',
                                    borderInlineStart: `2px solid ${
                                        on ? 'var(--gold)' : 'transparent'
                                    }`,
                                    borderTop: 0,
                                    borderInlineEnd: 0,
                                    borderBottom: 0,
                                    fontFamily: 'var(--font-body)',
                                    fontSize: 14,
                                    textAlign: 'start',
                                    cursor: it.disabled
                                        ? 'not-allowed'
                                        : 'pointer',
                                }}
                            >
                                <span
                                    style={{
                                        width: 18,
                                        height: 18,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        flexShrink: 0,
                                    }}
                                >
                                    {SECTION_ICONS[it.id]}
                                </span>
                                <span style={{ flex: 1 }}>{it.label}</span>
                                {it.badge ? (
                                    <span
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 9,
                                            textTransform: 'uppercase',
                                            letterSpacing: '0.14em',
                                            background: 'var(--surface-2)',
                                            color: 'var(--muted)',
                                            padding: '2px 6px',
                                            borderRadius: 3,
                                        }}
                                    >
                                        {it.badge}
                                    </span>
                                ) : it.shortcut ? (
                                    <span
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 10,
                                            color: 'var(--dim)',
                                            letterSpacing: '0.06em',
                                        }}
                                    >
                                        {it.shortcut}
                                    </span>
                                ) : null}
                            </button>
                        );
                    })}
                </div>
            ))}

            <div
                style={{
                    marginTop: 'auto',
                    padding: '14px 18px',
                    borderBlockStart: '1px solid var(--line-soft)',
                }}
            >
                {footer}
            </div>
        </aside>
    );
}
