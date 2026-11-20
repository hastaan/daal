// SidebarFull — labelled vertical nav for DesktopShell.
//
// Calm by default: names and icons only. A section whose label is ''
// has no label row; a keyboard shortcut shows only while its row is
// hovered or focused; a disabled item is not drawn at all (a feature
// that is off is hidden, not shown as "OFF").

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

/** The shortcut hint for the n-th item: "⌘1" on a Mac, "Ctrl+1" elsewhere. */
export function shortcutLabel(n: number): string {
    let mac = false;
    try {
        const nav = typeof navigator === 'undefined' ? undefined : navigator;
        const hint = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`;
        mac = /Mac|iPhone|iPad|iPod/i.test(hint);
    } catch {
        /* no navigator: not a Mac */
    }
    return mac ? `⌘${n}` : `Ctrl+${n}`;
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
            {/* Sidebar header intentionally empty — no logo at the top
                of the desktop sidebar. The brand mark lives on the
                Connection page. */}

            {sections.map((sec, si) => {
                const items = sec.items.filter((it) => !it.disabled);
                if (!items.length) return null;
                return (
                    <div key={si} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        {sec.label !== '' && (
                            <div
                                style={{
                                    fontFamily: 'var(--font-body)',
                                    fontSize: 12,
                                    fontWeight: 600,
                                    color: 'var(--muted)',
                                    padding: '12px 18px 6px',
                                }}
                            >
                                {sec.label}
                            </div>
                        )}
                        {items.map((it) => {
                            const on = active === it.id;
                            return (
                                <button
                                    key={it.id}
                                    type="button"
                                    className="daal-nav-item daal-hover"
                                    data-button={`nav-${it.id}`}
                                    aria-current={on ? 'page' : undefined}
                                    onClick={() => onChange(it.id)}
                                    style={{
                                        width: '100%',
                                        minHeight: 44,
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: 12,
                                        padding: '10px 18px',
                                        color: on ? 'var(--fg)' : 'var(--muted)',
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
                                        fontWeight: on ? 600 : 500,
                                        textAlign: 'start',
                                        cursor: 'pointer',
                                    }}
                                >
                                    <span
                                        style={{
                                            width: 20,
                                            height: 20,
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                            flexShrink: 0,
                                            color: on ? 'var(--gold-warm)' : undefined,
                                        }}
                                    >
                                        {SECTION_ICONS[it.id]}
                                    </span>
                                    <span style={{ flex: 1 }}>{it.label}</span>
                                    {it.badge ? (
                                        <span
                                            style={{
                                                fontFamily: 'var(--font-body)',
                                                fontSize: 11,
                                                fontWeight: 600,
                                                background: 'var(--surface-2)',
                                                color: 'var(--muted)',
                                                padding: '2px 8px',
                                                borderRadius: 'var(--r-pill)',
                                            }}
                                        >
                                            {it.badge}
                                        </span>
                                    ) : it.shortcut ? (
                                        <span
                                            className="daal-nav-shortcut"
                                            aria-hidden
                                            style={{
                                                fontFamily: 'var(--font-body)',
                                                fontSize: 11,
                                                color: 'var(--muted)',
                                                direction: 'ltr',
                                            }}
                                        >
                                            {it.shortcut}
                                        </span>
                                    ) : null}
                                </button>
                            );
                        })}
                    </div>
                );
            })}

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
