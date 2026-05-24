// TabBar — bottom navigation for MobileShell.
//
// Generic on `id` so the mobile shell can use its own section model
// (Connection · Network · Settings) without polluting SectionId, which
// is the desktop/rail nav vocabulary. The caller supplies each item's
// icon (typically from SECTION_ICONS, or a custom one).
//
// Visual contract mirrors client-shared/designs/daal-mobile-app.html
// .bottom-nav + .nav-item:
//   * grid-template-columns: repeat(N, 1fr) so cells stay centred and
//     evenly spaced regardless of how many tabs are rendered.
//   * 22 × 22 icon stacked above 9.5px uppercase mono label.
//   * 2-px gold tick on top of the active cell, centred horizontally.
//   * bottom padding = `max(8px, env(safe-area-inset-bottom))` so the
//     bar stays above the iOS home indicator + Android gesture inset
//     instead of being eaten by it.

import type { ReactNode } from 'react';

interface Item<Id extends string> {
    id: Id;
    label: string;
    icon: ReactNode;
    disabled?: boolean;
}

interface Props<Id extends string> {
    active: Id;
    items: Array<Item<Id>>;
    onChange: (id: Id) => void;
}

export function TabBar<Id extends string>({
    active,
    items,
    onChange,
}: Props<Id>) {
    return (
        <nav
            role="tablist"
            style={{
                flexShrink: 0,
                display: 'grid',
                gridTemplateColumns: `repeat(${items.length}, 1fr)`,
                width: '100%',
                borderTop: '1px solid var(--line-soft)',
                background: 'color-mix(in oklab, var(--bg) 92%, transparent)',
                backdropFilter: 'blur(14px)',
                WebkitBackdropFilter: 'blur(14px)',
                paddingBlockStart: 8,
                paddingInline: 6,
                paddingBlockEnd:
                    'calc(env(safe-area-inset-bottom, 0px) + 8px)',
            }}
        >
            {items.map((it) => {
                const on = active === it.id;
                return (
                    <button
                        key={it.id}
                        role="tab"
                        aria-selected={on}
                        aria-label={it.label}
                        disabled={it.disabled}
                        onClick={() => onChange(it.id)}
                        style={{
                            appearance: 'none',
                            background: 'transparent',
                            border: 0,
                            color: on
                                ? 'var(--gold-warm)'
                                : it.disabled
                                    ? 'var(--dim)'
                                    : 'var(--muted)',
                            cursor: it.disabled ? 'not-allowed' : 'pointer',
                            position: 'relative',
                            padding: '6px 4px 4px',
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 4,
                            fontFamily: 'var(--font-mono)',
                            fontSize: 9.5,
                            letterSpacing: '0.06em',
                            textTransform: 'uppercase',
                            // Give every cell a minimum tap height so
                            // the bar stays comfortable on phones.
                            minBlockSize: 48,
                        }}
                    >
                        {on && (
                            <span
                                aria-hidden
                                style={{
                                    position: 'absolute',
                                    insetBlockStart: 0,
                                    insetInlineStart: '50%',
                                    transform: 'translateX(-50%)',
                                    inlineSize: 22,
                                    blockSize: 2,
                                    background: 'var(--gold-warm)',
                                    borderRadius: 2,
                                }}
                            />
                        )}
                        <span
                            style={{
                                inlineSize: 22,
                                blockSize: 22,
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                            }}
                        >
                            {it.icon}
                        </span>
                        <span>{it.label}</span>
                    </button>
                );
            })}
        </nav>
    );
}
