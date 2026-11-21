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
//   * 24 × 24 icon stacked above an 11px sentence-case label (body
//     font, no tracking: Persian has no capitals and the mono face no
//     Persian letters). Each cell is at least 56 px high.
//   * the active cell: gold icon and label, and a 3-px gold bar on top.
//   * bottom padding = `max(8px, env(safe-area-inset-bottom))` so the
//     bar stays above the iOS home indicator + Android gesture inset
//     instead of being eaten by it.

import type { ReactNode } from 'react';
import { mix } from '../mix';

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
                background: mix('var(--bg)', 92, 'transparent'),
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
                        type="button"
                        role="tab"
                        data-button={`tab-${it.id}`}
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
                            gap: 3,
                            fontFamily: 'var(--font-body)',
                            fontSize: 11,
                            fontWeight: on ? 600 : 500,
                            lineHeight: 1.2,
                            // Every cell is a comfortable tap target.
                            minBlockSize: 56,
                        }}
                    >
                        {on && (
                            <span
                                aria-hidden
                                style={{
                                    position: 'absolute',
                                    // Sits on the bar's top edge.
                                    insetBlockStart: -8,
                                    insetInlineStart: '50%',
                                    marginInlineStart: -14,
                                    inlineSize: 28,
                                    blockSize: 3,
                                    background: 'var(--gold-warm)',
                                    borderRadius: 2,
                                }}
                            />
                        )}
                        <span
                            style={{
                                inlineSize: 24,
                                blockSize: 24,
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                            }}
                        >
                            {it.icon}
                        </span>
                        <span
                            style={{
                                maxWidth: '100%',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                // Room for descenders (g, y, Persian ی).
                                lineHeight: 1.45,
                            }}
                        >
                            {it.label}
                        </span>
                    </button>
                );
            })}
        </nav>
    );
}
