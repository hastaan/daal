// SidebarRail — narrow icon-only nav for TabletShell. The names are the
// buttons' accessible names and tooltips. A disabled item is not drawn.

import type { SectionId } from './icons';
import { SECTION_ICONS } from './icons';
import { mix } from '../mix';

interface Item {
    id: SectionId;
    label: string;
    disabled?: boolean;
}

interface Props {
    active: SectionId;
    items: Item[];
    onChange: (id: SectionId) => void;
    footer?: React.ReactNode;
}

export function SidebarRail({ active, items, onChange, footer }: Props) {
    return (
        <aside
            style={{
                background: 'var(--bg-deep)',
                borderInlineEnd: '1px solid var(--line-soft)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                padding: '14px 0',
                gap: 6,
                width: 72,
            }}
        >
            {/* Rail header intentionally empty — no logo at the top
                of the collapsed-icon rail (matches the full sidebar
                in tablet/desktop). */}
            {items.filter((it) => !it.disabled).map((it) => {
                const on = active === it.id;
                return (
                    <button
                        key={it.id}
                        type="button"
                        title={it.label}
                        aria-label={it.label}
                        aria-current={on ? 'page' : undefined}
                        data-button={`nav-${it.id}`}
                        onClick={() => onChange(it.id)}
                        style={{
                            width: 48,
                            height: 48,
                            border: 0,
                            background: on
                                ? mix('var(--gold)', 12, 'transparent')
                                : 'transparent',
                            color: on ? 'var(--gold-warm)' : 'var(--muted)',
                            borderRadius: 12,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                        }}
                    >
                        <span style={{ width: 22, height: 22, display: 'block' }}>
                            {SECTION_ICONS[it.id]}
                        </span>
                    </button>
                );
            })}
            <div style={{ marginTop: 'auto', padding: '12px 0' }}>{footer}</div>
        </aside>
    );
}
