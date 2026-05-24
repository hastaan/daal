// SidebarRail — narrow icon-only nav for TabletShell.

import type { SectionId } from './icons';
import { SECTION_ICONS } from './icons';

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
            {items.map((it) => {
                const on = active === it.id;
                return (
                    <button
                        key={it.id}
                        title={it.label}
                        disabled={it.disabled}
                        onClick={() => onChange(it.id)}
                        style={{
                            width: 48,
                            height: 48,
                            border: 0,
                            background: on
                                ? 'rgba(201,162,58,0.12)'
                                : 'transparent',
                            color: on
                                ? 'var(--gold-warm)'
                                : it.disabled
                                    ? 'var(--dim)'
                                    : 'var(--muted)',
                            borderRadius: 12,
                            cursor: it.disabled ? 'not-allowed' : 'pointer',
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
