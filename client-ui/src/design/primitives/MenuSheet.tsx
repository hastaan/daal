// MenuSheet — a short list of actions in a sheet (bottom sheet on a phone,
// a small dialog on desktop). Each row is an icon disc, a label and an
// optional one-line hint. No Cancel button: the handle, the backdrop,
// Escape and Back all close it.

import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { mix } from '../mix';
import { Icon } from './icons';
import type { IconName } from './icons';
import { Sheet } from './Sheet';

export interface MenuItem {
    /** Also written as `data-button`. */
    id: string;
    label: string;
    icon?: IconName;
    /** One muted line under the label. */
    hint?: string;
    tone?: 'default' | 'danger';
    disabled?: boolean;
    onSelect: () => void;
}

interface MenuSheetProps {
    title?: ReactNode;
    /** One line under the title, e.g. "Only Maman's phone can open it." */
    subtitle?: ReactNode;
    items: MenuItem[];
    /** This item's icon disc is gold. */
    primaryId?: string;
    onClose: () => void;
    /** Small print under the list. */
    footer?: ReactNode;
}

/** Danger items always come last (after a divider), in their given order. */
export function orderMenuItems(items: MenuItem[]): MenuItem[] {
    return [...items.filter((i) => i.tone !== 'danger'), ...items.filter((i) => i.tone === 'danger')];
}

export function MenuSheet({ title, subtitle, items, primaryId, onClose, footer }: MenuSheetProps) {
    const { density } = useDensity();
    const phone = density === 'phone';
    const ordered = orderMenuItems(items);
    const firstDanger = ordered.findIndex((i) => i.tone === 'danger');
    const pick = (it: MenuItem) => {
        if (it.disabled) return;
        // Close first, then act: a sheet the item opens is not closed by
        // this one going away.
        onClose();
        it.onSelect();
    };
    return (
        <Sheet title={title} onClose={onClose} width={420}>
            {subtitle && (
                <p
                    data-menu-subtitle
                    style={{
                        margin: title ? '-6px 0 10px' : '0 0 10px',
                        fontSize: 'var(--fs-sm)',
                        color: 'var(--muted)',
                        lineHeight: 1.45,
                    }}
                >
                    {subtitle}
                </p>
            )}
            <div role="menu" style={{ display: 'flex', flexDirection: 'column', marginInline: -8 }}>
                {ordered.map((it, i) => {
                    const danger = it.tone === 'danger';
                    const primary = it.id === primaryId;
                    return (
                        <div key={it.id}>
                            {i === firstDanger && i > 0 && (
                                <div aria-hidden style={{ height: 1, background: 'var(--line-soft)', margin: '6px 8px' }} />
                            )}
                            <button
                                type="button"
                                role="menuitem"
                                data-button={it.id}
                                disabled={it.disabled}
                                onClick={() => pick(it)}
                                className="daal-hover daal-inset-focus"
                                style={{
                                    appearance: 'none',
                                    width: '100%',
                                    minHeight: 56,
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 14,
                                    padding: '8px',
                                    background: 'transparent',
                                    border: 0,
                                    borderRadius: 'var(--r-tile)',
                                    color: danger ? 'var(--red)' : 'var(--fg)',
                                    cursor: it.disabled ? 'not-allowed' : 'pointer',
                                    opacity: it.disabled ? 0.5 : 1,
                                    textAlign: 'start',
                                }}
                            >
                                <span
                                    aria-hidden
                                    style={{
                                        width: 40,
                                        height: 40,
                                        borderRadius: '50%',
                                        flexShrink: 0,
                                        display: 'inline-flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        background: primary
                                            ? 'var(--gold)'
                                            : danger
                                              ? mix('var(--red)', 16, 'transparent')
                                              : 'var(--surface-2)',
                                        color: primary ? '#1f1401' : danger ? 'var(--red)' : 'var(--fg)',
                                    }}
                                >
                                    {it.icon && <Icon name={it.icon} size={20} />}
                                </span>
                                <span style={{ flex: 1, minWidth: 0 }}>
                                    <span
                                        style={{
                                            display: 'block',
                                            fontSize: phone ? 15 : 14,
                                            fontWeight: 600,
                                            lineHeight: 1.3,
                                        }}
                                    >
                                        {it.label}
                                    </span>
                                    {it.hint && (
                                        <span
                                            style={{
                                                display: 'block',
                                                fontSize: 12,
                                                color: 'var(--muted)',
                                                lineHeight: 1.35,
                                                marginBlockStart: 2,
                                            }}
                                        >
                                            {it.hint}
                                        </span>
                                    )}
                                </span>
                            </button>
                        </div>
                    );
                })}
            </div>
            {footer && (
                <div
                    data-menu-footer
                    style={{
                        marginBlockStart: 10,
                        fontSize: 12,
                        color: 'var(--muted)',
                        lineHeight: 1.45,
                    }}
                >
                    {footer}
                </div>
            )}
        </Sheet>
    );
}
