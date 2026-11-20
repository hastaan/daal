// OverflowMenu — the ⋯ button and the actions behind it.
//
// Phone: the actions open in a MenuSheet. Tablet and desktop: a small
// popover aligned to the trigger's inline-end edge, opening upward when
// there is no room below; arrow keys move, Enter/Space choose, Escape
// closes and gives focus back to the ⋯. It also closes on a click
// outside, on scroll, on resize and on Back.
//
// Choosing an item closes the menu FIRST, then runs the item, so a sheet
// the item opens is not closed by the menu going away.

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react';
import { useBack } from '../../lib/useBack';
import { useDensity } from '../DensityProvider';
import { IconButton } from './IconButton';
import { Icon } from './icons';
import { MenuSheet, orderMenuItems } from './MenuSheet';
import type { MenuItem } from './MenuSheet';

export type { MenuItem } from './MenuSheet';

interface OverflowMenuProps {
    /** The trigger's accessible name, normally t('ui.more'). */
    label: string;
    /** [] renders nothing at all. */
    items: MenuItem[];
    /** Title of the phone sheet. */
    title?: ReactNode;
    /** Default 'more'. */
    dataButton?: string;
}

interface Place {
    top?: number;
    bottom?: number;
    end: number;
}

const ITEM_H = 44;

export function OverflowMenu({ label, items, title, dataButton = 'more' }: OverflowMenuProps) {
    const { density, isRTL } = useDensity();
    const phone = density === 'phone';
    const [open, setOpen] = useState(false);
    // undefined: not measured yet (render nothing for that one pass);
    // null: no layout to measure (the test DOM): render in flow.
    const [place, setPlace] = useState<Place | null | undefined>(undefined);
    const triggerRef = useRef<HTMLSpanElement | null>(null);
    const menuRef = useRef<HTMLDivElement | null>(null);

    // A fixed element is placed against the viewport unless an ancestor
    // has a transform or filter; then it is off by that ancestor's offset.
    // Measured once after placing and corrected (no portal: importing
    // react-dom here would load it before a test's DOM exists).
    const [shift, setShift] = useState<{ dx: number; dy: number } | null>(null);
    const close = useCallback(() => setOpen(false), []);
    useEffect(() => {
        if (!open) {
            setPlace(undefined);
            setShift(null);
        }
    }, [open]);
    const focusTrigger = () => {
        const b = triggerRef.current?.querySelector?.('button');
        try {
            (b as HTMLButtonElement | null | undefined)?.focus();
        } catch {
            /* focus is a nicety */
        }
    };

    // The popover answers Back; the phone sheet registers its own.
    useBack(open && !phone, close);

    // Where the popover goes. No layout (the test DOM) → render in flow.
    useLayoutEffect(() => {
        if (!open || phone) return;
        const el = (triggerRef.current?.querySelector?.('button') ?? null) as
            | (HTMLElement & { getBoundingClientRect?: () => DOMRect })
            | null;
        const rect = typeof el?.getBoundingClientRect === 'function' ? el.getBoundingClientRect() : null;
        if (!rect || (rect.width === 0 && rect.height === 0 && rect.top === 0 && rect.left === 0)) {
            setPlace(null);
            return;
        }
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const need = items.length * ITEM_H + 16;
        const end = isRTL ? rect.left : vw - rect.right;
        setPlace(vh - rect.bottom < need && rect.top > vh - rect.bottom ? { bottom: vh - rect.top + 4, end } : { top: rect.bottom + 4, end });
    }, [open, phone, isRTL, items.length]);

    useLayoutEffect(() => {
        if (!place || shift) return;
        const el = menuRef.current as (HTMLElement & { getBoundingClientRect?: () => DOMRect }) | null;
        if (!el || typeof el.getBoundingClientRect !== 'function') return;
        const r = el.getBoundingClientRect();
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const dy = place.top !== undefined ? place.top - r.top : vh - (place.bottom ?? 0) - r.bottom;
        const dx = isRTL ? place.end - r.left : vw - place.end - r.right;
        setShift({ dx: Math.abs(dx) > 1 ? dx : 0, dy: Math.abs(dy) > 1 ? dy : 0 });
    }, [place, shift, isRTL]);

    // Outside click, scroll and resize close the popover.
    useEffect(() => {
        if (!open || phone) return;
        const onDown = (e: Event) => {
            const tgt = e.target as Node | null;
            if (menuRef.current?.contains(tgt) || triggerRef.current?.contains(tgt)) return;
            setOpen(false);
        };
        const onGone = () => setOpen(false);
        document.addEventListener('pointerdown', onDown, true);
        window.addEventListener('scroll', onGone, true);
        window.addEventListener('resize', onGone);
        return () => {
            document.removeEventListener('pointerdown', onDown, true);
            window.removeEventListener('scroll', onGone, true);
            window.removeEventListener('resize', onGone);
        };
    }, [open, phone]);

    // Keyboard users land on the first item.
    useEffect(() => {
        if (!open || phone) return;
        const first = menuRef.current?.querySelector?.('[role="menuitem"]:not([disabled])') as HTMLElement | null | undefined;
        try {
            first?.focus();
        } catch {
            /* focus is a nicety */
        }
    }, [open, phone, place]);

    if (items.length === 0) return null;

    const ordered = orderMenuItems(items);
    const firstDanger = ordered.findIndex((i) => i.tone === 'danger');

    const choose = (it: MenuItem) => {
        if (it.disabled) return;
        setOpen(false);
        it.onSelect();
    };

    const onMenuKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
        const list = Array.from(
            (menuRef.current?.querySelectorAll?.('[role="menuitem"]:not([disabled])') ?? []) as ArrayLike<HTMLElement>,
        );
        if (e.key === 'Escape') {
            e.preventDefault();
            e.stopPropagation();
            setOpen(false);
            focusTrigger();
            return;
        }
        if (!list.length) return;
        const at = list.indexOf(document.activeElement as HTMLElement);
        let next = -1;
        if (e.key === 'ArrowDown') next = at < 0 ? 0 : (at + 1) % list.length;
        else if (e.key === 'ArrowUp') next = at <= 0 ? list.length - 1 : at - 1;
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = list.length - 1;
        else if (e.key === 'Tab') {
            setOpen(false);
            return;
        }
        if (next >= 0) {
            e.preventDefault();
            list[next].focus();
        }
    };

    const popoverStyle: CSSProperties = place
        ? {
              position: 'fixed',
              top: place.top,
              bottom: place.bottom,
              insetInlineEnd: place.end,
              transform: shift && (shift.dx || shift.dy) ? `translate(${shift.dx}px, ${shift.dy}px)` : undefined,
          }
        : { position: 'relative', marginBlockStart: 4 };

    const popover = (
        <div
            ref={menuRef}
            role="menu"
            aria-label={label}
            data-overflow-menu
            onKeyDown={onMenuKey}
            onClick={(e) => e.stopPropagation()}
            style={{
                ...popoverStyle,
                zIndex: 300,
                minWidth: 220,
                maxWidth: 320,
                padding: '6px 0',
                background: 'var(--surface)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--r-tile)',
                boxShadow: '0 30px 60px rgba(0,0,0,0.45)',
                color: 'var(--fg)',
            }}
        >
            {ordered.map((it, i) => {
                const danger = it.tone === 'danger';
                return (
                    <div key={it.id}>
                        {i === firstDanger && i > 0 && (
                            <div aria-hidden style={{ height: 1, background: 'var(--line-soft)', margin: '6px 0' }} />
                        )}
                        <button
                            type="button"
                            role="menuitem"
                            data-button={it.id}
                            disabled={it.disabled}
                            onClick={() => choose(it)}
                            className="daal-hover daal-inset-focus"
                            style={{
                                appearance: 'none',
                                width: '100%',
                                minHeight: ITEM_H,
                                display: 'flex',
                                alignItems: 'center',
                                gap: 12,
                                padding: '6px 14px',
                                background: 'transparent',
                                border: 0,
                                color: danger ? 'var(--red)' : 'var(--fg)',
                                fontFamily: 'var(--font-body)',
                                fontSize: 14,
                                textAlign: 'start',
                                cursor: it.disabled ? 'not-allowed' : 'pointer',
                                opacity: it.disabled ? 0.5 : 1,
                            }}
                        >
                            {it.icon ? (
                                <span style={{ color: danger ? 'var(--red)' : 'var(--muted)', display: 'inline-flex' }}>
                                    <Icon name={it.icon} size={18} />
                                </span>
                            ) : null}
                            <span style={{ flex: 1, minWidth: 0 }}>
                                <span style={{ display: 'block', lineHeight: 1.3 }}>{it.label}</span>
                                {it.hint && (
                                    <span style={{ display: 'block', fontSize: 12, color: 'var(--muted)', lineHeight: 1.35 }}>
                                        {it.hint}
                                    </span>
                                )}
                            </span>
                        </button>
                    </div>
                );
            })}
        </div>
    );

    return (
        // Clicks here (the ⋯ and the menu) never reach a clickable row
        // this menu sits in.
        <span
            ref={triggerRef}
            data-overflow
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'inline-flex', position: 'relative', flexDirection: 'column', alignItems: 'flex-end' }}
        >
            <IconButton
                label={label}
                dataButton={dataButton}
                aria-haspopup="menu"
                aria-expanded={open}
                onClick={() => setOpen((v) => !v)}
            >
                <Icon name="more" size={20} />
            </IconButton>
            {open && phone && (
                <MenuSheet title={title} items={items} onClose={close} />
            )}
            {open && !phone && place !== undefined && popover}
        </span>
    );
}
