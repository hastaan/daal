// Segmented — a 2–4 option switch (language, theme, connection mode).
//
// Sentence case, 13 px; each option is a 44 px tap target. It never runs off the screen: when
// its options are wider than the space it has, it folds into a grid (a
// 4-option control becomes 2 × 2). `iconOnly` shows just each option's
// icon and keeps the label as its accessible name.

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Icon } from './icons';
import type { IconName } from './icons';

interface Item<T extends string> {
    value: T;
    label: ReactNode;
    icon?: IconName;
    /** Accessible name when the label is not plain text. */
    ariaLabel?: string;
}

interface Props<T extends string> {
    value: T;
    items: Array<Item<T>>;
    onChange: (next: T) => void;
    /** Only the icons show; labels become aria-labels. */
    iconOnly?: boolean;
    /** The control's id; each option is `${dataButton}-${value}`. */
    dataButton?: string;
}

export function Segmented<T extends string>({
    value,
    items,
    onChange,
    iconOnly,
    dataButton,
}: Props<T>) {
    const ref = useRef<HTMLDivElement | null>(null);
    const natural = useRef(0);
    const [folded, setFolded] = useState(false);

    // Measure the one-row width once, then fold whenever the parent is
    // narrower than that. No layout (tests): never folds.
    useLayoutEffect(() => {
        const el = ref.current as (HTMLDivElement & { offsetWidth?: number }) | null;
        if (!el || folded || typeof el.offsetWidth !== 'number') return;
        natural.current = el.offsetWidth;
        const parent = el.parentElement as HTMLElement | null;
        const room = parent?.clientWidth;
        if (items.length > 2 && typeof room === 'number' && room > 0 && natural.current > room + 1) setFolded(true);
    }, [folded, items.length]);

    useEffect(() => {
        if (typeof window === 'undefined' || items.length <= 2) return;
        const onResize = () => {
            const el = ref.current;
            const room = (el?.parentElement as HTMLElement | null)?.clientWidth;
            if (typeof room !== 'number' || room <= 0 || !natural.current) return;
            setFolded(natural.current > room + 1);
        };
        window.addEventListener('resize', onResize);
        return () => window.removeEventListener('resize', onResize);
    }, [items.length]);

    const cols = items.length === 4 ? 2 : 1;
    return (
        <div
            ref={ref}
            role="tablist"
            data-button={dataButton}
            data-folded={folded ? '1' : undefined}
            style={{
                display: folded ? 'grid' : 'inline-flex',
                gridTemplateColumns: folded ? `repeat(${cols}, minmax(0, 1fr))` : undefined,
                width: folded ? '100%' : undefined,
                maxWidth: '100%',
                background: 'var(--bg)',
                border: '1px solid var(--line)',
                borderRadius: folded ? 'var(--r-tile)' : 'var(--r-pill)',
                padding: 2,
                gap: 2,
            }}
        >
            {items.map((it) => {
                const on = it.value === value;
                const name = it.ariaLabel ?? (typeof it.label === 'string' ? it.label : undefined);
                return (
                    <button
                        key={it.value}
                        type="button"
                        role="tab"
                        aria-selected={on}
                        aria-label={iconOnly ? name : it.ariaLabel}
                        title={iconOnly ? name : undefined}
                        data-value={it.value}
                        data-button={dataButton ? `${dataButton}-${it.value}` : undefined}
                        onClick={() => onChange(it.value)}
                        style={{
                            appearance: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: 6,
                            minHeight: 44,
                            minWidth: iconOnly ? 44 : undefined,
                            background: on ? 'var(--gold-warm)' : 'transparent',
                            color: on ? '#1f1401' : 'var(--muted)',
                            border: 0,
                            padding: iconOnly ? '0 10px' : '0 14px',
                            fontFamily: 'var(--font-body)',
                            fontSize: 13,
                            fontWeight: 600,
                            whiteSpace: 'nowrap',
                            borderRadius: folded ? 9 : 'var(--r-pill)',
                            cursor: 'pointer',
                            transition: 'background var(--t-fast), color var(--t-fast)',
                        }}
                    >
                        {it.icon && <Icon name={it.icon} size={18} />}
                        {!iconOnly && <span>{it.label}</span>}
                    </button>
                );
            })}
        </div>
    );
}
