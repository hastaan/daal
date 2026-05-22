// Segmented — small 2–4 option segmented toggle used inside content
// areas (e.g. Network tab toggling Routes/Sources).

import type { ReactNode } from 'react';

interface Item<T extends string> {
    value: T;
    label: ReactNode;
}

interface Props<T extends string> {
    value: T;
    items: Array<Item<T>>;
    onChange: (next: T) => void;
}

export function Segmented<T extends string>({
    value,
    items,
    onChange,
}: Props<T>) {
    return (
        <div
            role="tablist"
            style={{
                display: 'inline-flex',
                background: 'var(--bg)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--r-pill)',
                padding: 3,
                gap: 2,
            }}
        >
            {items.map((it) => {
                const on = it.value === value;
                return (
                    <button
                        key={it.value}
                        role="tab"
                        aria-selected={on}
                        onClick={() => onChange(it.value)}
                        style={{
                            appearance: 'none',
                            background: on
                                ? 'var(--gold-warm)'
                                : 'transparent',
                            color: on
                                ? 'oklch(20% 0.04 80)'
                                : 'var(--muted)',
                            border: 0,
                            padding: '6px 14px',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            letterSpacing: '0.06em',
                            textTransform: 'uppercase',
                            borderRadius: 'var(--r-pill)',
                            cursor: 'pointer',
                            transition:
                                'background var(--t-fast), color var(--t-fast)',
                        }}
                    >
                        {it.label}
                    </button>
                );
            })}
        </div>
    );
}
