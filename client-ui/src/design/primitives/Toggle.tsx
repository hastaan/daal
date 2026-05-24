// Toggle — switch with label + optional subtitle row.

import type { ReactNode } from 'react';

interface Props {
    checked: boolean;
    onChange: (next: boolean) => void;
    label?: ReactNode;
    subtitle?: ReactNode;
    disabled?: boolean;
}

export function Toggle({
    checked,
    onChange,
    label,
    subtitle,
    disabled,
}: Props) {
    return (
        <label
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                cursor: disabled ? 'not-allowed' : 'pointer',
                opacity: disabled ? 0.5 : 1,
            }}
        >
            <button
                role="switch"
                aria-checked={checked}
                disabled={disabled}
                type="button"
                onClick={() => !disabled && onChange(!checked)}
                style={{
                    flexShrink: 0,
                    width: 36,
                    height: 20,
                    borderRadius: 10,
                    background: checked
                        ? 'var(--gold)'
                        : 'var(--surface-3)',
                    border: 0,
                    position: 'relative',
                    cursor: disabled ? 'not-allowed' : 'pointer',
                    transition: 'background var(--t-fast)',
                }}
            >
                <span
                    aria-hidden
                    style={{
                        position: 'absolute',
                        top: 2,
                        left: checked ? 18 : 2,
                        width: 16,
                        height: 16,
                        background: 'var(--fg)',
                        borderRadius: '50%',
                        transition: 'left var(--t-fast)',
                    }}
                />
            </button>
            {(label || subtitle) && (
                <div style={{ flex: 1, minWidth: 0 }}>
                    {label && (
                        <div
                            style={{
                                fontSize: 13,
                                color: 'var(--fg)',
                                fontWeight: 600,
                            }}
                        >
                            {label}
                        </div>
                    )}
                    {subtitle && (
                        <div
                            style={{
                                fontSize: 12,
                                color: 'var(--muted)',
                            }}
                        >
                            {subtitle}
                        </div>
                    )}
                </div>
            )}
        </label>
    );
}
