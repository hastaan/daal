// Toggle — switch with label + optional subtitle row. The switch itself
// has a 44 px tap area (the track stays 36 × 20); the knob moves toward
// the inline end when on, so it reads right in Persian too.

import type { ReactNode } from 'react';

interface Props {
    checked: boolean;
    onChange: (next: boolean) => void;
    label?: ReactNode;
    subtitle?: ReactNode;
    disabled?: boolean;
    /** Accessible name when there is no visible label (a row's title names it). */
    ariaLabel?: string;
    dataButton?: string;
}

export function Toggle({
    checked,
    onChange,
    label,
    subtitle,
    disabled,
    ariaLabel,
    dataButton,
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
                aria-label={ariaLabel}
                data-button={dataButton}
                disabled={disabled}
                type="button"
                onClick={() => !disabled && onChange(!checked)}
                style={{
                    flexShrink: 0,
                    // 44 × 44 target around a 36 × 20 track.
                    width: 44,
                    height: 44,
                    marginBlock: -12,
                    marginInline: -4,
                    padding: 0,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'transparent',
                    border: 0,
                    cursor: disabled ? 'not-allowed' : 'pointer',
                }}
            >
                <span
                    aria-hidden
                    style={{
                        width: 36,
                        height: 20,
                        borderRadius: 10,
                        background: checked ? 'var(--gold)' : 'var(--surface-3)',
                        position: 'relative',
                        display: 'block',
                        transition: 'background var(--t-fast)',
                    }}
                >
                    <span
                        style={{
                            position: 'absolute',
                            top: 2,
                            insetInlineStart: checked ? 18 : 2,
                            width: 16,
                            height: 16,
                            background: 'var(--fg)',
                            borderRadius: '50%',
                            transition: 'inset-inline-start var(--t-fast)',
                        }}
                    />
                </span>
            </button>
            {(label || subtitle) && (
                <div style={{ flex: 1, minWidth: 0 }}>
                    {label && (
                        <div
                            style={{
                                fontSize: 14,
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
                                fontSize: 13,
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
