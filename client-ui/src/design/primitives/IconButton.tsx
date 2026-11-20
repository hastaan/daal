// IconButton — square icon-only button used in headers, rows and
// toolbars. 44 × 44 by default (the smallest comfortable tap target);
// `label` is its accessible name, so every one says what it does.

import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { Icon } from './icons';
import type { IconName } from './icons';
import { mix } from '../mix';

interface Props extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
    /** The glyph; or pass `icon` instead. */
    children?: ReactNode;
    /** Draws `<Icon name={icon}/>` when no children are given. */
    icon?: IconName;
    size?: number;
    active?: boolean;
    label?: string;
    tone?: 'default' | 'danger';
    /** Written as `data-button`; the harness driver finds controls by it. */
    dataButton?: string;
}

export function IconButton({
    children,
    icon,
    size = 44,
    active,
    label,
    tone = 'default',
    dataButton,
    style,
    type,
    ...rest
}: Props) {
    const danger = tone === 'danger';
    return (
        <button
            type={type ?? 'button'}
            data-button={dataButton}
            {...rest}
            aria-label={label ?? rest['aria-label']}
            title={rest.title ?? label}
            className={['daal-hover', rest.className].filter(Boolean).join(' ')}
            style={{
                width: size,
                height: size,
                minWidth: size,
                flexShrink: 0,
                padding: 0,
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: active
                    ? mix('var(--gold)', 10, 'transparent')
                    : 'transparent',
                border: 0,
                borderRadius: 12,
                color: danger
                    ? 'var(--red)'
                    : active
                      ? 'var(--gold-warm)'
                      : 'var(--muted)',
                cursor: rest.disabled ? 'not-allowed' : 'pointer',
                opacity: rest.disabled ? 0.55 : 1,
                transition: 'background var(--t-fast), color var(--t-fast)',
                ...style,
            }}
        >
            {children ?? (icon ? <Icon name={icon} size={Math.round(Math.min(24, size * 0.5))} /> : null)}
        </button>
    );
}
