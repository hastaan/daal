// EmptyState — what an empty page shows: an icon, what is missing, and
// the one thing to do about it.

import type { ReactNode } from 'react';
import { Icon } from './icons';
import type { IconName } from './icons';

interface EmptyStateProps {
    icon: IconName;
    title: string;
    /** One line at most. */
    body?: string;
    /** A primary Button. */
    action?: ReactNode;
    /** A link Button under the action. */
    secondary?: ReactNode;
}

export function EmptyState({ icon, title, body, action, secondary }: EmptyStateProps) {
    return (
        <div
            data-empty-state
            style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                padding: '32px 16px',
            }}
        >
            <span
                aria-hidden
                style={{
                    width: 80,
                    height: 80,
                    borderRadius: '50%',
                    background: 'var(--surface-2)',
                    color: 'var(--gold-warm)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBlockEnd: 16,
                }}
            >
                <Icon name={icon} size={32} />
            </span>
            <h2
                style={{
                    margin: 0,
                    fontFamily: 'var(--font-display)',
                    fontSize: 'var(--fs-lg)',
                    fontWeight: 500,
                    lineHeight: 1.3,
                    color: 'var(--fg)',
                }}
            >
                {title}
            </h2>
            {body && (
                <p
                    style={{
                        margin: '6px 0 0',
                        fontSize: 'var(--fs-sm)',
                        color: 'var(--muted)',
                        lineHeight: 1.45,
                        maxWidth: 360,
                    }}
                >
                    {body}
                </p>
            )}
            {action && <div style={{ marginBlockStart: 16 }}>{action}</div>}
            {secondary && <div style={{ marginBlockStart: 4 }}>{secondary}</div>}
        </div>
    );
}
