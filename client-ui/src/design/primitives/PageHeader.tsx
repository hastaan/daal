// PageHeader — the first row of every page: [back] title [badge] … actions.
// No eyebrow, ever.

import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { IconButton } from './IconButton';
import { Icon } from './icons';

interface PageHeaderProps {
    title: ReactNode;
    /** A back control; `label` is its accessible name ("Settings", "Relays"). */
    back?: { label: string; onClick: () => void };
    /** One Badge next to the title. */
    badge?: ReactNode;
    /** At most one icon or compact button, plus one OverflowMenu. */
    actions?: ReactNode;
}

export function PageHeader({ title, back, badge, actions }: PageHeaderProps) {
    const { density } = useDensity();
    const phone = density === 'phone';
    return (
        <header
            data-page-header
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                minHeight: 56,
                minWidth: 0,
            }}
        >
            {back && (
                <IconButton
                    label={back.label}
                    dataButton="page-back"
                    onClick={back.onClick}
                    style={{ marginInlineStart: -10, color: 'var(--fg)' }}
                >
                    <Icon name="back" size={22} />
                </IconButton>
            )}
            <div
                style={{
                    flex: 1,
                    minWidth: 0,
                    display: 'flex',
                    alignItems: 'center',
                    // A badge that does not fit beside the title goes
                    // under it rather than squeezing the title to "R…".
                    flexWrap: 'wrap',
                    columnGap: 10,
                    rowGap: 2,
                }}
            >
                <h1
                    style={{
                        margin: 0,
                        minWidth: 0,
                        flexShrink: 1,
                        fontFamily: 'var(--font-display)',
                        fontSize: phone ? 24 : 28,
                        fontWeight: 500,
                        lineHeight: 1.25,
                        color: 'var(--fg)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                    }}
                >
                    {title}
                </h1>
                {badge && <span style={{ display: 'inline-flex', minWidth: 0, maxWidth: '100%' }}>{badge}</span>}
            </div>
            {actions && (
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        flexShrink: 0,
                        marginInlineEnd: -6,
                    }}
                >
                    {actions}
                </div>
            )}
        </header>
    );
}
