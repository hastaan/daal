// TopBar — section title strip used by Tablet + Desktop shells.

import type { ReactNode } from 'react';

interface Props {
    title: ReactNode;
    actions?: ReactNode;
    eyebrow?: ReactNode;
}

export function TopBar({ title, actions, eyebrow }: Props) {
    return (
        <header
            style={{
                flexShrink: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 16,
                padding: '14px var(--gutter)',
                borderBottom: '1px solid var(--line-soft)',
                background:
                    'color-mix(in oklab, var(--bg-deep) 70%, transparent)',
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
            }}
        >
            <div>
                {eyebrow && (
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            letterSpacing: '0.18em',
                            textTransform: 'uppercase',
                            color: 'var(--gold-warm)',
                        }}
                    >
                        {eyebrow}
                    </div>
                )}
                <div
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 20,
                        fontWeight: 500,
                        color: 'var(--fg)',
                    }}
                >
                    {title}
                </div>
            </div>
            {actions}
        </header>
    );
}
