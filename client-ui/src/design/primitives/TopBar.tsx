// TopBar — section title strip used by Tablet + Desktop shells.

import type { ReactNode } from 'react';
import { mix } from '../mix';

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
                    mix('var(--bg-deep)', 70, 'transparent'),
                backdropFilter: 'blur(10px)',
                WebkitBackdropFilter: 'blur(10px)',
            }}
        >
            <div>
                {eyebrow && (
                    <div
                        style={{
                            fontFamily: 'var(--font-body)',
                            fontSize: 12,
                            fontWeight: 600,
                            color: 'var(--muted)',
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
