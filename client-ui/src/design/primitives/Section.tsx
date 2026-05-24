// Section — vertical block with optional eyebrow + title + content.
// Used at the top of screens and inside Cards.

import type { ReactNode } from 'react';

interface Props {
    eyebrow?: ReactNode;
    title?: ReactNode;
    action?: ReactNode;
    children: ReactNode;
}

export function Section({ eyebrow, title, action, children }: Props) {
    return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(eyebrow || title || action) && (
                <header
                    style={{
                        display: 'flex',
                        alignItems: 'baseline',
                        justifyContent: 'space-between',
                        gap: 12,
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
                        {title && (
                            <h2
                                style={{
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 22,
                                    fontWeight: 500,
                                    lineHeight: 1.15,
                                    letterSpacing: '-0.01em',
                                    margin: '4px 0',
                                    color: 'var(--fg)',
                                }}
                            >
                                {title}
                            </h2>
                        )}
                    </div>
                    {action}
                </header>
            )}
            <div>{children}</div>
        </section>
    );
}
