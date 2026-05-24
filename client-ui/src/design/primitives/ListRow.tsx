// ListRow — single horizontal row used inside Cards for list-style
// content (sources, routes, settings, etc.). Matches the .list-row
// styling in client-shared/designs/daal-mobile-app.html.

import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';

interface Props {
    leading?: ReactNode;
    title: ReactNode;
    subtitle?: ReactNode;
    meta?: ReactNode;
    trailing?: ReactNode;
    onClick?: () => void;
    /** Hide the bottom hairline (last row in a card). */
    last?: boolean;
    /**
     * Force the trailing control to wrap to a new line below the title
     * (instead of sitting next to it). Use for wide controls — Segmented
     * with 3+ items, multi-step pickers — that would otherwise collide
     * with the title on phones.
     */
    stack?: boolean;
}

export function ListRow({
    leading,
    title,
    subtitle,
    meta,
    trailing,
    onClick,
    last,
    stack,
}: Props) {
    const { density, isRTL } = useDensity();
    const isPhone = density === 'phone';
    // On phones we auto-stack unless the caller has explicitly passed
    // `stack={false}`. Trailing controls on a 360-wide screen don't
    // have room next to a title + subtitle ellipsis, and the resulting
    // overlap (e.g. "Mode" vs "NORMAL/LIFELINE/STRICT/BULK") is the
    // single biggest readability issue on the mobile settings page.
    const stacked = stack ?? (isPhone && !!trailing);
    return (
        <div
            onClick={onClick}
            role={onClick ? 'button' : undefined}
            tabIndex={onClick ? 0 : undefined}
            style={{
                display: 'flex',
                flexDirection: stacked ? 'column' : 'row',
                alignItems: stacked ? 'stretch' : 'center',
                gap: stacked ? 8 : 12,
                padding: '11px 0',
                borderBottom: last ? 'none' : '1px solid var(--line-soft)',
                cursor: onClick ? 'pointer' : 'default',
                direction: isRTL ? 'rtl' : 'ltr',
            }}
        >
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    minWidth: 0,
                    flex: stacked ? '0 0 auto' : 1,
                }}
            >
                {leading && (
                    <span style={{ flexShrink: 0 }}>{leading}</span>
                )}
                <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                        style={{
                            fontWeight: 600,
                            fontSize: 13,
                            color: 'var(--fg)',
                            lineHeight: 1.25,
                        }}
                    >
                        {title}
                    </div>
                    {subtitle && (
                        <div
                            style={{
                                fontSize: 12,
                                color: 'var(--muted)',
                                // When stacked there's room for the help
                                // text to wrap; in the inline layout we
                                // keep it on one line so the row height
                                // stays constant.
                                overflow: stacked ? undefined : 'hidden',
                                textOverflow: stacked
                                    ? undefined
                                    : 'ellipsis',
                                whiteSpace: stacked ? 'normal' : 'nowrap',
                            }}
                        >
                            {subtitle}
                        </div>
                    )}
                </div>
                {!stacked && meta && (
                    <span
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            color: 'var(--dim)',
                            letterSpacing: '0.04em',
                        }}
                    >
                        {meta}
                    </span>
                )}
            </div>
            {trailing && (
                <span
                    style={{
                        flexShrink: 0,
                        // In the stacked layout the trailing control sits
                        // full-width under the title; it's free to scroll
                        // horizontally (Segmented in particular needs
                        // this on small screens).
                        ...(stacked
                            ? {
                                  display: 'block',
                                  overflowX: 'auto',
                                  WebkitOverflowScrolling: 'touch',
                                  paddingBottom: 2,
                              }
                            : null),
                    }}
                >
                    {trailing}
                </span>
            )}
            {stacked && meta && (
                <span
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        color: 'var(--dim)',
                        letterSpacing: '0.04em',
                    }}
                >
                    {meta}
                </span>
            )}
        </div>
    );
}
