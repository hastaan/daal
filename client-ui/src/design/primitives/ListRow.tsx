// ListRow — one row of a list inside a Card: [leading] title [badge]
// [meta] … [trailing] [chevron], with an optional one-line subtitle.
//
// A clickable row (`onClick`) is a real <button> for its main part, so
// it is reached by Tab and opened with Enter or Space, and it is at
// least 52 px high. A control in `trailing` (a toggle, a ⋯ menu, a send
// button) does its own thing: its click does not also open the row.

import type { MouseEvent, ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { Icon } from './icons';

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
    /** A trailing chevron that points to the inline end (the row opens something). */
    chevron?: boolean;
    /** The title in red (a destructive row such as "Erase Daal"). */
    danger?: boolean;
    /** Shown right after the title; it never wraps. */
    badge?: ReactNode;
    /**
     * Let the subtitle wrap onto more lines. By default it is one line
     * with an ellipsis; a stacked row (a help line above a wide control)
     * wraps unless this is set to false.
     */
    wrapSubtitle?: boolean;
    dataButton?: string;
}

const INTERACTIVE = new Set(['BUTTON', 'A', 'INPUT', 'SELECT', 'TEXTAREA', 'LABEL']);

/** True when the click started on a control inside `boundary`. */
function fromControl(e: MouseEvent): boolean {
    const boundary = e.currentTarget as unknown as { parentNode?: unknown };
    let n = e.target as unknown as { nodeName?: string; getAttribute?: (k: string) => string | null; parentNode?: unknown } | null;
    while (n && n !== boundary) {
        if (n.nodeName && INTERACTIVE.has(n.nodeName.toUpperCase())) return true;
        const role = n.getAttribute?.('role');
        if (role === 'switch' || role === 'button' || role === 'menuitem' || role === 'tab') return true;
        n = (n.parentNode ?? null) as typeof n;
    }
    return false;
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
    chevron,
    danger,
    badge,
    wrapSubtitle,
    dataButton,
}: Props) {
    const { density, isRTL } = useDensity();
    const isPhone = density === 'phone';
    // On phones we auto-stack unless the caller has explicitly passed
    // `stack={false}`. Trailing controls on a 360-wide screen don't
    // have room next to a title + subtitle ellipsis.
    const stacked = stack ?? (isPhone && !!trailing);
    const wrapSub = wrapSubtitle ?? stacked;
    const clickable = !!onClick;

    const metaNode = meta ? (
        <span
            style={{
                fontFamily: 'var(--font-body)',
                fontSize: 12,
                color: 'var(--muted)',
                flexShrink: 0,
                whiteSpace: 'nowrap',
            }}
        >
            {meta}
        </span>
    ) : null;

    const text = (
        <span style={{ display: 'block', flex: 1, minWidth: 0 }}>
            <span
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    minWidth: 0,
                }}
            >
                <span
                    style={{
                        display: 'block',
                        minWidth: 0,
                        fontWeight: 600,
                        fontSize: isPhone ? 15 : 14,
                        color: danger ? 'var(--red)' : 'var(--fg)',
                        lineHeight: 1.3,
                        overflowWrap: 'anywhere',
                    }}
                >
                    {title}
                </span>
                {badge && (
                    <span style={{ display: 'inline-flex', flexShrink: 0, maxWidth: '60%', minWidth: 0 }}>{badge}</span>
                )}
            </span>
            {subtitle && (
                <span
                    style={{
                        display: 'block',
                        fontSize: 13,
                        color: 'var(--muted)',
                        lineHeight: 1.4,
                        marginBlockStart: 2,
                        overflow: wrapSub ? undefined : 'hidden',
                        textOverflow: wrapSub ? undefined : 'ellipsis',
                        whiteSpace: wrapSub ? 'normal' : 'nowrap',
                    }}
                >
                    {subtitle}
                </span>
            )}
        </span>
    );

    const chevronNode = chevron ? (
        <span style={{ color: 'var(--muted)', display: 'inline-flex', flexShrink: 0 }}>
            <Icon name="chevron" size={18} />
        </span>
    ) : null;

    const mainStyle = {
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        minWidth: 0,
        flex: stacked ? '0 0 auto' : 1,
    } as const;

    const mainInner = (
        <>
            {leading && <span style={{ flexShrink: 0, display: 'inline-flex' }}>{leading}</span>}
            {text}
            {!stacked && metaNode}
            {!trailing && chevronNode}
        </>
    );

    const main = clickable ? (
        // The row's own button. It has no handler of its own: its click
        // bubbles to the row, so a tap anywhere on the row (but not on a
        // trailing control) opens it, and Enter/Space work natively.
        <button
            type="button"
            data-button={dataButton}
            className="daal-hover"
            style={{
                ...mainStyle,
                appearance: 'none',
                background: 'transparent',
                border: 0,
                padding: 0,
                margin: 0,
                minHeight: 44,
                width: stacked ? '100%' : undefined,
                color: 'inherit',
                font: 'inherit',
                textAlign: 'start',
                cursor: 'pointer',
                borderRadius: 8,
            }}
        >
            {mainInner}
        </button>
    ) : (
        <div data-button={dataButton} style={mainStyle}>
            {mainInner}
        </div>
    );

    return (
        <div
            data-list-row
            onClick={clickable ? () => onClick?.() : undefined}
            style={{
                display: 'flex',
                flexDirection: stacked ? 'column' : 'row',
                alignItems: stacked ? 'stretch' : 'center',
                gap: stacked ? 8 : 12,
                padding: '11px 0',
                minHeight: clickable ? 52 : undefined,
                borderBottom: last ? 'none' : '1px solid var(--line-soft)',
                cursor: clickable ? 'pointer' : 'default',
                direction: isRTL ? 'rtl' : 'ltr',
            }}
        >
            {main}
            {trailing && (
                <span
                    onClick={
                        clickable
                            ? (e) => {
                                  // A control in the trailing slot answers its
                                  // own tap; the row does not open as well.
                                  if (fromControl(e)) e.stopPropagation();
                              }
                            : undefined
                    }
                    style={{
                        flexShrink: 0,
                        display: stacked ? 'block' : 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        // In the stacked layout the trailing control sits
                        // full-width under the title; it's free to scroll
                        // horizontally if it must.
                        ...(stacked
                            ? {
                                  overflowX: 'auto',
                                  WebkitOverflowScrolling: 'touch',
                                  paddingBottom: 2,
                              }
                            : null),
                    }}
                >
                    {trailing}
                    {chevron && chevronNode}
                </span>
            )}
            {stacked && metaNode}
        </div>
    );
}
