// Badge — a state in one to three words: a tinted pill with an icon.
//
// Body font, sentence case, no letter-spacing: the old mono capitals
// broke words in two on a phone and Persian has no capitals at all. The
// text never wraps; a badge too long for its row ends in an ellipsis.

import type { ReactNode } from 'react';
import { mix } from '../mix';
import { Icon } from './icons';
import type { IconName } from './icons';

export type BadgeTone = 'good' | 'warn' | 'bad' | 'neutral' | 'info' | 'gold';

export interface BadgeProps {
    tone: BadgeTone;
    /** Three words at most. */
    children: ReactNode;
    /** Default by tone: good→check, warn→alert, bad→cross, info→info, neutral/gold→none. */
    icon?: IconName | false;
    /** sm: 22 px high, 12 px text. md (default): 28 px high, 13 px text. */
    size?: 'sm' | 'md';
    /** A breathing dot instead of the icon (connecting, checking). */
    pulse?: boolean;
    /** Makes the badge a button with a 44 px hit area. */
    onClick?: () => void;
    dataButton?: string;
    /** Tooltip on desktop; also its accessible description. */
    title?: string;
    /**
     * Never cut the text: it may wrap onto a second line instead. For a
     * badge that carries a warning which must be read whole
     * ("Unfinished · may cost money").
     */
    wrap?: boolean;
}

export const BADGE_TONE_COLOR: Record<BadgeTone, string> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    neutral: 'var(--muted)',
    info: 'var(--info)',
    gold: 'var(--gold-warm)',
};

const DEFAULT_ICON: Record<BadgeTone, IconName | false> = {
    good: 'check',
    warn: 'alert',
    bad: 'cross',
    info: 'info',
    neutral: false,
    gold: false,
};

export function Badge({
    tone,
    children,
    icon,
    size = 'md',
    pulse,
    onClick,
    dataButton,
    title,
    wrap,
}: BadgeProps) {
    const color = BADGE_TONE_COLOR[tone];
    const h = size === 'sm' ? 22 : 28;
    const glyph = icon === undefined ? DEFAULT_ICON[tone] : icon;
    const pill = (
        <span
            data-badge={tone}
            title={onClick ? undefined : title}
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                height: wrap ? undefined : h,
                minHeight: wrap ? h : undefined,
                paddingBlock: wrap ? 3 : undefined,
                maxWidth: '100%',
                minWidth: 0,
                paddingInline: size === 'sm' ? 8 : 10,
                background: mix(color, 16, 'transparent'),
                color,
                fontFamily: 'var(--font-body)',
                fontSize: size === 'sm' ? 12 : 13,
                fontWeight: 600,
                lineHeight: 1,
                letterSpacing: 0,
                textTransform: 'none',
                whiteSpace: wrap ? 'normal' : 'nowrap',
                borderRadius: wrap ? 12 : 'var(--r-pill)',
                verticalAlign: 'middle',
                flexShrink: 1,
            }}
        >
            {pulse ? (
                <span
                    aria-hidden
                    className="daal-badge-dot"
                    style={{
                        width: 7,
                        height: 7,
                        borderRadius: '50%',
                        background: color,
                        flexShrink: 0,
                        animation: 'daal-badge-pulse 1.4s ease-in-out infinite',
                    }}
                />
            ) : glyph ? (
                <Icon name={glyph} size={size === 'sm' ? 13 : 15} />
            ) : null}
            <span
                style={{
                    minWidth: 0,
                    overflow: wrap ? undefined : 'hidden',
                    textOverflow: wrap ? undefined : 'ellipsis',
                    whiteSpace: wrap ? 'normal' : 'nowrap',
                    // The descenders of Persian letters sit low; a line box
                    // of 1 clips them under overflow:hidden.
                    lineHeight: 1.6,
                }}
            >
                {children}
            </span>
        </span>
    );
    if (!onClick) return pill;
    // A button whose hit area is 44 px high while the pill keeps its own
    // height: padding grows the target, the negative margin keeps the
    // layout where the pill alone would put it.
    const grow = (44 - h) / 2;
    return (
        <button
            type="button"
            data-button={dataButton}
            onClick={(e) => {
                e.stopPropagation();
                onClick();
            }}
            title={title}
            aria-description={title}
            style={{
                appearance: 'none',
                background: 'transparent',
                border: 0,
                padding: 0,
                paddingBlock: grow,
                marginBlock: -grow,
                minWidth: 44,
                maxWidth: '100%',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                color: 'inherit',
                font: 'inherit',
                verticalAlign: 'middle',
            }}
        >
            {pill}
        </button>
    );
}
