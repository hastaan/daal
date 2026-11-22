// Avatar — a disc with the first letter of a name (Persian letters too).

interface AvatarProps {
    name: string;
    size?: number;
}

/** The first user-perceived character of `name`, or '' for a blank name. */
export function firstGrapheme(name: string): string {
    const s = (name ?? '').trim();
    if (!s) return '';
    try {
        const Seg = (Intl as unknown as { Segmenter?: typeof Intl.Segmenter }).Segmenter;
        if (Seg) {
            const first = new Seg(undefined, { granularity: 'grapheme' }).segment(s)[Symbol.iterator]().next();
            if (!first.done) return first.value.segment.toLocaleUpperCase();
        }
    } catch {
        /* an old web view without Intl.Segmenter: code points below */
    }
    return (Array.from(s)[0] ?? '').toLocaleUpperCase();
}

export function Avatar({ name, size = 36 }: AvatarProps) {
    return (
        <span
            aria-hidden
            data-avatar
            style={{
                width: size,
                height: size,
                borderRadius: '50%',
                background: 'var(--surface-3)',
                color: 'var(--fg)',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
                fontFamily: 'var(--font-body)',
                fontWeight: 600,
                fontSize: Math.round(size * 0.44),
                lineHeight: 1,
                userSelect: 'none',
            }}
        >
            {firstGrapheme(name)}
        </span>
    );
}
