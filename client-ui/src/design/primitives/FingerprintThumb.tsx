// FingerprintThumb — a 36×36 (or sizable) glyph derived from a
// publisher fingerprint hex. We hash the first chars into a stable
// SVG pattern so each fingerprint has a recognisable visual.

interface Props {
    fingerprint: string;
    size?: number;
}

export function FingerprintThumb({ fingerprint, size = 36 }: Props) {
    // Trivial deterministic colorisation: hash hex → two oklch hues.
    const a = parseInt(fingerprint.slice(0, 4) || '0000', 16) % 360;
    const b = parseInt(fingerprint.slice(4, 8) || '0000', 16) % 360;
    const c = parseInt(fingerprint.slice(8, 12) || '0000', 16) % 360;
    return (
        <div
            style={{
                width: size,
                height: size,
                borderRadius: 9,
                background: 'var(--surface-2)',
                overflow: 'hidden',
                position: 'relative',
                flexShrink: 0,
            }}
        >
            <svg
                viewBox="0 0 36 36"
                width={size}
                height={size}
                aria-hidden
                style={{ display: 'block' }}
            >
                <circle cx="9" cy="9" r="6" fill={`oklch(72% 0.12 ${a})`} opacity="0.85" />
                <circle cx="27" cy="9" r="5" fill={`oklch(72% 0.12 ${b})`} opacity="0.75" />
                <circle cx="18" cy="26" r="7" fill={`oklch(72% 0.12 ${c})`} opacity="0.7" />
            </svg>
        </div>
    );
}
