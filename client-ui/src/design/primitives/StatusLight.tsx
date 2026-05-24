// StatusLight — small glowing circle indicator used on dashboard tiles.

interface Props {
    tone: 'good' | 'warn' | 'bad' | 'neutral';
    size?: number;
    pulse?: boolean;
}

const TONE: Record<Props['tone'], string> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    neutral: 'var(--muted)',
};

export function StatusLight({ tone, size = 10, pulse }: Props) {
    const color = TONE[tone];
    return (
        <span
            aria-hidden
            style={{
                width: size,
                height: size,
                borderRadius: '50%',
                background: color,
                boxShadow: `0 0 ${size}px ${color}`,
                display: 'inline-block',
                animation: pulse ? 'daal-pulse 1.6s ease-in-out infinite' : undefined,
            }}
        />
    );
}
