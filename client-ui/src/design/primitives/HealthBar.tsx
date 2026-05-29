// HealthBar — simple horizontal percent bar used inside cards.

interface Props {
    pct: number;
    tone?: 'good' | 'warn' | 'bad' | 'neutral';
}

const TONE: Record<NonNullable<Props['tone']>, string> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    neutral: 'var(--muted)',
};

export function HealthBar({ pct, tone = 'good' }: Props) {
    const clamped = Math.max(0, Math.min(100, Math.round(pct)));
    return (
        <div
            style={{
                width: '100%',
                height: 6,
                background: 'var(--surface-3)',
                borderRadius: 999,
                overflow: 'hidden',
            }}
        >
            <div
                style={{
                    width: `${clamped}%`,
                    height: '100%',
                    background: TONE[tone],
                    transition: 'width var(--t-slow)',
                }}
            />
        </div>
    );
}
