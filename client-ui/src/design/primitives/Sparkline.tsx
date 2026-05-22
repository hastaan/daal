// Sparkline — tiny inline SVG line chart for trend visualisation.
// Renders normalised values into a fixed viewBox.

interface Props {
    values: number[];
    width?: number;
    height?: number;
    tone?: 'good' | 'warn' | 'bad' | 'neutral' | 'gold';
}

const TONE: Record<NonNullable<Props['tone']>, string> = {
    good: 'var(--green)',
    warn: 'var(--amber)',
    bad: 'var(--red)',
    neutral: 'var(--muted)',
    gold: 'var(--gold-warm)',
};

export function Sparkline({
    values,
    width = 96,
    height = 28,
    tone = 'gold',
}: Props) {
    if (values.length === 0) {
        return (
            <svg width={width} height={height} aria-hidden>
                <line
                    x1={0}
                    y1={height - 1}
                    x2={width}
                    y2={height - 1}
                    stroke="var(--line)"
                    strokeWidth={1}
                />
            </svg>
        );
    }
    const min = Math.min(...values);
    const max = Math.max(...values);
    const range = max - min || 1;
    const step = values.length > 1 ? width / (values.length - 1) : width;
    const points = values.map((v, i) => {
        const x = i * step;
        const y = height - 2 - ((v - min) / range) * (height - 4);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    const fillPath = `M0,${height} L ${points.join(' L ')} L ${width},${height} Z`;
    return (
        <svg
            width={width}
            height={height}
            viewBox={`0 0 ${width} ${height}`}
            aria-hidden
        >
            <path d={fillPath} fill={TONE[tone]} opacity="0.18" />
            <polyline
                points={points.join(' ')}
                fill="none"
                stroke={TONE[tone]}
                strokeWidth={1.5}
                strokeLinecap="round"
                strokeLinejoin="round"
            />
        </svg>
    );
}
