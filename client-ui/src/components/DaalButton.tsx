// DaalButton.tsx — the bird on Home. It IS the button (spec C2).
//
// One piece of artwork (the eagle) in every state, inside a ring that
// carries the state by colour and motion, so the person sees what is
// happening without reading:
//   none     grey, dimmed: nothing to connect with yet
//   ready    a gold ring that breathes: tap to connect
//   busy     a gold arc that turns: connecting
//   holding  an amber arc that turns: reconnecting
//   good     green ring, the eagle in colour: connected
//   slow     amber ring, the eagle in colour: connected, slow
//   bad      red ring, the eagle grey: could not connect
//
// The accessible name is what a tap does ("Connect", "Cancel",
// "Disconnect"), given by the page.

import daal3dUrl from '@branding/sources/daal-eagle-transparent.png?url';
import type { HomeTone } from '../lib/mainScreen';

/** Kept for callers of the old prop; the page now passes `tone`. */
export type DaalConnectState = 'disconnected' | 'connecting' | 'connected' | 'error';

interface Props {
    tone: HomeTone;
    onClick: () => void;
    label: string;
    /** Outer size in px: 168 on phone, 200 on desktop. */
    size?: number;
}

const RING: Record<HomeTone, string> = {
    none: 'var(--line)',
    ready: 'var(--gold)',
    busy: 'var(--gold)',
    holding: 'var(--amber)',
    good: 'var(--green)',
    slow: 'var(--amber)',
    bad: 'var(--red)',
};

/** The eagle in colour only when something is connected. */
function eagleStyle(tone: HomeTone): React.CSSProperties {
    if (tone === 'good' || tone === 'slow') return { filter: 'none', opacity: 1 };
    if (tone === 'none') return { filter: 'grayscale(1)', opacity: 0.4 };
    if (tone === 'busy' || tone === 'holding') return { filter: 'grayscale(0.6)', opacity: 0.75 };
    return { filter: 'grayscale(1)', opacity: 0.6 };
}

export default function DaalButton({ tone, onClick, label, size = 168 }: Props) {
    const stroke = 4;
    const r = size / 2 - stroke;
    const c = 2 * Math.PI * r;
    const spinning = tone === 'busy' || tone === 'holding';
    return (
        <button
            type="button"
            onClick={onClick}
            aria-label={label}
            data-button="bird"
            data-tone={tone}
            className="d2-bird"
            style={{
                width: size,
                height: size,
                position: 'relative',
                background: 'transparent',
                border: 0,
                borderRadius: '50%',
                cursor: 'pointer',
                padding: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
            }}
        >
            <svg
                aria-hidden
                width={size}
                height={size}
                viewBox={`0 0 ${size} ${size}`}
                className={tone === 'ready' ? 'd2-bird-breathe' : undefined}
                style={{
                    position: 'absolute',
                    inset: 0,
                    animation: spinning ? 'daal-spin 1.4s linear infinite' : undefined,
                }}
            >
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={r}
                    fill="none"
                    stroke="var(--line-soft)"
                    strokeWidth={stroke}
                    opacity={spinning ? 0.6 : 0}
                />
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={r}
                    fill="none"
                    stroke={RING[tone]}
                    strokeWidth={stroke}
                    strokeLinecap="round"
                    strokeDasharray={spinning ? `${c * 0.28} ${c}` : undefined}
                    opacity={tone === 'none' ? 0.6 : 1}
                />
            </svg>
            <img
                src={daal3dUrl}
                alt=""
                aria-hidden
                width={Math.round(size * 0.84)}
                height={Math.round(size * 0.84)}
                style={{
                    position: 'relative',
                    zIndex: 1,
                    objectFit: 'contain',
                    transition: 'filter 240ms ease, opacity 240ms ease',
                    pointerEvents: 'none',
                    ...eagleStyle(tone),
                }}
            />
        </button>
    );
}
