// DaalButton.tsx — the signature Connect button (D-2 §5C).
//
// One piece of artwork (the eagle) for every state. The state is
// communicated through CSS treatment of the same image so the brand
// mark is consistent across the connect lifecycle:
//   - 'connected'     full-color eagle, no filter
//   - 'connecting'    grayscale + dimmed + soft pulse — "warming up"
//   - 'disconnected'  grayscale + dimmed — "tap to start"
//   - 'error'         grayscale + dimmed; the surrounding UI carries the
//                     red error text/banner. Keeping the eagle silver
//                     (instead of red-tinted) lets the existing error
//                     text and recovery hint do the colour work.
//
// The button itself stays transparent — the eagle PNG already has its
// own padding and sits on whatever page bg is active (D-2 page is dark
// teal so the gold/blue eagle reads cleanly).

import daal3dUrl from '@branding/sources/daal-eagle-transparent.png?url';

export type DaalConnectState =
    | 'disconnected'
    | 'connecting'
    | 'connected'
    | 'error';

interface Props {
    state: DaalConnectState;
    onClick: () => void;
    label: string;
}

// CSS treatment per state. Kept as a constant so it's easy to tweak
// later without scanning the JSX.
const STATE_STYLES: Record<DaalConnectState, React.CSSProperties> = {
    connected: {
        filter: 'none',
        opacity: 1,
    },
    connecting: {
        filter: 'grayscale(1)',
        opacity: 0.55,
        animation: 'daal-pulse 1.6s ease-in-out infinite',
    },
    disconnected: {
        filter: 'grayscale(1)',
        opacity: 0.5,
    },
    error: {
        filter: 'grayscale(1)',
        opacity: 0.5,
    },
};

export default function DaalButton({ state, onClick, label }: Props) {
    return (
        <button
            onClick={onClick}
            aria-label={label}
            style={{
                width: 280,
                height: 280,
                position: 'relative',
                background: 'transparent',
                border: 0,
                cursor: 'pointer',
                padding: 0,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
            }}
        >
            <img
                src={daal3dUrl}
                alt=""
                aria-hidden
                width={220}
                height={220}
                style={{
                    position: 'relative',
                    zIndex: 1,
                    objectFit: 'contain',
                    transition: 'filter 240ms ease, opacity 240ms ease',
                    pointerEvents: 'none',
                    ...STATE_STYLES[state],
                }}
            />
        </button>
    );
}
