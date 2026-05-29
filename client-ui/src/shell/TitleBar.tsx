// TitleBar.tsx — 36px custom titlebar matching client-shared/designs/daal-desktop.html .titlebar.
//
// Layout (LTR):
//   ┌─[mac traffic-lights via OS overlay]─[Daal]──────[• Connected · 02:14:38]─[—□×]─┐
// On macOS we leave the left zone empty (Tauri renders native traffic lights via
// titleBarStyle: "overlay" in tauri.conf.json + decorations:false on Windows/Linux).
// On Linux/Windows we draw our own minimize / maximize / close on the right.
//
// The window itself has decorations off in tauri.conf.json so this React-rendered
// titlebar IS the only chrome. data-tauri-drag-region makes the bar draggable.

import { useEffect, useState } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';

interface Props {
    t: (k: string) => string;
    /** UNIX ms when the engine entered `connected`. Null if not connected. */
    connectedSinceUnixMs: number | null;
    isConnected: boolean;
}

type Plat = 'macos' | 'windows' | 'linux' | 'other';

function detectPlatform(): Plat {
    // Probe the webview's user-agent: WebKit on macOS reports "Macintosh",
    // WebView2 on Windows reports "Windows", WebKitGTK on Linux reports "Linux".
    // Good enough for picking which window-controls to render; the actual
    // window APIs come from @tauri-apps/api/window which works on all three.
    try {
        const ua = (navigator.userAgent || '').toLowerCase();
        if (ua.includes('mac os') || ua.includes('macintosh')) return 'macos';
        if (ua.includes('windows')) return 'windows';
        if (ua.includes('linux')) return 'linux';
        return 'other';
    } catch {
        return 'other';
    }
}

function formatDuration(ms: number): string {
    const total = Math.max(0, Math.floor(ms / 1000));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

export default function TitleBar({
    t,
    connectedSinceUnixMs,
    isConnected,
}: Props) {
    const [plat] = useState<Plat>(detectPlatform);
    const [now, setNow] = useState<number>(Date.now());

    useEffect(() => {
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, []);

    const elapsed =
        isConnected && connectedSinceUnixMs
            ? formatDuration(now - connectedSinceUnixMs)
            : null;

    const showOurControls = plat !== 'macos';

    const onMin = async () => {
        try {
            await getCurrentWindow().minimize();
        } catch {
            /* ignore */
        }
    };
    const onMax = async () => {
        try {
            await getCurrentWindow().toggleMaximize();
        } catch {
            /* ignore */
        }
    };
    const onClose = async () => {
        try {
            await getCurrentWindow().close();
        } catch {
            /* ignore */
        }
    };

    return (
        <div
            data-tauri-drag-region
            style={{
                height: 36,
                flex: '0 0 36px',
                background:
                    'linear-gradient(180deg, #052E3E 0%, #032834 100%)',
                borderBlockEnd: '1px solid var(--teal-hairline)',
                display: 'flex',
                alignItems: 'center',
                paddingInline: 14,
                gap: 14,
                userSelect: 'none',
                // On macOS the system overlays traffic lights on the left.
                // Pad the wordmark over so it doesn't collide.
                paddingInlineStart: plat === 'macos' ? 76 : 14,
            }}
        >
            <span
                data-tauri-drag-region
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 13,
                    color: 'var(--paper-dim)',
                    letterSpacing: '0.02em',
                }}
            >
                {t('app.title')}
            </span>

            <div data-tauri-drag-region style={{ flex: 1 }} />

            {elapsed && (
                <div
                    data-tauri-drag-region
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: 'var(--success)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        fontVariantNumeric: 'tabular-nums',
                    }}
                    aria-live="polite"
                    role="status"
                >
                    <span
                        aria-hidden
                        style={{
                            width: 7,
                            height: 7,
                            borderRadius: '50%',
                            background: 'var(--success)',
                            boxShadow: '0 0 8px var(--success)',
                            display: 'inline-block',
                        }}
                    />
                    {t('connected_label')} · {elapsed}
                </div>
            )}

            {showOurControls && (
                <div
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 0,
                        marginInlineStart: elapsed ? 14 : 0,
                    }}
                >
                    <WinCtrl ariaLabel={t('window.minimize')} onClick={onMin}>
                        <svg
                            width="10"
                            height="10"
                            viewBox="0 0 10 10"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.2"
                        >
                            <line x1="2" y1="5" x2="8" y2="5" />
                        </svg>
                    </WinCtrl>
                    <WinCtrl ariaLabel={t('window.maximize')} onClick={onMax}>
                        <svg
                            width="10"
                            height="10"
                            viewBox="0 0 10 10"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.2"
                        >
                            <rect x="2" y="2" width="6" height="6" />
                        </svg>
                    </WinCtrl>
                    <WinCtrl
                        ariaLabel={t('window.close')}
                        onClick={onClose}
                        danger
                    >
                        <svg
                            width="10"
                            height="10"
                            viewBox="0 0 10 10"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.2"
                        >
                            <line x1="2" y1="2" x2="8" y2="8" />
                            <line x1="8" y1="2" x2="2" y2="8" />
                        </svg>
                    </WinCtrl>
                </div>
            )}
        </div>
    );
}

function WinCtrl({
    children,
    ariaLabel,
    onClick,
    danger,
}: {
    children: React.ReactNode;
    ariaLabel: string;
    onClick: () => void;
    danger?: boolean;
}) {
    return (
        <button
            onClick={onClick}
            aria-label={ariaLabel}
            type="button"
            style={{
                width: 32,
                height: 28,
                background: 'transparent',
                border: 0,
                color: 'var(--ink-soft)',
                cursor: 'pointer',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: 4,
                transition: 'background 120ms, color 120ms',
            }}
            onMouseEnter={(e) => {
                const el = e.currentTarget;
                el.style.background = danger
                    ? 'rgba(200,85,61,0.18)'
                    : 'rgba(255,255,255,0.06)';
                el.style.color = danger ? '#E07A66' : 'var(--paper)';
            }}
            onMouseLeave={(e) => {
                const el = e.currentTarget;
                el.style.background = 'transparent';
                el.style.color = 'var(--ink-soft)';
            }}
        >
            {children}
        </button>
    );
}
