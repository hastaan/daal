// HandoffCard — "Other apps that may work right now", under a failed
// automatic connect (docs/exotic-transports-plan.md, Corrected Wave 1,
// W1-B).
//
// When every way Daal has has failed, the honest next step is often
// someone else's network. This card names three, one line each, says
// plainly that they are other organisations' networks and not Daal's,
// and promises nothing: no user counts, no "this will work". Each link
// opens outside the app (the store on a phone, the project's own site on
// a computer).
//
// Tor bridge lines this build cannot dial (no tor binary ships: see
// core/routestore/family.go, `tor-bridge`) can be handed to Orbot, which
// can. Only through the system share sheet or a QR code on this screen,
// never the clipboard: a bridge address is not published, and a
// clipboard is readable by every other app on the phone.
import { useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button } from '../../design/primitives';
import { encodeText } from '../../qr/qrcodegen';
import { QUIET_MODULES } from '../../qr/paint';

type T = (k: string) => string;

export interface HandoffApp {
    id: 'psiphon' | 'lantern' | 'tor';
    /** Store page on Android. */
    phone: string;
    /** The project's own download page elsewhere. */
    computer: string;
}

/** The three apps, in a fixed order. Links are the projects' own store
 *  listings and download pages; nothing else is ever opened from here. */
export const HANDOFF_APPS: readonly HandoffApp[] = [
    {
        id: 'psiphon',
        phone: 'https://play.google.com/store/apps/details?id=com.psiphon3.subscription',
        computer: 'https://psiphon.ca/download.html',
    },
    {
        id: 'lantern',
        phone: 'https://play.google.com/store/apps/details?id=org.getlantern.lantern',
        computer: 'https://lantern.io/download',
    },
    {
        id: 'tor',
        phone: 'https://play.google.com/store/apps/details?id=org.torproject.android',
        computer: 'https://www.torproject.org/download/',
    },
];

/** Failed-connect verdicts after which another network is worth naming:
 *  Daal's own ways ran out. Not `network_down` (the phone has no
 *  internet, so no app helps), not `none_usable` (the person can still
 *  choose a way by hand), not `cancelled`. */
const NOT_AFTER = new Set(['network_down', 'none_usable', 'cancelled', 'moved_on', '']);

export function handoffShown(verdict: string): boolean {
    return !NOT_AFTER.has(verdict);
}

function onPhone(): boolean {
    try {
        return /Android/i.test(navigator.userAgent);
    } catch {
        return false;
    }
}

/** Open a page in the system browser or store, outside the app. */
export async function openOutside(url: string): Promise<void> {
    try {
        await invoke('open_external_url', { url });
        return;
    } catch {
        /* not in the app shell */
    }
    try {
        window.open(url, '_blank', 'noopener,noreferrer');
    } catch {
        /* nothing to open with */
    }
}

/** The text handed to Orbot: one bridge line per line, nothing else. */
export function bridgeText(lines: readonly string[]): string {
    return lines
        .map((l) => l.trim().replace(/^bridge\s+/i, ''))
        .filter(Boolean)
        .join('\n');
}

function BridgeQr({ text }: { text: string }) {
    const path = useMemo(() => {
        try {
            const code = encodeText(text, 'M');
            let d = '';
            for (let y = 0; y < code.size; y++) {
                for (let x = 0; x < code.size; x++) {
                    if (code.modules[y * code.size + x]) d += `M${x + QUIET_MODULES} ${y + QUIET_MODULES}h1v1h-1z`;
                }
            }
            return { d, side: code.size + 2 * QUIET_MODULES };
        } catch {
            return undefined;
        }
    }, [text]);
    if (!path) return null;
    // Always black on white, whatever the theme: a themed QR is a scan
    // failure (qr/paint.ts).
    return (
        <svg
            data-testid="handoff-bridge-qr"
            role="img"
            viewBox={`0 0 ${path.side} ${path.side}`}
            width={240}
            height={240}
            shapeRendering="crispEdges"
            style={{ display: 'block', margin: '8px auto 0', background: '#ffffff', maxWidth: '100%' }}
        >
            <rect width={path.side} height={path.side} fill="#ffffff" />
            <path d={path.d} fill="#000000" />
        </svg>
    );
}

interface Props {
    t: T;
    /** Tor bridge lines the person holds and this build cannot dial.
     *  Absent or empty: no bridge section. */
    bridgeLines?: readonly string[];
}

export default function HandoffCard({ t, bridgeLines }: Props) {
    const phone = onPhone();
    const bridges = bridgeText(bridgeLines ?? []);
    const [qr, setQr] = useState(false);
    const [shareFailed, setShareFailed] = useState(false);
    const share = async () => {
        try {
            await invoke('share_text', { text: bridges, title: t('handoff.bridges.title') });
            setShareFailed(false);
        } catch {
            setShareFailed(true);
            setQr(true);
        }
    };
    return (
        <section
            data-testid="handoff-card"
            style={{
                marginBlockStart: 16,
                padding: '14px 16px',
                background: 'var(--surface)',
                border: '1px solid var(--line-soft)',
                borderRadius: 'var(--r-card)',
                textAlign: 'start',
            }}
        >
            <h3 style={{ fontSize: 15, fontWeight: 600, margin: 0, color: 'var(--fg)' }}>{t('handoff.title')}</h3>
            <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5, margin: '6px 0 0' }}>{t('handoff.body')}</p>
            <ul style={{ listStyle: 'none', padding: 0, margin: '10px 0 0', display: 'grid', gap: 8 }}>
                {HANDOFF_APPS.map((a) => (
                    <li key={a.id} data-handoff={a.id} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <bdi style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg)' }}>{t(`handoff.${a.id}.name`)}</bdi>
                            <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>{t(`handoff.${a.id}.about`)}</div>
                        </div>
                        <Button
                            size="sm"
                            variant="secondary"
                            leading="external"
                            dataButton={`handoff-${a.id}`}
                            onClick={() => void openOutside(phone ? a.phone : a.computer)}
                        >
                            {t('handoff.get')}
                        </Button>
                    </li>
                ))}
            </ul>
            {bridges && (
                <div data-testid="handoff-bridges" style={{ marginBlockStart: 14, borderBlockStart: '1px solid var(--line-soft)', paddingBlockStart: 12 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg)' }}>{t('handoff.bridges.title')}</div>
                    <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5, margin: '4px 0 8px' }}>{t('handoff.bridges.body')}</p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                        {phone && (
                            <Button size="sm" variant="secondary" leading="share" dataButton="handoff-bridges-share" onClick={() => void share()}>
                                {t('handoff.bridges.share')}
                            </Button>
                        )}
                        <Button size="sm" variant="ghost" leading="qr" dataButton="handoff-bridges-qr" onClick={() => setQr((v) => !v)}>
                            {qr ? t('handoff.bridges.qr_hide') : t('handoff.bridges.qr')}
                        </Button>
                    </div>
                    {shareFailed && (
                        <p role="status" style={{ fontSize: 12, color: 'var(--muted)', margin: '6px 0 0' }}>
                            {t('handoff.bridges.share_failed')}
                        </p>
                    )}
                    {qr && (
                        <>
                            <BridgeQr text={bridges} />
                            <p style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5, margin: '6px 0 0' }}>{t('handoff.bridges.qr_hint')}</p>
                        </>
                    )}
                </div>
            )}
        </section>
    );
}
