// ShareLinksSheet — "Links for other apps" for one person.
//
// Standard links (vless:// REALITY, ss://, and the Cloudflare way where
// the relay allows it) that v2rayNG, Hiddify, Streisand, Shadowrocket or
// NekoBox can import, so an iPhone or a second app can use the relay as
// this person. Which ways get a link is decided by `daal-deploy
// users-share-links`: never a link that needs "allow insecure".
//
// One decision: the sheet shows ONE link (the first; the verb puts
// REALITY first) with Copy and QR. Any further links, and the ways left
// out with the reason, are folded away.
//
// A link is a credential. The screen is marked sensitive (no
// screenshots, no app-switcher preview) while it is open, nothing here
// logs a link, and an error never carries one.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Disclosure, Sheet } from '../../design/primitives';
import { familyLabel } from '../../lib/familyName';
import { effectiveLocale } from '../../lib/i18n';
import { writeClipboardText } from '../../lib/clipboard';
import { encodeText } from '../../qr/qrcodegen';
import { QUIET_MODULES } from '../../qr/paint';
import { useSecureScreen } from '../useSecureScreen';
import { Wizard } from '../wizardCommands';
import type { ShareLinksResult } from '../wizardCommands';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    recipientId: number;
    /** What the publisher calls this person. */
    name: string;
    onClose: () => void;
    /** Test seam; the Tauri command by default. */
    load?: (operatorId: number, recipientId: number) => Promise<ShareLinksResult>;
}

const SUB: React.CSSProperties = { fontSize: 13, color: 'var(--muted)', lineHeight: 1.55 };

/** The way's name: the one every other screen uses (lib/familyName),
 *  the Cloudflare route's own name for `cdn`. */
export function wayName(t: (k: string) => string, way: string): string {
    if (way === 'cdn') {
        const c = t('route.label.ws_cdn');
        if (c !== 'route.label.ws_cdn') return c;
    }
    const f = familyLabel(t, way);
    if (f) return f;
    const key = `pub.links.way.${way.replace(/[^a-z0-9]/g, '_')}`;
    const s = t(key);
    return s === key ? way : s;
}

/** Left-out ways grouped by reason: "A, B, C: reason", one line each. */
export function leftOutLines(t: (k: string) => string, left: ShareLinksResult['left_out']): string[] {
    const by = new Map<string, string[]>();
    for (const w of left) {
        const r = leftOutReason(t, w.reason);
        by.set(r, [...(by.get(r) ?? []), wayName(t, w.way)]);
    }
    const sep = effectiveLocale() === 'fa' ? '\u060c\u200f ' : ', ';
    return [...by.entries()].map(([r, ways]) => `${ways.join(sep)}: ${r}`);
}

/** The plain reason a way has no link; '' for a code this build does not know. */
export function leftOutReason(t: (k: string) => string, reason: string): string {
    const key = `pub.links.why.${reason}`;
    const s = t(key);
    return s === key ? t('pub.links.why.other') : s;
}

/** One link as a QR code: always black on white (a themed QR is a scan
 *  failure, qr/paint.ts). Built with the app's own vendored encoder. */
export function LinkQr({ text }: { text: string }) {
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
    return (
        <svg
            data-testid="share-link-qr"
            role="img"
            viewBox={`0 0 ${path.side} ${path.side}`}
            width={260}
            height={260}
            shapeRendering="crispEdges"
            style={{ display: 'block', margin: '8px auto 0', background: '#ffffff', maxWidth: '100%' }}
        >
            <rect width={path.side} height={path.side} fill="#ffffff" />
            <path d={path.d} fill="#000000" />
        </svg>
    );
}

type State =
    | { kind: 'loading' }
    | { kind: 'failed' }
    | { kind: 'ready'; result: ShareLinksResult };

export function ShareLinksSheet({ t, operatorId, recipientId, name, onClose, load }: Props) {
    useSecureScreen(true);
    const [state, setState] = useState<State>({ kind: 'loading' });
    const [qrFor, setQrFor] = useState<string | null>(null);
    const [copied, setCopied] = useState<{ way: string; ok: boolean } | null>(null);

    const fetchLinks = useCallback(() => {
        let live = true;
        setState({ kind: 'loading' });
        (load ?? Wizard.recipientShareLinks)(operatorId, recipientId).then(
            (result) => {
                if (live) setState({ kind: 'ready', result });
            },
            () => {
                // The error is not shown or logged here: the shell has
                // already logged it, and it carries no link.
                if (live) setState({ kind: 'failed' });
            },
        );
        return () => {
            live = false;
        };
    }, [load, operatorId, recipientId]);
    useEffect(() => fetchLinks(), [fetchLinks]);

    const copy = async (way: string, link: string) => {
        try {
            await writeClipboardText(link);
            setCopied({ way, ok: true });
        } catch {
            setCopied({ way, ok: false });
        }
    };

    const linkRow = (l: ShareLinksResult['links'][number], named: boolean) => (
        <div
            key={l.way}
            data-testid="share-link-row"
            data-way={l.way}
            style={{ display: 'grid', gap: 6, paddingBottom: 10, borderBottom: '1px solid var(--line)' }}
        >
            {named && <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>{wayName(t, l.way)}</div>}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <Button size="sm" leading="copy" dataButton="share-link-copy" onClick={() => void copy(l.way, l.link)}>
                    {copied?.way === l.way && copied.ok ? t('pub.links.copied') : t('pub.links.copy')}
                </Button>
                <Button
                    size="sm"
                    variant="ghost"
                    leading="qr"
                    dataButton="share-link-qr"
                    onClick={() => setQrFor((w) => (w === l.way ? null : l.way))}
                >
                    {qrFor === l.way ? t('pub.links.qr_hide') : t('pub.links.qr_show')}
                </Button>
            </div>
            {copied?.way === l.way && !copied.ok && (
                <div style={SUB} data-testid="share-link-copy-failed">
                    {t('pub.links.copy_failed')}
                </div>
            )}
            {qrFor === l.way && <LinkQr text={l.link} />}
        </div>
    );

    return (
        <Sheet title={t('pub.links.title')} width={520} onClose={onClose}>
            <div style={{ display: 'grid', gap: 14 }} data-testid="share-links-sheet" data-secure="1">
                <div style={{ fontSize: 14, lineHeight: 1.55, color: 'var(--fg)' }} data-testid="share-links-warning">
                    {t('pub.links.warning').replace(/\{name\}/g, name)}
                </div>
                <div style={SUB} data-testid="share-links-for-apps">
                    {t('pub.links.for_apps')}
                </div>

                {state.kind === 'loading' && <div style={SUB}>{t('pub.links.loading')}</div>}

                {state.kind === 'failed' && (
                    <div style={{ display: 'grid', gap: 8, justifyItems: 'start' }} data-testid="share-links-failed">
                        <div style={SUB}>{t('pub.links.error')}</div>
                        <Button size="sm" variant="ghost" leading="refresh" dataButton="share-links-retry" onClick={() => fetchLinks()}>
                            {t('pub.links.retry')}
                        </Button>
                    </div>
                )}

                {state.kind === 'ready' && state.result.links.length === 0 && (
                    <div style={SUB} data-testid="share-links-none">
                        {t('pub.links.none')}
                    </div>
                )}

                {state.kind === 'ready' && state.result.links.length > 0 && linkRow(state.result.links[0], false)}

                {state.kind === 'ready' && state.result.links.length > 1 && (
                    <Disclosure summary={t('pub.links.more')} dataButton="share-links-more">
                        <div style={{ display: 'grid', gap: 10, paddingTop: 6 }}>
                            {state.result.links.slice(1).map((l) => linkRow(l, true))}
                        </div>
                    </Disclosure>
                )}

                {state.kind === 'ready' && state.result.left_out.length > 0 && (
                    <Disclosure summary={t('pub.links.left_out')} dataButton="share-links-left-out-toggle">
                        <div style={{ display: 'grid', gap: 4, paddingTop: 4 }} data-testid="share-links-left-out">
                            {leftOutLines(t, state.result.left_out).map((line) => (
                                <div key={line} style={SUB}>
                                    {line}
                                </div>
                            ))}
                        </div>
                    </Disclosure>
                )}

                <div>
                    <Button variant="ghost" dataButton="share-links-close" onClick={onClose}>
                        {t('pub.links.close')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}
