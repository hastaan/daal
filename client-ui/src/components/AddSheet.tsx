// AddSheet.tsx — D-2 unified intake. "Clean and powerful."
//
// Two surfaces only:
//   • Paste   — single textarea. Auto-detects on input: .sbp/.sbpx
//               base64, vless://, vmess://, subscription URL, etc.
//   • File    — native file picker (Android SAF / desktop dialog).
//               PIN field appears only after the picked file sniffs
//               as .sbpx.
//
// "My Daal address" is reachable from a separate top-level action
// next to Add on the Network page header; it is NOT a tab here.
//
// Everything is wired end-to-end:
//   • previewBundle / importSbp for plain .sbp
//   • Sbpx.sniff / Sbpx.import (device-key decrypt) → importSbp for .sbpx
//   • importSbpBytes for a .sbp or .sbpx pasted as
//     base64 text — the offline path for a channel that bans files
//     (Wave 4 Step 11). Same verification as the file path; the only
//     difference is how the bytes arrived.
//   • uri_detect / uri_import for one-off vless/vmess/etc URIs
//   • subscriptionAdd for http(s) URLs

import { useEffect, useMemo, useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle } from '../contract/D2Contract';
import { PickedFile, Sbpx } from '../recipient/recipientCommands';
import { detectPastedContainer } from '../lib/pastedBundle';
import { Sheet, Button } from '../design/primitives';
import TrustPrompt from './TrustPrompt';
import {
    syntheticSubscriptionFingerprint,
    subscriptionDisplayName,
} from '../lib/subscriptionIdentity';
import {
    KIND_REJECTED,
    KIND_TRUST_PROMPT_NEEDED,
    friendlyError,
    friendlyReason,
    parseVerdict,
    trustFailure,
    trustFromVerdict,
} from '../lib/importVerdict';
import type { ImportVerdict, TrustResolution } from '../lib/importVerdict';





interface Props {
    t: (k: string) => string;
    onClose: () => void;
    onImported?: () => void;
}

type Tab = 'paste' | 'file';

/** Best-effort client-side classifier for the paste box. The engine
 *  is the source of truth — this only drives the "What I see" pill. */
type PasteKind = 'empty' | 'sbp-b64' | 'sbpx-b64' | 'http' | 'uri' | 'unknown';

function classifyPaste(s: string): PasteKind {
    const trimmed = s.trim();
    if (!trimmed) return 'empty';
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return 'http';
    // URI schemes the engine's uri.ParseAny handles.
    if (/^(vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wg|amneziawg|naive|brook|snowflake):\/\//i.test(
            trimmed,
        ))
        return 'uri';
    // A pasted bundle is located by the base64 spelling of its
    // container magic, after the joiners a messenger inserts are
    // dropped — see lib/pastedBundle.ts.
    //
    // The previous rule here was `/^RFNCU/` plus "longer than 200
    // chars means sealed", which was wrong twice over: RFNCU is the
    // .sbpx envelope magic, so a plain .sbp (a zip — "UEsDB…") never
    // matched at all and the Import button stayed dead for it, and a
    // short .sbpx was mislabelled a bundle. Neither mattered while
    // both were handed to uriImport, which cannot parse base64
    // anyway; both matter now that the paste actually imports.
    const container = detectPastedContainer(trimmed);
    if (container === 'sbpx') return 'sbpx-b64';
    if (container === 'sbp') return 'sbp-b64';
    return 'unknown';
}

export default function AddSheet({ t, onClose, onImported }: Props) {
    const contract = useContract();
    const [tab, setTab] = useState<Tab>('paste');
    const [pasted, setPasted] = useState('');
    const [filePath, setFilePath] = useState('');
    const [isSbpx, setIsSbpx] = useState(false);
    const [preview, setPreview] = useState<PreviewedBundle | null>(null);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [done, setDone] = useState(false);
    /** True after the engine returns VerdictTrustPromptNeeded — the
     *  user must confirm the publisher EN+FA word grid before any
     *  routes commit. */
    const [awaitingTrust, setAwaitingTrust] = useState(false);

    const kind = useMemo(() => classifyPaste(pasted), [pasted]);

    // When the user picks a file, immediately sniff it so the PIN
    // input appears (or stays hidden) without an extra click.
    useEffect(() => {
        let cancelled = false;
        if (!filePath) {
            setIsSbpx(false);
            return;
        }
        Sbpx.sniff(filePath)
            .then((b) => {
                if (!cancelled) setIsSbpx(b);
            })
            .catch(() => {
                if (!cancelled) setIsSbpx(false);
            });
        return () => {
            cancelled = true;
        };
    }, [filePath]);

    const chooseFile = async () => {
        setError(null);
        try {
            // Android SAF goes through this plugin too; the engine's
            // recipient_sbpx_sniff can handle the resulting URI as
            // long as Rust resolves it to a real path. The Tauri
            // dialog plugin already does that translation on Android.
            const picked = await openDialog({
                multiple: false,
                directory: false,
            });
            if (typeof picked === 'string') {
                // On Android the picker returns a content:// SAF URI
                // that std::fs cannot open. stage_picked_file copies
                // the bytes into the app's private staging dir and
                // returns a real path. On desktop this is a no-op.
                const staged = await PickedFile.stage(picked);
                setFilePath(staged);
                setPreview(null);
                setDone(false);
            }
        } catch (e) {
            setError(String(e));
        }
    };

    const previewPickedFile = async () => {
        setBusy(true);
        setError(null);
        try {
            // Device Custody v1: .sbpx unwrap uses the recipient X25519
            // priv held in device custody — no PIN at this layer. The
            // recipient must have created an identity first; otherwise
            // the Rust side returns `IdentityMissing` and the friendly
            // error mapper points to "Set up your Daal address first".
            const target = isSbpx ? await Sbpx.import(filePath) : filePath;
            const p = await contract.previewBundle(target);
            setPreview(p);
        } catch (e) {
            setError(friendlyError(t, (e as Error).message || String(e)));
        } finally {
            setBusy(false);
        }
    };

    const importPickedFile = async () => {
        setBusy(true);
        setError(null);
        try {
            const target = isSbpx ? await Sbpx.import(filePath) : filePath;
            const verdictJson = await contract.importSbp(target);
            // Engine returns a JSON Verdict; branch on Kind.
            // 0=Imported (silent), 1=TrustPromptNeeded (first-seen
            // publisher — caller must render the EN+FA word grid and
            // call resolveTrustPrompt before the routes commit),
            // 2=RotationAccepted (silent, accepted via valid
            // rotation chain), 3=Rejected (Reason populated).
            // A non-JSON response (older ABI or an error path) parses
            // to null and falls through to silent success, so the
            // desktop scenario does not regress.
            const v: ImportVerdict | null = parseVerdict(verdictJson);
            if (v && v.Kind === KIND_TRUST_PROMPT_NEEDED) {
                // Hold the modal open with the trust prompt, showing
                // the engine's word grid over the preview's (the
                // preview renders placeholder words — see
                // trustFromVerdict).
                setPreview(trustFromVerdict(preview, v));
                setAwaitingTrust(true);
                return;
            }
            if (v && v.Kind === KIND_REJECTED) {
                setError(friendlyReason(t, v.Reason || ''));
                return;
            }
            // KIND_IMPORTED, KIND_ROTATION_ACCEPTED, or unknown-but-no-error
            setDone(true);
            onImported?.();
        } catch (e) {
            setError(friendlyError(t, (e as Error).message || String(e)));
        } finally {
            setBusy(false);
        }
    };

    /** Called by TrustPrompt with what the ENGINE said, not with what
     *  the user tapped. resolveTrustPrompt re-verifies the pending
     *  bundle before committing, so it can refuse at this point; this
     *  used to set `done`, which renders the full-sheet "added"
     *  confirmation, no matter what came back. */
    const onTrustResolved = (r: TrustResolution) => {
        setAwaitingTrust(false);
        if (r.decision === 2) {
            // user cancelled — nothing to refresh, nothing to report
            return;
        }
        const failure = trustFailure(t, r);
        if (failure) {
            setError(failure);
            return;
        }
        setDone(true);
        onImported?.();
    };

    const importPasted = async () => {
        setBusy(true);
        setError(null);
        try {
            if (kind === 'http') {
                // Gap 4-recipient bug fix: the engine rejects an
                // empty publisher_fingerprint. Synthesise a stable
                // per-URL id and surface the URL's host as the
                // display name so derive_tree groups these rows
                // visibly.
                const url = pasted.trim();
                await contract.subscriptionAdd({
                    publisherFingerprint: await syntheticSubscriptionFingerprint(url),
                    url,
                    displayName: subscriptionDisplayName(url),
                });
            } else if (kind === 'sbp-b64' || kind === 'sbpx-b64') {
                // Wave 4 Step 11. This is the whole point of the paste
                // box: a bundle that travelled as text because the
                // channel bans files. It used to be handed to
                // uriImport, which cannot parse base64 — the UI said
                // it recognised the blob and then failed.
                //
                // importSbpBytes runs the same signature, revocation
                // and expiry checks the file picker runs, and a sealed
                // .sbpx still needs this phone's Daal address.
                const verdictJson = await contract.importSbpBytes(pasted);
                // Non-JSON response (older ABI) parses to null and is
                // treated as success, matching the picked-file path.
                const v: ImportVerdict | null = parseVerdict(verdictJson);
                if (v && v.Kind === KIND_TRUST_PROMPT_NEEDED) {
                    // First time we've seen this publisher. Same
                    // EN+FA word grid as the file path — a pasted
                    // route does not get a quieter trust decision.
                    // The words come off the verdict, so nothing has
                    // to be decoded or decrypted a second time.
                    setPreview(trustFromVerdict(null, v));
                    setAwaitingTrust(true);
                    return;
                }
                if (v && v.Kind === KIND_REJECTED) {
                    setError(friendlyReason(t, v.Reason || ''));
                    return;
                }
            } else if (kind === 'uri') {
                const res = await contract.uriImport(pasted.trim());
                if (res.error) throw new Error(res.error);
            } else {
                // Best-effort: hand the body to the engine as a URI
                // anyway; the engine's parser is strict and will
                // reject anything it doesn't understand.
                const res = await contract.uriImport(pasted.trim());
                if (res.error) throw new Error(res.error);
            }
            setDone(true);
            onImported?.();
        } catch (e) {
            setError(friendlyError(t, (e as Error).message || String(e)));
        } finally {
            setBusy(false);
        }
    };

    if (done) {
        return (
            <Sheet
                title={t('add.title')}
                onClose={onClose}
                width={520}
                footer={
                    <Button onClick={onClose}>{t('common.continue')}</Button>
                }
            >
                <div
                    style={{
                        fontSize: 14,
                        color: 'var(--paper)',
                        padding: '10px 0',
                    }}
                >
                    {t('add.done')}
                </div>
            </Sheet>
        );
    }

    return (
        <Sheet
            title={t('add.title')}
            onClose={onClose}
            width={520}
            footer={
                <>
                    <Button variant="ghost" onClick={onClose}>
                        {t('common.cancel')}
                    </Button>
                    {awaitingTrust ? (
                        // TrustPrompt provides its own Trust / Once /
                        // Cancel buttons; no footer action needed.
                        null
                    ) : tab === 'paste' ? (
                        <Button
                            onClick={importPasted}
                            disabled={busy || kind === 'empty' || kind === 'unknown'}
                        >
                            {busy ? '…' : t('add.import')}
                        </Button>
                    ) : preview ? (
                        <Button onClick={importPickedFile} disabled={busy}>
                            {busy ? '…' : t('add.confirm_import')}
                        </Button>
                    ) : (
                        <Button
                            onClick={previewPickedFile}
                            disabled={busy || !filePath}
                        >
                            {busy ? '…' : t('add.preview')}
                        </Button>
                    )}
                </>
            }
        >
            <div
                role="tablist"
                style={{
                    display: 'flex',
                    gap: 4,
                    background: 'var(--teal-deep)',
                    padding: 4,
                    borderRadius: 'var(--radius-md)',
                    marginBottom: 16,
                }}
            >
                <TabButton label={t('add.tab.paste')} active={tab === 'paste'} onClick={() => setTab('paste')} />
                <TabButton label={t('add.tab.file')} active={tab === 'file'} onClick={() => setTab('file')} />
            </div>

            {tab === 'paste' && (
                <div>
                    <textarea
                        value={pasted}
                        onChange={(e) => setPasted(e.target.value)}
                        placeholder={t('add.paste_placeholder')}
                        rows={5}
                        style={inputStyle()}
                    />
                    <DetectPill t={t} kind={kind} />
                    {awaitingTrust && preview && (
                        <TrustPrompt
                            t={t}
                            preview={preview}
                            onResolve={onTrustResolved}
                        />
                    )}
                </div>
            )}

            {tab === 'file' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <Button variant="secondary" onClick={chooseFile} disabled={busy}>
                        {filePath ? t('add.file.change') : t('add.file.choose')}
                    </Button>
                    {filePath && (
                        <div
                            style={{
                                fontSize: 12,
                                color: 'var(--paper-dim)',
                            }}
                        >
                            {isSbpx
                                ? t('add.file.picked_sbpx')
                                : t('add.file.picked')}
                        </div>
                    )}
                    {filePath && isSbpx && (
                        <div
                            style={{
                                fontSize: 12,
                                color: 'var(--paper-dim)',
                                fontStyle: 'italic',
                            }}
                        >
                            {t('add.file.sbpx_custody_hint')}
                        </div>
                    )}
                    {preview && !awaitingTrust && (
                        <div
                            style={{
                                border: '1px solid var(--teal-border)',
                                borderRadius: 'var(--radius-md)',
                                padding: 12,
                                background: 'var(--teal-deep)',
                                fontSize: 13,
                                color: 'var(--paper)',
                                display: 'grid',
                                gap: 4,
                            }}
                        >
                            <div>
                                <strong>{preview.publisherName}</strong>
                            </div>
                            <div style={{ color: 'var(--paper-dim)', fontSize: 12 }}>
                                {t('add.file.preview_routes').replace(
                                    '{n}',
                                    String(preview.routeCount),
                                )}
                            </div>
                            <div
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 11,
                                    color: 'var(--ink-mute)',
                                    marginTop: 4,
                                }}
                            >
                                {preview.fingerprintEN}
                            </div>
                        </div>
                    )}
                    {awaitingTrust && preview && (
                        <TrustPrompt
                            t={t}
                            preview={preview}
                            onResolve={onTrustResolved}
                        />
                    )}
                </div>
            )}

            {error && (
                <div
                    style={{
                        color: 'var(--red, #c8553d)',
                        fontSize: 12,
                        marginTop: 12,
                        fontFamily: 'var(--font-mono)',
                    }}
                >
                    {error}
                </div>
            )}
        </Sheet>
    );
}

function TabButton({
    label,
    active,
    onClick,
}: {
    label: string;
    active: boolean;
    onClick: () => void;
}) {
    return (
        <button
            role="tab"
            aria-selected={active}
            onClick={onClick}
            style={{
                flex: 1,
                background: active ? 'var(--teal-raised)' : 'transparent',
                border: 0,
                color: active ? 'var(--paper)' : 'var(--paper-dim)',
                padding: '10px 12px',
                borderRadius: 'var(--radius-md)',
                cursor: 'pointer',
                fontFamily: 'var(--font-body)',
                fontSize: 13,
            }}
        >
            {label}
        </button>
    );
}

function DetectPill({ t, kind }: { t: (k: string) => string; kind: PasteKind }) {
    if (kind === 'empty') return null;
    const label = (() => {
        switch (kind) {
            case 'sbp-b64':
                return t('add.detect.sbp');
            case 'sbpx-b64':
                return t('add.detect.sbpx');
            case 'http':
                return t('add.detect.subscription');
            case 'uri':
                return t('add.detect.uri');
            default:
                return t('add.detect.unknown');
        }
    })();
    const bad = kind === 'unknown';
    return (
        <div
            style={{
                marginTop: 8,
                display: 'inline-block',
                padding: '4px 10px',
                borderRadius: 999,
                background: bad
                    ? 'rgba(200,85,61,0.10)'
                    : 'rgba(193,158,80,0.10)',
                border: bad
                    ? '1px solid rgba(200,85,61,0.40)'
                    : '1px solid rgba(193,158,80,0.40)',
                color: bad ? 'var(--red, #c8553d)' : 'var(--gold-warm)',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                letterSpacing: '0.04em',
            }}
        >
            {label}
        </div>
    );
}

function inputStyle() {
    return {
        width: '100%',
        background: 'var(--teal-deep)',
        border: '1px solid var(--teal-border)',
        color: 'var(--paper)',
        padding: 10,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 13,
        outline: 'none',
        boxSizing: 'border-box' as const,
    };
}
