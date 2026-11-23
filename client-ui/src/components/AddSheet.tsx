// AddSheet.tsx — "Add to Daal": one sheet, no tabs (spec C3). Its title
// names no kind of thing (`add.title`): it takes a file, links, a
// scanned code and a standby code alike.
//
// Three ways in, as three large rows:
//   Choose a file  the system picker opens at once (Android SAF or the
//                  desktop dialog); the file is read and checked by itself
//   Paste text     a box with a Paste button. Opening it takes what is on
//                  the clipboard (lib/clipboard.ts: the phone's own) ONLY
//                  when that is something Daal can add (a link it can
//                  import, a Daal file: lib/pasteItems.ts usableClipboard);
//                  anything else, the phone's own Daal address among it,
//                  stays there, and the box opens empty with no error. The
//                  Paste button always takes it: then the person pasted.
//                  A Daal file goes on by itself
//                  (its own signature check and trust question follow). A
//                  web address or a proxy link waits for one "Add" tap: a
//                  link copied for another reason, or half typed, must not
//                  become a subscription the engine starts fetching.
//   Scan a code    the camera starts at once (recipient/RecipientImport)
// and one more way that needs no tap here: a file handed to Daal by
// Android ("Open with Daal", recipient/openedFile.ts) arrives as
// `openedPath` and goes straight to the check.
//
// Every way ends in the same place (components/ImportResult.tsx):
//   a new publisher      the trust question replaces the whole sheet
//   imported             "File added" + "Connect"
//   refused / changed    one reason + "Close"
// There is no "Preview" or "Import" tap: nothing waits for a button the
// person cannot know they need.
//
// Wiring, unchanged from before this wave:
//   • previewBundle / importSbp for a plain .sbp
//   • Sbpx.sniff / Sbpx.import (device-key decrypt) → importSbp for .sbpx
//   • importSbpBytes for a .sbp or .sbpx pasted as base64 text — the
//     offline path for a channel that bans files; same verification
//   • uriImport for one-off vless/vmess/… links
//   • subscriptionAdd for http(s) addresses

import { useEffect, useMemo, useRef, useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle } from '../contract/D2Contract';
import { DeviceCustody, PickedFile, Sbpx } from '../recipient/recipientCommands';
import { sealedCustody } from './PickedFileNote';
import { recordImportOrigin } from '../lib/importOrigin';
import { detectPastedContainer } from '../lib/pastedBundle';
import { Badge, Button, Disclosure, Icon, Input, Sheet, StateIcon } from '../design/primitives';
import type { IconName } from '../design/primitives';
import { useDensity } from '../design/DensityProvider';
import TrustPrompt from './TrustPrompt';
import ImportResult, { importOutcome, trustOutcome, type ImportOutcome } from './ImportResult';
import RecipientImport from '../recipient/RecipientImport';
import { syntheticSubscriptionFingerprint, subscriptionDisplayName } from '../lib/subscriptionIdentity';
import { friendlyError, parseVerdict, type ImportVerdict, type TrustResolution } from '../lib/importVerdict';
import { StandbyCodeEntry } from './StandbyCodeEntry';
import { readClipboardText } from '../lib/clipboard';
import { errorText } from '../lib/errorText';
import { pasteItems, usableClipboard, type PasteItem } from '../lib/pasteItems';
import PasteList, { openWithSystem, refusalText, type PastePhase } from './PasteList';
import { importLink } from '../lib/pasteImport';

/** Kept for callers of the old two-tab sheet. */
export type Tab = 'paste' | 'file';
export type AddStep = 'choose' | 'paste' | 'scan';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    /** Routes committed: the page reads its list again. */
    onImported?: () => void;
    /** "Connect" on the result: the page connects (and closes the sheet). */
    onConnect?: () => void;
    /** Kept for old callers: 'paste' opens on the paste box. */
    initialTab?: Tab;
    /** Where the sheet opens. Default: the three choices. */
    initialStep?: AddStep;
    /** A file handed to Daal by Android, already staged: checked at once. */
    openedPath?: string;
    /** Told whether the sheet is in the middle of something (anything but
     *  the three choices or a result), so a newly handed-over file waits
     *  instead of replacing it (recipient/openedFile.ts). */
    onProgress?: (inProgress: boolean) => void;
}

/** Best-effort client-side classifier for the paste box. The engine is
 *  the source of truth; this only decides what to hand it. */
export type PasteKind = 'empty' | 'sbp-b64' | 'sbpx-b64' | 'http' | 'uri' | 'unknown';

export function classifyPaste(s: string): PasteKind {
    const trimmed = s.trim();
    if (!trimmed) return 'empty';
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return 'http';
    // URI schemes the engine's uri.ParseAny handles.
    if (/^(vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wg|amneziawg|naive|brook|snowflake):\/\//i.test(trimmed))
        return 'uri';
    // A pasted bundle is located by the base64 spelling of its container
    // magic, after the joiners a messenger inserts are dropped — see
    // lib/pastedBundle.ts.
    const container = detectPastedContainer(trimmed);
    if (container === 'sbpx') return 'sbpx-b64';
    if (container === 'sbp') return 'sbp-b64';
    return 'unknown';
}

/** How long the paste box waits after the last change before it hands
 *  the text on: a paste arrives at once, typing does not. */
export const PASTE_SETTLE_MS = 400;

/** Only a Daal file (base64 .sbp/.sbpx) goes on by itself after a paste. */
export function autoAdvances(k: PasteKind | 'messenger'): boolean {
    return k === 'sbp-b64' || k === 'sbpx-b64';
}

/** Engine errors that mean the file must not be used (bad signature,
 *  withdrawn, not for this phone, damaged, expired): the refused screen,
 *  not a line under the box. */
const UNSAFE = /^(ErrInvalidSignature|ErrFingerprintMismatch|ErrRevokedPublisher|ErrRevokedRoute|ErrEnvelopeCorrupt|ErrZip|ErrJson|ErrMissingSignature|ErrMissingManifest|ErrMissingPublisherKey|ErrInvalidPublisherKey|ErrUnsafePath|ErrExpiredBundle|ErrExpiredRoute)\b|envelope corrupt or not addressed/;
export function unsafeError(raw: string): boolean {
    return UNSAFE.test(raw);
}

type Stage =
    | { at: 'choose' }
    | { at: 'paste' }
    | { at: 'scan' }
    | { at: 'code' }
    | { at: 'working' }
    | { at: 'unlock'; path: string }
    | { at: 'trust'; preview: PreviewedBundle; origin: Origin }
    | { at: 'result'; outcome: Exclude<ImportOutcome, { kind: 'trust' }>; name?: string; title?: string };

type Origin = 'paste' | 'file' | 'sealed_file' | 'scan';

function errText(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
}

export default function AddSheet({ t, onClose, onImported, onConnect, initialTab, initialStep, openedPath, onProgress }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const first: AddStep = initialStep ?? (initialTab === 'paste' ? 'paste' : 'choose');
    const [stage, setStage] = useState<Stage>(openedPath ? { at: 'working' } : { at: first });
    const [pasted, setPasted] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [passphrase, setPassphrase] = useState('');
    // Blocks the scanner holds: closing then asks first.
    const [scanBlocks, setScanBlocks] = useState(0);
    const [confirmClose, setConfirmClose] = useState(false);
    const lastHanded = useRef<string>('');
    const alive = useRef(true);
    useEffect(() => {
        alive.current = true;
        return () => {
            alive.current = false;
        };
    }, []);

    // What the paste holds, item by item (lib/pasteItems.ts). Two or
    // more items go to the list (PasteList); one keeps the single flow.
    const parsed = useMemo(() => pasteItems(pasted), [pasted]);
    const single: PasteItem | undefined = parsed.items.length === 1 ? parsed.items[0] : undefined;
    const kind = useMemo(() => (single ? singleKind(single) : parsed.items.length > 1 ? 'unknown' : classifyPaste(pasted)), [pasted, single, parsed]);
    const multi = parsed.items.length > 1;
    // A pasted link of a kind the engine cannot import yet: no tick, no
    // Add, the plain line at once.
    const cannot = single?.kind === 'route' && !single.importable;
    // While the list adds or checks (and after), the box is read-only:
    // one stray key would start a new list and stop the add part way.
    const [listPhase, setListPhase] = useState<PastePhase>('review');
    const boxLocked = multi && listPhase !== 'review';

    /** The publisher's name for "From {name}": the preview's, else the
     *  list's entry for that fingerprint. Never blocks the result. */
    const nameFor = async (fp: string | undefined, preview: PreviewedBundle | null): Promise<string | undefined> => {
        if (preview?.publisherName) return preview.publisherName;
        if (!fp) return undefined;
        try {
            const tree = await contract.listPublishers();
            return tree.find((p) => p.publisherId === fp)?.displayName || undefined;
        } catch {
            return undefined;
        }
    };

    /** One verdict, read the same way for every lane. */
    const settle = async (v: ImportVerdict | null, preview: PreviewedBundle | null, origin: Origin) => {
        const o = importOutcome(t, v, preview);
        if (o.kind === 'trust') {
            if (alive.current) setStage({ at: 'trust', preview: o.preview, origin });
            return;
        }
        if (o.kind === 'done') {
            recordImportOrigin(v?.Fingerprint || preview?.fingerprintHex, origin);
            onImported?.();
        }
        const name = o.kind === 'done' ? await nameFor(v?.Fingerprint || preview?.fingerprintHex, preview) : undefined;
        if (alive.current) setStage({ at: 'result', outcome: o, name });
    };

    /** A thrown error: the refused screen when the file must not be
     *  used, else one line on the step the person came from. */
    const fail = (e: unknown, back: Stage) => {
        const raw = errText(e);
        const text = friendlyError(t, raw);
        if (unsafeError(raw)) {
            setStage({ at: 'result', outcome: { kind: 'refused', text, changed: false } });
            return;
        }
        setError(text);
        setStage(back);
    };

    /** A staged path (picked, or handed over by Android): sniff, unlock
     *  if needed, preview and import, with no tap in between. */
    const readFile = async (path: string, back: Stage, opened = false) => {
        setError(null);
        // Android hands shared text that holds no Daal file over as a
        // `.txt` (ANDROID lane). The person used Share, not Paste: the
        // advice says what to share instead.
        if (/\.txt$/i.test(path)) {
            setError(t(opened ? 'add.detect.unknown_shared' : 'add.detect.unknown'));
            setStage(back);
            return;
        }
        setStage({ at: 'working' });
        let sealed = false;
        try {
            sealed = await Sbpx.sniff(path);
        } catch {
            sealed = false;
        }
        if (sealed) {
            let unlocked: boolean | undefined;
            try {
                unlocked = await DeviceCustody.isUnlocked();
            } catch {
                unlocked = undefined;
            }
            if (sealedCustody(unlocked) === 'locked') {
                setStage({ at: 'unlock', path });
                return;
            }
        }
        await importPath(path, sealed, back);
    };

    const importPath = async (path: string, sealed: boolean, back: Stage) => {
        setStage({ at: 'working' });
        try {
            // Device custody opens a sealed file with this phone's key;
            // the plaintext path is read once and used for both calls.
            const target = sealed ? await Sbpx.import(path) : path;
            let preview: PreviewedBundle | null = null;
            try {
                preview = await contract.previewBundle(target);
            } catch (e) {
                // A preview that refuses is the same refusal the import
                // would give: say it now.
                if (unsafeError(errText(e))) throw e;
                preview = null;
            }
            const v = parseVerdict(await contract.importSbp(target));
            await settle(v, preview, sealed ? 'sealed_file' : 'file');
        } catch (e) {
            fail(e, back);
        }
    };

    useEffect(() => {
        onProgress?.(!(stage.at === 'choose' || stage.at === 'result'));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [stage.at]);

    // A file Android handed over: straight to the check.
    useEffect(() => {
        if (openedPath) void readFile(openedPath, { at: 'choose' }, true);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [openedPath]);

    const chooseFile = async () => {
        setError(null);
        try {
            const picked = await openDialog({ multiple: false, directory: false });
            if (typeof picked !== 'string') return;
            // On Android the picker returns a content:// URI that std::fs
            // cannot open; stage_picked_file copies it into the app's
            // staging dir and returns a real path. A no-op on desktop.
            const staged = await PickedFile.stage(picked);
            await readFile(staged, { at: 'choose' });
        } catch (e) {
            setError(friendlyError(t, errText(e)));
            setStage({ at: 'choose' });
        }
    };

    const importPasted = async (text: string, k: PasteKind) => {
        setError(null);
        setStage({ at: 'working' });
        const back: Stage = { at: 'paste' };
        try {
            if (k === 'http') {
                // The engine rejects an empty publisher fingerprint: a
                // stable per-address id, and the host as the name.
                const url = single?.kind === 'web' ? single.text : text.trim();
                await contract.subscriptionAdd({
                    publisherFingerprint: await syntheticSubscriptionFingerprint(url),
                    url,
                    displayName: subscriptionDisplayName(url),
                });
                onImported?.();
                setStage({ at: 'result', outcome: { kind: 'done', verdict: null }, name: subscriptionDisplayName(url) });
                return;
            }
            if (k === 'sbp-b64' || k === 'sbpx-b64') {
                // The same signature, revocation and expiry checks the
                // file picker runs; a sealed one still needs this
                // phone's Daal address.
                const v = parseVerdict(await contract.importSbpBytes(text));
                await settle(v, null, 'paste');
                return;
            }
            // One link: the same reading as the list (lib/pasteImport.ts):
            // the first paste ever answers this phone's own trust prompt,
            // and a rejected verdict is a refusal, never "added".
            const r = await importLink(contract, t, single?.kind === 'route' ? single.text : text.trim());
            if (!r.ok) {
                setError(r.text);
                setStage(back);
                return;
            }
            onImported?.();
            setStage({ at: 'result', outcome: { kind: 'done', verdict: null }, title: t('add.multi.link_added') });
        } catch (e) {
            if (k === 'uri') {
                // A link the importer refused: its plain reason, on the
                // paste step (the link may simply be a kind this build
                // cannot dial).
                setError(refusalText(t, errorText(e)));
                setStage(back);
                return;
            }
            fail(e, back);
        }
    };

    // Detection on every change. Only a Daal file goes on by itself
    // (spec C3.2): it is signed, and a new publisher still gets the trust
    // question. A web address or a link waits for "Add" (`add-pasted`).
    useEffect(() => {
        if (stage.at !== 'paste') return;
        if (multi || kind === 'messenger' || !autoAdvances(kind)) return;
        const text = pasted;
        if (text === lastHanded.current) return;
        const id = setTimeout(() => {
            lastHanded.current = text;
            void importPasted(text, kind);
        }, PASTE_SETTLE_MS);
        return () => clearTimeout(id);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pasted, kind, stage.at]);

    /** The clipboard into the box. `onlyUsable`: when the box opens by
     *  itself, take only what Daal can add; the Paste button takes
     *  anything (the person asked for it). */
    const readClipboard = async (onlyUsable = false): Promise<boolean> => {
        try {
            const text = await readClipboardText();
            if (text && text.trim() && (!onlyUsable || usableClipboard(text))) {
                setError(null);
                setPasted(text);
                return true;
            }
        } catch {
            /* not allowed here: the box takes it */
        }
        return false;
    };
    const openPaste = async () => {
        setError(null);
        setStage({ at: 'paste' });
        await readClipboard(true);
    };

    const onTrustResolved = (r: TrustResolution, origin: Origin, preview: PreviewedBundle) => {
        const o = trustOutcome(t, r);
        if (!o) {
            // "No": nothing was added.
            onClose();
            return;
        }
        if (o.kind === 'done') {
            recordImportOrigin(r.verdict?.Fingerprint || preview.fingerprintHex, origin);
            onImported?.();
            void nameFor(r.verdict?.Fingerprint || preview.fingerprintHex, preview).then((name) => {
                if (alive.current) setStage({ at: 'result', outcome: o, name });
            });
            return;
        }
        if (o.kind !== 'trust') setStage({ at: 'result', outcome: o });
    };

    const onScanVerdict = (raw: string) => {
        setScanBlocks(0);
        void settle(parseVerdict(raw), null, 'scan');
    };

    const requestClose = () => {
        if (stage.at === 'scan' && scanBlocks > 0 && !confirmClose) {
            setConfirmClose(true);
            return;
        }
        onClose();
    };

    const connect = onConnect
        ? () => {
              onClose();
              onConnect();
          }
        : undefined;

    const title =
        stage.at === 'choose' || stage.at === 'paste' || stage.at === 'working' || stage.at === 'unlock'
            ? t('add.title')
            : stage.at === 'scan'
            ? t('scan.title')
            : stage.at === 'code'
            ? t('add.choose.code')
            : undefined;

    return (
        <Sheet title={title} onClose={requestClose} width={480}>
            {stage.at === 'choose' && (
                <div style={{ display: 'grid', gap: 4 }}>
                    <div role="list" style={{ display: 'grid', gap: 4, marginInline: -8 }}>
                        <ChoiceRow icon="file" label={t('add.choose.file')} onClick={() => void chooseFile()} dataButton="add-choose-file" />
                        <ChoiceRow icon="paste" label={t('add.choose.paste')} onClick={() => void openPaste()} dataButton="add-paste" />
                        <ChoiceRow icon="camera" label={t('add.choose.scan')} onClick={() => setStage({ at: 'scan' })} dataButton="add-scan" />
                        {/* Optional add-ons: the standby code a relay's
                            owner sends after switching addresses. */}
                        <ChoiceRow icon="key" label={t('add.choose.code')} onClick={() => setStage({ at: 'code' })} dataButton="add-code" />
                    </div>
                    {error && <ErrorLine text={error} />}
                    <PasteHelp t={t} />
                </div>
            )}

            {stage.at === 'paste' && (
                <div style={{ display: 'grid', gap: 10 }}>
                    <textarea
                        value={pasted}
                        readOnly={boxLocked}
                        onChange={(e) => {
                            if (boxLocked) return;
                            setError(null);
                            setPasted(e.target.value);
                        }}
                        placeholder={t('add.multi.placeholder')}
                        rows={density === 'phone' ? 4 : 5}
                        autoFocus
                        aria-label={t('add.choose.paste')}
                        data-button="paste-box"
                        // A pasted message keeps its own direction: Latin
                        // text is not laid out right to left in Farsi.
                        dir="auto"
                        style={inputStyle()}
                    />
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <Button
                            variant="secondary"
                            leading="paste"
                            onClick={() => void readClipboard()}
                            disabled={boxLocked}
                            dataButton="paste-again"
                        >
                            {t('ui.paste')}
                        </Button>
                        {!multi && <DetectBadge t={t} kind={kind} single={single} />}
                    </div>
                    {multi && (
                        <PasteList
                            // A new paste is a new list.
                            key={pasted}
                            t={t}
                            items={parsed.items}
                            truncated={parsed.truncated}
                            onImported={onImported}
                            onConnect={onConnect}
                            onClose={onClose}
                            onPhase={setListPhase}
                        />
                    )}
                    {single?.kind === 'messenger' && <MessengerRow t={t} item={single} />}
                    {!multi && single?.kind === 'route' && single.manualOnly && (
                        <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }} data-testid="paste-manual-only">
                            {t('add.multi.manual_only')}
                        </div>
                    )}
                    {!multi && cannot && (
                        <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }} data-testid="paste-cannot-add">
                            {t('add.multi.refused.no_match')}
                        </div>
                    )}
                    {!multi && !cannot && (kind === 'http' || kind === 'uri') && (
                        <div>
                            <Button onClick={() => void importPasted(pasted, kind)} dataButton="add-pasted">
                                {t('add.pasted.add')}
                            </Button>
                        </div>
                    )}
                    {!multi && kind === 'unknown' && <ErrorLine text={t('add.multi.unknown_single')} />}
                    {error && <ErrorLine text={error} />}
                    {!multi && <PasteHelp t={t} />}
                </div>
            )}

            {stage.at === 'code' && <StandbyCodeEntry t={t} onAccepted={() => onImported?.()} />}

            {stage.at === 'scan' && (
                <div>
                    {confirmClose && (
                        <div
                            role="alert"
                            style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: 8,
                                flexWrap: 'wrap',
                                marginBlockEnd: 12,
                                fontSize: 14,
                            }}
                        >
                            <span style={{ flex: 1, minWidth: 160 }}>{t('scan.discard.confirm')}</span>
                            <Button variant="secondary" size="sm" onClick={() => setConfirmClose(false)} dataButton="scan-keep">
                                {t('scan.keep')}
                            </Button>
                            <Button variant="danger" size="sm" onClick={onClose} dataButton="scan-discard-close">
                                {t('scan.discard')}
                            </Button>
                        </div>
                    )}
                    <RecipientImport
                        t={t}
                        onVerdict={onScanVerdict}
                        onProgress={setScanBlocks}
                        onUsePaste={() => void openPaste()}
                    />
                </div>
            )}

            {stage.at === 'working' && (
                <div
                    role="status"
                    style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, padding: '28px 0' }}
                >
                    <StateIcon state="busy" size={24} />
                    <span style={{ fontSize: 15, color: 'var(--muted)' }}>{t('add.working')}</span>
                </div>
            )}

            {stage.at === 'unlock' && (
                <form
                    onSubmit={(e) => {
                        e.preventDefault();
                        const path = stage.path;
                        void (async () => {
                            try {
                                await DeviceCustody.unlock(passphrase);
                                setPassphrase('');
                                await importPath(path, true, { at: 'choose' });
                            } catch (err) {
                                setError(friendlyError(t, errText(err)));
                            }
                        })();
                    }}
                    style={{ display: 'grid', gap: 10 }}
                >
                    <p style={{ margin: 0, fontSize: 14, color: 'var(--muted)' }}>{t('recipient.import.sbpx_pin_required')}</p>
                    <Input
                        type="password"
                        autoFocus
                        value={passphrase}
                        onChange={(e) => setPassphrase(e.target.value)}
                        placeholder={t('recipient.import.sbpx_pin_placeholder')}
                        aria-label={t('recipient.import.sbpx_pin_placeholder')}
                    />
                    {error && <ErrorLine text={error} />}
                    <Button type="submit" block disabled={!passphrase} dataButton="unlock-open">
                        {t('add.unlock.open')}
                    </Button>
                </form>
            )}

            {stage.at === 'trust' && (
                <TrustPrompt
                    t={t}
                    preview={stage.preview}
                    onResolve={(r) => onTrustResolved(r, stage.origin, stage.preview)}
                />
            )}

            {stage.at === 'result' && (
                <ImportResult
                    t={t}
                    outcome={stage.outcome}
                    name={stage.name}
                    title={stage.title}
                    onConnect={stage.outcome.kind === 'done' ? connect : undefined}
                    onClose={onClose}
                />
            )}
        </Sheet>
    );
}

function ChoiceRow({
    icon,
    label,
    onClick,
    dataButton,
}: {
    icon: IconName;
    label: string;
    onClick: () => void;
    dataButton: string;
}) {
    return (
        <button
            type="button"
            role="listitem"
            onClick={onClick}
            data-button={dataButton}
            className="daal-hover daal-inset-focus"
            style={{
                appearance: 'none',
                width: '100%',
                minHeight: 64,
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                padding: 8,
                background: 'transparent',
                border: 0,
                borderRadius: 'var(--r-tile)',
                color: 'var(--fg)',
                cursor: 'pointer',
                textAlign: 'start',
                fontFamily: 'var(--font-body)',
            }}
        >
            <span
                aria-hidden
                style={{
                    width: 44,
                    height: 44,
                    borderRadius: '50%',
                    flexShrink: 0,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'var(--surface-2)',
                    color: 'var(--gold-warm)',
                }}
            >
                <Icon name={icon} size={22} />
            </span>
            <span style={{ flex: 1, fontSize: 16, fontWeight: 600 }}>{label}</span>
        </button>
    );
}

function PasteHelp({ t }: { t: (k: string) => string }) {
    // The kinds of link Daal understands are named here and only here:
    // behind a question the person chooses to ask.
    return (
        <Disclosure summary={t('add.paste_help.title')} icon="help" dataButton="paste-help">
            <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6 }}>{t('add.multi.help.body')}</div>
        </Disclosure>
    );
}

/** One item of the paste, as the single flow reads it. A messenger
 *  proxy is not added: it is handed to its own app (MessengerRow). */
function singleKind(it: PasteItem): PasteKind | 'messenger' {
    switch (it.kind) {
        case 'route':
            return 'uri';
        case 'web':
            return 'http';
        case 'file':
            return it.container === 'sbpx' ? 'sbpx-b64' : 'sbp-b64';
        case 'messenger':
            return 'messenger';
        case 'unknown':
            return 'unknown';
    }
}

function MessengerRow({ t, item }: { t: (k: string) => string; item: Extract<PasteItem, { kind: 'messenger' }> }) {
    return (
        <div style={{ display: 'grid', gap: 10 }} data-item="messenger">
            <div style={{ fontSize: 14, color: 'var(--muted)', lineHeight: 1.5 }}>{t(`add.multi.${item.app}.note`)}</div>
            <div>
                <Button leading="external" onClick={() => void openWithSystem(item.open)} dataButton={`paste-open-${item.app}`}>
                    {t(`add.multi.${item.app}.open`)}
                </Button>
            </div>
        </div>
    );
}

function DetectBadge({ t, kind, single }: { t: (k: string) => string; kind: PasteKind | 'messenger'; single?: PasteItem }) {
    if (kind === 'empty' || kind === 'unknown') return null;
    if (single?.kind === 'route' && !single.importable) return null;
    if (kind === 'messenger' && single?.kind === 'messenger')
        return (
            <Badge tone="info" icon={false}>
                {t(`add.multi.kind.${single.app}`)}
            </Badge>
        );
    const key = kind === 'http' ? 'add.detect.subscription' : kind === 'uri' ? 'add.detect.uri' : 'add.detect.ok';
    return (
        <Badge tone="good" icon="check">
            {t(key)}
        </Badge>
    );
}

function ErrorLine({ text }: { text: string }) {
    return (
        <div role="alert" style={{ color: 'var(--red)', fontSize: 13, lineHeight: 1.5 }}>
            {text}
        </div>
    );
}

function inputStyle() {
    return {
        width: '100%',
        background: 'var(--bg)',
        border: '1px solid var(--line)',
        color: 'var(--fg)',
        padding: 12,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 14,
        outline: 'none',
        boxSizing: 'border-box' as const,
        resize: 'vertical' as const,
    };
}
