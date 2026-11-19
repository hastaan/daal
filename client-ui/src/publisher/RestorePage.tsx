// RestorePage — carry on from a backup made on another phone (D2).
//
//   R1 choose the file → R2 type the twelve words → R3 what it holds
//   (and, if this phone already has relays, exactly what is replaced) →
//   R4 restoring → R5 done, and the truth about the old phone.
//
// Every refusal changes nothing on the phone and gets its own sentence;
// the raw text is under Details. A restore over existing relays needs
// the button that names them, and the shell refuses it again if
// anything changed since the preview (the digest).

import { useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { Button, Card, Section, Textarea } from '../design/primitives';
import type { BackupPreview, RestoreNotice } from './wizardCommands';
import { PickedFile } from '../recipient/recipientCommands';
import { useBack } from '../lib/useBack';
import { backupFailure, fill, previewText, relayNames, wordCount, WORD_COUNT } from './backup';
import type { BackupFailure } from './backup';
import { backupApi } from './backupHarness';
import type { BackupApi } from './backupHarness';
import { FailureLine, WORD_INPUT } from './BackupPage';
import { NewHostingKeySheet, RestoreNoticeCard } from './RestoreNotice';
import { isTauriRuntime } from '../backends';
import { isHarnessActive } from '../harness/scenarios';

/** `unfinished`: the restore committed and its last steps failed. Only
 *  "Try again" is offered there: the preview's Restore button would
 *  now run against the relays it just restored. */
export type RestoreStep = 'pick' | 'words' | 'preview' | 'working' | 'unfinished' | 'done';

export interface RestoreFlow {
    step: RestoreStep;
    path: string | null;
    preview: BackupPreview | null;
    notice: RestoreNotice | null;
}

/** Which step a failure sends the flow back to. Nothing was written. */
export function stepAfterFailure(f: BackupFailure, current: RestoreStep): RestoreStep {
    switch (f.after) {
        case 'pick_again':
            return 'pick';
        case 'words_again':
            return 'words';
        case 'look_again':
            return 'preview';
        case 'finish':
            return 'unfinished';
        default:
            return current === 'working' ? 'preview' : current;
    }
}

/** Back may not interrupt opening or restoring. */
export function restoreBackRefused(step: RestoreStep, busy: boolean): boolean {
    return busy || step === 'working';
}

/** Where Back goes. Once the relays are on this phone (done), or the
 *  restore committed and must still finish (unfinished), Back goes to
 *  the relay list like "Go to my relays" (the list finishes a pending
 *  restore), never back to an empty first-run wizard. */
export function restoreBack(step: RestoreStep, busy: boolean): 'refuse' | 'to_relays' | 'back' {
    if (restoreBackRefused(step, busy)) return 'refuse';
    if (step === 'done' || step === 'unfinished') return 'to_relays';
    return 'back';
}

const BODY: React.CSSProperties = { fontSize: 13, lineHeight: 1.6, color: 'var(--fg)' };
const SUB: React.CSSProperties = { fontSize: 12, lineHeight: 1.55, color: 'var(--muted)' };

export function RestorePreview({
    t,
    preview,
    busy,
    onRestore,
    onCancel,
}: {
    t: (k: string) => string;
    preview: BackupPreview;
    busy: boolean;
    onRestore: (digest: string | null) => void;
    onCancel: () => void;
}) {
    const rep = preview.replace;
    return (
        <div style={{ display: 'grid', gap: 10 }} data-state="preview">
            <div style={BODY}>{previewText(t, preview.made_at_unix, preview.contents)}</div>
            {rep && (
                <div
                    data-testid="restore-replace"
                    style={{
                        ...BODY,
                        border: '1px solid var(--red)',
                        borderRadius: 'var(--radius-md)',
                        padding: '10px 12px',
                        display: 'grid',
                        gap: 6,
                    }}
                >
                    <div style={{ color: 'var(--red)' }}>
                        {fill(t('pub.restore.replace'), { names: relayNames(rep.this_phone) })}
                    </div>
                    {rep.only_on_this_phone.length > 0 && (
                        <div>{fill(t('pub.restore.replace.orphans'), { names: relayNames(rep.only_on_this_phone) })}</div>
                    )}
                </div>
            )}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {rep ? (
                    <Button variant="danger" disabled={busy} onClick={() => onRestore(rep.digest)} data-button="replace">
                        {fill(t('pub.restore.replace.go'), { names: relayNames(rep.this_phone) })}
                    </Button>
                ) : (
                    <Button disabled={busy} onClick={() => onRestore(null)} data-button="restore">
                        {t('pub.restore.go')}
                    </Button>
                )}
                <Button variant="ghost" disabled={busy} onClick={onCancel} data-button="cancel">
                    {t('common.cancel')}
                </Button>
            </div>
        </div>
    );
}

async function pickFile(): Promise<string | null> {
    if (!isTauriRuntime() || isHarnessActive()) return 'harness.daalbackup';
    // No extension filter: Android's picker cannot filter by an
    // extension it does not know.
    const picked = await openDialog({ multiple: false, directory: false });
    if (typeof picked !== 'string') return null;
    // A content:// URI on Android becomes a real path in staging.
    return PickedFile.stage(picked);
}

export default function RestorePage({
    t,
    onBack,
    onDone,
    api = backupApi(),
    pick = pickFile,
}: {
    t: (k: string) => string;
    /** Where the person came from (the list, or the first wizard step). */
    onBack: () => void;
    /** Restored: show the relays. */
    onDone: () => void;
    api?: BackupApi;
    pick?: () => Promise<string | null>;
}) {
    const [flow, setFlow] = useState<RestoreFlow>({ step: 'pick', path: null, preview: null, notice: null });
    // The typed words: React state for this flow only, cleared when the
    // restore finishes and gone when the page closes.
    const [words, setWords] = useState('');
    const [busy, setBusy] = useState(false);
    const [failure, setFailure] = useState<BackupFailure | null>(null);
    const [keySheet, setKeySheet] = useState(false);

    const goBack = () => {
        const a = restoreBack(flow.step, busy);
        if (a === 'to_relays') onDone();
        else if (a === 'back') onBack();
    };
    useBack(true, goBack, 'page');

    const fail = (e: unknown, at: RestoreStep) => {
        const f = backupFailure(e, 'restore');
        setFailure(f);
        setFlow((s) => ({ ...s, step: stepAfterFailure(f, at) }));
        return f;
    };

    const choose = async () => {
        setBusy(true);
        setFailure(null);
        try {
            const path = await pick();
            if (!path) return;
            await api.inspect(path);
            setFlow({ step: 'words', path, preview: null, notice: null });
        } catch (e) {
            fail(e, 'pick');
        } finally {
            setBusy(false);
        }
    };

    const openIt = async () => {
        if (!flow.path) return;
        setBusy(true);
        setFailure(null);
        try {
            const preview = await api.open(flow.path, words);
            setFlow((s) => ({ ...s, step: 'preview', preview }));
        } catch (e) {
            fail(e, 'words');
        } finally {
            setBusy(false);
        }
    };

    /** Something changed on this phone since the preview: look again. */
    const lookAgain = async () => {
        if (!flow.path) return;
        try {
            await api.inspect(flow.path);
            const preview = await api.open(flow.path, words);
            setFlow((s) => ({ ...s, step: 'preview', preview }));
        } catch (e) {
            fail(e, 'preview');
        }
    };

    const restore = async (digest: string | null) => {
        if (!flow.path) return;
        setBusy(true);
        setFailure(null);
        setFlow((s) => ({ ...s, step: 'working' }));
        try {
            const r = await api.restore(flow.path, words, digest);
            setWords('');
            setFlow((s) => ({ ...s, step: 'done', notice: r.notice }));
        } catch (e) {
            const f = fail(e, 'working');
            if (f.after === 'look_again') await lookAgain();
        } finally {
            setBusy(false);
        }
    };

    const finish = async () => {
        setBusy(true);
        setFailure(null);
        try {
            await api.finishRestore();
            const s = await api.status();
            setWords('');
            setFlow((f) => ({ ...f, step: 'done', notice: s.restore_notice }));
        } catch (e) {
            const f = backupFailure(e, 'restore');
            setFailure(f.after === 'none' ? { ...f, after: 'finish' } : f);
        } finally {
            setBusy(false);
        }
    };

    const n = wordCount(words);

    return (
        <div style={{ padding: '12px 16px 24px 16px', display: 'grid', gap: 12 }}>
            <div>
                <Button
                    variant="ghost"
                    disabled={restoreBackRefused(flow.step, busy)}
                    onClick={goBack}
                    data-button="page-back"
                >
                    {t('pub.relay.back')}
                </Button>
            </div>
            <Section title={t('pub.restore.title')}>
                <Card>
                    <div style={{ display: 'grid', gap: 12 }}>
                        {flow.step === 'pick' && (
                            <div style={{ display: 'grid', gap: 10 }} data-state="pick">
                                <div style={BODY}>{t('pub.restore.pick')}</div>
                                <div>
                                    <Button disabled={busy} onClick={() => void choose()} data-button="choose">
                                        {t('pub.restore.pick.go')}
                                    </Button>
                                </div>
                            </div>
                        )}
                        {flow.step === 'words' && (
                            <div style={{ display: 'grid', gap: 10 }} data-state="words">
                                <div style={BODY}>{t('pub.restore.words')}</div>
                                <Textarea
                                    {...WORD_INPUT}
                                    rows={4}
                                    value={words}
                                    onChange={(e) => setWords(e.target.value)}
                                />
                                <div style={SUB}>{fill(t('pub.restore.words.count'), { n, total: WORD_COUNT })}</div>
                                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                    <Button disabled={busy || n === 0} onClick={() => void openIt()} data-button="open">
                                        {busy ? t('pub.restore.opening') : t('pub.restore.open')}
                                    </Button>
                                    <Button
                                        variant="ghost"
                                        disabled={busy}
                                        onClick={() => {
                                            setFailure(null);
                                            setFlow({ step: 'pick', path: null, preview: null, notice: null });
                                        }}
                                    >
                                        {t('pub.restore.pick.other')}
                                    </Button>
                                </div>
                            </div>
                        )}
                        {flow.step === 'preview' && flow.preview && (
                            <RestorePreview
                                t={t}
                                preview={flow.preview}
                                busy={busy}
                                onRestore={(d) => void restore(d)}
                                onCancel={onBack}
                            />
                        )}
                        {flow.step === 'working' && (
                            <div style={BODY} data-state="working">
                                {t('pub.restore.working')}
                            </div>
                        )}
                        {flow.step === 'done' && (
                            <div style={{ display: 'grid', gap: 10 }} data-state="done">
                                <div style={BODY}>{t('pub.restore.done')}</div>
                                <div>
                                    <Button onClick={onDone} data-button="to-relays">
                                        {t('pub.restore.to_relays')}
                                    </Button>
                                </div>
                            </div>
                        )}
                        {failure && <FailureLine t={t} failure={failure} />}
                        {flow.step === 'unfinished' && failure?.after === 'finish' && (
                            <div data-state="unfinished">
                                <Button disabled={busy} onClick={() => void finish()} data-button="finish">
                                    {t('pub.restore.try_again')}
                                </Button>
                            </div>
                        )}
                    </div>
                </Card>
            </Section>
            {flow.step === 'done' && flow.notice && (
                <RestoreNoticeCard
                    t={t}
                    notice={flow.notice}
                    busy={busy}
                    onEnterKey={() => setKeySheet(true)}
                    onDismiss={async () => {
                        try {
                            await api.dismissNotice();
                        } catch {
                            /* the list shows it again; nothing is lost */
                        }
                        setFlow((f) => ({ ...f, notice: null }));
                    }}
                />
            )}
            {keySheet && flow.notice && (
                <NewHostingKeySheet t={t} notice={flow.notice} onClose={() => setKeySheet(false)} />
            )}
        </div>
    );
}
