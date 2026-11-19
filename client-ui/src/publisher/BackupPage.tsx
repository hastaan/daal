// BackupPage — one backup file of everything needed to carry on from
// another phone (D1).
//
//   B0 loading → B1 what it holds (or Bx: why not now) → B2 the twelve
//   words, shown once → B3 three of them typed back → B1 → B4 making →
//   B5 done (a file handed to another app first asks whether it
//   arrived: only a yes makes it the last backup).
//
// Back goes one step at a time: B3 → B2, and B2 asks before leaving,
// because leaving there throws away words the person may have just
// written down (and, when replacing words, keeps the old ones in use).
//
// The words are in React state from B2 to the end of B3 and nowhere
// else: never logged, never stored by this screen, dropped as soon as
// they are confirmed and gone when the page closes. The shell keeps the
// confirmed words in device custody, so later backups reuse them and the
// person writes words down once.

import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Section, Sheet, Textarea } from '../design/primitives';
import type { BackupStatus, MadeBackup } from './wizardCommands';
import { useBack } from '../lib/useBack';
import { useSecureScreen } from './useSecureScreen';
import { WhatIsThis } from './Disclosure';
import {
    backupFailure,
    backupHasText,
    blockedKey,
    confirmAnswers,
    confirmPositions,
    dayLabel,
    fill,
    firstMismatch,
    unfinishedText,
} from './backup';
import type { BackupFailure } from './backup';
import { backupApi } from './backupHarness';
import type { BackupApi } from './backupHarness';

export type BackupState =
    | { k: 'loading' }
    | { k: 'ready'; status: BackupStatus }
    | { k: 'words'; status: BackupStatus; words: string[] }
    | {
          k: 'confirm';
          status: BackupStatus;
          words: string[];
          positions: number[];
          typed: Record<number, string>;
          /** 0-based position the person got wrong, or -2 when the shell
           *  said "mismatch" without a position, or null. */
          wrong: number | null;
      }
    | { k: 'making'; status: BackupStatus; destination: 'downloads' | 'share' }
    /** Handed to another app: did it arrive? */
    | { k: 'shared'; status: BackupStatus; made: MadeBackup }
    | { k: 'done'; made: MadeBackup };

/** Back may not interrupt a call that is running. */
export function backupBackRefused(s: BackupState, busy: boolean): boolean {
    return busy || s.k === 'making';
}

/** What Back does on this page: one step at a time, and never silently
 *  throws away words on screen. */
export type BackupBackAction = 'refuse' | 'to_words' | 'ask_leave' | 'leave';

export function backupBack(s: BackupState, busy: boolean): BackupBackAction {
    if (backupBackRefused(s, busy)) return 'refuse';
    if (s.k === 'confirm') return 'to_words';
    if (s.k === 'words') return 'ask_leave';
    return 'leave';
}

const BODY: React.CSSProperties = { fontSize: 13, lineHeight: 1.6, color: 'var(--fg)' };
const SUB: React.CSSProperties = { fontSize: 12, lineHeight: 1.55, color: 'var(--muted)' };
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)', fontSize: 11 };

/** The input attributes every word field uses: no keyboard help that
 *  could change or remember a word. */
export const WORD_INPUT = {
    autoCapitalize: 'off',
    autoCorrect: 'off',
    autoComplete: 'off',
    spellCheck: false,
    dir: 'ltr' as const,
};

export function FailureLine({ t, failure }: { t: (k: string) => string; failure: BackupFailure }) {
    return (
        <div role="alert" style={{ display: 'grid', gap: 4 }} data-testid="backup-failure">
            <div style={{ ...BODY, color: 'var(--red)' }}>{t(failure.key)}</div>
            {failure.detail && (
                <WhatIsThis label={t('pub.fb.details')}>
                    <div dir="ltr" style={MONO}>
                        {failure.detail}
                    </div>
                </WhatIsThis>
            )}
        </div>
    );
}

/** The twelve words, numbered, left to right whatever the language. */
export function WordGrid({ words }: { words: string[] }) {
    return (
        <ol
            dir="ltr"
            data-testid="backup-words"
            style={{
                margin: 0,
                padding: '12px 14px',
                listStyle: 'none',
                display: 'grid',
                gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                gap: '8px 16px',
                background: 'var(--surface-2)',
                borderRadius: 'var(--radius-md)',
                fontFamily: 'var(--font-mono)',
                fontSize: 15,
                textAlign: 'left',
            }}
        >
            {words.map((w, i) => (
                <li key={i}>
                    <span style={{ color: 'var(--dim)', marginInlineEnd: 6 }}>{i + 1}.</span>
                    {w}
                </li>
            ))}
        </ol>
    );
}

/** "Did the backup arrive in the app you chose?" */
export function SharedAsk({
    t,
    busy,
    waitingSince,
    onAnswer,
}: {
    t: (k: string) => string;
    busy: boolean;
    /** Asked again on B1 for a file handed over earlier. */
    waitingSince?: number;
    onAnswer: (arrived: boolean) => void;
}) {
    return (
        <div style={{ display: 'grid', gap: 8 }} data-testid="shared-ask">
            {waitingSince ? (
                <div style={{ ...BODY, color: 'var(--gold)' }}>
                    {fill(t('pub.backup.share.waiting'), { date: dayLabel(waitingSince) })}
                </div>
            ) : (
                <div style={BODY}>{t('pub.backup.done.share')}</div>
            )}
            <div style={BODY}>{t('pub.backup.share.ask')}</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <Button disabled={busy} onClick={() => onAnswer(true)} data-button="share-yes">
                    {t('pub.backup.share.yes')}
                </Button>
                <Button variant="secondary" disabled={busy} onClick={() => onAnswer(false)} data-button="share-no">
                    {t('pub.backup.share.no')}
                </Button>
            </div>
        </div>
    );
}

/** B1 / Bx: what a backup made now would hold, or why one cannot be. */
export function BackupReady({
    t,
    status,
    busy,
    savedWords,
    onCreateWords,
    onMake,
    onCheckWords,
    onNewWords,
    onSharedAnswer,
}: {
    t: (k: string) => string;
    status: BackupStatus;
    busy: boolean;
    /** The words were confirmed a moment ago. */
    savedWords: boolean;
    onCreateWords: () => void;
    onMake: (d: 'downloads' | 'share') => void;
    onCheckWords: () => void;
    onNewWords: () => void;
    onSharedAnswer?: (arrived: boolean) => void;
}) {
    const blocked = blockedKey(status.blocked);
    if (blocked) {
        return (
            <div style={{ display: 'grid', gap: 8 }} data-state="blocked" data-blocked={status.blocked}>
                <div style={BODY}>{t(blocked)}</div>
                {status.blocked_detail && (
                    <WhatIsThis label={t('pub.fb.details')}>
                        <div dir="ltr" style={MONO}>
                            {status.blocked_detail}
                        </div>
                    </WhatIsThis>
                )}
            </div>
        );
    }
    if (!status.has_publisher_data) {
        return (
            <div style={BODY} data-state="nothing">
                {t('pub.backup.err.nothing')}
            </div>
        );
    }
    const c = status.contents;
    return (
        <div style={{ display: 'grid', gap: 10 }} data-state="ready">
            <div style={BODY}>{backupHasText(t, c)}</div>
            {c.unfinished_setups > 0 && (
                <div style={SUB}>{unfinishedText(t, c.unfinished_setups)}</div>
            )}
            <div style={SUB}>{t('pub.backup.hasnot')}</div>
            <div
                style={{
                    ...BODY,
                    border: '1px solid var(--red)',
                    borderRadius: 'var(--radius-md)',
                    padding: '10px 12px',
                }}
            >
                {t('pub.backup.warning')}
            </div>
            <div style={SUB}>
                {status.last_backup_at_unix > 0
                    ? fill(t('pub.backup.last'), { date: dayLabel(status.last_backup_at_unix) })
                    : t('pub.backup.last.never')}
            </div>
            {status.words_changed ? (
                <div style={{ ...BODY, color: 'var(--gold)' }} data-testid="words-changed">
                    {t('pub.backup.words.changed')}
                </div>
            ) : (
                status.stale && <div style={{ ...SUB, color: 'var(--gold)' }}>{t('pub.backup.card.stale')}</div>
            )}
            {status.words_set && status.words_pending && !savedWords && (
                <div style={{ ...BODY, color: 'var(--gold)' }} data-testid="words-pending">
                    {t('pub.backup.words.pending')}
                </div>
            )}
            {(status.share_unconfirmed_at_unix ?? 0) > 0 && onSharedAnswer && (
                <SharedAsk
                    t={t}
                    busy={busy}
                    waitingSince={status.share_unconfirmed_at_unix}
                    onAnswer={onSharedAnswer}
                />
            )}
            {savedWords && <div style={{ ...BODY, color: 'var(--green)' }}>{t('pub.backup.words.saved')}</div>}
            {!status.words_set ? (
                <div>
                    <Button disabled={busy} onClick={onCreateWords} data-button="create-words">
                        {t('pub.backup.words.create')}
                    </Button>
                </div>
            ) : (
                <>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button disabled={busy} onClick={() => onMake('downloads')} data-button="save-downloads">
                            {t('pub.backup.save.downloads')}
                        </Button>
                        <Button
                            variant="secondary"
                            disabled={busy}
                            onClick={() => onMake('share')}
                            data-button="save-share"
                        >
                            {t('pub.backup.save.share')}
                        </Button>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button variant="ghost" size="sm" disabled={busy} onClick={onCheckWords} data-button="check-words">
                            {t('pub.backup.words.check')}
                        </Button>
                        <Button variant="ghost" size="sm" disabled={busy} onClick={onNewWords} data-button="new-words">
                            {t('pub.backup.words.renew')}
                        </Button>
                    </div>
                </>
            )}
        </div>
    );
}

/** B2: the words, once. */
export function BackupWords({
    t,
    words,
    onWrote,
}: {
    t: (k: string) => string;
    words: string[];
    onWrote: () => void;
}) {
    // PB-20: the words are on the screen.
    useSecureScreen(true);
    return (
        <div style={{ display: 'grid', gap: 10 }} data-state="words">
            <div style={BODY}>{t('pub.backup.words.body')}</div>
            <WordGrid words={words} />
            <div>
                <Button onClick={onWrote} data-button="wrote">
                    {t('pub.backup.words.wrote')}
                </Button>
            </div>
        </div>
    );
}

/** B3: three of the words typed back. */
export function BackupConfirm({
    t,
    positions,
    typed,
    wrong,
    busy,
    onType,
    onCheck,
    onShowAgain,
}: {
    t: (k: string) => string;
    positions: number[];
    typed: Record<number, string>;
    wrong: number | null;
    busy: boolean;
    onType: (i: number, v: string) => void;
    onCheck: () => void;
    onShowAgain: () => void;
}) {
    // PB-20: three of the words are typed here.
    useSecureScreen(true);
    return (
        <div style={{ display: 'grid', gap: 10 }} data-state="confirm">
            <div style={BODY}>{t('pub.backup.confirm.body')}</div>
            {positions.map((i) => (
                <label key={i} style={{ display: 'grid', gap: 4 }}>
                    <span style={SUB}>{fill(t('pub.backup.confirm.ask'), { i: i + 1 })}</span>
                    <input
                        {...WORD_INPUT}
                        data-word-index={i}
                        value={typed[i] ?? ''}
                        onChange={(e) => onType(i, e.target.value)}
                        style={{
                            width: '100%',
                            background: 'var(--bg)',
                            border: `1px solid ${wrong === i ? 'var(--red)' : 'var(--line)'}`,
                            color: 'var(--fg)',
                            padding: '10px 12px',
                            borderRadius: 'var(--radius-md)',
                            fontFamily: 'var(--font-mono)',
                            fontSize: 15,
                        }}
                    />
                </label>
            ))}
            {wrong !== null && (
                <div role="alert" style={{ ...BODY, color: 'var(--red)' }} data-testid="words-mismatch">
                    {wrong >= 0
                        ? fill(t('pub.backup.words.mismatch'), { i: wrong + 1 })
                        : t('pub.backup.words.mismatch.any')}
                </div>
            )}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <Button disabled={busy} onClick={onCheck} data-button="confirm">
                    {t('pub.backup.confirm.go')}
                </Button>
                {wrong !== null && (
                    <Button variant="secondary" disabled={busy} onClick={onShowAgain} data-button="show-again">
                        {t('pub.backup.words.show_again')}
                    </Button>
                )}
            </div>
        </div>
    );
}

/** B5. */
export function BackupDone({ t, made, onDone }: { t: (k: string) => string; made: MadeBackup; onDone: () => void }) {
    return (
        <div style={{ display: 'grid', gap: 10 }} data-state="done">
            <div style={BODY}>
                {made.destination === 'downloads'
                    ? fill(t('pub.backup.done.downloads'), { file: made.file_name })
                    : t('pub.backup.done.share.ok')}
            </div>
            <div>
                <Button onClick={onDone} data-button="done">
                    {t('pub.backup.done')}
                </Button>
            </div>
        </div>
    );
}

/** "Check my words": the person types them, the shell compares. */
function CheckWordsSheet({
    t,
    api,
    onClose,
}: {
    t: (k: string) => string;
    api: BackupApi;
    onClose: () => void;
}) {
    const [text, setText] = useState('');
    const [busy, setBusy] = useState(false);
    const [result, setResult] = useState<boolean | null>(null);
    const [failure, setFailure] = useState<BackupFailure | null>(null);
    // PB-20: all twelve words are typed here.
    useSecureScreen(true);
    return (
        <Sheet
            title={t('pub.backup.words.check')}
            width={520}
            onClose={() => {
                if (!busy) onClose();
            }}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    <Button variant="ghost" disabled={busy} onClick={onClose}>
                        {t('common.cancel')}
                    </Button>
                    <Button
                        disabled={busy || text.trim() === ''}
                        onClick={async () => {
                            setBusy(true);
                            setFailure(null);
                            try {
                                setResult(await api.wordsCheck(text));
                            } catch (e) {
                                setFailure(backupFailure(e));
                            } finally {
                                setBusy(false);
                            }
                        }}
                    >
                        {t('pub.backup.words.check.go')}
                    </Button>
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 8 }}>
                <div style={SUB}>{t('pub.backup.words.check.body')}</div>
                <Textarea {...WORD_INPUT} rows={4} value={text} onChange={(e) => setText(e.target.value)} />
                {result === true && <div style={{ ...BODY, color: 'var(--green)' }}>{t('pub.backup.words.check.ok')}</div>}
                {result === false && <div style={{ ...BODY, color: 'var(--red)' }}>{t('pub.backup.words.check.bad')}</div>}
                {failure && <FailureLine t={t} failure={failure} />}
            </div>
        </Sheet>
    );
}

export default function BackupPage({
    t,
    onBack,
    api = backupApi(),
    rand,
}: {
    t: (k: string) => string;
    onBack: () => void;
    api?: BackupApi;
    rand?: () => number;
}) {
    const [state, setState] = useState<BackupState>({ k: 'loading' });
    const [busy, setBusy] = useState(false);
    const [failure, setFailure] = useState<BackupFailure | null>(null);
    const [checking, setChecking] = useState(false);
    const [renewAsk, setRenewAsk] = useState(false);
    const [leaveAsk, setLeaveAsk] = useState(false);
    const [savedWords, setSavedWords] = useState(false);
    const [note, setNote] = useState<string | null>(null);

    const load = useCallback(async () => {
        try {
            const status = await api.status();
            setState({ k: 'ready', status });
            setFailure(null);
        } catch (e) {
            setFailure(backupFailure(e));
        }
    }, [api]);

    useEffect(() => {
        void load();
    }, [load]);

    // Back: one step at a time (see the header). The same for the
    // system Back and the on-screen one.
    const goBack = () => {
        switch (backupBack(state, busy)) {
            case 'refuse':
                return;
            case 'to_words':
                setState((s) => (s.k === 'confirm' ? { k: 'words', status: s.status, words: s.words } : s));
                return;
            case 'ask_leave':
                setLeaveAsk(true);
                return;
            default:
                onBack();
        }
    };
    useBack(true, goBack, 'page');

    const status = state.k === 'loading' || state.k === 'done' ? null : state.status;

    /** The answer to "did it arrive?" (on B5, or on B1 for an earlier one). */
    const answerShared = async (arrived: boolean, made?: MadeBackup) => {
        setBusy(true);
        setFailure(null);
        setNote(null);
        try {
            await api.confirmShared(arrived);
            const fresh = await api.status();
            if (arrived && made) setState({ k: 'done', made: { ...made, confirmed: true } });
            else setState({ k: 'ready', status: fresh });
            if (!arrived) setNote(t('pub.backup.share.not'));
        } catch (e) {
            setFailure(backupFailure(e));
        } finally {
            setBusy(false);
        }
    };

    const newWords = async () => {
        if (!status) return;
        setBusy(true);
        setFailure(null);
        setSavedWords(false);
        try {
            const { words } = await api.wordsNew();
            setState({ k: 'words', status, words });
        } catch (e) {
            setFailure(backupFailure(e));
        } finally {
            setBusy(false);
        }
    };

    const toConfirm = () => {
        if (state.k !== 'words') return;
        setState({
            k: 'confirm',
            status: state.status,
            words: state.words,
            positions: confirmPositions(rand),
            typed: {},
            wrong: null,
        });
    };

    const check = async () => {
        if (state.k !== 'confirm') return;
        const s = state;
        // Said here, from the words still on screen, before anything is
        // sent: the shell checks again and is the one that decides.
        const local = firstMismatch(s.words, s.positions, s.typed);
        if (local >= 0) {
            setState({ ...s, wrong: local });
            return;
        }
        setBusy(true);
        setFailure(null);
        try {
            await api.wordsConfirm(confirmAnswers(s.positions, s.typed));
            const fresh = await api.status().catch(() => ({ ...s.status, words_set: true }));
            // The words leave state here.
            setState({ k: 'ready', status: fresh });
            setSavedWords(true);
        } catch (e) {
            const f = backupFailure(e);
            if (f.key === 'pub.backup.words.mismatch.any') setState({ ...s, wrong: -2 });
            else setFailure(f);
        } finally {
            setBusy(false);
        }
    };

    const make = async (destination: 'downloads' | 'share') => {
        if (state.k !== 'ready') return;
        const before = state.status;
        setBusy(true);
        setFailure(null);
        setState({ k: 'making', status: before, destination });
        try {
            const made = await api.make(destination, undefined, t('pub.backup.share.title'));
            // A share sheet that opened proves nothing: ask.
            if (destination === 'share' && made.confirmed !== true) setState({ k: 'shared', status: before, made });
            else setState({ k: 'done', made });
        } catch (e) {
            setState({ k: 'ready', status: before });
            setFailure(backupFailure(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div style={{ padding: '12px 16px 24px 16px', display: 'grid', gap: 12 }}>
            <div>
                <Button
                    variant="ghost"
                    disabled={backupBackRefused(state, busy)}
                    onClick={goBack}
                    data-button="page-back"
                >
                    {t('pub.relay.back')}
                </Button>
            </div>
            <Section eyebrow={t('pub.backup.eyebrow')} title={t('pub.backup.title')}>
                <Card>
                    <div style={{ display: 'grid', gap: 12 }}>
                        {state.k === 'loading' && !failure && <div style={SUB}>{t('common.loading')}</div>}
                        {state.k === 'ready' && (
                            <BackupReady
                                t={t}
                                status={state.status}
                                busy={busy}
                                savedWords={savedWords}
                                onCreateWords={() => void newWords()}
                                onMake={(d) => void make(d)}
                                onCheckWords={() => setChecking(true)}
                                onNewWords={() => setRenewAsk(true)}
                                onSharedAnswer={(a) => void answerShared(a)}
                            />
                        )}
                        {state.k === 'words' && <BackupWords t={t} words={state.words} onWrote={toConfirm} />}
                        {state.k === 'confirm' && (
                            <BackupConfirm
                                t={t}
                                positions={state.positions}
                                typed={state.typed}
                                wrong={state.wrong}
                                busy={busy}
                                onType={(i, v) =>
                                    setState((s) =>
                                        s.k === 'confirm' ? { ...s, typed: { ...s.typed, [i]: v }, wrong: null } : s,
                                    )
                                }
                                onCheck={() => void check()}
                                onShowAgain={() =>
                                    // From state: no new words, no call.
                                    setState((s) => (s.k === 'confirm' ? { k: 'words', status: s.status, words: s.words } : s))
                                }
                            />
                        )}
                        {state.k === 'making' && (
                            <div style={BODY} data-state="making">
                                {t('pub.backup.making')}
                            </div>
                        )}
                        {state.k === 'shared' && (
                            <SharedAsk t={t} busy={busy} onAnswer={(a) => void answerShared(a, state.made)} />
                        )}
                        {state.k === 'done' && <BackupDone t={t} made={state.made} onDone={onBack} />}
                        {note && (
                            <div role="status" style={{ ...BODY, color: 'var(--gold)' }} data-testid="backup-note">
                                {note}
                            </div>
                        )}
                        {failure && <FailureLine t={t} failure={failure} />}
                    </div>
                </Card>
            </Section>

            {checking && <CheckWordsSheet t={t} api={api} onClose={() => setChecking(false)} />}
            {leaveAsk && (
                <Sheet
                    title={t('pub.backup.leave.title')}
                    width={480}
                    onClose={() => setLeaveAsk(false)}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button variant="ghost" onClick={() => setLeaveAsk(false)} data-button="leave-stay">
                                {t('pub.backup.leave.stay')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => {
                                    setLeaveAsk(false);
                                    onBack();
                                }}
                                data-button="leave-go"
                            >
                                {t('pub.backup.leave.go')}
                            </Button>
                        </span>
                    }
                >
                    <div style={BODY} data-testid="leave-body">
                        {t(status?.words_set ? 'pub.backup.leave.body' : 'pub.backup.leave.body.first')}
                    </div>
                </Sheet>
            )}
            {renewAsk && (
                <Sheet
                    title={t('pub.backup.words.renew')}
                    width={480}
                    onClose={() => setRenewAsk(false)}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button variant="ghost" onClick={() => setRenewAsk(false)}>
                                {t('common.cancel')}
                            </Button>
                            <Button
                                onClick={() => {
                                    setRenewAsk(false);
                                    void newWords();
                                }}
                            >
                                {t('pub.backup.words.renew.go')}
                            </Button>
                        </span>
                    }
                >
                    <div style={BODY}>{t('pub.backup.words.renew.confirm')}</div>
                </Sheet>
            )}
        </div>
    );
}
