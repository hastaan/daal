// The file's backup update routes on the Files tab (round 3a): the one
// muted line in the file's sheet that names them, and the small sheet
// "Check the backup update routes" opens — a calm waiting line while
// the engine tries them (up to two minutes), then one line per route
// family in plain words and one sentence for how it went
// (lib/backupCheck.ts reads the engine's words).
import type { BackupRoute } from '../../contract/D2Contract';
import { Button, Sheet } from '../../design/primitives';
import { formatTime } from '../../lib/format';
import type { Locale } from '../../lib/i18n';
import { backupNames, drillLines, drillMessage, type DrillAnswer, type DrillWord } from '../../lib/backupCheck';

type T = (k: string) => string;

/** "Backup update routes: GitHub, DNS". Nothing for a file with none. */
export function BackupLine({ t, list }: { t: T; list: readonly BackupRoute[] }) {
    if (list.length === 0) return null;
    return (
        <div data-backup-line style={{ fontSize: 12, color: 'var(--muted)' }}>
            {t('files.backup.line').replace('{list}', backupNames(t, list))}
        </div>
    );
}

export interface BackupCheckState {
    /** The file (its display name in the tree). */
    name: string;
    running: boolean;
    answer?: DrillAnswer;
    /** When the answer came (ms): the rate limit's "again at" counts from it. */
    at?: number;
    /** The sheet is showing (the check goes on when it is closed). */
    open: boolean;
    /** A kept answer shown again (the engine refuses a new check for 10
     *  minutes): when a new check may run (ms). The lines are the kept
     *  ones; this sentence goes under them. */
    againAt?: number;
}

const WORD_COLOR: Record<DrillWord, string> = {
    works: 'var(--green)',
    nothing_new: 'var(--fg)',
    no_answer: 'var(--red)',
    not_here: 'var(--muted)',
};

const TONE_COLOR = { good: 'var(--fg)', neutral: 'var(--fg)', bad: 'var(--red)' } as const;

/** The sentence for an answer, with `{time}` filled in. */
export function drillSentence(t: T, locale: Locale, a: DrillAnswer, at: number): string {
    const m = drillMessage(a);
    return t(m.key).replace('{time}', formatTime(locale, new Date(at + a.retryAfterS * 1000)));
}

export function BackupCheckSheet({
    t,
    locale,
    state,
    onClose,
}: {
    t: T;
    locale: Locale;
    state: BackupCheckState;
    onClose: () => void;
}) {
    const a = state.answer;
    const lines = a ? drillLines(a) : [];
    return (
        <Sheet
            title={t('files.check.title')}
            onClose={onClose}
            width={440}
            footer={
                <Button block variant="secondary" onClick={onClose} dataButton="backup-check-close">
                    {t('common.close')}
                </Button>
            }
        >
            <div data-check-file style={{ fontSize: 13, color: 'var(--muted)', marginBlockEnd: 10 }}>
                <bdi>{state.name}</bdi>
            </div>
            {state.running || !a ? (
                <div role="status" aria-live="polite" style={{ display: 'grid', gap: 8 }}>
                    <p style={{ margin: 0, fontSize: 15, color: 'var(--fg)' }}>{t('files.check.running')}</p>
                    <p style={{ margin: 0, fontSize: 13, color: 'var(--muted)' }}>{t('files.check.running_close')}</p>
                </div>
            ) : (
                <div style={{ display: 'grid', gap: 14 }}>
                    <p
                        role="status"
                        data-check-outcome={a.outcome}
                        style={{ margin: 0, fontSize: 15, color: TONE_COLOR[drillMessage(a).tone] }}
                    >
                        {drillSentence(t, locale, a, state.at ?? Date.now())}
                    </p>
                    {lines.length > 0 && (
                        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                            {lines.map((l, i) => (
                                <li
                                    key={l.family}
                                    data-check-family={l.family}
                                    data-check-word={l.word}
                                    style={{
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'baseline',
                                        gap: 12,
                                        padding: '10px 0',
                                        borderBlockEnd: i === lines.length - 1 ? undefined : '1px solid var(--line-soft)',
                                        fontSize: 14,
                                    }}
                                >
                                    <span style={{ color: 'var(--fg)' }}>{t(`files.check.family.${l.family}`)}</span>
                                    <span style={{ color: WORD_COLOR[l.word], textAlign: 'end' }}>
                                        {t(`files.check.word.${l.word}`)}
                                    </span>
                                </li>
                            ))}
                        </ul>
                    )}
                    {state.againAt !== undefined && (
                        <p data-check-again style={{ margin: 0, fontSize: 13, color: 'var(--muted)' }}>
                            {t('files.check.wait_until').replace('{time}', formatTime(locale, new Date(state.againAt)))}
                        </p>
                    )}
                </div>
            )}
        </Sheet>
    );
}
