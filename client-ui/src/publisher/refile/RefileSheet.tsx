// RefileSheet — "New files for everyone" (refile.ts says when).
//
// One decision, then a list:
//   ask      one sentence of why, the plain cost (their current files
//            stop working), how many people, "Make new files"
//   working  one wait line while the relay re-keys them all at once
//   list     one row per person: their name, Share and Show QR, and a
//            tick once their file has been handed over. A person whose
//            file could not be made gets the reason and "Try again",
//            which makes just theirs (the per-person repack path). The
//            same list works for one person and for ten.
//
// The list outlives the sheet: the page keeps it per relay (`kept` /
// `onKeep`), so closing half way and opening again returns to the list
// with its ticks; making the files again sits behind the same question
// («Make them again»). Done with people still unsent says so once.
//
// Share and Show QR are the ones the per-person send sheet uses
// (Wizard.shareInviteSbpx, QrSendSheet). Nothing here holds or shows a
// credential: the paths are files on this phone.
import { useState } from 'react';
import { Avatar, Button, Icon, Sheet, StateIcon } from '../../design/primitives';
import { failureBlock } from '../failureText';
import { QrSendSheet } from '../QrSendSheet';
import { num, useLocale } from '../ui';
import { Wizard, recipientArtifact, type RefileReport } from '../wizardCommands';
import { allHandled, refileRows, type RefileRow } from './refile';

type T = (k: string) => string;

/** Runs a relay call through the page's helper-address repair. */
export type Mgmt = <R>(fn: () => Promise<R>) => () => Promise<R>;

/** What the page keeps of a sheet that was closed on its list. */
export interface RefileKept {
    report: RefileReport;
    rows: RefileRow[];
    handled: number[];
}

interface Props {
    t: T;
    operatorId: number;
    relayName: string;
    /** Why new files: the standby code (default), or the update switches. */
    reason?: 'code' | 'updates';
    /** The list from an earlier opening of this sheet (this relay). */
    kept?: RefileKept | null;
    /** Called with the list whenever it changes, so the page keeps it. */
    onKeep?: (k: RefileKept | null) => void;
    /** The people not removed, by name, for the question. */
    people: string[];
    onClose: () => void;
    /** Files and credentials changed: the page reads its lists again. */
    onChanged?: () => void;
    mgmt?: Mgmt;
}

type Stage =
    | { at: 'ask'; error?: string }
    | { at: 'working' }
    | { at: 'list'; report: RefileReport; rows: RefileRow[] };

const direct: Mgmt = (fn) => fn;

export function RefileSheet({
    t,
    operatorId,
    relayName,
    reason = 'code',
    kept,
    onKeep,
    people,
    onClose,
    onChanged,
    mgmt = direct,
}: Props) {
    const locale = useLocale();
    const [stage, setStageRaw] = useState<Stage>(() =>
        kept ? { at: 'list', report: kept.report, rows: kept.rows } : { at: 'ask' },
    );
    const [handled, setHandledRaw] = useState<ReadonlySet<number>>(() => new Set(kept?.handled ?? []));
    const [busyRow, setBusyRow] = useState<number | null>(null);
    const [rowError, setRowError] = useState<Record<number, string>>({});
    const [qr, setQr] = useState<RefileRow | null>(null);
    const [unsentShown, setUnsentShown] = useState(false);
    const [removalBusy, setRemovalBusy] = useState(false);
    const [removalError, setRemovalError] = useState('');

    // Every change of the list reaches the page, which keeps it.
    const keep = (st: Stage, h: ReadonlySet<number>) => {
        if (st.at === 'list') onKeep?.({ report: st.report, rows: st.rows, handled: [...h] });
    };
    const setStage = (st: Stage) => {
        setStageRaw(st);
        keep(st, handled);
    };
    const mark = (id: number) =>
        setHandledRaw((prev) => {
            const next = new Set(prev).add(id);
            keep(stage, next);
            return next;
        });

    const make = async () => {
        setStageRaw({ at: 'working' });
        try {
            const report = await mgmt(() => Wizard.refilePeople(operatorId))();
            onChanged?.();
            setHandledRaw(new Set());
            const st: Stage = { at: 'list', report, rows: refileRows(report) };
            setStageRaw(st);
            onKeep?.({ report: st.report, rows: st.rows, handled: [] });
        } catch (e) {
            setStageRaw({ at: 'ask', error: failureBlock(t, e) });
        }
    };

    /** «Try again» under a removal the relay did not confirm: only the
     *  removals go again; nobody is re-keyed, no question. */
    const retryRemovals = async () => {
        if (stage.at !== 'list') return;
        setRemovalBusy(true);
        setRemovalError('');
        try {
            const r = await mgmt(() => Wizard.refileRemovals(operatorId))();
            setStage({ ...stage, report: { ...stage.report, removal_failed: r.removal_failed } });
        } catch (e) {
            setRemovalError(failureBlock(t, e));
        } finally {
            setRemovalBusy(false);
        }
    };

    const unsent = stage.at === 'list' ? stage.rows.filter((r) => r.state === 'ready' && !handled.has(r.id)).length : 0;
    const done = () => {
        if (unsent > 0 && !unsentShown) {
            // Said once; the list stays as it is (and the page keeps it).
            setUnsentShown(true);
            return;
        }
        onClose();
    };

    const share = async (r: RefileRow) => {
        setBusyRow(r.id);
        try {
            await Wizard.shareInviteSbpx(r.path, r.label);
            mark(r.id);
            setRowError((p) => ({ ...p, [r.id]: '' }));
        } catch {
            setRowError((p) => ({ ...p, [r.id]: t('pub.fb.send.fail') }));
        } finally {
            setBusyRow(null);
        }
    };

    /** Just this person's file, again (the per-person repack). */
    const retry = async (r: RefileRow) => {
        if (stage.at !== 'list') return;
        setBusyRow(r.id);
        try {
            const s = await mgmt(() => Wizard.recipientRepackSbpx(operatorId, r.id))();
            onChanged?.();
            const rows = stage.rows.map((x) => (x.id === r.id ? { ...x, state: 'ready' as const, path: s.sbpx_path, reasonKey: undefined } : x));
            setStage({ ...stage, rows });
            setRowError((p) => ({ ...p, [r.id]: '' }));
        } catch (e) {
            setRowError((p) => ({ ...p, [r.id]: failureBlock(t, e) }));
        } finally {
            setBusyRow(null);
        }
    };

    const n = people.length;
    const count = n === 1 ? t('pub.refile.count_one') : t('pub.refile.count').replace('{n}', num(locale, n));

    return (
        <>
            <Sheet title={t('pub.refile.title')} onClose={onClose} width={520}>
                <div style={{ display: 'grid', gap: 14 }} data-testid="refile" data-refile-stage={stage.at}>
                    {stage.at === 'ask' && (
                        <>
                            <p style={P}>{t(reason === 'updates' ? 'pub.refile.why.updates' : 'pub.refile.why')}</p>
                            <p style={MUTED}>{t('pub.refile.old_stop')}</p>
                            <div style={{ ...MUTED, color: 'var(--fg)' }} data-testid="refile-count">
                                {count}
                            </div>
                            {stage.error && (
                                <div role="alert" style={{ ...MUTED, color: 'var(--red)', whiteSpace: 'pre-wrap' }}>
                                    {stage.error}
                                </div>
                            )}
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <Button leading="refresh" onClick={() => void make()} dataButton="refile-go">
                                    {t('pub.refile.go')}
                                </Button>
                                <Button variant="secondary" onClick={onClose} dataButton="refile-cancel">
                                    {t('common.cancel')}
                                </Button>
                            </div>
                        </>
                    )}

                    {stage.at === 'working' && (
                        <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '20px 0', ...MUTED }}>
                            <StateIcon state="busy" size={22} />
                            {t('pub.refile.working')}
                        </div>
                    )}

                    {stage.at === 'list' && (
                        <>
                            <p style={P}>
                                {stage.report.code_wrapped && allHandled(stage.rows, handled)
                                    ? t('pub.refile.all_sent')
                                    : t('pub.refile.send_line')}
                            </p>
                            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid' }}>
                                {stage.rows.map((r, i) => (
                                    <PersonLine
                                        key={r.id}
                                        t={t}
                                        row={r}
                                        done={handled.has(r.id)}
                                        busy={busyRow === r.id}
                                        disabled={busyRow !== null}
                                        error={rowError[r.id]}
                                        last={i === stage.rows.length - 1}
                                        onShare={() => void share(r)}
                                        onQr={() => setQr(r)}
                                        onRetry={() => void retry(r)}
                                    />
                                ))}
                            </ul>
                            {stage.report.removal_failed.map((g) => (
                                <div key={g.recipient_id} role="alert" style={{ ...MUTED, color: 'var(--red)' }} data-testid="refile-removal-failed">
                                    {t('pub.refile.removal_failed').replace(/\{name\}/g, g.display_name || g.name)}
                                </div>
                            ))}
                            {stage.report.removal_failed.length > 0 && (
                                <div style={{ display: 'grid', gap: 6 }}>
                                    <div>
                                        <Button
                                            size="sm"
                                            variant="secondary"
                                            leading="refresh"
                                            disabled={removalBusy || busyRow !== null}
                                            onClick={() => void retryRemovals()}
                                            dataButton="refile-removal-retry"
                                        >
                                            {t('pub.refile.retry')}
                                        </Button>
                                    </div>
                                    {removalError && (
                                        <div role="alert" style={{ ...MUTED, color: 'var(--red)', whiteSpace: 'pre-wrap' }}>
                                            {removalError}
                                        </div>
                                    )}
                                </div>
                            )}
                            {unsentShown && unsent > 0 && (
                                <div role="status" style={{ ...MUTED, color: 'var(--fg)' }} data-testid="refile-unsent">
                                    {t('pub.refile.unsent').replace('{n}', num(locale, unsent))}
                                </div>
                            )}
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                                <Button variant={allHandled(stage.rows, handled) ? 'primary' : 'secondary'} onClick={done} dataButton="refile-done">
                                    {t('pub.refile.done')}
                                </Button>
                                <Button variant="ghost" size="sm" onClick={() => setStageRaw({ at: 'ask' })} dataButton="refile-again">
                                    {t('pub.refile.again')}
                                </Button>
                            </div>
                        </>
                    )}
                </div>
            </Sheet>
            {qr && (
                <QrSendSheet
                    t={t}
                    operatorId={operatorId}
                    relayName={relayName}
                    artifact={recipientArtifact(qr.id)}
                    name={qr.label}
                    onClose={() => {
                        // Closing the code after showing it is the hand-over.
                        mark(qr.id);
                        setQr(null);
                    }}
                />
            )}
        </>
    );
}

function PersonLine({
    t,
    row,
    done,
    busy,
    disabled,
    error,
    last,
    onShare,
    onQr,
    onRetry,
}: {
    t: T;
    row: RefileRow;
    done: boolean;
    busy: boolean;
    disabled: boolean;
    error?: string;
    last: boolean;
    onShare: () => void;
    onQr: () => void;
    onRetry: () => void;
}) {
    return (
        <li
            data-refile-person={row.label}
            data-refile-state={done ? 'sent' : row.state}
            style={{ display: 'grid', gap: 6, padding: '10px 0', borderBlockEnd: last ? 'none' : '1px solid var(--line-soft)' }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <Avatar name={row.label} />
                <span style={{ flex: '1 1 120px', minWidth: 0, fontSize: 15, fontWeight: 600, overflowWrap: 'anywhere' }}>
                    <bdi>{row.label}</bdi>
                </span>
                {done && (
                    <span
                        role="img"
                        aria-label={t('pub.refile.sent')}
                        title={t('pub.refile.sent')}
                        data-testid="refile-tick"
                        style={{ color: 'var(--green)', display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 13 }}
                    >
                        <Icon name="check" size={18} />
                        {t('pub.refile.sent')}
                    </span>
                )}
                {busy && <StateIcon state="busy" size={18} />}
            </div>
            {row.state === 'ready' && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', paddingInlineStart: 46 }}>
                    <Button size="sm" variant={done ? 'secondary' : 'primary'} leading="share" disabled={disabled} onClick={onShare} dataButton="refile-share">
                        {t('pub.refile.share')}
                    </Button>
                    <Button size="sm" variant="secondary" leading="qr" disabled={disabled} onClick={onQr} dataButton="refile-qr">
                        {t('pub.refile.qr')}
                    </Button>
                </div>
            )}
            {row.state !== 'ready' && row.reasonKey && (
                <div style={{ ...MUTED, paddingInlineStart: 46 }}>
                    {row.state === 'failed' ? `${t('pub.refile.not_made')} ${t(row.reasonKey)}` : t(row.reasonKey)}
                </div>
            )}
            {row.state === 'failed' && (
                <div style={{ paddingInlineStart: 46 }}>
                    <Button size="sm" variant="secondary" leading="refresh" disabled={disabled} onClick={onRetry} dataButton="refile-retry">
                        {t('pub.refile.retry')}
                    </Button>
                </div>
            )}
            {error && (
                <div role="alert" style={{ ...MUTED, color: 'var(--red)', paddingInlineStart: 46, whiteSpace: 'pre-wrap' }}>
                    {error}
                </div>
            )}
        </li>
    );
}

const P: React.CSSProperties = { margin: 0, fontSize: 14, lineHeight: 1.6, color: 'var(--fg)' };
const MUTED: React.CSSProperties = { margin: 0, fontSize: 13, lineHeight: 1.5, color: 'var(--muted)' };
