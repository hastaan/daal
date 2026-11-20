// RenewSheet — confirm, progress and per-person result for "Renew
// everyone's files" (D2). Rules in renew.ts.

import { useEffect, useState } from 'react';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { Button, Card, Sheet } from '../design/primitives';
import { onRenewEvent } from './wizardCommands';
import type { RecipientSummary, RenewItem, RenewReport, RestoreUnsettledPerson } from './wizardCommands';
import { WhatIsThis } from './Disclosure';
import { personLabel } from './PeopleSection';
import { explainFailure } from './failureText';
import { classifyPublisherError } from './wizardCommands';
import {
    applyRenewEvent,
    progressKey,
    reasonKey,
    renewResultKey,
    renewTargets,
    renewWaiting,
    reportRows,
    rowOk,
    statusKey,
} from './renew';
import type { RenewBannerText, RenewProgress } from './renew';
import { settleReport } from './restoreSettle';

const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 };
const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 };

/** Why the whole renew could not run, in plain words. "Nothing was
 *  changed" is only said when the shell says so (the relay did not
 *  answer, so no person was touched); anything else gets the general
 *  explanation for its code. Exported for the tests. */
export function renewFailure(t: (k: string) => string, e: unknown): { message: string; detail: string } {
    const f = explainFailure(t, e);
    return classifyPublisherError(e) === 'E_RELAY_UNREACHABLE' ? { ...f, message: t('pub.renew.failed') } : f;
}

/** The banner on the relay page. */
export function RenewBanner({
    t,
    onRenew,
    text = { key: 'pub.renew.banner', n: 0 },
}: {
    t: (k: string) => string;
    onRenew: () => void;
    /** From `renewBannerText`: what the banner may truthfully claim. */
    text?: RenewBannerText;
}) {
    return (
        <Card style={{ border: '1px solid var(--gold)' }}>
            <div style={{ display: 'grid', gap: 8 }} data-testid="renew-banner">
                <div style={{ ...BODY, fontWeight: 600 }}>{t(text.key).replace('{n}', String(text.n))}</div>
                <div style={SUB}>{t('pub.renew.banner.line')}</div>
                <div>
                    <Button onClick={onRenew}>{t('pub.renew.action')}</Button>
                </div>
            </div>
        </Card>
    );
}

export interface RenewSendActions {
    /** Open the send sheet for this person's new file. */
    onOpen: (recipientId: number, path: string, label: string) => void;
}

function itemLabel(t: (k: string) => string, i: RenewItem): string {
    return i.recipient_id == null ? t('pub.renew.everyone_file') : i.display_name || i.name;
}

/** One result row. Exported for the tests. */
export function RenewResultRow({
    t,
    item,
    send,
}: {
    t: (k: string) => string;
    item: RenewItem;
    send?: RenewSendActions;
}) {
    const label = itemLabel(t, item);
    const ok = rowOk(item);
    const why = reasonKey(item.reason);
    return (
        <div style={{ display: 'grid', gap: 6, padding: '8px 0', borderBottom: '1px solid var(--line-soft)' }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                <span aria-hidden style={{ color: ok ? 'var(--green)' : item.status === 'failed' ? 'var(--red)' : 'var(--dim)' }}>
                    {ok ? '✓' : item.status === 'failed' ? '✗' : '·'}
                </span>
                <span style={{ ...BODY, fontWeight: 600, flex: 1 }}>{label}</span>
                <span style={SUB}>{t(statusKey(item.status))}</span>
            </div>
            {item.status === 'failed' && why && <div style={{ ...SUB, color: 'var(--red)' }}>{t(why)}</div>}
            {item.status === 'needs_answer' && (
                <div style={{ ...SUB, color: 'var(--gold)' }} data-testid="renew-needs-answer">
                    {t('pub.renew.reason.needs_answer')}
                </div>
            )}
            {ok && send && item.recipient_id != null && item.sbpx_path && (
                <div>
                    {/* One button: the four ways out are in the send sheet. */}
                    <Button
                        size="sm"
                        variant="secondary"
                        leading="share"
                        onClick={() => send.onOpen(item.recipient_id!, item.sbpx_path, label)}
                        dataButton="renew-send"
                    >
                        {t('pub.send.open')}
                    </Button>
                </div>
            )}
            {item.detail && (
                <WhatIsThis label={t('pub.fb.details')}>
                    <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                        {item.detail}
                    </div>
                </WhatIsThis>
            )}
        </div>
    );
}

export function RenewSheet({
    t,
    operatorId,
    recipients,
    hasEveryoneFile,
    renew,
    send,
    onClose,
    initialReport,
    waiting = [],
}: {
    t: (k: string) => string;
    operatorId: number;
    recipients: RecipientSummary[];
    hasEveryoneFile: boolean;
    /** Wizard.renewEveryone behind the page's helper-address repair. */
    renew: () => Promise<RenewReport>;
    send: RenewSendActions;
    /** `changed` once anything ran, so the page reloads. */
    onClose: (changed: boolean) => void;
    /** Tests and the harness: open straight on a result. */
    initialReport?: RenewReport;
    /** PB-1: people waiting for an answer after a restore. Never
     *  renewed from here; named as waiting, and while any waits the
     *  result is not "all done". */
    waiting?: RestoreUnsettledPerson[];
}) {
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<RenewReport | null>(initialReport ?? null);
    const [failure, setFailure] = useState<{ message: string; detail: string } | null>(null);
    const [progress, setProgress] = useState<RenewProgress>({});
    const waitingSet = new Set(waiting.map((p) => p.recipient_id));
    const people = renewTargets(recipients, waitingSet);
    const asked = renewWaiting(recipients, waitingSet);

    useEffect(() => {
        if (!busy) return;
        let un: UnlistenFn | null = null;
        let dead = false;
        void onRenewEvent((ev) => setProgress((p) => applyRenewEvent(p, ev, operatorId)))
            .then((u) => {
                if (dead) u();
                else un = u;
            })
            .catch(() => {
                /* no event bridge (preview): the result still arrives */
            });
        return () => {
            dead = true;
            un?.();
        };
    }, [busy, operatorId]);

    const start = async () => {
        setBusy(true);
        setFailure(null);
        setProgress({});
        try {
            setReport(await renew());
        } catch (e) {
            setFailure(renewFailure(t, e));
        } finally {
            setBusy(false);
        }
    };

    // What the shell said, with every waiting person shown as waiting.
    const shown = report ? settleReport(report, waiting, recipients) : null;
    const rows = shown ? reportRows(shown) : [];

    return (
        <Sheet
            title={t('pub.renew.title')}
            width={560}
            onClose={() => {
                if (!busy) onClose(report !== null);
            }}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    {!report && (
                        <Button variant="ghost" disabled={busy} onClick={() => onClose(false)}>
                            {t('common.cancel')}
                        </Button>
                    )}
                    {report ? (
                        <>
                            {/* Safe to press again: only the people who
                                still have no working file are touched. */}
                            {!shown!.all_done && (
                                <Button variant="secondary" disabled={busy} onClick={() => void start()}>
                                    {busy ? t('pub.renew.working') : t('pub.renew.again')}
                                </Button>
                            )}
                            <Button disabled={busy} onClick={() => onClose(true)}>
                                {t('common.close')}
                            </Button>
                        </>
                    ) : (
                        <Button disabled={busy} onClick={() => void start()}>
                            {busy ? t('pub.renew.working') : t('pub.renew.confirm')}
                        </Button>
                    )}
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 10 }}>
                {!report && (
                    <>
                        <div style={BODY}>
                            {t('pub.renew.confirm.body').replace('{n}', String(people.length))}
                        </div>
                        <ul style={{ margin: 0, paddingInlineStart: 18, display: 'grid', gap: 4 }}>
                            {people.map((r) => (
                                <li key={r.id} style={BODY}>
                                    {personLabel(r)}
                                    {busy && progress[progressKey(r.id)] && (
                                        <span style={{ ...SUB, marginInlineStart: 8 }}>
                                            {t(statusKey(progress[progressKey(r.id)]))}
                                        </span>
                                    )}
                                </li>
                            ))}
                            {asked.map((r) => (
                                <li key={r.id} style={BODY} data-waiting={r.id}>
                                    {personLabel(r)}
                                    <span style={{ ...SUB, color: 'var(--gold)', marginInlineStart: 8 }}>
                                        {t('pub.renew.status.needs_answer')}
                                    </span>
                                </li>
                            ))}
                            {hasEveryoneFile && (
                                <li style={BODY}>
                                    {t('pub.renew.everyone_file')}
                                    {busy && progress.everyone && (
                                        <span style={{ ...SUB, marginInlineStart: 8 }}>
                                            {t(statusKey(progress.everyone))}
                                        </span>
                                    )}
                                </li>
                            )}
                        </ul>
                        {asked.length > 0 && (
                            <div style={SUB} data-testid="renew-waiting-line">
                                {t('pub.renew.waiting_line')}
                            </div>
                        )}
                        <div style={SUB}>{t('pub.renew.removed_stay_removed')}</div>
                        <div style={SUB}>{t('pub.renew.safe_twice')}</div>
                    </>
                )}

                {failure && (
                    <div style={{ display: 'grid', gap: 6 }}>
                        <div style={{ ...BODY, color: 'var(--red)' }}>{failure.message}</div>
                        <WhatIsThis label={t('pub.fb.details')}>
                            <div dir="ltr">{failure.detail}</div>
                        </WhatIsThis>
                    </div>
                )}

                {shown && (
                    <>
                        <div style={BODY} data-testid="renew-result-line">
                            {t(renewResultKey(shown))}
                        </div>
                        <div style={SUB}>{t('pub.renew.result.hand_over')}</div>
                        <div data-testid="renew-results">
                            {rows.map((i) => (
                                <RenewResultRow key={progressKey(i.recipient_id)} t={t} item={i} send={send} />
                            ))}
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}
