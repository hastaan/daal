// RenewSheet — confirm, progress and per-person result for "Renew
// everyone's files" (D2). Rules in renew.ts.

import { useEffect, useState } from 'react';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { Button, Card, Sheet } from '../design/primitives';
import { onRenewEvent } from './wizardCommands';
import type { RecipientSummary, RenewItem, RenewReport } from './wizardCommands';
import { WhatIsThis } from './Disclosure';
import { personLabel } from './PeopleSection';
import { explainFailure } from './failureText';
import { classifyPublisherError } from './wizardCommands';
import {
    applyRenewEvent,
    progressKey,
    reasonKey,
    renewTargets,
    reportRows,
    rowOk,
    statusKey,
} from './renew';
import type { RenewBannerText, RenewProgress } from './renew';

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
    onSend: (path: string, label: string) => void;
    onSave: (path: string, label: string) => void;
    onQr: (recipientId: number, label: string) => void;
    onCopy: (recipientId: number, label: string) => void;
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
            {ok && send && item.recipient_id != null && item.sbpx_path && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    <Button size="sm" onClick={() => send.onSend(item.sbpx_path, label)}>
                        {t('pub.people.send')}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => send.onSave(item.sbpx_path, label)}>
                        {t('pub.people.save')}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => send.onQr(item.recipient_id!, label)}>
                        {t('pub.person.qr')}
                    </Button>
                    <Button size="sm" variant="secondary" onClick={() => send.onCopy(item.recipient_id!, label)}>
                        {t('pub.person.copy')}
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
}) {
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<RenewReport | null>(initialReport ?? null);
    const [failure, setFailure] = useState<{ message: string; detail: string } | null>(null);
    const [progress, setProgress] = useState<RenewProgress>({});
    const people = renewTargets(recipients);

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

    const rows = report ? reportRows(report) : [];

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
                            {!report.all_done && (
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

                {report && (
                    <>
                        <div style={BODY}>
                            {report.all_done ? t('pub.renew.result.all_done') : t('pub.renew.result.some_failed')}
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
