// SetupRecoveryCard — the card a resumed setup shows before it does
// anything that costs money, and the Cancel sheet that offers to delete
// what an unfinished setup made (D1). Wording and button choice come
// from setupRecovery.ts; this file only draws them and asks for the one
// confirmation each destructive button needs.

import { useState } from 'react';
import { Button, Card, Sheet } from '../design/primitives';
import type { DestroyReport, SetupRecovery } from './wizardCommands';
import { WhatIsThis } from './Disclosure';
import { AddressLines } from './DestroyAddresses';
import { OtherServerNote, otherServerId } from './OtherServerNote';
import {
    DESTRUCTIVE,
    buttonKey,
    cancelBodyKey,
    cancelPlan,
    confirmKey,
    kindKey,
    recoveryView,
    serverWhere,
} from './setupRecovery';
import type { RecoveryButton } from './setupRecovery';

const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 };
const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.55 };
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--dim)' };

/** In the phone's own time zone: a UTC time reads as hours off. */
export function dateLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toLocaleString(undefined, {
            dateStyle: 'medium',
            timeStyle: 'short',
        });
    } catch {
        return '';
    }
}

function fill(t: (k: string) => string, key: string, rec: SetupRecovery | null): string {
    return t(key)
        .replace('{where}', rec ? serverWhere(rec) || t('pub.setup.recover.where_unknown') : '')
        .replace('{date}', rec ? dateLabel(rec.started_at_unix) : '');
}

/** What exists, listed — used by the confirm and the Cancel sheet. */
export function WhatWillGo({ t, rec }: { t: (k: string) => string; rec: SetupRecovery }) {
    if (rec.leftovers.length === 0) return null;
    return (
        <ul style={{ margin: 0, paddingInlineStart: 18, display: 'grid', gap: 4 }}>
            {rec.leftovers.map((l) => (
                <li key={`${l.kind}:${l.id}`} style={BODY}>
                    {t(kindKey(l.kind))}{' '}
                    <span style={MONO} dir="ltr">
                        {l.name || l.id}
                    </span>{' '}
                    <span style={{ ...SUB, color: l.billing ? 'var(--red)' : 'var(--muted)' }}>
                        {l.billing ? t('pub.account.billing.yes') : t('pub.account.billing.no')}
                    </span>
                </li>
            ))}
        </ul>
    );
}

/** The report after a delete, in plain words. */
export function DeleteOutcome({
    t,
    report,
    onRetry,
    busy,
}: {
    t: (k: string) => string;
    report: DestroyReport;
    onRetry?: () => void;
    busy?: boolean;
}) {
    return (
        <div style={{ display: 'grid', gap: 6 }} data-testid="setup-delete-outcome">
            {otherServerId(report) !== '' ? (
                // PA-3: not deleted because another Daal server has this
                // relay's name; the relay is kept.
                <OtherServerNote t={t} report={report} />
            ) : (
                <div style={{ ...BODY, color: report.server_deleted ? 'var(--fg)' : 'var(--red)' }}>
                    {report.server_deleted
                        ? t('pub.setup.recover.deleted.ok')
                        : t('pub.setup.recover.deleted.server_kept')}
                </div>
            )}
            <AddressLines t={t} addresses={report.addresses ?? []} onRetry={onRetry} retryBusy={busy} />
            {(report.warnings ?? []).length > 0 && (
                <WhatIsThis label={t('pub.fb.details')}>
                    {report.warnings.map((w, i) => (
                        <div key={i} dir="ltr" style={MONO}>
                            {w}
                        </div>
                    ))}
                </WhatIsThis>
            )}
        </div>
    );
}

export function SetupRecoveryCard({
    t,
    rec,
    busy,
    error,
    outcome,
    onButton,
    onReview,
    onRetry,
    onDone,
}: {
    t: (k: string) => string;
    /** null while the question is out. */
    rec: SetupRecovery | null;
    busy: boolean;
    /** Plain sentence for a failed press; raw text goes in `errorDetail`. */
    error: { message: string; detail: string } | null;
    /** Result of the last delete, shown under the card. */
    outcome: DestroyReport | null;
    /** Called after any confirm the button needs. */
    onButton: (b: RecoveryButton) => void;
    /** Go back and change the plan instead. */
    onReview?: () => void;
    /** A delete left an address Daal reserved still billing: the same
     *  removal again. */
    onRetry?: () => void;
    /** The relay itself is gone: the outcome is the last thing to read,
     *  and this leaves. When set, the state's buttons are not drawn. */
    onDone?: () => void;
}) {
    const [confirming, setConfirming] = useState<RecoveryButton | null>(null);
    const view = recoveryView(rec);
    const press = (b: RecoveryButton) => {
        if (DESTRUCTIVE.has(b)) setConfirming(b);
        else onButton(b);
    };
    return (
        <Card style={{ marginBottom: 14, background: 'var(--surface-2)' }}>
            <div style={{ display: 'grid', gap: 8 }} data-testid="setup-recovery" data-state={rec?.state ?? 'loading'}>
                <div style={{ fontSize: 13, fontWeight: 600, lineHeight: 1.45 }}>{fill(t, view.titleKey, rec)}</div>
                {view.bodyKeys.map((k) => (
                    <div key={k} style={SUB}>
                        {fill(t, k, rec)}
                    </div>
                ))}
                {rec && view.billing && rec.billing === 'yes' && rec.leftovers.length > 0 && (
                    <WhatWillGo t={t} rec={rec} />
                )}
                {outcome && <DeleteOutcome t={t} report={outcome} onRetry={onDone ? undefined : onRetry} busy={busy} />}
                {onDone && (
                    <div>
                        <Button variant="primary" onClick={onDone} data-button="done">
                            {t('pub.setup.recover.done')}
                        </Button>
                    </div>
                )}
                {error && (
                    <div style={{ display: 'grid', gap: 4 }}>
                        <div style={{ ...SUB, color: 'var(--red)' }}>{error.message}</div>
                        {error.detail && (
                            <WhatIsThis label={t('pub.fb.details')}>
                                <div dir="ltr">{error.detail}</div>
                            </WhatIsThis>
                        )}
                    </div>
                )}
                {!onDone && view.buttons.length > 0 && (
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {view.buttons.map((b, i) => (
                            <Button
                                key={b}
                                data-button={b}
                                variant={DESTRUCTIVE.has(b) ? 'danger' : i === 0 ? 'primary' : 'secondary'}
                                disabled={busy}
                                onClick={() => press(b)}
                            >
                                {t(buttonKey(b))}
                            </Button>
                        ))}
                        {onReview && (rec?.state === 'none' || rec?.state === 'nothing_billing') && (
                            <Button variant="ghost" disabled={busy} onClick={onReview}>
                                {t('wiz.build.resume.review')}
                            </Button>
                        )}
                    </div>
                )}
                {rec && rec.details.length > 0 && (
                    <WhatIsThis label={t('pub.fb.details')}>
                        {rec.details.map((d, i) => (
                            <div key={i} dir="ltr" style={MONO}>
                                {d}
                            </div>
                        ))}
                    </WhatIsThis>
                )}
            </div>
            {confirming && rec && (
                <Sheet
                    title={t('pub.setup.recover.confirm.title')}
                    width={520}
                    onClose={() => setConfirming(null)}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button variant="ghost" onClick={() => setConfirming(null)}>
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => {
                                    const b = confirming;
                                    setConfirming(null);
                                    onButton(b);
                                }}
                            >
                                {t(buttonKey(confirming))}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 8 }}>
                        <div style={BODY}>{fill(t, confirmKey(confirming), rec)}</div>
                        <WhatWillGo t={t} rec={rec} />
                        <div style={{ ...SUB, color: 'var(--red)' }}>{t('pub.setup.recover.confirm.final')}</div>
                    </div>
                </Sheet>
            )}
        </Card>
    );
}

/** Cancel, for a setup that may have rented something. */
export function CancelSetupSheet({
    t,
    rec,
    busy,
    outcome,
    error,
    onDelete,
    onKeep,
    onCheckAgain,
    onClose,
    onDone,
}: {
    t: (k: string) => string;
    rec: SetupRecovery;
    busy: boolean;
    outcome: DestroyReport | null;
    error: { message: string; detail: string } | null;
    /** relayDestroy(op, true) */
    onDelete: () => void;
    /** cancelAndCleanup: forget the relay, leave the server. */
    onKeep: () => void;
    onCheckAgain: () => void;
    onClose: () => void;
    /** The relay is gone (the report says so): read it, then leave. */
    onDone: () => void;
}) {
    const plan = cancelPlan(rec);
    const gone = outcome?.local_removed === true;
    return (
        <Sheet
            title={t('pub.setup.cancel.title')}
            width={520}
            onClose={() => {
                if (busy) return;
                if (gone) onDone();
                else onClose();
            }}
            footer={
                gone ? (
                    <span style={{ display: 'inline-flex', gap: 8 }}>
                        <Button variant="primary" onClick={onDone} data-button="done">
                            {t('pub.setup.recover.done')}
                        </Button>
                    </span>
                ) : (
                <span style={{ display: 'inline-flex', gap: 8, flexWrap: 'wrap' }}>
                    <Button variant="ghost" disabled={busy} onClick={onClose}>
                        {t('pub.setup.cancel.back')}
                    </Button>
                    {plan === 'wait' && (
                        <Button disabled={busy} onClick={onCheckAgain}>
                            {t('pub.setup.recover.btn.check_again')}
                        </Button>
                    )}
                    {plan === 'yours_choice' && (
                        <Button variant="secondary" disabled={busy} onClick={onKeep} data-button="keep">
                            {t('pub.setup.cancel.keep_mine')}
                        </Button>
                    )}
                    {(plan === 'delete' || plan === 'yours_choice') && (
                        <Button variant="danger" disabled={busy} onClick={onDelete} data-button="delete">
                            {busy
                                ? t('pub.relays.destroy.working.server')
                                : plan === 'yours_choice'
                                  ? t('pub.setup.cancel.delete_mine')
                                  : t('pub.setup.cancel.delete')}
                        </Button>
                    )}
                </span>
                )
            }
        >
            <div style={{ display: 'grid', gap: 8 }} data-plan={plan}>
                {!gone && <div style={BODY}>{fill(t, cancelBodyKey(rec), rec)}</div>}
                {!gone && <WhatWillGo t={t} rec={rec} />}
                {plan === 'yours_choice' && <div style={SUB}>{t('pub.setup.cancel.keep_mine.line')}</div>}
                {outcome && <DeleteOutcome t={t} report={outcome} onRetry={onDelete} busy={busy} />}
                {error && (
                    <div style={{ display: 'grid', gap: 4 }}>
                        <div style={{ ...SUB, color: 'var(--red)' }}>{error.message}</div>
                        <WhatIsThis label={t('pub.fb.details')}>
                            <div dir="ltr">{error.detail}</div>
                        </WhatIsThis>
                    </div>
                )}
            </div>
        </Sheet>
    );
}
