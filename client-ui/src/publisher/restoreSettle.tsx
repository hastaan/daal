// restoreSettle — the relay page after this phone was restored from a
// backup (PB-1, PB-2).
//
// A backup is a snapshot. Two things can have changed on the old phone
// since it was made:
//
//   PB-1  someone was REMOVED. The restored list still has them, the
//         relay does not. Re-creating them would silently give a removed
//         person access again, so the shell keeps the relay "restored,
//         not yet settled" and lists them; this page asks about each one
//         BY NAME ("still should have access" / "was removed"), nothing
//         pre-selected, and until answered the renew skips them and is
//         never "all done".
//   PB-2  someone was ADDED. The relay lets them in, the list has no
//         row for them. They are listed under People with their relay
//         name and "Remove access", behind a sheet that names the relay
//         user and says it cannot be undone from this phone.
//
// If the relay cannot be asked, nothing is assumed either way: the card
// says so and offers to check again.

import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Card, Sheet } from '../design/primitives';
import { WhatIsThis } from './Disclosure';
import { ActionButton } from './useAction';
import type { ActionState } from './useAction';
import { withHelperIp } from './helperIp';
import { Wizard } from './wizardCommands';
import type {
    RecipientSummary,
    RelayHealth,
    RenewItem,
    RenewReport,
    RestoreUnsettled,
    RestoreUnsettledPerson,
} from './wizardCommands';
import { personLabel } from './PeopleSection';

const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 };
const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 };
const MONO: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    wordBreak: 'break-all',
    textAlign: 'start',
};

// ---- pure ---------------------------------------------------------------

/** What the question card shows. */
export type SettleCard = 'hidden' | 'ask' | 'could_not_check';

export function settleCard(u: RestoreUnsettled | null): SettleCard {
    if (!u) return 'hidden';
    if (u.people.length > 0) return 'ask';
    if (!u.checked && u.check_error) return 'could_not_check';
    return 'hidden';
}

/** The ids still waiting for an answer. */
export function waitingIds(u: RestoreUnsettled | null): Set<number> {
    return new Set((u?.people ?? []).map((p) => p.recipient_id));
}

/** The name to ask about: the label this phone's list shows for them,
 *  else the name the shell sent, else the row number. */
export function waitingLabel(p: RestoreUnsettledPerson, recipients: RecipientSummary[]): string {
    const r = recipients.find((x) => x.id === p.recipient_id);
    return (r ? personLabel(r) : '') || p.name || `#${p.recipient_id}`;
}

/** The health result as the page shows it while people wait for an
 *  answer: those people are not "missing on the relay, renew to fix",
 *  they are a question, so neither the health line nor the renew banner
 *  may invite a renew that would bring them back. The shell already
 *  leaves the `people_needing_answer` it counted out of `people_missing`;
 *  only waiting people beyond that count (a shell built before the wave
 *  sends none) are taken out here, never anyone twice. */
export function healthWithoutWaiting(h: RelayHealth | null, waiting: number): RelayHealth | null {
    if (!h || h.people_missing == null) return h;
    const extra = waiting - (h.people_needing_answer ?? 0);
    if (extra <= 0) return h;
    return { ...h, people_missing: Math.max(0, h.people_missing - extra) };
}

/** A renew result as the page shows it while people wait: every waiting
 *  person is a "needs your answer" row (whatever the shell sent for them
 *  unless it actually made them a file, which is shown as it is), one
 *  is added for a waiting person the shell left out, and the result is
 *  never "all done" while anyone waits. */
export function settleReport(
    report: RenewReport,
    waiting: RestoreUnsettledPerson[],
    recipients: RecipientSummary[],
): RenewReport {
    if (waiting.length === 0) return report;
    const ids = new Set(waiting.map((p) => p.recipient_id));
    const asked = (i: RenewItem): RenewItem =>
        i.recipient_id != null && ids.has(i.recipient_id) && i.status !== 'done' && i.status !== 'already_done'
            ? { ...i, status: 'needs_answer', reason: 'restore_unanswered', sbpx_path: '' }
            : i;
    const items = report.items.map(asked);
    const seen = new Set(items.map((i) => i.recipient_id));
    for (const p of waiting) {
        if (seen.has(p.recipient_id)) continue;
        const r = recipients.find((x) => x.id === p.recipient_id);
        items.push({
            recipient_id: p.recipient_id,
            name: r?.name ?? '',
            display_name: waitingLabel(p, recipients),
            status: 'needs_answer',
            reason: 'restore_unanswered',
            sbpx_path: '',
            detail: '',
        });
    }
    const stillWaiting = items.some((i) => i.status === 'needs_answer');
    return { ...report, items, all_done: report.all_done && !stillWaiting };
}

/** Relay users this page may offer to remove, from the names the health
 *  check read with its `people_unknown` count (the same read, cached
 *  with it: listing them never reaches the relay again). Never one that
 *  IS in this phone's list (those go through the normal remove, which
 *  also keeps the list right). */
export function relayOnlyRows(h: RelayHealth | null, recipients: RecipientSummary[]): string[] {
    if (!h?.relay_only) return [];
    const known = new Set(recipients.map((r) => r.name).filter(Boolean));
    return [...new Set(h.relay_only)].filter((n) => n && !known.has(n));
}

/** The health result once one relay user's access was removed: they
 *  leave the list (and the count) now, whatever the re-check says or
 *  whether it can run at all. */
export function withoutRelayOnly(h: RelayHealth | null, user: string): RelayHealth | null {
    if (!h?.relay_only?.includes(user)) return h;
    const relay_only = h.relay_only.filter((u) => u !== user);
    return { ...h, relay_only, people_unknown: relay_only.length };
}

// ---- the data -------------------------------------------------------------

export interface SettleApi {
    restoreUnsettled: (op: number) => Promise<RestoreUnsettled>;
    restoreAnswer: (op: number, recipientId: number, keep: boolean) => Promise<void>;
    relayOnlyRevoke: (op: number, relayUser: string) => Promise<void>;
}

export const settleApi: SettleApi = {
    restoreUnsettled: (op) => withHelperIp(op, () => Wizard.restoreUnsettled(op)),
    restoreAnswer: (op, id, keep) => Wizard.restoreAnswer(op, id, keep),
    relayOnlyRevoke: (op, user) => Wizard.relayOnlyRevoke(op, user),
};

function errText(e: unknown): string {
    if (typeof e === 'string') return e;
    if (e instanceof Error) return e.message;
    try {
        return JSON.stringify(e);
    } catch {
        return String(e);
    }
}

/** The PB-1 list for one relay, read after every health check (`tick`).
 *  It reaches the relay only while a restore is not yet settled and the
 *  health check could not read the relay's people; otherwise it is one
 *  local query. A read that fails is "could not check", never "nobody".
 *  (The PB-2 names come with the health result: `relayOnlyRows`.) */
export function useRestoreSettle(operatorId: number, enabled: boolean, tick: number, api: SettleApi = settleApi) {
    const [unsettled, setUnsettled] = useState<RestoreUnsettled | null>(null);
    const alive = useRef(true);
    useEffect(() => {
        alive.current = true;
        return () => {
            alive.current = false;
        };
    }, []);

    const reloadUnsettled = useCallback(async () => {
        try {
            const u = await api.restoreUnsettled(operatorId);
            if (alive.current) setUnsettled(u);
        } catch (e) {
            if (alive.current) setUnsettled((prev) => ({ people: prev?.people ?? [], checked: false, check_error: errText(e) }));
        }
    }, [api, operatorId]);

    // Only after a health check has run (`tick` > 0): that check is
    // what settles a restore when it can read the relay, so reading
    // before it would ask the relay twice on the first opening.
    useEffect(() => {
        if (!enabled || tick === 0) return;
        void reloadUnsettled();
    }, [enabled, tick, reloadUnsettled]);

    return { unsettled, reloadUnsettled };
}

// ---- PB-1: the question card ---------------------------------------------

export function RestoreQuestionCard({
    t,
    unsettled,
    recipients,
    action,
    onAnswer,
    onCheckAgain,
}: {
    t: (k: string) => string;
    unsettled: RestoreUnsettled | null;
    recipients: RecipientSummary[];
    action: ActionState;
    onAnswer: (p: RestoreUnsettledPerson, keep: boolean) => void;
    onCheckAgain: () => void;
}) {
    const card = settleCard(unsettled);
    if (card === 'hidden' || !unsettled) return null;
    if (card === 'could_not_check') {
        return (
            <Card style={{ border: '1px solid var(--gold)' }}>
                <div style={{ display: 'grid', gap: 8 }} data-testid="restore-question" data-state="could_not_check">
                    <div style={BODY}>{t('pub.restore_settle.could_not_check')}</div>
                    <div>
                        <Button variant="secondary" size="sm" disabled={action.busy !== null} onClick={onCheckAgain} data-button="settle-check-again">
                            {t('pub.restore_settle.check_again')}
                        </Button>
                    </div>
                    <WhatIsThis label={t('pub.fb.details')}>
                        <div dir="ltr" style={MONO}>
                            {unsettled.check_error}
                        </div>
                    </WhatIsThis>
                </div>
            </Card>
        );
    }
    return (
        <Card style={{ border: '1px solid var(--gold)' }}>
            <div style={{ display: 'grid', gap: 10 }} data-testid="restore-question" data-state="ask">
                <div style={{ ...BODY, fontWeight: 600 }}>{t('pub.restore_settle.title')}</div>
                <div style={BODY}>{t('pub.restore_settle.why')}</div>
                {unsettled.people.map((p, i) => (
                    <div
                        key={p.recipient_id}
                        data-person={p.recipient_id}
                        style={{
                            display: 'grid',
                            gap: 6,
                            padding: '8px 0',
                            borderTop: i === 0 ? 'none' : '1px solid var(--line-soft)',
                        }}
                    >
                        <div style={{ ...BODY, fontWeight: 600 }}>{waitingLabel(p, recipients)}</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            <ActionButton
                                action={action}
                                k={`settle:keep:${p.recipient_id}`}
                                busyLabel={t('pub.restore_settle.saving')}
                                variant="secondary"
                                size="sm"
                                onClick={() => onAnswer(p, true)}
                                data-button={`settle-keep-${p.recipient_id}`}
                            >
                                {t('pub.restore_settle.keep')}
                            </ActionButton>
                            <ActionButton
                                action={action}
                                k={`settle:removed:${p.recipient_id}`}
                                busyLabel={t('pub.restore_settle.saving')}
                                variant="secondary"
                                size="sm"
                                onClick={() => onAnswer(p, false)}
                                data-button={`settle-removed-${p.recipient_id}`}
                            >
                                {t('pub.restore_settle.removed')}
                            </ActionButton>
                        </div>
                    </div>
                ))}
                <div style={SUB}>{t('pub.restore_settle.until')}</div>
            </div>
        </Card>
    );
}

// ---- PB-2: remove a relay user this phone has no name for -----------------

export function RelayOnlyRemoveSheet({
    t,
    user,
    busy,
    error,
    onCancel,
    onConfirm,
}: {
    t: (k: string) => string;
    user: string;
    busy: boolean;
    error: string | null;
    onCancel: () => void;
    onConfirm: () => void;
}) {
    const fill = (k: string) => t(k).replace(/\{user\}/g, user);
    return (
        <Sheet
            title={fill('pub.people.relay_only.confirm.title')}
            width={520}
            // Back is cancel, except while the removal runs.
            onClose={() => {
                if (!busy) onCancel();
            }}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    <Button variant="ghost" disabled={busy} onClick={onCancel} data-button="relay-only-cancel">
                        {t('common.cancel')}
                    </Button>
                    <Button variant="danger" disabled={busy} onClick={onConfirm} data-button="relay-only-confirm">
                        {busy ? t('pub.people.relay_only.removing') : t('pub.people.relay_only.confirm.go')}
                    </Button>
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 10 }} data-testid="relay-only-sheet">
                <div style={BODY}>{fill('pub.people.relay_only.confirm.body')}</div>
                <div style={SUB}>{t('pub.people.relay_only.confirm.undo')}</div>
                {error && (
                    <div role="alert" style={{ ...BODY, color: 'var(--red)', whiteSpace: 'pre-wrap' }}>
                        {error}
                    </div>
                )}
            </div>
        </Sheet>
    );
}
