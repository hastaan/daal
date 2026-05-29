// SubscriptionsPanel — Gap 4-recipient UI.
//
// Lists every active subscription with its last-refresh outcome,
// exposes a manual ↻ that calls `subscriptionRefresh`, and a remove
// affordance. The host-driven 60-s scheduler tick (engine_scheduler_tick,
// fired by the Tauri shell) handles auto-refresh transparently; the
// UI just shows the current state and offers explicit overrides.
//
// Settings → Network section is the host. All copy is i18n-keyed
// under `subs.*`.

import { useCallback, useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { SubscriptionRow } from '../contract/D2Contract';
import { Card, ListRow, Button } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

function relTime(t: (k: string) => string, bucketIso: string): string {
    if (!bucketIso) return t('subs.never');
    const then = Date.parse(bucketIso);
    if (Number.isNaN(then)) return bucketIso;
    const delta = Math.max(0, Date.now() - then);
    const mins = Math.floor(delta / 60_000);
    if (mins < 1) return t('subs.just_now');
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h`;
    return `${Math.floor(hrs / 24)}d`;
}

function outcomeColor(outcome: string): string {
    if (!outcome) return 'var(--dim)';
    if (outcome === 'ok' || outcome.startsWith('ok')) return 'var(--green)';
    if (outcome.startsWith('error') || outcome === 'failed') return 'var(--red)';
    return 'var(--amber)';
}

export default function SubscriptionsPanel({ t }: Props) {
    const contract = useContract();
    const [rows, setRows] = useState<SubscriptionRow[]>([]);
    const [busyId, setBusyId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

    const reload = useCallback(async () => {
        try {
            setRows(await contract.subscriptionList());
        } catch (e) {
            setError(String(e));
        }
    }, [contract]);

    useEffect(() => {
        void reload();
        // Refresh-on-open is the cheap fallback in case the host's
        // scheduler tick hasn't run yet. 10 s polling keeps the
        // outcome column live without hammering the engine — the
        // engine's scheduler.Plan is the actual cadence governor.
        const h = window.setInterval(() => { void reload(); }, 10_000);
        return () => window.clearInterval(h);
    }, [reload]);

    const refresh = async (id: string) => {
        setBusyId(id);
        setError(null);
        try {
            await contract.subscriptionRefresh(id, 15_000);
        } catch (e) {
            setError(String(e));
        } finally {
            setBusyId(null);
            await reload();
        }
    };

    const remove = async (id: string) => {
        setBusyId(id);
        setError(null);
        try {
            await contract.subscriptionRemove(id);
            setConfirmRemove(null);
        } catch (e) {
            setError(String(e));
        } finally {
            setBusyId(null);
            await reload();
        }
    };

    if (rows.length === 0) {
        return (
            <Card>
                <ListRow
                    title={t('subs.empty.title')}
                    subtitle={t('subs.empty.help')}
                    last
                />
            </Card>
        );
    }

    return (
        <div style={{ display: 'grid', gap: 8 }}>
            {error && (
                <div
                    style={{
                        color: 'var(--red)',
                        fontSize: 12,
                        padding: '4px 12px',
                    }}
                >
                    {error}
                </div>
            )}
            <Card>
                {rows.map((r, i) => (
                    <ListRow
                        key={r.subscriptionId}
                        title={r.displayName || r.subscriptionId}
                        subtitle={
                            <span>
                                <span
                                    style={{
                                        color: outcomeColor(r.lastRefreshOutcome),
                                    }}
                                >
                                    {r.lastRefreshOutcome || t('subs.no_outcome')}
                                </span>
                                {' · '}
                                {t('subs.last_good')}{' '}
                                {relTime(t, r.lastGoodRefreshBucket)}
                                {typeof r.routeCount === 'number' && (
                                    <>
                                        {' · '}
                                        {r.routeCount} {t('subs.routes')}
                                    </>
                                )}
                            </span>
                        }
                        trailing={
                            <span style={{ display: 'inline-flex', gap: 6 }}>
                                <Button
                                    onClick={() => refresh(r.subscriptionId)}
                                    disabled={busyId === r.subscriptionId}
                                >
                                    {busyId === r.subscriptionId
                                        ? t('subs.refreshing')
                                        : t('subs.refresh')}
                                </Button>
                                <Button
                                    onClick={() =>
                                        setConfirmRemove(r.subscriptionId)
                                    }
                                    disabled={busyId === r.subscriptionId}
                                >
                                    {t('subs.remove')}
                                </Button>
                            </span>
                        }
                        last={i === rows.length - 1}
                    />
                ))}
            </Card>
            {confirmRemove && (
                <Card
                    style={{
                        borderColor:
                            'color-mix(in oklab, var(--red) 35%, var(--line-soft))',
                    }}
                >
                    <ListRow
                        title={t('subs.confirm_remove.title')}
                        subtitle={t('subs.confirm_remove.help')}
                        trailing={
                            <span style={{ display: 'inline-flex', gap: 6 }}>
                                <Button
                                    onClick={() => setConfirmRemove(null)}
                                >
                                    {t('common.cancel')}
                                </Button>
                                <Button
                                    onClick={() => remove(confirmRemove)}
                                    disabled={busyId === confirmRemove}
                                >
                                    {t('subs.remove')}
                                </Button>
                            </span>
                        }
                        last
                    />
                </Card>
            )}
        </div>
    );
}
