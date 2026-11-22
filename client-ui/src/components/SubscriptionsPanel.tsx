// SubscriptionsPanel — "Automatic updates" in Settings → Advanced
// (spec C5.2). Rendered only when there is at least one: an empty card
// that says "none yet" is not something a person can use.
//
// One row per update address: a state icon from the last check, the
// name, "Updated 2 hours ago", a "Check for updates" button and a ⋯
// with "Remove" (asks first). The host's 60-s scheduler tick
// (engine_scheduler_tick) does the real refreshing; this only shows
// the state and offers the manual check.

import { useCallback, useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { SubscriptionRow } from '../contract/D2Contract';
import type { Locale } from '../lib/i18n';
import { errorText } from '../lib/errorText';
import { formatAgo } from '../lib/format';
import { useDeveloperMode } from '../lib/devMode';
import { Button, Card, IconButton, ListRow, OverflowMenu, StateIcon } from '../design/primitives';
import { mix } from '../design/mix';

interface Props {
    t: (k: string) => string;
    locale?: Locale;
}

/** The last check's outcome as a state icon. */
export function outcomeState(outcome: string): 'ok' | 'bad' | 'warn' | 'none' {
    if (!outcome) return 'none';
    if (outcome === 'ok' || outcome.startsWith('ok')) return 'ok';
    if (outcome.startsWith('error') || outcome === 'failed') return 'bad';
    return 'warn';
}

/** "Updated 2 hours ago", or "Not updated yet" without a good check. */
export function updatedText(t: (k: string) => string, locale: Locale, bucketIso: string, nowMs = Date.now()): string {
    const then = bucketIso ? Date.parse(bucketIso) : NaN;
    if (Number.isNaN(then)) return t('subs.never');
    return t('subs.updated').replace('{ago}', formatAgo(locale, Math.max(0, nowMs - then), t('ui.just_now')));
}

export default function SubscriptionsPanel({ t, locale = 'en' }: Props) {
    const contract = useContract();
    const dev = useDeveloperMode();
    const [rows, setRows] = useState<SubscriptionRow[]>([]);
    const [busyId, setBusyId] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [confirmRemove, setConfirmRemove] = useState<SubscriptionRow | null>(null);

    const reload = useCallback(async () => {
        try {
            setRows(await contract.subscriptionList());
        } catch (e) {
            setError(errorText(e));
        }
    }, [contract]);

    useEffect(() => {
        void reload();
        // Refresh-on-open is the cheap fallback in case the host's
        // scheduler tick hasn't run yet. 10 s polling keeps the
        // state live without hammering the engine.
        const h = window.setInterval(() => {
            void reload();
        }, 10_000);
        return () => window.clearInterval(h);
    }, [reload]);

    const refresh = async (id: string) => {
        setBusyId(id);
        setError(null);
        try {
            await contract.subscriptionRefresh(id, 15_000);
        } catch (e) {
            setError(errorText(e));
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
            setError(errorText(e));
        } finally {
            setBusyId(null);
            await reload();
        }
    };

    if (rows.length === 0 && !error) return null;

    const name = (r: SubscriptionRow) => r.displayName || r.profileTitle || r.subscriptionId;

    return (
        <Card style={{ paddingBlockEnd: 4 }}>
            <h2
                data-subscriptions-panel
                style={{ margin: 0, fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 500, color: 'var(--fg)' }}
            >
                {t('subs.section_title')}
            </h2>
            {error && (
                <div role="alert" style={{ display: 'flex', gap: 8, color: 'var(--red)', fontSize: 13, lineHeight: 1.45, paddingBlock: 8 }}>
                    <StateIcon state="bad" size={16} />
                    <span>
                        {t('subs.failed')}
                        {dev && (
                            <span style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' }}>{error}</span>
                        )}
                    </span>
                </div>
            )}
            <div style={{ marginBlockStart: 4 }}>
                {rows.map((r, i) => {
                    const busy = busyId === r.subscriptionId;
                    return (
                        <ListRow
                            key={r.subscriptionId}
                            leading={<StateIcon state={busy ? 'busy' : outcomeState(r.lastRefreshOutcome)} size={20} />}
                            title={name(r)}
                            subtitle={updatedText(t, locale, r.lastGoodRefreshBucket)}
                            meta={
                                dev
                                    ? `${r.lastRefreshOutcome || '—'}${typeof r.routeCount === 'number' ? ` · ${r.routeCount} ${t('subs.routes')}` : ''}`
                                    : undefined
                            }
                            stack={false}
                            trailing={
                                <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                                    <IconButton
                                        icon="refresh"
                                        label={busy ? t('subs.refreshing') : t('subs.refresh')}
                                        dataButton="sub-refresh"
                                        disabled={busy}
                                        onClick={() => void refresh(r.subscriptionId)}
                                    />
                                    <OverflowMenu
                                        label={t('ui.more')}
                                        dataButton="sub-more"
                                        title={name(r)}
                                        items={[
                                            {
                                                id: 'sub-remove',
                                                label: t('subs.remove'),
                                                icon: 'trash',
                                                tone: 'danger',
                                                disabled: busy,
                                                onSelect: () => setConfirmRemove(r),
                                            },
                                        ]}
                                    />
                                </span>
                            }
                            last={i === rows.length - 1}
                        />
                    );
                })}
            </div>
            {confirmRemove && (
                <div
                    data-sub-confirm
                    style={{
                        marginBlock: '8px 10px',
                        padding: '12px 14px',
                        borderRadius: 'var(--r-tile)',
                        border: `1px solid ${mix('var(--red)', 45, 'var(--line-soft)')}`,
                        background: mix('var(--red)', 8, 'transparent'),
                    }}
                >
                    <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--fg)' }}>
                        {t('subs.confirm_remove.title').replace('{name}', name(confirmRemove))}
                    </div>
                    <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.45, marginBlockStart: 4 }}>
                        {t('subs.confirm_remove.help')}
                    </div>
                    <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginBlockStart: 10, flexWrap: 'wrap' }}>
                        <Button variant="ghost" dataButton="sub-remove-cancel" onClick={() => setConfirmRemove(null)}>
                            {t('common.cancel')}
                        </Button>
                        <Button
                            variant="danger"
                            dataButton="sub-remove-confirm"
                            disabled={busyId === confirmRemove.subscriptionId}
                            onClick={() => void remove(confirmRemove.subscriptionId)}
                        >
                            {t('subs.remove')}
                        </Button>
                    </div>
                </div>
            )}
        </Card>
    );
}
