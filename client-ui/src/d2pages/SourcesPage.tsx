// SourcesPage.tsx — subscriptions (user-visible name "Sources"). One
// row per subscription, collapsed by default to display name + route
// count + last-refresh meta. Tap to reveal Refresh / Remove actions.
// Engine APIs and i18n keys retain `subscription_*` per D-2 §3.

import { useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { SubscriptionRow } from '../contract/D2Contract';
import AddEntryModal from '../components/AddEntryModal';
import { Button, Card } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

export default function SourcesPage({ t }: Props) {
    const contract = useContract();
    const [rows, setRows] = useState<SubscriptionRow[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [open, setOpen] = useState(false);
    const [expandedId, setExpandedId] = useState<string | null>(null);

    const load = async () => {
        try {
            const r = await contract.subscriptionList();
            setRows(r);
            setError(null);
        } catch (e) {
            setError((e as Error).message || 'unknown');
        }
    };
    useEffect(() => {
        load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [contract]);

    return (
        <div
            style={{
                padding: 'var(--gutter)',
                width: '100%',
                maxWidth: 980,
                margin: '0 auto',
            }}
        >
            <header
                style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    marginBottom: 8,
                    flexWrap: 'wrap',
                }}
            >
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 24,
                        color: 'var(--fg)',
                        margin: 0,
                    }}
                >
                    {t('subs.title')}
                </h1>
                <div style={{ display: 'flex', gap: 8 }}>
                    <Button
                        variant="secondary"
                        size="md"
                        title={t('sources.refresh.tip')}
                        onClick={async () => {
                            try {
                                await contract.revocationRefreshAll(8000);
                                await load();
                            } catch {
                                /* ignore */
                            }
                        }}
                    >
                        ↻ Revocations
                    </Button>
                    <Button onClick={() => setOpen(true)}>
                        + {t('subs.add')}
                    </Button>
                </div>
            </header>
            <p
                style={{
                    color: 'var(--muted)',
                    fontSize: 13,
                    margin: '0 0 18px',
                    maxInlineSize: '64ch',
                }}
            >
                {t('page.sources.lede')}
            </p>

            {error && (
                <div
                    style={{
                        background: 'rgba(200,85,61,0.10)',
                        border: '1px solid rgba(200,85,61,0.40)',
                        color: 'var(--red)',
                        padding: 12,
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 20,
                        fontSize: 13,
                    }}
                >
                    {t('common.error')}: {error}
                </div>
            )}

            {rows == null && !error && (
                <div style={{ color: 'var(--muted)', fontSize: 14 }}>
                    {t('subs.loading')}
                </div>
            )}
            {rows && rows.length === 0 && (
                <div
                    style={{
                        background: 'var(--surface)',
                        border: '1px dashed var(--line)',
                        borderRadius: 'var(--r-card)',
                        padding: 48,
                        textAlign: 'center',
                        color: 'var(--muted)',
                        fontSize: 14,
                    }}
                >
                    {t('subs.empty')}
                </div>
            )}
            {rows && rows.length > 0 && (
                <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {rows.map((r) => {
                        const isOpen = expandedId === r.subscriptionId;
                        const countLabel =
                            typeof r.routeCount === 'number'
                                ? r.routeCount === 1
                                    ? t('sources.route_count_one')
                                    : t('sources.route_count_other').replace(
                                          '{n}',
                                          String(r.routeCount),
                                      )
                                : t('sources.route_count_unknown');
                        return (
                            <li
                                key={r.subscriptionId}
                                style={{ marginBottom: 8 }}
                            >
                                <Card style={{ padding: 0 }}>
                                    <div
                                        role="button"
                                        aria-expanded={isOpen}
                                        onClick={() =>
                                            setExpandedId(
                                                isOpen
                                                    ? null
                                                    : r.subscriptionId,
                                            )
                                        }
                                        style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: 12,
                                            padding: '12px 14px',
                                            cursor: 'pointer',
                                        }}
                                    >
                                        <div style={{ flex: 1, minWidth: 0 }}>
                                            <div
                                                style={{
                                                    fontFamily:
                                                        'var(--font-display)',
                                                    fontSize: 15,
                                                    color: 'var(--fg)',
                                                    fontWeight: 500,
                                                }}
                                            >
                                                {r.displayName ||
                                                    r.profileTitle}
                                            </div>
                                            <div
                                                style={{
                                                    fontFamily:
                                                        'var(--font-mono)',
                                                    fontSize: 11,
                                                    color: 'var(--dim)',
                                                    marginTop: 2,
                                                }}
                                            >
                                                {countLabel} ·{' '}
                                                {t('subs.last_refresh')}:{' '}
                                                {r.lastRefreshBucket || '—'}
                                                {r.lastRefreshOutcome &&
                                                    ` · ${r.lastRefreshOutcome}`}
                                            </div>
                                        </div>
                                        <span
                                            aria-hidden
                                            style={{
                                                color: 'var(--dim)',
                                                fontSize: 14,
                                                transform: isOpen
                                                    ? 'rotate(180deg)'
                                                    : 'none',
                                                transition:
                                                    'transform var(--t-fast)',
                                            }}
                                        >
                                            ⌄
                                        </span>
                                    </div>
                                    {isOpen && (
                                        <div
                                            style={{
                                                display: 'flex',
                                                flexWrap: 'wrap',
                                                gap: 8,
                                                padding: '0 14px 14px',
                                                borderTop:
                                                    '1px solid var(--line-soft)',
                                                paddingTop: 12,
                                            }}
                                        >
                                            <Button
                                                size="sm"
                                                onClick={async () => {
                                                    await contract.subscriptionRefresh(
                                                        r.subscriptionId,
                                                        5000,
                                                    );
                                                    await load();
                                                }}
                                            >
                                                {t('subs.refresh')}
                                            </Button>
                                            <Button
                                                variant="danger"
                                                size="sm"
                                                onClick={async () => {
                                                    await contract.subscriptionRemove(
                                                        r.subscriptionId,
                                                    );
                                                    await load();
                                                }}
                                            >
                                                {t('subs.remove')}
                                            </Button>
                                        </div>
                                    )}
                                </Card>
                            </li>
                        );
                    })}
                </ul>
            )}

            {open && (
                <AddEntryModal
                    t={t}
                    mode="source"
                    onClose={async () => {
                        setOpen(false);
                        await load();
                    }}
                />
            )}
        </div>
    );
}
