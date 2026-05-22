// RoutesPage.tsx — list of routes with lede, tap-to-expand row actions.
//
// A "route" is one concrete connectable endpoint. The default row
// shows just the nickname, family/trust/health meta and provenance
// (subscription source or "pinned manually"). The four actions
// (Connect / Cooldown 15m / Cap / Redistribute) appear only when the
// user clicks the row open.

import { useEffect, useState } from 'react';
import AddEntryModal from '../components/AddEntryModal';
import RouteBudgetModal from '../components/RouteBudgetModal';
import { useContract } from '../contract/ContractProvider';
import type { RouteDisplayRow } from '../contract/D2Contract';
import { Button, Card } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

export default function RoutesPage({ t }: Props) {
    const contract = useContract();
    const [open, setOpen] = useState(false);
    const [routes, setRoutes] = useState<RouteDisplayRow[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [budgetFor, setBudgetFor] = useState<RouteDisplayRow | null>(null);
    const [expandedId, setExpandedId] = useState<string | null>(null);

    const load = async () => {
        try {
            const r = await contract.availableRoutes();
            setRoutes(r);
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
                    {t('routes.title')}
                </h1>
                <Button onClick={() => setOpen(true)} size="md">
                    + {t('routes.add')}
                </Button>
            </header>
            <p
                style={{
                    color: 'var(--muted)',
                    fontSize: 13,
                    margin: '0 0 18px',
                    maxWidth: 64,
                    maxInlineSize: '64ch',
                }}
            >
                {t('page.routes.lede')}
            </p>

            {error && (
                <div
                    style={{
                        background: 'rgba(200,85,61,0.10)',
                        border: '1px solid rgba(200,85,61,0.40)',
                        color: 'var(--red)',
                        padding: 12,
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 16,
                        fontSize: 13,
                    }}
                >
                    {error}
                </div>
            )}

            {routes === null ? (
                <EmptyState text={t('common.loading')} />
            ) : routes.length === 0 ? (
                <EmptyState text={t('routes.empty')} />
            ) : (
                <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {routes.map((r) => {
                        const isOpen = expandedId === r.routeId;
                        return (
                            <li key={r.routeId} style={{ marginBottom: 8 }}>
                                <Card
                                    style={{
                                        cursor: 'pointer',
                                        padding: 0,
                                    }}
                                >
                                    <div
                                        onClick={() =>
                                            setExpandedId(
                                                isOpen ? null : r.routeId,
                                            )
                                        }
                                        style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: 12,
                                            padding: '12px 14px',
                                        }}
                                        role="button"
                                        aria-expanded={isOpen}
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
                                                {r.routeNickname}
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
                                                {r.family} · {r.trustClass}
                                                {typeof r.healthPct ===
                                                    'number' &&
                                                    ` · ${r.healthPct}%`}
                                                {r.inCooldown && ' · cooldown'}
                                                {r.budgetExhausted &&
                                                    ' · budget'}
                                            </div>
                                            <div
                                                style={{
                                                    fontFamily:
                                                        'var(--font-mono)',
                                                    fontSize: 10,
                                                    color: 'var(--muted)',
                                                    marginTop: 4,
                                                    letterSpacing: '0.04em',
                                                }}
                                            >
                                                {r.sourceName
                                                    ? `${t(
                                                          'routes.from_source',
                                                      )} ${r.sourceName}`
                                                    : t('routes.pinned_manual')}
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
                                                onClick={async () => {
                                                    try {
                                                        await contract.connect(
                                                            r.routeId,
                                                        );
                                                    } catch {
                                                        /* ignore */
                                                    }
                                                }}
                                                size="sm"
                                            >
                                                {t('routes.connect') ||
                                                    'Connect'}
                                            </Button>
                                            <Button
                                                variant="secondary"
                                                size="sm"
                                                onClick={async () => {
                                                    try {
                                                        await contract.applyCooldown(
                                                            r.routeId,
                                                            15 * 60 * 1000,
                                                            'manual',
                                                        );
                                                        await load();
                                                    } catch {
                                                        /* ignore */
                                                    }
                                                }}
                                            >
                                                {t('routes.cooldown') ||
                                                    'Cool 15m'}
                                            </Button>
                                            <Button
                                                variant="secondary"
                                                size="sm"
                                                onClick={() => setBudgetFor(r)}
                                            >
                                                {t('routes.budget') || 'Cap'}
                                            </Button>
                                            <Button
                                                variant="secondary"
                                                size="sm"
                                                title={t('routes.redistribute.tip')}
                                                onClick={async () => {
                                                    try {
                                                        await contract.redistributeRoute(
                                                            r.routeId,
                                                        );
                                                        await load();
                                                    } catch {
                                                        /* ignore */
                                                    }
                                                }}
                                            >
                                                ⇄
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
                    mode="route"
                    onClose={() => {
                        setOpen(false);
                        void load();
                    }}
                />
            )}
            {budgetFor && (
                <RouteBudgetModal
                    t={t}
                    route={budgetFor}
                    onClose={() => setBudgetFor(null)}
                    onSaved={() => {
                        setBudgetFor(null);
                        void load();
                    }}
                />
            )}
        </div>
    );
}

function EmptyState({ text }: { text: string }) {
    return (
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
            {text}
        </div>
    );
}
