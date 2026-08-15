// NetworkPage.tsx — D-2 unified Connections page.
//
// Replaces the old Routes + Sources split with one publisher-rooted
// tree (Publisher → Cell → Family → Route) that mirrors what the
// engine actually stores in core/routestore. M1 renders the static
// tree built by buildPublisherTree() from existing engine projections;
// later milestones wire connect-by-scope (M3), cooldown chips (M4),
// and editable cell labels (M5).

import { useEffect, useState } from 'react';
import AddSheet from '../components/AddSheet';
import MyAddressSheet from '../components/MyAddressSheet';
import RouteBudgetModal from '../components/RouteBudgetModal';
import { useContract } from '../contract/ContractProvider';
import type {
    BurnpressureVerdict,
    CellRow,
    FamilyChip,
    PublisherTreeRow,
    RouteDisplayRow,
} from '../contract/D2Contract';
import { Button, Card } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

function sourceBadge(p: PublisherTreeRow, t: (k: string) => string): string {
    switch (p.sourceKind) {
        case 'sbpx':
            return t('network.badge.sealed');
        case 'sbp':
            return t('network.badge.signed');
        case 'subscription':
            return t('network.badge.subscription');
        case 'pasted':
            return t('network.badge.pasted');
        case 'mixed':
            return t('network.badge.mixed');
    }
}

function trustGlyph(level: string): string {
    if (level === 'trusted') return '🛡';
    if (level === 'pinned') return '🤝';
    return '·';
}

export default function NetworkPage({ t }: Props) {
    const contract = useContract();
    const [tree, setTree] = useState<PublisherTreeRow[] | null>(null);
    const [verdict, setVerdict] = useState<BurnpressureVerdict | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<Set<string>>(new Set());
    const [addOpen, setAddOpen] = useState(false);
    const [addrOpen, setAddrOpen] = useState(false);
    const [budgetFor, setBudgetFor] = useState<RouteDisplayRow | null>(null);
    // Which route the user just tapped Connect on. Used to render
    // per-row "Connecting…" feedback (disables the button + swaps the
    // label) so a sub-second `contract.connect` resolution doesn't
    // feel like a dead tap.
    const [connectingId, setConnectingId] = useState<string | null>(null);

    const load = async () => {
        try {
            const [tr, v] = await Promise.all([
                contract.listPublishers(),
                contract.burnpressureVerdict(),
            ]);
            setTree(tr);
            setVerdict(v);
            setError(null);
        } catch (e) {
            setError((e as Error).message || 'unknown');
        }
    };
    useEffect(() => {
        void load();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [contract]);

    const toggle = (id: string) => {
        setExpanded((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

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
                    {t('network.title')}
                </h1>
                <div style={{ display: 'flex', gap: 8 }}>
                    <Button
                        variant="secondary"
                        onClick={() => setAddrOpen(true)}
                        size="md"
                    >
                        {t('network.my_address')}
                    </Button>
                    <Button onClick={() => setAddOpen(true)} size="md">
                        + {t('network.add')}
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
                {t('network.lede')}
            </p>

            {verdict?.promote && (
                <div
                    style={{
                        background: 'rgba(193,158,80,0.10)',
                        border: '1px solid rgba(193,158,80,0.40)',
                        color: 'var(--gold-warm)',
                        padding: '10px 14px',
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 16,
                        fontSize: 13,
                    }}
                >
                    {t('network.banner.autopromoted')}
                </div>
            )}

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

            {tree === null ? (
                <EmptyState text={t('common.loading')} />
            ) : tree.length === 0 ? (
                <EmptyState text={t('network.empty')} />
            ) : (
                <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                    {tree.map((p) => (
                        <PublisherRowView
                            key={p.publisherId}
                            t={t}
                            p={p}
                            open={expanded.has(p.publisherId)}
                            onToggle={() => toggle(p.publisherId)}
                            connectingId={connectingId}
                            onConnectRoute={async (routeId) => {
                                setError(null);
                                // Optimistic feedback: flag the row so
                                // its button reads "Connecting…" and
                                // disables, instantly. Cleared in
                                // finally so error/success both
                                // re-enable the affordance.
                                setConnectingId(routeId);
                                try {
                                    await contract.connect(routeId);
                                    // Move user to the Connection page so
                                    // they see the link state transition.
                                    // (No router; we just refresh state.)
                                    await load();
                                } catch (e) {
                                    // Engine connect errors are usually
                                    // either route-not-found or the
                                    // sing-box runner not running. Show
                                    // the raw message — better than a
                                    // dead-feeling button.
                                    setError(
                                        (e as Error).message ||
                                            String(e) ||
                                            'connect failed',
                                    );
                                } finally {
                                    setConnectingId(null);
                                }
                            }}
                            onCool={async (routeId) => {
                                try {
                                    await contract.applyCooldown(
                                        routeId,
                                        15 * 60 * 1000,
                                        'manual',
                                    );
                                    await load();
                                } catch {
                                    /* ignore */
                                }
                            }}
                            onBudget={(r) => setBudgetFor(r)}
                            onRefresh={async () => {
                                if (!p.subscription) return;
                                try {
                                    await contract.subscriptionRefresh(
                                        p.subscription.subscriptionId,
                                        5000,
                                    );
                                    await load();
                                } catch {
                                    /* ignore */
                                }
                            }}
                            onRemoveSub={async () => {
                                if (!p.subscription) return;
                                try {
                                    await contract.subscriptionRemove(
                                        p.subscription.subscriptionId,
                                    );
                                    await load();
                                } catch {
                                    /* ignore */
                                }
                            }}
                        />
                    ))}
                </ul>
            )}

            {addOpen && (
                <AddSheet
                    t={t}
                    onClose={() => {
                        setAddOpen(false);
                        void load();
                    }}
                    onImported={() => void load()}
                />
            )}
            {addrOpen && (
                <MyAddressSheet t={t} onClose={() => setAddrOpen(false)} />
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

interface PublisherRowProps {
    t: (k: string) => string;
    p: PublisherTreeRow;
    open: boolean;
    onToggle: () => void;
    onConnectRoute: (routeId: string) => void | Promise<void>;
    onCool: (routeId: string) => void | Promise<void>;
    onBudget: (r: RouteDisplayRow) => void;
    onRefresh: () => void | Promise<void>;
    onRemoveSub: () => void | Promise<void>;
    /** Route id whose Connect button is currently in flight, or null. */
    connectingId: string | null;
}

function PublisherRowView({
    t,
    p,
    open,
    onToggle,
    onConnectRoute,
    onCool,
    onBudget,
    onRefresh,
    onRemoveSub,
    connectingId,
}: PublisherRowProps) {
    // The "trivial" case: one publisher with one cell and one route.
    // We collapse the entire row to a single Connect button so a
    // .sbpx recipient like Bahar never has to think about cells.
    const allRoutes = p.cells.flatMap((c) => c.routes);
    const trivial = p.cells.length <= 1 && allRoutes.length === 1;

    const meta = (() => {
        const sub = p.subscription;
        if (sub) {
            return `${sourceBadge(p, t)} · ${t('network.last_refresh')}: ${
                sub.lastRefreshBucket || '—'
            }${sub.lastRefreshOutcome ? ` · ${sub.lastRefreshOutcome}` : ''}`;
        }
        if (allRoutes.length === 0) return sourceBadge(p, t);
        const fams = Array.from(new Set(allRoutes.map((r) => r.family))).join(', ');
        return `${sourceBadge(p, t)} · ${fams}`;
    })();

    return (
        <li style={{ marginBottom: 8 }}>
            <Card style={{ padding: 0 }}>
                <div
                    role="button"
                    aria-expanded={open}
                    onClick={onToggle}
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
                                fontFamily: 'var(--font-display)',
                                fontSize: 15,
                                color: 'var(--fg)',
                                fontWeight: 500,
                            }}
                        >
                            {trustGlyph(p.trustLevel)} {p.displayName}
                        </div>
                        <div
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 11,
                                color: 'var(--dim)',
                                marginTop: 2,
                            }}
                        >
                            {meta}
                            {' · '}
                            {p.routeCount === 1
                                ? t('network.route_count_one')
                                : t('network.route_count_other').replace(
                                      '{n}',
                                      String(p.routeCount),
                                  )}
                        </div>
                    </div>
                    {trivial && allRoutes[0] && (() => {
                        const r0 = allRoutes[0];
                        const isConnecting = connectingId === r0.routeId;
                        const anyInFlight = connectingId !== null;
                        return (
                            <Button
                                size="sm"
                                disabled={anyInFlight}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    void onConnectRoute(r0.routeId);
                                }}
                            >
                                {isConnecting
                                    ? t('network.connecting')
                                    : t('network.connect')}
                            </Button>
                        );
                    })()}
                    <span
                        aria-hidden
                        style={{
                            color: 'var(--dim)',
                            fontSize: 14,
                            marginInlineStart: 8,
                            transform: open ? 'rotate(180deg)' : 'none',
                            transition: 'transform var(--t-fast)',
                        }}
                    >
                        ⌄
                    </span>
                </div>
                {open && (
                    <div
                        style={{
                            borderTop: '1px solid var(--line-soft)',
                            padding: '12px 14px',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 10,
                        }}
                    >
                        {p.cells.map((cell) => (
                            <CellRowView
                                key={cell.cellIdFpHex}
                                t={t}
                                cell={cell}
                                onConnectRoute={onConnectRoute}
                                onCool={onCool}
                                onBudget={onBudget}
                                connectingId={connectingId}
                            />
                        ))}
                        {p.subscription && (
                            <div
                                style={{
                                    display: 'flex',
                                    gap: 8,
                                    flexWrap: 'wrap',
                                    paddingTop: 6,
                                    borderTop: '1px dashed var(--line-soft)',
                                }}
                            >
                                <Button
                                    variant="secondary"
                                    size="sm"
                                    onClick={() => void onRefresh()}
                                >
                                    ↻ {t('network.refresh')}
                                </Button>
                                <Button
                                    variant="danger"
                                    size="sm"
                                    onClick={() => void onRemoveSub()}
                                >
                                    {t('network.remove')}
                                </Button>
                            </div>
                        )}
                    </div>
                )}
            </Card>
        </li>
    );
}

function CellRowView({
    t,
    cell,
    onConnectRoute,
    onCool,
    onBudget,
    connectingId,
}: {
    t: (k: string) => string;
    cell: CellRow;
    onConnectRoute: (routeId: string) => void | Promise<void>;
    onCool: (routeId: string) => void | Promise<void>;
    onBudget: (r: RouteDisplayRow) => void;
    connectingId: string | null;
}) {
    return (
        <div>
            {/* M1: cell label is purely descriptive. M5 adds inline edit. */}
            {cell.label && (
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: 'var(--muted)',
                        marginBottom: 4,
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                    }}
                >
                    {cell.label}
                </div>
            )}
            {cell.families.length > 0 && (
                <div
                    style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        gap: 6,
                        marginBottom: 8,
                    }}
                >
                    {cell.families.map((f) => (
                        <FamilyChipView key={f.family} t={t} chip={f} />
                    ))}
                </div>
            )}
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                {cell.routes.map((r) => (
                    <li
                        key={r.routeId}
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            padding: '6px 0',
                            borderTop: '1px dashed var(--line-soft)',
                        }}
                    >
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <div
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 12,
                                    color: 'var(--fg)',
                                }}
                            >
                                {r.routeNickname}
                            </div>
                            <div
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 10,
                                    color: 'var(--dim)',
                                }}
                            >
                                {r.family}
                                {r.proven && typeof r.healthPct === 'number'
                                    ? ` · ${r.healthPct}%`
                                    : ` · ${t('network.untested')}`}
                                {r.inCooldown && ` · ${t('network.cooled')}`}
                                {r.budgetExhausted && ` · ${t('network.budget_full')}`}
                            </div>
                        </div>
                        <Button
                            size="sm"
                            disabled={connectingId !== null}
                            onClick={() => void onConnectRoute(r.routeId)}
                        >
                            {connectingId === r.routeId
                                ? t('network.connecting')
                                : t('network.connect')}
                        </Button>
                        <Button
                            variant="secondary"
                            size="sm"
                            disabled={connectingId !== null}
                            onClick={() => void onCool(r.routeId)}
                            title={t('network.cool_15m')}
                        >
                            ❄
                        </Button>
                        <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => onBudget(r)}
                            title={t('network.cap')}
                        >
                            ⓘ
                        </Button>
                    </li>
                ))}
            </ul>
        </div>
    );
}

function FamilyChipView({
    t,
    chip,
}: {
    t: (k: string) => string;
    chip: FamilyChip;
}) {
    const cooled = chip.cooledCount > 0;
    const exp = chip.experimental;
    const bg = cooled
        ? 'rgba(200,85,61,0.10)'
        : exp
        ? 'rgba(193,158,80,0.10)'
        : 'var(--surface)';
    const border = cooled
        ? '1px solid rgba(200,85,61,0.40)'
        : exp
        ? '1px solid rgba(193,158,80,0.40)'
        : '1px solid var(--line-soft)';
    const fg = cooled ? 'var(--red)' : exp ? 'var(--gold-warm)' : 'var(--fg)';
    return (
        <span
            title={
                cooled
                    ? `${chip.family} · ${t('network.cooled')}${
                          chip.lastErrorTag ? ` · ${chip.lastErrorTag}` : ''
                      }`
                    : chip.family
            }
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: fg,
                background: bg,
                border,
                padding: '2px 8px',
                borderRadius: 999,
                letterSpacing: '0.04em',
            }}
        >
            {cooled && '🚨 '}
            {exp && !cooled && '⚡ '}
            {chip.family} · {chip.count}
            {chip.proven && typeof chip.healthPct === 'number'
                ? ` · ${chip.healthPct}%`
                : ` · ${t('network.untested')}`}
        </span>
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
