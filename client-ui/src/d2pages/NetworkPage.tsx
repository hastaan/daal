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
import ScanSheet from '../components/ScanSheet';
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
    const [scanOpen, setScanOpen] = useState(false);
    const [budgetFor, setBudgetFor] = useState<RouteDisplayRow | null>(null);
    // Which route the user just tapped Connect on. Used to render
    // per-row "Connecting…" feedback (disables the button + swaps the
    // label) so a sub-second `contract.connect` resolution doesn't
    // feel like a dead tap.
    const [connectingId, setConnectingId] = useState<string | null>(null);
    // The route the engine reports as currently connected (from the 2 s
    // connectionSummary poll), or null. Drives Connect ↔ Disconnect and the
    // active-route highlight — without this poll the page had no live link
    // truth, so a connected route still read "Connect / not tested yet".
    const [activeRouteId, setActiveRouteId] = useState<string | null>(null);
    // Whether the loaded engine has a data plane at all. On desktop it
    // does not (core/abi links engine.NewStub), so engine_set_route
    // refuses with ErrNoDataPlane — deliberately, because the Stub would
    // otherwise publish "Connected" without opening a socket.
    //
    // ConnectionPage already reads this, but ConnectionPage's Connect
    // only fires when an active route EXISTS. The first connect on a
    // fresh install happens HERE, on the per-route button, so without
    // this the refusal reached the user as the raw Go error string —
    // in English, to a Farsi user, complete with a `-tags singbox`
    // build instruction. `undefined` is "unknown", not "none": an older
    // engine emits no field and must not be accused.
    const [noDataPlane, setNoDataPlane] = useState(false);

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

    // Live connection poll (same source of truth as ConnectionPage and the
    // shell title bar): read connectionSummary every 2 s and remember which
    // route the engine is actually routing through.
    useEffect(() => {
        let alive = true;
        const tick = async () => {
            try {
                const s = await contract.connectionSummary();
                if (!alive) return;
                setActiveRouteId(
                    s.state === 'connected'
                        ? s.activeRoute?.routeId ?? null
                        : null,
                );
                setNoDataPlane(s.dataPlane === 'none');
            } catch {
                /* transient read failure — keep last known state */
            }
        };
        void tick();
        const id = setInterval(() => void tick(), 2000);
        return () => {
            alive = false;
            clearInterval(id);
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [contract]);

    const onDisconnect = async () => {
        setError(null);
        // Optimistic: clear the active route immediately so the button flips
        // to "Connect" without waiting for the next poll; the poll reconciles.
        setActiveRouteId(null);
        try {
            await contract.disconnect();
            await load();
        } catch (e) {
            setError((e as Error).message || String(e) || 'disconnect failed');
        }
    };

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
                    <Button
                        variant="secondary"
                        onClick={() => setScanOpen(true)}
                        size="md"
                    >
                        {t('scan.open')}
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

            {noDataPlane && (
                <div
                    role="alert"
                    style={{
                        background: 'rgba(200,85,61,0.10)',
                        border: '1px solid var(--danger, #c0392b)',
                        color: 'var(--fg)',
                        padding: 12,
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 16,
                        fontSize: 13,
                    }}
                >
                    <strong style={{ display: 'block', marginBottom: 6 }}>
                        {t('conn.no_data_plane.title')}
                    </strong>
                    <span style={{ opacity: 0.9 }}>
                        {t('conn.no_data_plane.body')}
                    </span>
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
                            // displayName, not publisherId: the tree is
                            // grouped by display name (so it is unique by
                            // construction) and publisherId is empty for a
                            // subscription-only row whose first refresh
                            // has not landed.
                            key={p.displayName}
                            t={t}
                            p={p}
                            open={expanded.has(p.displayName)}
                            onToggle={() => toggle(p.displayName)}
                            connectingId={connectingId}
                            activeRouteId={activeRouteId}
                            onDisconnect={onDisconnect}
                            onConnectRoute={async (routeId) => {
                                setError(null);
                                // Optimistic feedback: flag the row so
                                // its button reads "Connecting…" and
                                // disables, instantly. Cleared in
                                // finally so error/success both
                                // re-enable the affordance.
                                // Refuse before the press does anything.
                                // The engine would refuse anyway; letting
                                // the call through only swaps honest,
                                // translated copy for a developer string.
                                if (noDataPlane) {
                                    setError(t('conn.no_data_plane.title'));
                                    return;
                                }
                                setConnectingId(routeId);
                                try {
                                    await contract.connect(routeId);
                                    // Optimistic: mark this route active so
                                    // the button flips to "Disconnect" at
                                    // once; the 2 s poll reconciles.
                                    setActiveRouteId(routeId);
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
                            onRemovePublisher={async () => {
                                if (
                                    !window.confirm(
                                        t('network.remove_publisher_confirm'),
                                    )
                                )
                                    return;
                                try {
                                    // Drop the tunnel ONLY if the live route
                                    // belongs to this publisher. The bare
                                    // disconnect that used to sit here fired
                                    // on every removal, so tidying up
                                    // publisher B killed a working tunnel
                                    // through publisher A — on a censored
                                    // network, with no warning and nothing in
                                    // the confirm text to explain it.
                                    const ownsActiveRoute =
                                        activeRouteId !== null &&
                                        p.cells.some((c) =>
                                            c.routes.some(
                                                (r) => r.routeId === activeRouteId,
                                            ),
                                        );
                                    if (ownsActiveRoute) {
                                        await contract.disconnect().catch(() => {});
                                    }
                                    await contract.publisherDelete(p.publisherId);
                                    await load();
                                } catch (e) {
                                    setError(String(e));
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
            {scanOpen && (
                <ScanSheet
                    t={t}
                    onClose={() => setScanOpen(false)}
                    onImported={() => void load()}
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
    onRemovePublisher: () => void | Promise<void>;
    /** Route id whose Connect button is currently in flight, or null. */
    connectingId: string | null;
    /** Route id the engine is currently connected through, or null. */
    activeRouteId: string | null;
    /** Tear down the active tunnel. */
    onDisconnect: () => void | Promise<void>;
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
    onRemovePublisher,
    connectingId,
    activeRouteId,
    onDisconnect,
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
                        const isActive = activeRouteId === r0.routeId;
                        const isConnecting = connectingId === r0.routeId;
                        const anyInFlight = connectingId !== null;
                        return (
                            <Button
                                size="sm"
                                variant={isActive ? 'secondary' : 'primary'}
                                disabled={anyInFlight}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    if (isActive) void onDisconnect();
                                    else void onConnectRoute(r0.routeId);
                                }}
                            >
                                {isConnecting
                                    ? t('network.connecting')
                                    : isActive
                                    ? t('network.disconnect')
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
                                activeRouteId={activeRouteId}
                                onDisconnect={onDisconnect}
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
                        {/* Only offered when there is an engine publisher
                            to remove. A subscription-only row whose first
                            refresh has not landed has no publisher_id, so
                            this action could only ever no-op; its own
                            "Remove" above (onRemoveSub) is the real one. */}
                        {p.publisherId !== '' && (
                            <div
                                style={{
                                    display: 'flex',
                                    justifyContent: 'flex-end',
                                    paddingTop: 6,
                                    borderTop: '1px dashed var(--line-soft)',
                                }}
                            >
                                <Button
                                    variant="danger"
                                    size="sm"
                                    onClick={() => void onRemovePublisher()}
                                >
                                    {t('network.remove_publisher')}
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
    activeRouteId,
    onDisconnect,
}: {
    t: (k: string) => string;
    cell: CellRow;
    onConnectRoute: (routeId: string) => void | Promise<void>;
    onCool: (routeId: string) => void | Promise<void>;
    onBudget: (r: RouteDisplayRow) => void;
    connectingId: string | null;
    activeRouteId: string | null;
    onDisconnect: () => void | Promise<void>;
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
                {cell.routes.map((r) => {
                    const isActive = activeRouteId === r.routeId;
                    return (
                    <li
                        key={r.routeId}
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                            padding: '6px 8px',
                            borderTop: '1px dashed var(--line-soft)',
                            borderInlineStart: isActive
                                ? '2px solid var(--green)'
                                : '2px solid transparent',
                            background: isActive
                                ? 'rgba(80,200,120,0.08)'
                                : 'transparent',
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
                                    color: isActive
                                        ? 'var(--green)'
                                        : 'var(--dim)',
                                }}
                            >
                                {r.family}
                                {r.familyMaturity === 'unsupported' &&
                                    ` · ${t('network.family.unsupported')}`}
                                {isActive && ` · ${t('network.connected')}`}
                                {/* Presence, not truthiness: a missing
                                    healthPct means "never measured" and
                                    must not print as 0%. */}
                                {typeof r.healthPct === 'number'
                                    ? ` · ${r.healthPct}%`
                                    : ` · ${t('network.unmeasured')}`}
                                {/* `=== true` on purpose: undefined here
                                    means the path manager has not looked
                                    at this route, which is not the same
                                    as "not cooled" — so we claim neither. */}
                                {r.inCooldown === true && ` · ${t('network.cooled')}`}
                                {r.budgetExhausted === true && ` · ${t('network.budget_full')}`}
                            </div>
                        </div>
                        <Button
                            size="sm"
                            variant={isActive ? 'secondary' : 'primary'}
                            disabled={connectingId !== null}
                            onClick={() =>
                                isActive
                                    ? void onDisconnect()
                                    : void onConnectRoute(r.routeId)
                            }
                        >
                            {isActive
                                ? t('network.disconnect')
                                : connectingId === r.routeId
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
                    );
                })}
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
    const [open, setOpen] = useState(false);
    const cooled = chip.cooledCount > 0;
    // Three grades now reach this chip, not one boolean:
    //   unsupported — this build cannot dial the family at all
    //   experimental — dialable, unproven, never soaked. NOT "gated":
    //     the 3A experimental filter (pathmanager/family_filter.go) has
    //     no production caller — nothing in core/abi ever invokes
    //     ExperimentalFilter / RankWithExperimentalGate — so the
    //     Settings toggle records a preference the selector does not
    //     read. The chip text must not promise a gate that isn't wired.
    //   stable / other — no badge
    // The old code only knew "experimental", derived from a mirror that
    // omitted the five families the Go table wrongly graded Stable, so
    // tuic / shadowsocks / tor-bridge / wireguard / amneziawg rendered
    // as ordinary supported families.
    const unsupported = chip.maturity === 'unsupported';
    const exp = chip.maturity === 'experimental';
    // A per-family help line, when one exists, beats the generic grade
    // line. The grade says how PROVEN a transport is; it cannot say what
    // a transport is FOR, and for some families that difference is the
    // whole point. shadowsocks is the case that forced this: it is the
    // only family Daal serves with no TLS handshake, so it survives a
    // classifier that threatens the other three at once — and it is also
    // the best-studied target of entropy classifiers, so it is weak on
    // its own. "Experimental transport — unproven in the field" is true
    // and tells the user neither half. translate() returns the key
    // unchanged when there is no string, which is the miss signal.
    const famHelpKey = `network.family.${chip.family.replace(/-/g, '_')}.help`;
    const famHelpRaw = t(famHelpKey);
    const famHelp = famHelpRaw === famHelpKey ? '' : famHelpRaw;
    const bg = cooled
        ? 'rgba(200,85,61,0.10)'
        : unsupported
        ? 'rgba(140,140,150,0.12)'
        : exp
        ? 'rgba(193,158,80,0.10)'
        : 'var(--surface)';
    const border = cooled
        ? '1px solid rgba(200,85,61,0.40)'
        : unsupported
        ? '1px dashed var(--line)'
        : exp
        ? '1px solid rgba(193,158,80,0.40)'
        : '1px solid var(--line-soft)';
    const fg = cooled
        ? 'var(--red)'
        : unsupported
        ? 'var(--muted)'
        : exp
        ? 'var(--gold-warm)'
        : 'var(--fg)';
    // The generic "this build cannot dial it" first, because that is the
    // part that decides whether the route can be used at all — then the
    // family's own explanation when there is one. amneziawg needs both:
    // a route so labelled cannot be dialled AND an AmneziaWG config the
    // user pastes becomes an ordinary WireGuard route, which is a
    // different fact and the one they will otherwise be surprised by.
    const detail = cooled
        ? `${t('network.cooled')}${chip.lastErrorTag ? ` · ${chip.lastErrorTag}` : ''}`
        : unsupported
        ? `${t('network.family.unsupported.help')}${famHelp ? ` ${famHelp}` : ''}`
        : exp
        ? famHelp || t('network.family.experimental.help')
        : famHelp;

    // TAP TO REVEAL, NOT HOVER TO REVEAL.
    //
    // Every per-family value claim on this page used to be delivered
    // ONLY through `title=`, which is a hover tooltip. Android is the
    // primary target platform and the only hardware this project has;
    // a mobile WebView has no hover, so `title` never fires and the
    // whole sentence — tuic's "this is not a new way in", wireguard's
    // "one of the first shapes Iranian operators block on sight",
    // shadowsocks' "not a stronger route" — was unreachable on the one
    // device that matters. The badge word alone ("experimental") says
    // none of it.
    //
    // So the chip is a button: `title` still serves desktop hover, and
    // a tap expands the same text inline. flexBasis 100% makes the
    // expanded line take its own row inside the wrapping flex
    // container rather than squeezing the chips.
    return (
        <>
        <button
            type="button"
            onClick={detail ? () => setOpen((v) => !v) : undefined}
            aria-expanded={detail ? open : undefined}
            title={detail ? `${chip.family} · ${detail}` : chip.family}
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
                cursor: detail ? 'pointer' : 'default',
                textAlign: 'start',
            }}
        >
            {cooled && '🚨 '}
            {unsupported && !cooled && '⛔ '}
            {exp && !cooled && '⚡ '}
            {chip.family} · {chip.count}
            {unsupported
                ? ` · ${t('network.family.unsupported')}`
                : typeof chip.healthPct === 'number'
                ? ` · ${chip.healthPct}%`
                : ` · ${t('network.unmeasured')}`}
            {detail && (open ? ' ▴' : ' ▾')}
        </button>
        {detail && open && (
            <div
                style={{
                    flexBasis: '100%',
                    fontSize: 11,
                    lineHeight: 1.5,
                    color: 'var(--muted)',
                    background: bg,
                    border,
                    borderRadius: 'var(--r-card)',
                    padding: '6px 10px',
                }}
            >
                {detail}
            </div>
        )}
        </>
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
