// NetworkPage.tsx — D-2 unified Connections page.
//
// Replaces the old Routes + Sources split with one publisher-rooted
// tree (Publisher → Cell → Family → Route) that mirrors what the
// engine actually stores in core/routestore. M1 renders the static
// tree built by buildPublisherTree() from existing engine projections;
// later milestones wire connect-by-scope (M3), cooldown chips (M4),
// and editable cell labels (M5).

import { useEffect, useRef, useState } from 'react';
import AddSheet from '../components/AddSheet';
import MyAddressSheet from '../components/MyAddressSheet';
import ScanSheet from '../components/ScanSheet';
import RouteBudgetModal from '../components/RouteBudgetModal';
import { useContract } from '../contract/ContractProvider';
import type {
    BurnpressureVerdict,
    CellRow,
    ConnectionSummary,
    FamilyChip,
    PublisherTreeRow,
    RouteDisplayRow,
} from '../contract/D2Contract';
import { Button, Card } from '../design/primitives';
import {
    connectFailedKey,
    connectRefusedKey,
    parseConnectRefused,
    refusedToShow,
    type ConnectRefused,
} from '../lib/routeCheck';
import { runningRouteId, summaryExtras } from '../lib/activeRoute';
import { errorText } from '../lib/errorText';
import {
    acceptPending,
    listView,
    pendingFailureKey,
    resolvePending,
    rowAction,
    rowActionDisabled,
    rowActionLabelKey,
    rowState,
    rowStateLabelKey,
    runningPhase,
    startPending,
    switchingAwayFromRunning,
    type PendingConnect,
    type RunningPhase,
} from '../lib/networkRows';
import { markStoreResetNoticeSeen, storeResetNoticeDue } from '../lib/storeNotice';
import { EngineStartNotice, FailureBox, StoreResetNotice } from './PageNotices';
import { useEngineStartProblem } from '../lib/engineStart';

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
    // The list could not be read: the RAW error text, for the details
    // fold only. What the person reads is `network.load_failed`.
    const [loadError, setLoadError] = useState<string | null>(null);
    // Something the person asked for did not happen: the i18n key of our
    // own sentence, and the raw error text when there is one.
    // `routeId` is set when the sentence is about one route's connect, so
    // it can be taken down the moment that route is reported connected.
    const [failure, setFailure] = useState<{ key: string; detail?: string; routeId?: string } | null>(null);
    const [expanded, setExpanded] = useState<Set<string>>(new Set());
    const [addOpen, setAddOpen] = useState(false);
    const [addrOpen, setAddrOpen] = useState(false);
    const [scanOpen, setScanOpen] = useState(false);
    const [budgetFor, setBudgetFor] = useState<RouteDisplayRow | null>(null);
    // The route the user tapped Connect on, until the ENGINE has
    // answered for it — not until the connect call returns: on Android
    // that call resolves as soon as the VPN service is started, long
    // before the engine has decided anything. While it is set the row
    // reads "Checking the connection…" with a Cancel button, and the
    // route that was connected before the tap stays marked connected
    // until the engine reports the new one (lib/networkRows.ts).
    const [pending, setPendingState] = useState<PendingConnect | null>(null);
    const pendingRef = useRef<PendingConnect | null>(null);
    const setPending = (p: PendingConnect | null) => {
        pendingRef.current = p;
        setPendingState(p);
    };
    // Set when the person cancelled the connect they started here: the
    // connect call then rejects ("connection attempt cancelled"), which
    // is the expected outcome and not an error to report.
    const cancelledRef = useRef(false);
    // What the engine is doing with the route it has running: proved
    // ('steady'), still proving it, or lost and being retried.
    const [verifying, setVerifying] = useState<RunningPhase>('steady');
    const lastSummaryRef = useRef<ConnectionSummary | null>(null);
    // The engine set a damaged store aside at start; said once.
    const [storeReset, setStoreReset] = useState(false);
    // Daal could not start its engine: nothing here can work, and the
    // page says that instead of "could not read… Try again".
    const [startProblem, reportRejection] = useEngineStartProblem();
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
    // Why the engine refused the last connect, as a closed code. On
    // Android it is the only way the reason arrives (the connect call
    // resolves when the VPN service starts, before the engine decides).
    const [refused, setRefused] = useState<ConnectRefused | undefined>(undefined);
    // The refusal that answered a Connect tap made on THIS page. Kept
    // apart from the polled one because it must be shown even while
    // another route stays connected (the engine refuses before touching
    // the running route): the poll-driven sentence is hidden then, and
    // the tap used to end in silence. Cleared by the next tap.
    const [tapRefused, setTapRefused] = useState<ConnectRefused | undefined>(undefined);
    const refusedShown = refusedToShow(refused, tapRefused, activeRouteId !== null);

    const load = async () => {
        try {
            const [tr, v] = await Promise.all([
                contract.listPublishers(),
                contract.burnpressureVerdict(),
            ]);
            setTree(tr);
            setVerdict(v);
            setLoadError(null);
        } catch (e) {
            // A rejected Tauri command is a plain string, not an Error;
            // errorText reads either. The rows already on screen stay.
            setLoadError(errorText(e));
            reportRejection(e);
        }
    };

    // Everything the page takes from one connectionSummary read,
    // including the answer to a tap that is still waiting for one.
    const applySummary = (s: ConnectionSummary) => {
        lastSummaryRef.current = s;
        // "Active" is whatever the engine has RUNNING, not only
        // what it has finished proving: a route still being
        // checked, or lost and being retried, must be stoppable
        // here too. Offering Connect for it called connect on a
        // route in its cooldown (refused) and left no way to stop
        // it from this page.
        setActiveRouteId(runningRouteId(s));
        setVerifying(runningPhase(s));
        setRefused(s.connectRefused);
        // A "could not connect" sentence about a route the engine now
        // reports connected is no longer true (the permission dialog
        // can outlast the page's patience, and the connect then goes
        // through): take it down.
        if (s.state === 'connected' && s.activeRoute?.routeId) {
            const up = s.activeRoute.routeId;
            setFailure((f) => (f && f.routeId === up ? null : f));
        }
        setNoDataPlane(s.dataPlane === 'none');
        setStoreReset(storeResetNoticeDue(summaryExtras(s).storeRecovered));
        const p = pendingRef.current;
        if (!p) return;
        const outcome = resolvePending(p, s, Date.now());
        if (outcome === 'waiting') return;
        setPending(null);
        const note = summaryExtras(s).lastSwitch;
        const noteIsOurs = note?.routeId === p.routeId;
        if (outcome === 'refused') {
            // Shown also while the old route stays connected: the
            // engine refuses before it touches what is running. The
            // service's note carries the code when the engine's blob no
            // longer does.
            setTapRefused(
                s.connectRefused ??
                    (noteIsOurs ? parseConnectRefused(note?.reason) ?? 'other' : undefined),
            );
        } else if (outcome === 'failed' || outcome === 'timeout') {
            // Never end a tap in silence: a failed switch that left the
            // old route connected says so, and a wait that ran out says
            // that too.
            setFailure({
                key:
                    pendingFailureKey(p.routeId, outcome, s) ??
                    connectFailedKey(s.routeCheck, s.routeCheckCategory),
                routeId: p.routeId,
            });
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
                applySummary(s);
            } catch (e) {
                /* transient read failure — keep last known state */
                reportRejection(e);
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

    // Stops whatever the engine has running. Also how a connection check
    // is cancelled — the engine abandons it at once — whether this page
    // started it or not: the same mechanism as the Connection page's
    // main button.
    const onDisconnect = async () => {
        setFailure(null);
        setTapRefused(undefined);
        if (pendingRef.current) cancelledRef.current = true;
        setPending(null);
        // Optimistic: clear the active route immediately so the button flips
        // to "Connect" without waiting for the next poll; the poll reconciles.
        setActiveRouteId(null);
        setVerifying('steady');
        try {
            await contract.disconnect();
            await load();
        } catch (e) {
            setFailure({ key: 'network.action_failed', detail: errorText(e) });
        }
    };

    const onConnectRoute = async (routeId: string) => {
        setFailure(null);
        setTapRefused(undefined);
        // Refuse before the press does anything. The engine would
        // refuse anyway; letting the call through only swaps honest,
        // translated copy for a developer string.
        if (noDataPlane) {
            setFailure({ key: 'conn.no_data_plane.title' });
            return;
        }
        // One connect at a time from this page; the tapped row offers
        // Cancel meanwhile.
        if (pendingRef.current) return;
        cancelledRef.current = false;
        setPending(startPending(routeId, Date.now(), lastSummaryRef.current));
        // Read through a function: the ref changes while this handler is
        // suspended (the poll answers, the person cancels), which the
        // compiler's narrowing of `pendingRef.current` cannot know.
        const current = (): PendingConnect | null => pendingRef.current;
        const stillOurs = () => current()?.routeId === routeId;
        try {
            await contract.connect(routeId);
            // The call returning is not the answer everywhere (on
            // Android it means "the VPN service was started"). Ask the
            // engine now rather than waiting out the poll; nothing is
            // marked connected on the strength of the call alone.
            const mine = stillOurs() ? current() : null;
            if (mine) {
                // The host has accepted the connect: the wait for the
                // engine's answer is counted from here.
                setPending(acceptPending(mine, Date.now()));
                try {
                    applySummary(await contract.connectionSummary());
                } catch {
                    /* the poll will catch up */
                }
            }
            void load();
        } catch (e) {
            // Cancelled by the person, or the poll already reported how
            // it ended: nothing more to say.
            if (cancelledRef.current || !stillOurs()) return;
            // A refusal the engine can name gets its own sentence, shown
            // whether or not another route is still connected. A route
            // that started and failed its connection check gets the
            // sentence the Connection page shows for the same event. The
            // host's own error text ("engine call returned -1") goes
            // under Details, never into the sentence.
            let summary: ConnectionSummary | undefined;
            try {
                summary = await contract.connectionSummary();
            } catch {
                /* the plain sentence below */
            }
            setPending(null);
            if (summary) applySummary(summary);
            const code = summary?.connectRefused;
            if (code) {
                setRefused(code);
                setTapRefused(code);
            } else {
                setFailure({
                    key: connectFailedKey(summary?.routeCheck, summary?.routeCheckCategory),
                    detail: errorText(e),
                    routeId,
                });
            }
        }
    };

    const pendingId = pending?.routeId ?? null;
    const view = listView(tree, loadError !== null);

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

            {storeReset && (
                <StoreResetNotice
                    t={t}
                    onDismiss={() => {
                        markStoreResetNoticeSeen();
                        setStoreReset(false);
                    }}
                />
            )}

            {refusedShown && !failure && (
                <div
                    role="alert"
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
                    {t(connectRefusedKey(refusedShown))}
                </div>
            )}

            {failure && (
                <FailureBox t={t} text={t(failure.key)} detail={failure.detail} />
            )}

            {startProblem && <EngineStartNotice t={t} detail={startProblem.detail} />}

            {loadError !== null && !startProblem && (
                <FailureBox
                    t={t}
                    text={t('network.load_failed')}
                    detail={loadError}
                    onRetry={() => void load()}
                />
            )}

            {view === 'loading' ? (
                <EmptyState text={t('common.loading')} />
            ) : view === 'failed' ? null : view === 'empty' || tree === null ? (
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
                            pendingId={pendingId}
                            verifying={verifying}
                            activeRouteId={activeRouteId}
                            onDisconnect={onDisconnect}
                            onConnectRoute={onConnectRoute}
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
                                    setFailure({
                                        key: 'network.action_failed',
                                        detail: errorText(e),
                                    });
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
    /** Route id tapped here whose answer has not come back, or null. */
    pendingId: string | null;
    /** The engine is still proving the route it has running. */
    verifying: RunningPhase;
    /** Route id the engine currently has running, or null. */
    activeRouteId: string | null;
    /** Tear down the active tunnel (also cancels a connection check). */
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
    pendingId,
    verifying,
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
                    {trivial && allRoutes[0] && (
                        <RouteActionButton
                            t={t}
                            routeId={allRoutes[0].routeId}
                            activeRouteId={activeRouteId}
                            pendingId={pendingId}
                            verifying={verifying}
                            onConnectRoute={onConnectRoute}
                            onDisconnect={onDisconnect}
                        />
                    )}
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
                                pendingId={pendingId}
                                verifying={verifying}
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

// The one button a route has: Connect, Cancel (while its connection is
// being checked) or Disconnect. Used by the collapsed publisher row and
// by every route row, so the two can never disagree.
function RouteActionButton({
    t,
    routeId,
    activeRouteId,
    pendingId,
    verifying,
    onConnectRoute,
    onDisconnect,
}: {
    t: (k: string) => string;
    routeId: string;
    activeRouteId: string | null;
    pendingId: string | null;
    verifying: RunningPhase;
    onConnectRoute: (routeId: string) => void | Promise<void>;
    onDisconnect: () => void | Promise<void>;
}) {
    const action = rowAction(
        rowState(routeId, activeRouteId, pendingId, verifying),
        switchingAwayFromRunning(routeId, activeRouteId, pendingId),
    );
    return (
        <Button
            size="sm"
            variant={action === 'connect' ? 'primary' : 'secondary'}
            disabled={rowActionDisabled(action, pendingId)}
            onClick={(e) => {
                e.stopPropagation();
                if (action === 'connect') void onConnectRoute(routeId);
                else void onDisconnect();
            }}
        >
            {t(rowActionLabelKey(action))}
        </Button>
    );
}

function CellRowView({
    t,
    cell,
    onConnectRoute,
    onCool,
    onBudget,
    pendingId,
    verifying,
    activeRouteId,
    onDisconnect,
}: {
    t: (k: string) => string;
    cell: CellRow;
    onConnectRoute: (routeId: string) => void | Promise<void>;
    onCool: (routeId: string) => void | Promise<void>;
    onBudget: (r: RouteDisplayRow) => void;
    pendingId: string | null;
    verifying: RunningPhase;
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
                    const state = rowState(
                        r.routeId,
                        activeRouteId,
                        pendingId,
                        verifying,
                    );
                    const isActive = state === 'connected';
                    // A route that stopped carrying traffic is drawn like
                    // one being checked: not green, and with its own words.
                    const isChecking = state === 'checking' || state === 'lost';
                    const stateLabel = rowStateLabelKey(state);
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
                                : isChecking
                                ? '2px solid var(--gold-warm)'
                                : '2px solid transparent',
                            background: isActive
                                ? 'rgba(80,200,120,0.08)'
                                : isChecking
                                ? 'rgba(193,158,80,0.08)'
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
                                        : isChecking
                                        ? 'var(--gold-warm)'
                                        : 'var(--dim)',
                                }}
                            >
                                {r.family}
                                {r.familyMaturity === 'unsupported' &&
                                    ` · ${t('network.family.unsupported')}`}
                                {stateLabel && ` · ${t(stateLabel)}`}
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
                        <RouteActionButton
                            t={t}
                            routeId={r.routeId}
                            activeRouteId={activeRouteId}
                            pendingId={pendingId}
                            verifying={verifying}
                            onConnectRoute={onConnectRoute}
                            onDisconnect={onDisconnect}
                        />
                        <Button
                            variant="secondary"
                            size="sm"
                            disabled={pendingId !== null}
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
