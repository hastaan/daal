// ConnectionPage.tsx — D-2.1 Connection screen.
//
// Visual contract: client-shared/designs/daal-desktop.html (.work + .work-main + .rail).
// Data contract: client-ui/src/contract/d2-contract.ts
//   - connectionSummary()  : state, mode, activeRoute, networkLabel, pointerValidDays
//   - whyThisRoute()       : active + reasonText + skipped[]
//   - pointerRotation()    : lastRotated, validForDays, rotatedSuccessfully
//   - routeHealth()        : RouteHealthDisplayRow[]
//   - connect/disconnect/setMode/exportDiagnostics
//
// No legacy `bridge.diagnostics()` usage. The titlebar + connection-duration
// ticker live in the active shell (lifted state); this page only renders the
// center hero + right rail and dispatches actions.

import { useEffect, useRef, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type {
    ConnectionSummary,
    WhyThisRouteSummary,
    PointerRotationSummary,
    RouteHealthDisplayRow,
    ThroughputSnapshot,
    ConnState,
    ConnMode,
    RouteDisplayRow,
} from '../contract/D2Contract';
import { effectiveLocale } from '../lib/i18n';
import { useDensity } from '../design/DensityProvider';
import DaalButton, { type DaalConnectState } from '../components/DaalButton';
import WayChooser from '../components/connection/WayChooser';
import AutoFailure from '../components/connection/AutoFailure';
import MeasuredDetails from '../components/connection/MeasuredDetails';
import { anyMeasured } from '../lib/measured';
import AddSheet from '../components/AddSheet';
import { Button } from '../design/primitives';
import {
    autoFailure,
    autoProgressText,
    autoVerdictKey,
    failureSignature,
    getPinnedRoute,
    rememberPassFailure,
    setPinnedRoute,
    staleFailureAfterStart,
    startConnect,
    type PassFailure,
} from '../lib/autoConnect';
import { mainScreenView, retryTarget, runMainTap } from '../lib/mainScreen';
import StatusLine from '../components/connection/StatusLine';
import ModeChip from '../components/connection/ModeChip';
import WhyThisRoute from '../components/connection/WhyThisRoute';
import RouteHealthBars from '../components/connection/RouteHealthBars';
import PointerBanner from '../components/connection/PointerBanner';
import ModePickerSheet from '../components/connection/ModePickerSheet';
import { idOnlyRoute, routeForDisplay, summaryExtras } from '../lib/activeRoute';
import { markStoreResetNoticeSeen, storeResetNoticeDue } from '../lib/storeNotice';
import { EngineStartNotice, StoreResetNotice } from './PageNotices';
import { tapAllowedWithStartProblem, useEngineStartProblem } from '../lib/engineStart';
import RecoverySheet from '../components/RecoverySheet';
import type { SectionId } from '../shell/Sidebar';

interface Props {
    t: (k: string) => string;
    onNavigate: (s: SectionId) => void;
}

/** How often the route list is re-read while it could not be read. */
const ROUTES_RETRY_MS = 10_000;

// (what this page shows and what a tap does: lib/mainScreen.ts; copy
// for the connection-check states: lib/routeCheck.ts; for automatic
// connect: lib/autoConnect.ts)
function toDaalConnectState(s: ConnState): DaalConnectState {
    return s;
}

// `bps` is nullable on purpose: null means the build has no byte
// accounting, which is NOT the same as a measured zero. The caller
// shows no speed line in that case rather than "0 B/s"; see
// ThroughputSnapshot in contract/D2Contract.ts.
function formatBps(bps: number): string {
    if (!Number.isFinite(bps) || bps <= 0) return '0 B/s';
    const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s'];
    let v = bps;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i++;
    }
    return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export default function ConnectionPage({ t, onNavigate }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const [conn, setConn] = useState<ConnectionSummary | null>(null);
    const [why, setWhy] = useState<WhyThisRouteSummary | null>(null);
    const [pointer, setPointer] = useState<PointerRotationSummary | null>(null);
    const [health, setHealth] = useState<RouteHealthDisplayRow[]>([]);
    const [throughput, setThroughput] = useState<ThroughputSnapshot | null>(null);
    const [showMode, setShowMode] = useState(false);
    const [showRecovery, setShowRecovery] = useState(false);
    const [busy, setBusy] = useState(false);
    // A connect this page asked for and has not heard back from. On
    // desktop the call returns only when the engine has finished
    // checking the route (seconds; longer on a slow link), so a tap
    // meanwhile must be able to cancel it — `busy` alone used to
    // swallow that tap.
    const [connectInFlight, setConnectInFlight] = useState(false);
    // Set when the user cancelled the connect in flight: its rejection
    // ("connection attempt cancelled") is then the expected outcome and
    // must not open the recovery sheet.
    const cancelledRef = useRef(false);
    // Phone-only: the right rail (why-this-route + health + pointer
    // banner) collapses behind a single disclosure header so the first
    // paint is the Daal mark and route chip only.
    const [diagOpen, setDiagOpen] = useState(false);
    // Optimistic-UI flag: while a user-initiated connect/disconnect is
    // in flight, override the FSM-derived state so the eagle and
    // headline reflect the user's intent instantly instead of waiting
    // for the next 2 s diagnostics poll. Cleared whenever the polled
    // state matches the optimistic target, OR after a 6 s safety
    // timeout so a stuck backend can never freeze the UI.
    const [optimistic, setOptimistic] = useState<ConnState | null>(null);
    // Transient user-facing notice (export result, failed mode change, …).
    const [notice, setNotice] = useState<string | null>(null);
    // The engine set a damaged store aside at start; said once
    // (lib/storeNotice.ts), here and on the Connections page.
    const [storeReset, setStoreReset] = useState(false);
    // Daal could not start its engine. Without this the page drew an
    // ordinary "not connected" with a Connect button, as if it had read
    // that from somewhere.
    const [startProblem, reportRejection] = useEngineStartProblem();
    // The routes on this device, read strictly: `undefined` until read,
    // and whenever the list could not be read — which is not "none".
    // "Add your file" is offered only on a list that was read and is
    // empty.
    const [routes, setRoutes] = useState<RouteDisplayRow[] | undefined>(undefined);
    const routesReadRef = useRef<{ hint: number | undefined; atMs: number; ok: boolean } | null>(null);
    // The route the person chose by hand (null = Automatic, the
    // default). Remembered across launches (lib/autoConnect.ts).
    const [pinnedRaw, setPinnedRaw] = useState<string | null>(() => getPinnedRoute());
    const [chooserOpen, setChooserOpen] = useState(false);
    const [showAdd, setShowAdd] = useState(false);
    // What the connect this page last started was: automatic, or the
    // pinned route. Chooses the words while the page is still showing
    // its own optimistic "connecting".
    const [intent, setIntent] = useState<'auto' | 'pinned' | null>(null);
    // An automatic connect whose call itself failed (the host could not
    // start it): the generic sentence, never the caught text.
    const [hostFailed, setHostFailed] = useState(false);
    // True once this page has seen a connection up: when the engine
    // then moves to another route by itself the words are "that way
    // stopped working", not a first-time "trying way 2 of 4".
    const wasConnectedRef = useRef(false);
    // The last automatic pass that tried something and found nothing:
    // its sentence stays on screen when the next answer is only "the
    // ways are resting" (lib/autoConnect.ts failureToShow).
    const rememberedRef = useRef<PassFailure | undefined>(undefined);
    // Every summary this page takes goes through here.
    const applyConn = (c: ConnectionSummary) => {
        rememberedRef.current = rememberPassFailure(rememberedRef.current, c);
        setConn(c);
    };
    useEffect(() => {
        if (!notice) return;
        const id = setTimeout(() => setNotice(null), 4000);
        return () => clearTimeout(id);
    }, [notice]);
    const locale = effectiveLocale();

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const [c, w, p, h] = await Promise.all([
                    contract.connectionSummary(),
                    contract.whyThisRoute(),
                    contract.pointerRotation(),
                    contract.routeHealth(),
                ]);
                if (cancelled) return;
                applyConn(c);
                setStoreReset(storeResetNoticeDue(summaryExtras(c).storeRecovered));
                setWhy(w);
                setPointer(p);
                setHealth(h);
                void readRoutes(c.routeCountHint, false);
                // Clear optimistic flag as soon as the polled state
                // agrees with what the user asked for, so the UI
                // converges to the truth.
                // "Connected" also answers an optimistic "connecting":
                // nothing was connected when the person tapped, so it
                // cannot be old news — and a quick route can be proved
                // between two polls, which used to leave "Connecting…"
                // over a working connection until the safety timeout.
                setOptimistic((prev) => {
                    if (!prev) return prev;
                    if (prev === c.state) return null;
                    if (prev === 'connecting' && c.state === 'connected') return null;
                    return prev;
                });
            } catch (e) {
                reportRejection(e);
                if (!cancelled) {
                    setConn((prev) =>
                        prev
                            ? { ...prev, state: 'error' as ConnState }
                            : null,
                    );
                }
            }
        };
        tick();
        const id = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    // Reads the route list when there is a reason to: never read yet,
    // the engine's own count moved, it could not be read last time (not
    // more often than ROUTES_RETRY_MS), or `force` (a file was just
    // added). Not on every poll: the list changes only when the person
    // adds or removes something.
    const readRoutes = async (hint: number | undefined, force: boolean) => {
        const last = routesReadRef.current;
        const now = Date.now();
        if (!force && last) {
            const retryDue = !last.ok && now - last.atMs >= ROUTES_RETRY_MS;
            if (last.hint === hint && !retryDue) return;
        }
        const mark = { hint, atMs: now, ok: false };
        routesReadRef.current = mark;
        let rows: RouteDisplayRow[] | undefined;
        try {
            rows = await contract.routesStrict();
        } catch {
            rows = undefined;
        }
        mark.ok = rows !== undefined;
        setRoutes(rows);
    };

    // Throughput poll — only when state=connected, 1 s cadence.
    useEffect(() => {
        if (conn?.state !== 'connected') {
            setThroughput(null);
            return;
        }
        let cancelled = false;
        const tick = async () => {
            try {
                const tp = await contract.throughputSnapshot();
                if (!cancelled) setThroughput(tp);
            } catch { /* ignore */ }
        };
        tick();
        const id = setInterval(tick, 1000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [conn?.state, contract]);

    // Everything this page shows and what a tap does, decided in one
    // place (lib/mainScreen.ts) from what was read and what the page
    // itself knows.
    const view = mainScreenView({
        t,
        locale,
        nowMs: Date.now(),
        conn,
        optimistic,
        connectInFlight,
        intent,
        hostFailed,
        pinnedRaw,
        routes,
        wasConnected: wasConnectedRef.current,
        remembered: rememberedRef.current,
    });
    const { state, auto, plan, failure } = view;
    const mode: ConnMode = conn?.mode ?? 'normal';
    // The pin that still means something: a pinned route this device no
    // longer holds is no choice at all (back to Automatic).
    const pinnedId = view.pinnedId;
    useEffect(() => {
        if (pinnedRaw && pinnedId === null) {
            setPinnedRoute(null);
            setPinnedRaw(null);
        }
    }, [pinnedRaw, pinnedId]);
    if (state === 'connected') wasConnectedRef.current = true;
    else if (!view.holding && (state === 'disconnected' || state === 'error')) wasConnectedRef.current = false;

    // A failed pass has just rested some routes: the list read before it
    // does not know. Read it again, so the panel can say how long the
    // wait is and switch off a "Try again" that could do nothing.
    const failureSig = failureSignature(conn);
    useEffect(() => {
        if (failureSig !== undefined) void readRoutes(conn?.routeCountHint, true);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [failureSig]);

    // The loaded engine has no data plane linked: engine_set_route will
    // refuse (core/abi/dataplane.go), and it refuses precisely because
    // the Stub driver would otherwise publish "Connected" without
    // opening a socket. Say so up front rather than letting the user
    // press Connect and get a generic recovery sheet. `undefined` is
    // "unknown", not "none" — an older engine emits no field and must
    // not be accused.
    const noDataPlane = conn?.dataPlane === 'none';

    // Safety net: never let an optimistic state linger longer than
    // 6 s. If the backend never converged we drop the override and
    // fall back to whatever the diagnostics blob says.
    useEffect(() => {
        if (!optimistic) return;
        const id = setTimeout(() => setOptimistic(null), 6000);
        return () => clearTimeout(id);
    }, [optimistic]);

    const disconnectNow = async () => {
        // Whatever is running stops: a connected route, a route the
        // engine is still checking (this cancels the check — the
        // engine abandons it at once), an automatic connect wherever
        // it has got to, or a lost connection being retried. Not gated
        // on `busy`: the connect in flight is exactly what this is for.
        if (connectInFlight) cancelledRef.current = true;
        setHostFailed(false);
        // Optimistic: immediately render disconnected so the eagle
        // greys out the moment the user taps; the next poll confirms.
        setOptimistic('disconnected');
        try { await contract.disconnect(); }
        catch { setOptimistic(null); }
    };

    const connectNow = async (
        what: { kind: 'auto' } | { kind: 'pinned'; routeId: string },
    ) => {
        if (busy) return;
        // Daal could not start: the notice on the page says so, and a
        // connect could only fail.
        if (!tapAllowedWithStartProblem(startProblem, 'connect')) return;
        // No data plane: never flip the eagle to "connecting" for a
        // connection this binary cannot make. The engine would refuse
        // anyway; showing intent-state first would be a 6-second lie.
        if (noDataPlane) {
            setNotice(t('conn.no_data_plane.title'));
            return;
        }
        // Optimistic: flip to 'connecting' the instant the tap fires.
        // The eagle pulses, the headline reads "Looking for a way to
        // connect…" (or "Connecting…" for a pinned route), and the tap
        // registers as "something happened" whether the engine answers
        // in <50 ms or after trying every route.
        setIntent(what.kind);
        setHostFailed(false);
        setOptimistic('connecting');
        setBusy(true);
        setConnectInFlight(true);
        cancelledRef.current = false;
        // The failed pass on screen when the tap came, if any: the one
        // reading that must not be mistaken for the answer to this tap.
        const failureAtTap = what.kind === 'auto' ? failureSignature(conn) : undefined;
        try {
            const handedBack = await startConnect(contract, what);
            // The call returning is not the answer everywhere (on
            // Android it means "the VPN service was started"): ask the
            // engine now rather than waiting out the poll. Where it IS
            // the answer (desktop: the call blocks until the engine is
            // done) this is what takes the optimistic state down.
            try {
                const c = await contract.connectionSummary();
                // On Android the service may not have reached the engine
                // yet, and the blob still shows the pass that failed
                // BEFORE this tap. Taking the optimistic state down for
                // it flashed the old failure back (with an enabled "Try
                // again" that cancelled the pass just begun). It stays
                // until a poll shows the new pass, or the safety timeout.
                const stale = staleFailureAfterStart(handedBack !== null, failureAtTap, c);
                if (!stale) applyConn(c);
                if (c.state !== 'disconnected' && !stale) setOptimistic(null);
            } catch { /* the poll will catch up */ }
        } catch {
            setOptimistic(null);
            if (!cancelledRef.current) {
                // What happened is in the engine's own account: a
                // connect it REFUSED (an old file, a route still
                // cooling down) and an automatic connect that found
                // nothing each have their own sentence on the page; a
                // sheet on top would hide the one thing the person can
                // act on.
                let said = false;
                try {
                    const c = await contract.connectionSummary();
                    applyConn(c);
                    said = !!c.connectRefused || autoFailure(c) !== undefined;
                } catch { /* the poll will catch up */ }
                if (!said) {
                    // Automatic has no "other route" to offer: it says
                    // it could not connect, with Try again. A pinned
                    // route gets the sheet of other choices.
                    if (what.kind === 'auto') setHostFailed(true);
                    else setShowRecovery(true);
                }
            }
        } finally {
            setBusy(false);
            setConnectInFlight(false);
        }
    };

    const openAddFile = () => setShowAdd(true);

    const onDaalClick = () =>
        runMainTap(plan, {
            disconnect: disconnectNow,
            addFile: () => {
                if (!tapAllowedWithStartProblem(startProblem, 'connect')) return;
                openAddFile();
            },
            recovery: () => {
                if (busy) return;
                if (!tapAllowedWithStartProblem(startProblem, 'recovery')) return;
                setShowRecovery(true);
            },
            connect: connectNow,
        });

    const onPickRoute = (routeId: string) => {
        setPinnedRoute(routeId);
        setPinnedRaw(routeId);
        setChooserOpen(false);
    };
    const onBackToAuto = () => {
        setPinnedRoute(null);
        setPinnedRaw(null);
        setChooserOpen(false);
        // Connected on a way picked by hand: hand it to the engine NOW.
        // engine_connect_auto on a connected engine starts nothing and
        // takes charge of the route that is up, so "Automatic" on the
        // chip is true from this moment, not from the next connect.
        if (state === 'connected' && !view.engineAuto && !busy) {
            void contract.connectAuto().catch(() => { /* the chip keeps saying what is true */ });
        }
    };
    // "Let Daal choose" after the route the person chose did not work:
    // back to automatic, and connect.
    const onLetDaalChoose = () => {
        setPinnedRoute(null);
        setPinnedRaw(null);
        void connectNow({ kind: 'auto' });
    };

    const onPickMode = async (m: ConnMode) => {
        try {
            await contract.setMode(m);
        } catch {
            // Don't fail silently — tell the user the change didn't take.
            setNotice(t('conn.mode_failed'));
        }
    };

    // Diagnostics export: the Tauri fs plugin isn't wired, so we can't
    // write a file. Rather than show a save dialog that silently does
    // nothing, copy the JSON to the clipboard and say so plainly.
    const onExport = async () => {
        try {
            const json = await contract.exportDiagnostics();
            try {
                await navigator.clipboard.writeText(json);
                setNotice(t('conn.export_copied'));
            } catch {
                setNotice(t('conn.export_failed'));
            }
        } catch {
            setNotice(t('conn.export_failed'));
        }
    };

    const daalLabel = view.tapLabel;
    const { refusedKey, headline, stateLabel, needFile, noRoutes, showProgress } = view;
    const connectedNote = view.connectedNoteKey;
    // The row for the pinned route: its details when the list has them,
    // an id-only row (our own words for its name) when it does not.
    const pinnedRow = pinnedId
        ? routeForDisplay(routes?.find((r) => r.routeId === pinnedId) ?? idOnlyRoute(pinnedId), t) ?? null
        : null;
    const somethingRunning = state === 'connected' || state === 'connecting';

    // Layout: phone → single column, rail stacks under hero.
    // tablet  → single column with wider hero, rail collapses to
    //           cards below.
    // desktop → 1fr / 320px grid (the original layout).
    const isPhone = density === 'phone';
    const isDesktop = density === 'desktop';

    return (
        <div
            style={{
                flex: 1,
                display: isDesktop ? 'grid' : 'flex',
                flexDirection: isDesktop ? undefined : 'column',
                gridTemplateColumns: isDesktop ? '1fr 320px' : undefined,
                minHeight: 0,
                overflow: 'auto',
            }}
        >
            {/* Transient status line (export result, failed mode change). */}
            <div
                aria-live="polite"
                style={{
                    position: 'absolute',
                    insetInlineStart: 0,
                    insetInlineEnd: 0,
                    top: 8,
                    textAlign: 'center',
                    pointerEvents: 'none',
                    zIndex: 10,
                }}
            >
                {notice && (
                    <span
                        style={{
                            display: 'inline-block',
                            padding: '6px 14px',
                            borderRadius: 999,
                            background: 'var(--teal-hairline)',
                            color: 'var(--fg)',
                            fontSize: 13,
                        }}
                    >
                        {notice}
                    </span>
                )}
            </div>

            {/* CENTER: hero */}
            <section
                style={{
                    padding: isPhone ? '20px 4px' : '36px 48px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    overflow: 'auto',
                    borderInlineEnd: isDesktop
                        ? '1px solid var(--teal-hairline)'
                        : undefined,
                }}
            >
                {noDataPlane && (
                    <div
                        role="alert"
                        style={{
                            maxWidth: 520,
                            marginBlockEnd: 20,
                            padding: '12px 16px',
                            borderRadius: 12,
                            border: '1px solid var(--danger, #c0392b)',
                            background: 'var(--surface-2, transparent)',
                            color: 'var(--fg)',
                            textAlign: 'center',
                        }}
                    >
                        <strong style={{ display: 'block', marginBlockEnd: 6 }}>
                            {t('conn.no_data_plane.title')}
                        </strong>
                        <span style={{ fontSize: 13, opacity: 0.9 }}>
                            {t('conn.no_data_plane.body')}
                        </span>
                    </div>
                )}

                {startProblem && <EngineStartNotice t={t} detail={startProblem.detail} />}

                {storeReset && (
                    <StoreResetNotice
                        t={t}
                        onDismiss={() => {
                            markStoreResetNoticeSeen();
                            setStoreReset(false);
                        }}
                    />
                )}

                {refusedKey && (
                    <div
                        role="alert"
                        style={{
                            maxWidth: 520,
                            marginBlockEnd: 20,
                            padding: '12px 16px',
                            borderRadius: 12,
                            border: '1px solid var(--danger, #c0392b)',
                            background: 'var(--surface-2, transparent)',
                            color: 'var(--fg)',
                            textAlign: 'center',
                            fontSize: 14,
                        }}
                    >
                        {t(refusedKey)}
                    </div>
                )}

                <div className={`d2-conn-state-label ${state}`}>{stateLabel}</div>

                <DaalButton
                    state={toDaalConnectState(state)}
                    onClick={onDaalClick}
                    label={daalLabel}
                />

                <h1
                    className="d2-conn-headline"
                    // A verdict is a whole sentence, not three words:
                    // at headline size it filled the phone's screen and
                    // pushed "Try again" off it.
                    style={{
                        marginBlockStart: 24,
                        marginBlockEnd: 10,
                        ...(failure
                            ? { fontSize: 20, lineHeight: 1.4, maxWidth: 520, textAlign: 'center' as const }
                            : {}),
                    }}
                >
                    {headline}
                </h1>

                {/* While automatic connect works through its candidates
                    the progress sentence above is the whole story; the
                    same words again, a little longer, when the engine
                    moved by itself. */}
                {showProgress && wasConnectedRef.current && (
                    <div style={{ fontSize: 13, color: 'var(--ink-soft)', marginBlockEnd: 10 }}>
                        {autoProgressText(t, locale, auto)}
                    </div>
                )}

                {connectedNote && (
                    <div
                        style={{
                            maxWidth: 520,
                            fontSize: 13,
                            color: 'var(--ink-soft)',
                            textAlign: 'center',
                            marginBlockEnd: 12,
                        }}
                    >
                        {t(connectedNote)}
                    </div>
                )}

                {view.holding ? (
                    // Android: the VPN is kept closed while Daal retries.
                    // The phone has no internet meanwhile, so this says
                    // so, and offers both ways out.
                    <AutoFailure
                        t={t}
                        lead={failure ? t(autoVerdictKey(failure.verdict)) : undefined}
                        actionText={t('auto.holding.body')}
                        tried={failure?.tried ?? []}
                        verdict={failure?.verdict ?? ''}
                        retryLabel={t('auto.holding.try_now')}
                        onRetry={() => void connectNow({ kind: 'auto' })}
                        onDisconnect={() => void disconnectNow()}
                    />
                ) : failure ? (
                    <AutoFailure
                        t={t}
                        actionText={failure.actionText}
                        restText={failure.restText}
                        retryOff={failure.retryOff}
                        tried={failure.tried}
                        verdict={failure.verdict}
                        onRetry={failure.noRetry ? undefined : () => void connectNow(retryTarget(pinnedId))}
                        onChoose={failure.wantsChooser ? () => setChooserOpen(true) : undefined}
                        onAddFile={failure.wantsFile || noRoutes ? openAddFile : undefined}
                    />
                ) : view.pinnedFailed ? (
                    // The way the person chose did not work. The way
                    // forward is Daal choosing — not a list to pick from.
                    <div
                        role="alert"
                        style={{
                            maxWidth: 520,
                            marginBlockEnd: 16,
                            textAlign: 'center',
                            fontSize: 14,
                            color: 'var(--fg)',
                        }}
                    >
                        <div style={{ marginBlockEnd: 12 }}>{t('auto.pinned_failed.do')}</div>
                        <Button onClick={onLetDaalChoose}>{t('auto.let_daal_choose')}</Button>
                    </div>
                ) : null}

                {needFile ? (
                    // Nothing imported: say that a file is needed and
                    // offer the way to add one. Never an empty list.
                    <div
                        style={{
                            maxWidth: 520,
                            textAlign: 'center',
                            marginBlockEnd: 16,
                            fontSize: 14,
                            color: 'var(--ink-soft)',
                        }}
                    >
                        <div style={{ marginBlockEnd: 12 }}>{t('auto.need_file.body')}</div>
                        <Button onClick={openAddFile}>{t('auto.add_file')}</Button>
                    </div>
                ) : noRoutes ? null : (
                    <WayChooser
                        t={t}
                        pinned={pinnedRow}
                        routes={routes}
                        // A route whose details could not be read still
                        // has an id: it gets our own words, never an
                        // empty name under "You're connected."
                        running={
                            state === 'connected' ? routeForDisplay(conn?.activeRoute, t) : undefined
                        }
                        engineAuto={view.engineAuto}
                        busy={somethingRunning}
                        open={chooserOpen}
                        onToggle={() => setChooserOpen((v) => !v)}
                        onPick={onPickRoute}
                        onBackToAuto={onBackToAuto}
                        onManage={() => onNavigate('network')}
                    />
                )}

                {/* For the person helping: how each way has done on this
                    network, with the numbers. Folded away; absent when
                    the engine measured nothing. */}
                {routes && anyMeasured(routes) && (
                    <MeasuredDetails
                        t={t}
                        locale={locale}
                        routes={routes}
                        onOpen={() => void readRoutes(conn?.routeCountHint, true)}
                    />
                )}

                <StatusLine
                    locale={locale}
                    t={t}
                    networkLabel={
                        conn?.networkLabel
                            ? t('conn.network.wifi')
                            : undefined
                    }
                    pointerSource={conn?.pointerSource}
                    pointerValidDays={conn?.pointerValidDays}
                />

                {state === 'connected' && (
                    <ModeChip
                        mode={mode}
                        t={t}
                        onClick={() => setShowMode(true)}
                    />
                )}

                {/* A build without byte accounting shows no speed line
                 * at all: "not measured yet" under "You're connected."
                 * read as a verdict on the route (seen on the phone). */}
                {state === 'connected' &&
                    throughput &&
                    throughput.upBytesPerSec !== null &&
                    throughput.downBytesPerSec !== null && (
                    <div
                        className="d2-throughput"
                        style={{
                            marginTop: 14,
                            display: 'flex',
                            gap: 18,
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            color: 'var(--paper-dim)',
                            letterSpacing: '0.08em',
                        }}
                    >
                            <>
                                <span aria-label={t('conn.throughput.up')}>
                                    ↑ {formatBps(throughput.upBytesPerSec)}
                                </span>
                                <span aria-label={t('conn.throughput.down')}>
                                    ↓ {formatBps(throughput.downBytesPerSec)}
                                </span>
                            </>
                    </div>
                )}
            </section>

            {/* RIGHT RAIL
             * On desktop this is a stacked column of sections that sit
             * directly on the page background — no card wrapping. On
             * phone we mirror that exactly: same typography, same
             * sections; we just make the heading row tappable so the
             * body collapses by default. No outer card, so the gold
             * pointer banner doesn't look nested. */}
            {isPhone ? (
                <aside
                    className="d2-rail"
                    style={{ padding: '8px var(--gutter) 24px' }}
                >
                    <button
                        type="button"
                        aria-expanded={diagOpen}
                        onClick={() => setDiagOpen((v) => !v)}
                        style={{
                            appearance: 'none',
                            inlineSize: '100%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: 12,
                            background: 'transparent',
                            border: 0,
                            padding: '6px 0 10px',
                            color: 'var(--fg)',
                            cursor: 'pointer',
                            textAlign: 'start',
                            borderBlockEnd: '1px solid var(--line-soft)',
                        }}
                    >
                        <span>
                            <span
                                className="d2-rail-title"
                                style={{ marginBlockEnd: 4 }}
                            >
                                {t('rail_diagnostic')}
                            </span>
                            <span
                                style={{
                                    display: 'block',
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 14,
                                    fontWeight: 600,
                                    color: 'var(--paper)',
                                }}
                            >
                                {t('why_this_route')}
                            </span>
                        </span>
                        <span
                            aria-hidden
                            style={{
                                color: 'var(--muted)',
                                fontFamily: 'var(--font-mono)',
                                fontSize: 14,
                                transform: diagOpen
                                    ? 'rotate(180deg)'
                                    : 'rotate(0)',
                                transition: 'transform var(--t-fast)',
                            }}
                        >
                            ⌄
                        </span>
                    </button>
                    {diagOpen && (
                        <>
                            <WhyThisRoute data={why} t={t} headless />
                            <RouteHealthBars
                                rows={health}
                                locale={locale}
                                t={t}
                            />
                            <PointerBanner
                                data={pointer}
                                locale={locale}
                                t={t}
                            />
                        </>
                    )}
                </aside>
            ) : (
                <aside className="d2-rail">
                    <WhyThisRoute data={why} t={t} />
                    <RouteHealthBars rows={health} locale={locale} t={t} />
                    <PointerBanner data={pointer} locale={locale} t={t} />
                </aside>
            )}

            {showMode && (
                <ModePickerSheet
                    t={t}
                    current={mode}
                    onPick={onPickMode}
                    onClose={() => setShowMode(false)}
                />
            )}

            {showAdd && (
                <AddSheet
                    t={t}
                    initialTab="file"
                    onClose={() => {
                        setShowAdd(false);
                        void readRoutes(conn?.routeCountHint, true);
                    }}
                    onImported={() => void readRoutes(conn?.routeCountHint, true)}
                />
            )}

            {showRecovery && (
                <RecoverySheet
                    t={t}
                    onClose={() => setShowRecovery(false)}
                    onTryOther={() => {
                        setShowRecovery(false);
                        onNavigate('network');
                    }}
                    onRefreshSources={() => {
                        setShowRecovery(false);
                        onNavigate('network');
                    }}
                    onLifeline={() => {
                        setShowRecovery(false);
                        onPickMode('lifeline');
                    }}
                    onExportDiag={() => {
                        setShowRecovery(false);
                        void onExport();
                    }}
                />
            )}
        </div>
    );
}
