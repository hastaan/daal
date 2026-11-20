// ConnectionPage.tsx — Home (spec C2).
//
// One column, top to bottom: the ⋯ menu; at most one notice; the bird,
// which IS the button; one headline; at most one line ("Using Pars
// Relays · VLESS Reality", "Trying VLESS Reality · 2 of 4" with step
// dots, "4 ways ready · …" with the kinds as chips); at most two badges
// (Slow, Manual, Lifeline); the one gold button and the one link a
// state has. Connected, a card of what Daal knows sits under it: why
// this way, the network, live speed, quality — each row only when the
// engine sent its fact (lib/homeFacts.ts) — with a Details fold listing
// every way once, with its state here and its score. Developer mode
// adds the raw engine detail (ids, decision id, scores) in its own fold.
//
// Desktop: two columns in every state, so the bird never moves: the
// card is the right column while connected ("This connection"), "What
// Daal tried" after a failure, and the ways on this computer otherwise.
//
// What is shown and what a tap does is decided in lib/mainScreen.ts;
// this file draws it and runs the actions. Data contract:
// client-ui/src/contract/d2-contract.ts (connectionSummary, whyThisRoute,
// pointerRotation, routeHealth, connect/disconnect/setMode/
// exportDiagnostics).

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
import { effectiveLocale, toFaDigits } from '../lib/i18n';
import { useDensity } from '../design/DensityProvider';
import DaalButton from '../components/DaalButton';
import WayChooser, { routeLabel } from '../components/connection/WayChooser';
import AutoFailure from '../components/connection/AutoFailure';
import MeasuredDetails from '../components/connection/MeasuredDetails';
import { anyMeasured } from '../lib/measured';
import AddSheet from '../components/AddSheet';
import MyAddressSheet from '../components/MyAddressSheet';
import { Badge, Button, Disclosure, Icon, OverflowMenu, Sheet, useToast } from '../design/primitives';
import type { MenuItem } from '../design/primitives';
import {
    autoFailure,
    failureSignature,
    getPinnedRoute,
    rememberPassFailure,
    setPinnedRoute,
    staleFailureAfterStart,
    startConnect,
    type PassFailure,
} from '../lib/autoConnect';
import { failureDetailsShown, homeBadges, mainScreenView, retryTarget, runMainTap } from '../lib/mainScreen';
import { connectedFacts, rateText, triedRows, wayRows } from '../lib/homeFacts';
import { HomeDetails, HomeFactsCard, ReadyChips, TriedList, TryingSteps, WayList } from '../components/connection/HomeFacts';
import WhyThisRoute from '../components/connection/WhyThisRoute';
import RouteHealthBars from '../components/connection/RouteHealthBars';
import PointerBanner from '../components/connection/PointerBanner';
import ModePickerSheet from '../components/connection/ModePickerSheet';
import { idOnlyRoute, routeForDisplay, summaryExtras } from '../lib/activeRoute';
import { markStoreResetNoticeSeen, storeResetNoticeDue } from '../lib/storeNotice';
import { EngineStartNotice, NoticeRow, StoreResetNotice } from './PageNotices';
import { tapAllowedWithStartProblem, useEngineStartProblem } from '../lib/engineStart';
import RecoverySheet from '../components/RecoverySheet';
import { useDeveloperMode } from '../lib/devMode';
import { isolate } from '../lib/format';
import { useOpenedFileSheet } from '../recipient/openedFile';
import type { SectionId } from '../shell/Sidebar';

interface Props {
    t: (k: string) => string;
    onNavigate: (s: SectionId) => void;
}

/** How often the route list is re-read while it could not be read. */
const ROUTES_RETRY_MS = 10_000;

/** "01:02:03" in the page's digits. (The desktop panel no longer
 *  repeats the elapsed time; the title bar shows it.) */
export function elapsedText(locale: string, ms: number): string {
    const s = Math.floor(Math.max(0, ms) / 1000);
    const pad = (n: number) => String(n).padStart(2, '0');
    const out = `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`;
    return isolate(locale === 'fa' ? toFaDigits(out) : out);
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
    const [showAddress, setShowAddress] = useState(false);
    // A file Android handed to Daal: the add sheet opens on it.
    const [openedPath, setOpenedPath] = useState<string | undefined>(undefined);
    const dev = useDeveloperMode();
    const toast = useToast();
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
    // Optimistic-UI flag: while a user-initiated connect/disconnect is
    // in flight, override the FSM-derived state so the eagle and
    // headline reflect the user's intent instantly instead of waiting
    // for the next 2 s diagnostics poll. Cleared whenever the polled
    // state matches the optimistic target, OR after a 6 s safety
    // timeout so a stuck backend can never freeze the UI.
    const [optimistic, setOptimistic] = useState<ConnState | null>(null);
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
    // Bumped for every handed-over file, so the add sheet always starts
    // fresh on it (even when two files share a path).
    const [addNonce, setAddNonce] = useState(0);
    const openedSheet = useOpenedFileSheet(showAdd, (path) => {
        setOpenedPath(path);
        setAddNonce((n) => n + 1);
        setShowAdd(true);
    });
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
    const { state, plan, failure } = view;
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
            toast.show('bad', t('conn.no_data_plane.title'));
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

    const openAddFile = () => {
        setOpenedPath(undefined);
        setShowAdd(true);
    };

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
            toast.show('bad', t('conn.mode_failed'));
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
                toast.show('good', t('conn.export_copied'), 6000);
            } catch {
                toast.show('bad', t('conn.export_failed'));
            }
        } catch {
            toast.show('bad', t('conn.export_failed'));
        }
    };

    const { refusedKey } = view;
    // The row for the pinned route: its details when the list has them,
    // an id-only row (our own words for its name) when it does not.
    const pinnedRow = pinnedId
        ? routeForDisplay(routes?.find((r) => r.routeId === pinnedId) ?? idOnlyRoute(pinnedId), t) ?? null
        : null;
    const somethingRunning = state === 'connected' || state === 'connecting';
    const isPhone = density === 'phone';
    const isDesktop = density === 'desktop';
    // What Daal knows about the connection, as icon rows: why this way,
    // the network, live speed, quality — each only when the engine sent
    // it (lib/homeFacts.ts).
    const showFacts = state === 'connected' && !view.holding && !optimistic;
    // Slow while connected: the amber ring and the card's Quality badge
    // say it already; a third "Slow" pill under the line was one too many.
    const badges = homeBadges(view, mode).filter((b) => b !== 'slow' || !showFacts);
    const facts = showFacts ? connectedFacts({ t, locale, conn, throughput, pinnedId }) : {};
    // Every way on the device, once each: its state here (in use,
    // resting, failed just now, the engine's grade) and its score. The
    // tries of THIS pass count only while the engine's automatic pass is
    // the one that is up (after a connect by hand an older pass may
    // still be in the block).
    const passUp = conn?.auto?.mode === true && conn.auto.state === 'connected';
    const scores = new Map<string, number>();
    for (const h of health) if (typeof h.pct === 'number') scores.set(h.routeId, h.pct);
    const allWays = wayRows({
        t,
        locale,
        routes,
        activeId: state === 'connected' ? conn?.activeRoute?.routeId : undefined,
        why,
        tried: showFacts && passUp ? conn?.auto?.tried : undefined,
        scores,
        nowMs: Date.now(),
    });
    const waysTitle = t(isPhone ? 'home.details.ways' : 'home.details.ways_device');
    // No fold that opens onto nothing.
    const details = showFacts && allWays.length > 0 ? <HomeDetails t={t} locale={locale} ways={allWays} title={waysTitle} /> : null;
    const failureRows = failure ? triedRows(t, failure.tried, routes) : [];

    // One notice at most: Daal did not start > the saved files were
    // reset > this build cannot carry traffic > the engine refused.
    const notice = startProblem ? (
        <EngineStartNotice t={t} detail={startProblem.detail} />
    ) : storeReset ? (
        <StoreResetNotice
            t={t}
            onDismiss={() => {
                markStoreResetNoticeSeen();
                setStoreReset(false);
            }}
        />
    ) : noDataPlane ? (
        <NoticeRow t={t} text={t('conn.no_data_plane.title')} more={t('conn.no_data_plane.body')} />
    ) : refusedKey ? (
        <NoticeRow t={t} text={t(refusedKey)} />
    ) : null;

    const onTryAgain = () => void connectNow(retryTarget(pinnedId));
    const primaryButton =
        view.primary === 'add_file' ? (
            <Button size="lg" onClick={openAddFile} dataButton="add-my-file">
                {t('auto.add_file')}
            </Button>
        ) : view.primary === 'try_again' ? (
            <Button size="lg" onClick={onTryAgain} disabled={!!failure?.retryOff} dataButton="try-again">
                {t('auto.try_again')}
            </Button>
        ) : view.primary === 'try_now' ? (
            <Button size="lg" onClick={() => void connectNow({ kind: 'auto' })} dataButton="try-now">
                {t('auto.holding.try_now')}
            </Button>
        ) : view.primary === 'let_daal_choose' ? (
            <Button size="lg" onClick={onLetDaalChoose} dataButton="let-daal-choose">
                {t('auto.let_daal_choose')}
            </Button>
        ) : null;
    const link =
        view.link === 'no_file_address' ? (
            <Button variant="link" onClick={() => setShowAddress(true)} dataButton="no-file-address">
                {t('auto.no_file_link')}
            </Button>
        ) : view.link === 'add_new_file' ? (
            <Button variant="link" onClick={openAddFile} dataButton="add-new-file">
                {t('conn.recovery.add')}
            </Button>
        ) : view.link === 'choose' ? (
            <Button variant="link" onClick={() => setChooserOpen(true)} dataButton="choose-way">
                {t('conn.more.choose')}
            </Button>
        ) : view.link === 'disconnect' ? (
            <Button variant="link" onClick={() => void disconnectNow()} dataButton="disconnect">
                {t('auto.holding.disconnect')}
            </Button>
        ) : view.link === 'cancel' ? (
            <Button variant="link" onClick={() => void disconnectNow()} dataButton="cancel-connect">
                {t('conn.cancel_action')}
            </Button>
        ) : null;

    const moreItems: MenuItem[] = [];
    if (routes && routes.length >= 2) {
        moreItems.push({ id: 'choose-way', label: t('conn.more.choose'), icon: 'lock', onSelect: () => setChooserOpen(true) });
    }
    if (routes && routes.length > 0) {
        moreItems.push({ id: 'add-another', label: t('conn.more.add'), icon: 'plus', onSelect: openAddFile });
    }
    moreItems.push({ id: 'my-address', label: t('conn.more.address'), icon: 'person', onSelect: () => setShowAddress(true) });
    moreItems.push({ id: 'status', label: t('conn.more.status'), icon: 'info', onSelect: () => onNavigate('status') });

    // The desktop's right column, in every state so the bird never moves
    // sideways: this connection while connected, what was tried after a
    // failure, the ways on this computer otherwise (an empty column when
    // there are none).
    const panel: 'connected' | 'failed' | 'ways' | 'empty' | null = !isDesktop
        ? null
        : showFacts
        ? 'connected'
        : failure && !view.holding && failureDetailsShown(failure.tried, dev)
        ? 'failed'
        : allWays.length > 0
        ? 'ways'
        : 'empty';

    const helperFold = dev ? (
        <div data-dev style={{ inlineSize: '100%', maxWidth: 'var(--content-max)', marginBlockStart: 24 }}>
            <Disclosure summary={t('ui.helper_fold')} variant="card" icon="help" dataButton="helper-fold">
                <div style={{ display: 'grid', gap: 12, fontSize: 13, color: 'var(--muted)', textAlign: 'start' }}>
                    <div>{view.detail}</div>
                    {view.connectedNoteKey && <div>{t(view.connectedNoteKey)}</div>}
                    {state === 'connected' &&
                        throughput &&
                        throughput.upBytesPerSec !== null &&
                        throughput.downBytesPerSec !== null && (
                            <div
                                className="d2-throughput"
                                style={{ display: 'flex', gap: 18, fontFamily: 'var(--font-mono)', fontSize: 12 }}
                            >
                                <bdi dir="ltr" aria-label={t('conn.throughput.down')}>↓ {rateText(throughput.downBytesPerSec, locale)}</bdi>
                                <bdi dir="ltr" aria-label={t('conn.throughput.up')}>↑ {rateText(throughput.upBytesPerSec, locale)}</bdi>
                            </div>
                        )}
                    {routes && anyMeasured(routes) && (
                        <MeasuredDetails
                            t={t}
                            locale={locale}
                            routes={routes}
                            onOpen={() => void readRoutes(conn?.routeCountHint, true)}
                        />
                    )}
                    <WhyThisRoute data={why} t={t} headless />
                    <RouteHealthBars rows={health} locale={locale} t={t} />
                    <PointerBanner data={pointer} locale={locale} t={t} />
                </div>
            </Disclosure>
        </div>
    ) : null;

    const hero = (
        <section
            className="d2-home-hero"
            style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                inlineSize: '100%',
                maxWidth: 'var(--hero-max)',
                marginInline: 'auto',
            }}
        >
            {notice}
            <DaalButton tone={view.tone} onClick={onDaalClick} label={view.tapLabel} size={isDesktop ? 200 : 168} />
            <h1
                className="d2-home-headline"
                data-testid="home-headline"
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: isPhone ? 'var(--fs-xl)' : 'var(--fs-hero)',
                    fontWeight: 600,
                    lineHeight: 1.2,
                    color: 'var(--fg)',
                    margin: '20px 0 0',
                }}
            >
                {view.headline}
            </h1>
            {view.line && (
                <p
                    data-testid="home-line"
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 6,
                        margin: '8px 0 0',
                        fontSize: isPhone ? 'var(--fs-sm)' : 'var(--fs-md)',
                        color: 'var(--muted)',
                        lineHeight: 1.45,
                        maxWidth: 420,
                    }}
                >
                    {view.lineNoInternet && (
                        <span aria-hidden style={{ color: 'var(--red)', display: 'inline-flex', flexShrink: 0 }}>
                            <Icon name="wifiOff" size={18} />
                        </span>
                    )}
                    {/* Translated copy, not user data: laid out in the page's
                        direction. A <bdi> would take its direction from the
                        first strong letter («Wi-Fi …» → LTR in Farsi). */}
                    <span dir={locale === 'fa' ? 'rtl' : 'ltr'}>{view.line}</span>
                </p>
            )}
            {view.trying && !view.holding && <TryingSteps fact={view.trying} />}
            {view.readyKinds.tags.length > 0 && (
                <ReadyChips
                    t={t}
                    kinds={view.readyKinds.tags}
                    more={view.readyKinds.more}
                    moreText={`+${locale === 'fa' ? toFaDigits(String(view.readyKinds.more)) : view.readyKinds.more}`}
                />
            )}
            {badges.length > 0 && (
                <div style={{ display: 'flex', gap: 8, justifyContent: 'center', flexWrap: 'wrap', marginBlockStart: 12 }}>
                    {badges.map((b) =>
                        b === 'slow' ? (
                            <Badge key={b} tone="warn">
                                {t('conn.badge.slow')}
                            </Badge>
                        ) : b === 'manual' ? (
                            <Badge
                                key={b}
                                tone="neutral"
                                icon="lock"
                                onClick={() => setChooserOpen(true)}
                                dataButton="badge-manual"
                                title={pinnedRow ? routeLabel(t, pinnedRow, routes) : undefined}
                            >
                                {t('conn.badge.manual')}
                            </Badge>
                        ) : (
                            <Badge key={b} tone="info" onClick={() => setShowMode(true)} dataButton="badge-lifeline">
                                {t('conn.badge.lifeline')}
                            </Badge>
                        ),
                    )}
                </div>
            )}
            {(primaryButton || link) && (
                <div style={{ display: 'grid', justifyItems: 'center', gap: 4, marginBlockStart: 20 }}>
                    {primaryButton}
                    {link}
                </div>
            )}
            {/* Nothing tried (the phone itself has no internet): no
                empty fold (spec F.2). */}
            {failure && panel !== 'failed' && failureDetailsShown(failure.tried, dev) && (
                <div style={{ marginBlockStart: 8 }}>
                    <AutoFailure t={t} locale={locale} tried={failure.tried} verdict={failure.verdict} dev={dev} rows={failureRows} />
                </div>
            )}
            {/* Phone, ready: every way here and how it did, folded away
                under the chips (the computer shows it as its right
                column). */}
            {!isDesktop && !showFacts && !failure && view.readyKinds.tags.length > 0 && allWays.length > 0 && (
                <div
                    data-testid="home-ready-ways"
                    style={{
                        inlineSize: '100%',
                        maxWidth: 420,
                        marginBlockStart: 24,
                        background: 'var(--surface)',
                        borderRadius: 'var(--r-card)',
                        padding: '0 16px',
                        boxSizing: 'border-box',
                    }}
                >
                    <Disclosure summary={waysTitle} dataButton="home-ready-ways">
                        <div style={{ paddingBlockEnd: 12, textAlign: 'start' }}>
                            <WayList t={t} locale={locale} ways={allWays} />
                        </div>
                    </Disclosure>
                </div>
            )}
            {/* Phone: the facts card under the bird, Details at its foot. */}
            {showFacts && !isDesktop && (
                <div style={{ inlineSize: '100%', maxWidth: 420, marginBlockStart: 24 }}>
                    <HomeFactsCard t={t} facts={facts}>
                        {details}
                    </HomeFactsCard>
                </div>
            )}
        </section>
    );

    // The column's card: top-aligned with the ring, and never taller than
    // the window — Details scrolls inside it rather than scrolling the
    // bird out of view.
    const panelCard = {
        maxHeight: 'calc(100vh - 140px)',
        overflowY: 'auto' as const,
    };
    const sidePanel =
        panel === 'connected' ? (
            <aside className="d2-home-panel" data-testid="home-panel" style={{ inlineSize: '100%', maxWidth: 340, alignSelf: 'start' }}>
                <HomeFactsCard t={t} facts={facts} showWay title={t('conn.panel.title')} style={panelCard}>
                    {routes && routes.length >= 2 && (
                        <div style={{ borderBlockStart: '1px solid var(--line-soft)' }}>
                            <Button variant="link" onClick={() => setChooserOpen(true)} dataButton="panel-choose">
                                {t('conn.more.choose')}
                            </Button>
                        </div>
                    )}
                    {details}
                </HomeFactsCard>
            </aside>
        ) : panel === 'failed' ? (
            <aside
                className="d2-home-panel"
                data-testid="home-panel"
                style={{
                    background: 'var(--surface)',
                    borderRadius: 'var(--r-card)',
                    padding: '16px 18px',
                    inlineSize: '100%',
                    maxWidth: 340,
                    textAlign: 'start',
                    alignSelf: 'start',
                    boxSizing: 'border-box',
                    ...panelCard,
                }}
            >
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--fs-lg)', fontWeight: 600, margin: '0 0 12px' }}>
                    {t('conn.panel.tried')}
                </h2>
                {failureRows.length > 0 ? (
                    <TriedList rows={failureRows.slice(0, 6)} />
                ) : (
                    <div style={{ fontSize: 14, color: 'var(--muted)' }}>{t('auto.details.none')}</div>
                )}
                {dev && failure && (
                    <div style={{ marginBlockStart: 8 }}>
                        <AutoFailure t={t} locale={locale} tried={failure.tried} verdict={failure.verdict} dev />
                    </div>
                )}
            </aside>
        ) : panel === 'ways' ? (
            <aside
                className="d2-home-panel"
                data-testid="home-panel"
                data-panel="ways"
                style={{
                    background: 'var(--surface)',
                    borderRadius: 'var(--r-card)',
                    padding: '16px 18px',
                    inlineSize: '100%',
                    maxWidth: 340,
                    alignSelf: 'start',
                    textAlign: 'start',
                    boxSizing: 'border-box',
                    ...panelCard,
                }}
            >
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--fs-lg)', fontWeight: 600, margin: '0 0 8px' }}>
                    {waysTitle}
                </h2>
                <WayList t={t} locale={locale} ways={allWays} />
            </aside>
        ) : panel === 'empty' ? (
            <aside className="d2-home-panel" aria-hidden style={{ inlineSize: '100%', maxWidth: 340 }} />
        ) : null;

    return (
        <div
            className="d2-home"
            style={{
                flex: 1,
                minHeight: '100%',
                overflow: 'auto',
                display: 'flex',
                flexDirection: 'column',
                boxSizing: 'border-box',
                padding: isPhone ? '4px var(--gutter) 24px' : '16px 32px 32px',
            }}
        >
            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', minHeight: 48 }}>
                <OverflowMenu label={t('ui.more')} items={moreItems} dataButton="home-more" />
            </div>
            <div
                className={panel ? 'd2-home-body d2-home-body--panel' : 'd2-home-body'}
                // The bird sits at a fixed height (about a fifth of the way
                // down), and what is under it grows downward: centring the
                // whole block moved the button the person had just tapped
                // whenever a state added or dropped a line.
                style={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'flex-start',
                    paddingBlockStart: isPhone ? 'max(12px, calc(16vh - 56px))' : 'max(24px, calc(20vh - 64px))',
                    gap: 24,
                }}
            >
                {hero}
                {sidePanel}
            </div>
            {helperFold && <div style={{ display: 'flex', justifyContent: 'center' }}>{helperFold}</div>}

            {showMode && <ModePickerSheet t={t} current={mode} onPick={onPickMode} onClose={() => setShowMode(false)} />}

            {chooserOpen && (
                <Sheet title={t('conn.more.choose')} onClose={() => setChooserOpen(false)} width={480}>
                    <WayChooser
                        t={t}
                        bare
                        pinned={pinnedRow}
                        routes={routes}
                        // A route whose details could not be read still
                        // has an id: it gets our own words, never an empty
                        // name.
                        running={state === 'connected' ? routeForDisplay(conn?.activeRoute, t) : undefined}
                        engineAuto={view.engineAuto}
                        busy={somethingRunning}
                        open
                        onToggle={() => setChooserOpen(false)}
                        onPick={onPickRoute}
                        onBackToAuto={onBackToAuto}
                        onManage={() => {
                            setChooserOpen(false);
                            onNavigate('network');
                        }}
                    />
                </Sheet>
            )}

            {showAdd && (
                <AddSheet
                    key={`${openedPath ?? 'add'}#${addNonce}`}
                    t={t}
                    openedPath={openedPath}
                    onProgress={openedSheet.setInProgress}
                    onClose={() => {
                        setShowAdd(false);
                        setOpenedPath(undefined);
                        void readRoutes(conn?.routeCountHint, true);
                        openedSheet.closed();
                    }}
                    onImported={() => void readRoutes(conn?.routeCountHint, true)}
                    // Already connected (or on the way): no "Connect" on the
                    // result, just Close — the new file joins automatically.
                    onConnect={
                        conn?.state === 'connected' || conn?.state === 'connecting'
                            ? undefined
                            : () => void connectNow({ kind: 'auto' })
                    }
                />
            )}

            {showAddress && <MyAddressSheet t={t} onClose={() => setShowAddress(false)} />}

            {showRecovery && (
                <RecoverySheet
                    t={t}
                    onClose={() => setShowRecovery(false)}
                    onAuto={onLetDaalChoose}
                    onFiles={() => onNavigate('network')}
                    onAdd={openAddFile}
                    onLifeline={() => void onPickMode('lifeline')}
                    onExportDiag={() => void onExport()}
                />
            )}
            {toast.node}
        </div>
    );
}
