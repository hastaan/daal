// NetworkPage.tsx — the Files tab (spec C4).
//
// What the recipient holds: one card per file (a publisher who sent
// ways to connect) with its true state (in use / works here / not
// working here / resting / not tried here…), how many ways it holds
// and when it was updated, and the kinds of connection inside
// ("VLESS Reality ×2", each with a dot for how it does here). A tap
// opens the file: the one connect action, every way titled by its kind
// with what Daal measured of it on this network, a tap on a way for
// what the kind is and "Use only this way", and Check for updates /
// Remove behind ⋯ (components/files/FileParts.tsx, lib/fileFacts.ts).
// "+" adds a file; ⋯ has My Daal address. Route ids, cooldown and
// data-cap controls are in developer mode only.
//
// The tree comes from listPublishers() (Publisher → Cell → Route, as
// core/routestore stores it); the connect rules per route are
// lib/networkRows.ts.

import { checkForNewAddress, refreshMessage } from '../lib/relayRefresh';
import {
    backupRoutesOf,
    canOfferCheck,
    CHECK_AGAIN_MS,
    drillMessage,
    drillRouteOf,
    keptAnswerFor,
    keptCheck,
    setKeptCheck,
    subscribeKeptCheck,
    type KeptCheck,
} from '../lib/backupCheck';
import {
    acceptFileConnect,
    autoRoutesOf,
    fileConnectFromResult,
    resolveFileConnect,
    startFileConnect,
    type FileConnect,
    type FileConnectEnd,
} from '../lib/fileConnect';
import { BackupCheckSheet, BackupLine, drillSentence, type BackupCheckState } from '../components/files/BackupCheck';
import type { BackupRoute } from '../contract/D2Contract';
import { sep } from '../lib/format';
import { useEffect, useRef, useState } from 'react';
import AddSheet from '../components/AddSheet';
import MyAddressSheet from '../components/MyAddressSheet';
import RouteBudgetModal from '../components/RouteBudgetModal';
import { useContract } from '../contract/ContractProvider';
import type {
    BurnpressureVerdict,
    ConnectionSummary,
    FamilyChip,
    PublisherTreeRow,
    RouteDisplayRow,
} from '../contract/D2Contract';
import {
    Badge,
    Button,
    Card,
    EmptyState,
    IconButton,
    OverflowMenu,
    PageHeader,
    Sheet,
    StateIcon,
    useToast,
} from '../design/primitives';
import type { MenuItem } from '../design/primitives';
import { useDensity } from '../design/DensityProvider';
import { useDeveloperMode } from '../lib/devMode';
import { formatAgo } from '../lib/format';
import { useOpenedFileSheet } from '../recipient/openedFile';
import type { AddStep } from '../components/AddSheet';
import type { SectionId } from '../shell/Sidebar';
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
    bestRouteOf,
    connectionsModeLine,
    fileInUse,
    fileUpdatedMs,
    modeLineTexts,
    rowMetaText,
    listView,
    pendingFailureKey,
    pinAfterTap,
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
import { EngineStartNotice, FailureBox, NoticeRow, StoreResetNotice } from './PageNotices';
import { useEngineStartProblem } from '../lib/engineStart';
import { autoIsUsing, autoVerdictKey, getPinnedRoute, setPinnedRoute, startConnect } from '../lib/autoConnect';
import { chipHereText, chipScoreText, familyHere, localDigits } from '../lib/measured';
import { effectiveLocale } from '../lib/i18n';
import type { Locale } from '../lib/i18n';
import { formatTime } from '../lib/format';
import {
    familyTags,
    fileOrder,
    fileState as fileStateOf,
    restingUntilMs,
    waysCountText,
    wayState,
    wayTitles,
} from '../lib/fileFacts';
import { FileCard, WayRow } from '../components/files/FileParts';
import { fileTitle, isPastedGroup } from '../components/files/pasted';
import { failingHere, isPastedRoute, readSurvey, type SurveyRead } from '../components/pasteSurvey';

interface Props {
    t: (k: string) => string;
    /** Set by the shells: "Connect" after adding a file goes to Home. */
    onNavigate?: (s: SectionId) => void;
}

export default function NetworkPage({ t, onNavigate }: Props) {
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
    // The add sheet, and where it opens (null = closed).
    const [addStep, setAddStep] = useState<AddStep | null>(null);
    const [addrOpen, setAddrOpen] = useState(false);
    // The file whose sheet is open, by display name (unique in the tree).
    const [openName, setOpenName] = useState<string | null>(null);
    // A file Android handed to Daal while this page is open.
    const [openedPath, setOpenedPath] = useState<string | undefined>(undefined);
    const dev = useDeveloperMode();
    const toast = useToast();
    const [checking, setChecking] = useState(false);
    const { density } = useDensity();
    const [addNonce, setAddNonce] = useState(0);
    const openedSheet = useOpenedFileSheet(addStep !== null, (path) => {
        setOpenedPath(path);
        setAddNonce((n) => n + 1);
        setAddStep('choose');
    });
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
    // "Connect with this file" is on its way, until the ENGINE has
    // answered (lib/fileConnect.ts): on desktop the call lasts the whole
    // pass; on Android it returns when the VPN service has started and
    // the answer comes in the polled `auto` block.
    const [fileConnect, setFileConnectState] = useState<FileConnect | null>(null);
    const fileConnectRef = useRef<FileConnect | null>(null);
    const setFileConnect = (f: FileConnect | null) => {
        fileConnectRef.current = f;
        setFileConnectState(f);
    };
    // "Check the backup update routes": the check of this page, its
    // sheet open or closed. The running check and its last answer live
    // in lib/backupCheck.ts (keptCheck) so leaving the Files tab loses
    // neither; this page picks them up when it mounts.
    const tRef = useRef(t);
    tRef.current = t;
    const [check, setCheckState] = useState<BackupCheckState | null>(() => {
        const k = keptCheck();
        return k?.running ? { name: k.fileName, running: true, open: false } : null;
    });
    const checkRef = useRef<BackupCheckState | null>(null);
    const setCheck = (c: BackupCheckState | null) => {
        checkRef.current = c;
        setCheckState(c);
    };
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
    // The route the person chose by hand, or null for Automatic.
    // Connecting a route from this page IS choosing it: the main screen
    // then connects that one, and says so with the way back
    // (lib/autoConnect.ts).
    const [pinnedId, setPinnedId] = useState<string | null>(() => getPinnedRoute());
    // The route automatic connect has up, or null: marked on its row so
    // the person can see which one Daal picked.
    const [autoRouteId, setAutoRouteId] = useState<string | null>(null);
    // The sentence above the list: what the ENGINE is doing now, with
    // the saved choice as a line about next time when the two differ
    // (lib/networkRows.ts connectionsModeLine).
    const [summaryNow, setSummaryNow] = useState<ConnectionSummary | null>(null);
    const modeTexts = modeLineTexts(t, connectionsModeLine(pinnedId, summaryNow));
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
        setSummaryNow(s);
        // "Active" is whatever the engine has RUNNING, not only
        // what it has finished proving: a route still being
        // checked, or lost and being retried, must be stoppable
        // here too. Offering Connect for it called connect on a
        // route in its cooldown (refused) and left no way to stop
        // it from this page.
        setActiveRouteId(runningRouteId(s));
        setAutoRouteId(autoIsUsing(s.auto, runningRouteId(s)) ? runningRouteId(s) : null);
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
        const fc = fileConnectRef.current;
        if (fc) {
            const end = resolveFileConnect(fc, s, Date.now());
            if (end.outcome !== 'waiting') endFileConnect(end);
            else if (end.next !== fc) setFileConnect(end.next);
        }
        const p = pendingRef.current;
        if (!p) return;
        const outcome = resolvePending(p, s, Date.now());
        if (outcome === 'waiting') return;
        setPending(null);
        const pin = pinAfterTap(p.routeId, outcome);
        if (pin) {
            setPinnedRoute(pin);
            setPinnedId(pin);
        }
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
        if (pendingRef.current || fileConnectRef.current) cancelledRef.current = true;
        setPending(null);
        setFileConnect(null);
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
        // Picking a route by hand pins it — once it is CONNECTED
        // (applySummary). Pinning at the tap left the main button bound
        // to a route that then failed, was refused or was cancelled,
        // with automatic connect switched off behind the person's back.
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
                // Desktop: the engine went back to the route that was
                // connected and says so (`switch_back`) — the person is
                // told whether they are still connected, not only that
                // the new way failed.
                const wentBackKey = summary ? pendingFailureKey(routeId, 'failed', summary) : undefined;
                setFailure({
                    key: wentBackKey ?? connectFailedKey(summary?.routeCheck, summary?.routeCheckCategory),
                    detail: errorText(e),
                    routeId,
                });
            }
        }
    };

    const pendingId = pending?.routeId ?? null;
    // How a "Connect with this file" ended. Only once the file has
    // CONNECTED is a way chosen by hand before let go (as "Back to
    // automatic" does): a failed, cancelled or refused connect leaves the
    // person's pin as it was. Never ends in silence.
    const endFileConnect = (end: FileConnectEnd) => {
        setFileConnect(null);
        if (end.outcome === 'connected') {
            setPinnedRoute(null);
            setPinnedId(null);
            return;
        }
        if (end.outcome === 'cancelled' || cancelledRef.current) return;
        setFailure({ key: autoVerdictKey(end.outcome === 'failed' ? end.verdict : '') });
    };

    // "Connect with this file": Daal chooses automatically among THIS
    // file's ways (engine_set_auto_scope, then the ordinary automatic
    // connect). It is not a choice of one way: nothing is pinned.
    // Picking one way (its own row) stays onConnectRoute.
    const onConnectFile = async (routeIds: string[]) => {
        setFailure(null);
        setTapRefused(undefined);
        if (noDataPlane) {
            setFailure({ key: 'conn.no_data_plane.title' });
            return;
        }
        if (pendingRef.current || fileConnectRef.current || routeIds.length === 0) return;
        cancelledRef.current = false;
        setFileConnect(startFileConnect(routeIds, Date.now(), lastSummaryRef.current));
        try {
            const res = await contract.connectAutoWithin(routeIds);
            const mine = fileConnectRef.current;
            if (mine) {
                // Desktop hands the engine's answer back; on Android the
                // poll reads it from the `auto` block (applySummary).
                const end = fileConnectFromResult(res);
                if (end) endFileConnect(end);
                else {
                    setFileConnect(acceptFileConnect(mine, Date.now()));
                    try {
                        applySummary(await contract.connectionSummary());
                    } catch {
                        /* the poll will catch up */
                    }
                }
            }
            void load();
        } catch (e) {
            const mine = fileConnectRef.current;
            setFileConnect(null);
            if (mine && !cancelledRef.current) setFailure({ key: 'network.action_failed', detail: errorText(e) });
        }
    };

    // The check's answer, wherever the page was meanwhile: in its sheet
    // when that is open, else a short notice. The answer stays kept
    // (lib/backupCheck.ts) for the 10 minutes the engine refuses another.
    useEffect(() => {
        const onKept = () => {
            const k = keptCheck();
            const c = checkRef.current;
            if (!k || k.running || !k.answer || !c || !c.running || c.name !== k.fileName) return;
            if (c.open) {
                setCheck({ ...c, running: false, answer: k.answer, at: k.at });
            } else {
                setCheck(null);
                toast.show(drillMessage(k.answer).tone, drillSentence(tRef.current, effectiveLocale(), k.answer, k.at ?? Date.now()));
            }
            if (k.answer.outcome === 'updated') void load().catch(() => {});
        };
        onKept();
        return subscribeKeptCheck(onKept);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [contract]);

    // "Check the backup update routes" for one file: blocks up to about
    // two minutes; the sheet says so meanwhile. Closing the sheet, or
    // leaving the tab, does not stop it.
    const onCheckBackup = async (p: PublisherTreeRow) => {
        const running = keptCheck();
        if (running?.running) {
            // One check at a time: its sheet, named, whichever file it is.
            setCheck({ name: running.fileName, running: true, open: true });
            return;
        }
        const at = Date.now();
        // Checked a few minutes ago: the engine would refuse. Its lines
        // again, and when a new check may run.
        const before = keptAnswerFor(p.displayName, at, true);
        if (before) {
            setCheck(keptSheet(before));
            return;
        }
        const routeId = drillRouteOf(p);
        if (!routeId) return;
        const started: KeptCheck = { fileName: p.displayName, running: true, startedAt: at };
        setCheck({ name: p.displayName, running: true, open: true });
        setKeptCheck(started);
        const a = await contract.backupCheck(routeId);
        if (a.outcome === 'rate_limited') {
            // The engine still holds a stamp: show the lines it gave last
            // time, if they are kept.
            const last = keptAnswerFor(p.displayName, Date.now(), false);
            if (last) {
                const c = checkRef.current;
                if (c && c.running && c.name === p.displayName) {
                    if (c.open) setCheck(keptSheet(last, a.retryAfterS));
                    else {
                        setCheck(null);
                        toast.show(drillMessage(a).tone, drillSentence(tRef.current, effectiveLocale(), a, Date.now()));
                    }
                }
                // Set after the sheet, so the kept answer is not taken
                // for this press's news.
                setKeptCheck(last);
                return;
            }
        }
        setKeptCheck({ ...started, running: false, answer: a, at: Date.now() });
    };

    const view = listView(tree, loadError !== null);
    const nowMs = Date.now();
    // The open file's connect is the one on its way.
    const connectingOpenFile = (p: PublisherTreeRow | null): boolean =>
        fileConnect !== null && p !== null && p.cells.some((c) => c.routes.some((r) => fileConnect.routeIds.includes(r.routeId)));
    const locale = effectiveLocale();
    const openFile = tree?.find((p) => p.displayName === openName) ?? null;
    const stateOf = (routeId: string) => rowState(routeId, activeRouteId, pendingId, verifying);
    // "Back to automatic": the choice goes, and a connection on the way
    // that was chosen by hand is handed to the engine now (as the main
    // screen does): engine_connect_auto on a connected engine starts
    // nothing and takes charge of the route that is up.
    const onBackToAuto = () => {
        setPinnedRoute(null);
        setPinnedId(null);
        if (summaryNow?.state === 'connected' && summaryNow.auto?.mode !== true && pendingId === null) {
            void contract.connectAuto().catch(() => {
                /* the page keeps saying what is true */
            });
        }
    };

    const onRefreshFile = async (p: PublisherTreeRow) => {
        if (!p.subscription) return;
        try {
            await contract.subscriptionRefresh(p.subscription.subscriptionId, 5000);
            await load();
            toast.show('good', t('network.refreshed'));
        } catch (e) {
            setFailure({ key: 'network.action_failed', detail: errorText(e) });
        }
    };
    const onRemoveFile = async (p: PublisherTreeRow) => {
        try {
            if (p.publisherId === '' && p.subscription) {
                // A subscription whose first refresh has not landed has
                // no publisher to remove: its subscription is the file.
                await contract.subscriptionRemove(p.subscription.subscriptionId);
            } else {
                // Drop the tunnel ONLY if the live route belongs to this
                // publisher: tidying up publisher B must not kill a
                // working tunnel through publisher A.
                const ownsActiveRoute =
                    activeRouteId !== null && p.cells.some((c) => c.routes.some((r) => r.routeId === activeRouteId));
                if (ownsActiveRoute) {
                    await contract.disconnect().catch(() => {});
                }
                await contract.publisherDelete(p.publisherId);
            }
            setOpenName(null);
            await load();
        } catch (e) {
            setFailure({ key: 'network.action_failed', detail: errorText(e) });
        }
    };

    const onStopUpdates = async (p: PublisherTreeRow) => {
        if (!p.subscription) return;
        try {
            await contract.subscriptionRemove(p.subscription.subscriptionId);
            await load();
        } catch (e) {
            setFailure({ key: 'network.action_failed', detail: errorText(e) });
        }
    };

    // The pasted links' file: remove the ways that were checked here and
    // did not answer (components/pasteSurvey.ts failingHere). Never the
    // way in use; a way that was not checked stays.
    const onRemoveFailing = async (ids: string[]) => {
        let n = 0;
        for (const id of ids) {
            if (id === activeRouteId) continue;
            try {
                await contract.routeDelete(id);
                n++;
            } catch {
                /* it stays; the count says how many went */
            }
        }
        await load().catch(() => {});
        toast.show(n > 0 ? 'good' : 'bad', n > 0 ? (n === 1 ? t('files.bulk.removed_one') : t('files.bulk.removed')).replace('{n}', localDigits(n, effectiveLocale())) : t('network.action_failed'));
    };

    const onCheckNewAddress = async () => {
        if (checking) return;
        setChecking(true);
        toast.show('neutral', t('files.refresh.looking'), 60000);
        const a = await checkForNewAddress();
        setChecking(false);
        const m = refreshMessage(a);
        toast.show(m.tone, t(m.key));
        if (a.outcome === 'updated') await load().catch(() => {});
    };

    const moreItems: MenuItem[] = [
        { id: 'my-address', label: t('conn.more.address'), icon: 'person', onSelect: () => setAddrOpen(true) },
    ];
    if (tree && tree.length > 0) {
        moreItems.push({ id: 'check-address', label: t('files.refresh.action'), icon: 'refresh', onSelect: () => void onCheckNewAddress() });
    }
    if (dev) {
        moreItems.push(
            { id: 'dev-scan', label: t('add.choose.scan'), icon: 'camera', onSelect: () => setAddStep('scan') },
            { id: 'dev-paste', label: t('add.choose.paste'), icon: 'paste', onSelect: () => setAddStep('paste') },
        );
    }

    const isPhone = density === 'phone';

    return (
        <div
            style={{
                padding: isPhone ? '4px var(--gutter) 24px' : '16px 32px 32px',
                width: '100%',
                maxWidth: 'calc(var(--content-max) + 64px)',
                marginInline: isPhone ? 'auto' : undefined,
            }}
        >
            <PageHeader
                title={t('network.title')}
                actions={
                    view === 'list' ? (
                        <>
                            <IconButton icon="plus" label={t('auto.add_file')} onClick={() => setAddStep('choose')} dataButton="add" />
                            <OverflowMenu label={t('ui.more')} items={moreItems} dataButton="files-more" />
                        </>
                    ) : undefined
                }
            />

            {noDataPlane ? (
                <NoticeRow t={t} text={t('conn.no_data_plane.title')} more={t('conn.no_data_plane.body')} />
            ) : storeReset ? (
                <StoreResetNotice
                    t={t}
                    onDismiss={() => {
                        markStoreResetNoticeSeen();
                        setStoreReset(false);
                    }}
                />
            ) : null}

            {refusedShown && !failure && <NoticeRow t={t} text={t(connectRefusedKey(refusedShown))} />}

            {failure && <FailureBox t={t} text={t(failure.key)} detail={failure.detail} />}

            {startProblem && <EngineStartNotice t={t} detail={startProblem.detail} />}

            {loadError !== null && !startProblem && (
                <FailureBox t={t} text={t('network.load_failed')} detail={loadError} onRetry={() => void load()} />
            )}

            {dev && verdict?.promote && (
                <div data-dev style={{ fontSize: 13, color: 'var(--muted)', marginBlockEnd: 12 }}>
                    {t('network.banner.autopromoted')}
                </div>
            )}
            {dev && view === 'list' && (
                <div data-dev style={{ fontSize: 13, color: 'var(--muted)', marginBlockEnd: 12 }}>
                    {modeTexts.now}
                    {modeTexts.next && (
                        <span data-next style={{ display: 'block' }}>
                            {modeTexts.next}
                        </span>
                    )}
                    {pinnedId && (
                        <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                                setPinnedRoute(null);
                                setPinnedId(null);
                            }}
                        >
                            {t('auto.chooser.back')}
                        </Button>
                    )}
                </div>
            )}

            {view === 'loading' ? (
                <div role="status" style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
                    <StateIcon state="busy" size={24} label={t('common.loading')} />
                </div>
            ) : view === 'failed' ? null : view === 'empty' || tree === null ? (
                <EmptyState
                    icon="files"
                    title={t('network.empty')}
                    action={
                        <Button size="lg" onClick={() => setAddStep('choose')} dataButton="add-my-file">
                            {t('auto.add_file')}
                        </Button>
                    }
                    secondary={
                        <Button variant="link" onClick={() => setAddrOpen(true)} dataButton="my-address">
                            {t('conn.more.address')}
                        </Button>
                    }
                />
            ) : (
                // The rows sit inside the card's own padding: with none, the
                // state disc of each row hung half outside its edge.
                <Card style={{ paddingBlock: 0, paddingInline: 16 }}>
                    {/* The file carrying traffic first, then the ones that
                        work here, then the rest (fileOrder). */}
                    {tree
                        .map((p) => ({ p, state: fileStateOf(p, activeRouteId, stateOf, nowMs) }))
                        .map((x, i) => ({ ...x, i }))
                        .sort((a, b) => fileOrder(a.state) - fileOrder(b.state) || a.i - b.i)
                        .map(({ p, state }, i) => {
                        const routes = p.cells.flatMap((c) => c.routes);
                        const updated = fileUpdatedMs(p);
                        const until = state === 'resting' ? restingUntilMs(routes, nowMs) : undefined;
                        const summary = [
                            waysCountText(t, locale, routes.length),
                            updated !== undefined
                                ? t('network.updated').replace('{ago}', formatAgo(locale, nowMs - updated))
                                : undefined,
                        ]
                            .filter(Boolean)
                            .join(sep());
                        return (
                            <FileCard
                                // displayName, not publisherId: the tree is
                                // grouped by display name (unique by
                                // construction) and publisherId is empty for
                                // a subscription whose first refresh has not
                                // landed.
                                key={p.displayName}
                                t={t}
                                locale={locale}
                                p={p}
                                state={state}
                                summary={summary}
                                tags={familyTags(t, routes, activeRouteId, nowMs)}
                                restingUntil={until !== undefined ? formatTime(locale, new Date(until)) : undefined}
                                last={i === tree.length - 1}
                                onOpen={() => setOpenName(p.displayName)}
                            />
                        );
                    })}
                </Card>
            )}

            {check?.open && (
                <BackupCheckSheet
                    t={t}
                    locale={locale}
                    state={check}
                    onClose={() => {
                        const c = checkRef.current;
                        setCheck(c && c.running ? { ...c, open: false } : null);
                    }}
                />
            )}

            {openFile && !check?.open && (
                <FileSheet
                    t={t}
                    p={openFile}
                    dev={dev}
                    nowMs={nowMs}
                    pendingId={pendingId}
                    verifying={verifying}
                    activeRouteId={activeRouteId}
                    autoRouteId={autoRouteId}
                    pinnedId={pinnedId}
                    locale={locale}
                    onBackToAuto={onBackToAuto}
                    onClose={() => setOpenName(null)}
                    onConnectRoute={onConnectRoute}
                    onConnectFile={onConnectFile}
                    connectingFile={connectingOpenFile(openFile)}
                    backupRoutes={backupRoutesOf(openFile)}
                    canCheck={canOfferCheck(openFile, summaryNow, activeRouteId, pendingId) && fileConnect === null}
                    onCheck={() => void onCheckBackup(openFile)}
                    onDisconnect={onDisconnect}
                    onRefresh={() => void onRefreshFile(openFile)}
                    onStopUpdates={() => void onStopUpdates(openFile)}
                    onRemove={() => void onRemoveFile(openFile)}
                    onRemoveFailing={(ids) => void onRemoveFailing(ids)}
                    onCool={async (routeId) => {
                        try {
                            await contract.applyCooldown(routeId, 15 * 60 * 1000, 'manual');
                            await load();
                        } catch (e) {
                            setFailure({ key: 'network.action_failed', detail: errorText(e) });
                        }
                    }}
                    onBudget={(r) => setBudgetFor(r)}
                />
            )}

            {addStep && (
                <AddSheet
                    key={`${openedPath ?? addStep}#${addNonce}`}
                    t={t}
                    initialStep={addStep}
                    openedPath={openedPath}
                    onProgress={openedSheet.setInProgress}
                    onClose={() => {
                        setAddStep(null);
                        setOpenedPath(undefined);
                        void load();
                        openedSheet.closed();
                    }}
                    onImported={() => void load()}
                    onConnect={
                        summaryNow?.state === 'connected' || summaryNow?.state === 'connecting'
                            ? undefined
                            : () => {
                                  void startConnect(contract, { kind: 'auto' }).catch(() => {
                                      /* Home says how the connect went */
                                  });
                                  onNavigate?.('connection');
                              }
                    }
                />
            )}
            {addrOpen && <MyAddressSheet t={t} onClose={() => setAddrOpen(false)} />}
            {budgetFor && dev && (
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
            {toast.node}
        </div>
    );
}

/** A kept check's sheet: its lines again, and when a new check may run
 *  (the engine's own wait when it gave one, else 10 minutes from the
 *  start of the kept check). */
function keptSheet(k: KeptCheck, retryAfterS = 0): BackupCheckState {
    return {
        name: k.fileName,
        running: false,
        open: true,
        answer: k.answer,
        at: k.at,
        againAt: retryAfterS > 0 ? Date.now() + retryAfterS * 1000 : k.startedAt + CHECK_AGAIN_MS,
    };
}

export interface FileSheetProps {
    t: (k: string) => string;
    p: PublisherTreeRow;
    dev: boolean;
    nowMs: number;
    pendingId: string | null;
    verifying: RunningPhase;
    activeRouteId: string | null;
    autoRouteId: string | null;
    pinnedId: string | null;
    locale: Locale;
    /** Forget the way chosen by hand: Daal chooses again. */
    onBackToAuto: () => void;
    onClose: () => void;
    /** Picking ONE way by hand (its row): pinned once connected. */
    onConnectRoute: (routeId: string) => void | Promise<void>;
    /** "Connect with this file": automatic among these ways, no pin. */
    onConnectFile: (routeIds: string[]) => void | Promise<void>;
    /** That connect is on its way. */
    connectingFile: boolean;
    /** The backup update routes the file holds (the muted line). */
    backupRoutes: readonly BackupRoute[];
    /** "Check the backup update routes" is offered (the file has them,
     *  and nothing is up). */
    canCheck: boolean;
    onCheck: () => void;
    onDisconnect: () => void | Promise<void>;
    onRefresh: () => void;
    /** Keep the ways, stop checking the file's web address. */
    onStopUpdates: () => void;
    onRemove: () => void;
    /** The pasted links' file only: remove these ways (checked here,
     *  did not answer). */
    onRemoveFailing?: (routeIds: string[]) => void;
    onCool: (routeId: string) => void | Promise<void>;
    onBudget: (r: RouteDisplayRow) => void;
}

/** One file (spec C4.3): who it is from, the one connect action, the
 *  ways inside in plain words, and the rest behind ⋯. */
export function FileSheet({
    t,
    p,
    dev,
    nowMs,
    pendingId,
    verifying,
    activeRouteId,
    autoRouteId,
    pinnedId,
    locale,
    onBackToAuto,
    onClose,
    onConnectRoute,
    onConnectFile,
    connectingFile,
    backupRoutes,
    canCheck,
    onCheck,
    onDisconnect,
    onRefresh,
    onStopUpdates,
    onRemove,
    onRemoveFailing,
    onCool,
    onBudget,
}: FileSheetProps) {
    const [confirmRemove, setConfirmRemove] = useState(false);
    const [confirmBulk, setConfirmBulk] = useState<string[] | null>(null);
    // The way whose details are open (one at a time).
    const [openWay, setOpenWay] = useState<string | null>(null);
    const routes = p.cells.flatMap((c) => c.routes);
    // The file of pasted links (route ids "pasted-…"): the last check's
    // results, read once when the sheet opens.
    const pastedFile = routes.length >= 2 && routes.some((r) => isPastedRoute(r.routeId));
    const [survey, setSurvey] = useState<SurveyRead | null>(null);
    useEffect(() => {
        if (!pastedFile) return;
        let alive = true;
        void readSurvey().then((r) => {
            if (alive) setSurvey(r);
        });
        return () => {
            alive = false;
        };
    }, [pastedFile]);
    const failing = pastedFile ? failingHere(routes, survey, activeRouteId) : [];
    const titles = wayTitles(t, routes, locale);
    const here = chipHereText(t, locale, familyHere(routes));
    const verified = p.trustLevel === 'trusted' || p.trustLevel === 'pinned';
    const inUse = fileInUse(p, activeRouteId);
    const best = bestRouteOf(p, activeRouteId, nowMs);
    const pendingHere = pendingId !== null && routes.some((r) => r.routeId === pendingId);
    // The one action, through the same rules as the old per-route button:
    // Connect, Cancel while it is being checked, Disconnect when in use.
    const action = best
        ? rowAction(rowState(best.routeId, activeRouteId, pendingId, verifying), switchingAwayFromRunning(best.routeId, activeRouteId, pendingId))
        : 'connect';
    const items: MenuItem[] = [];
    if (p.subscription) items.push({ id: 'refresh', label: t('network.check_updates'), icon: 'refresh', onSelect: onRefresh });
    if (p.subscription && p.publisherId !== '') {
        items.push({ id: 'stop-updates', label: t('network.stop_updates'), icon: 'close', onSelect: onStopUpdates });
    }
    if (pastedFile && onRemoveFailing) {
        items.push({
            id: 'remove-failing',
            label: t('files.bulk.remove_failed'),
            icon: 'trash',
            tone: 'danger',
            disabled: failing.length === 0,
            hint: failing.length === 0 ? t('files.bulk.none') : undefined,
            onSelect: () => setConfirmBulk(failing),
        });
    }
    if (canCheck) {
        items.push({ id: 'check-backup', label: t('files.check.action'), icon: 'route', onSelect: onCheck });
    }
    if (p.publisherId !== '' || p.subscription) {
        items.push({ id: 'remove', label: t('network.remove_file'), icon: 'trash', tone: 'danger', onSelect: () => setConfirmRemove(true) });
    }

    return (
        <Sheet
            title={
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <bdi>{fileTitle(t, p)}</bdi>
                    {verified && (
                        <Badge tone="neutral" icon="lock" size="sm">
                            {t('network.verified')}
                        </Badge>
                    )}
                </span>
            }
            onClose={onClose}
            width={520}
        >
            {confirmBulk ? (
                <div role="alert" style={{ display: 'grid', gap: 14 }}>
                    <p style={{ margin: 0, fontSize: 15, color: 'var(--fg)' }}>
                        {(confirmBulk.length === 1 ? t('files.bulk.confirm_one') : t('files.bulk.confirm')).replace('{n}', localDigits(confirmBulk.length, locale))}
                    </p>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button
                            variant="danger"
                            onClick={() => {
                                const ids = confirmBulk;
                                setConfirmBulk(null);
                                onRemoveFailing?.(ids);
                            }}
                            dataButton="bulk-remove-confirm"
                        >
                            {t('network.remove')}
                        </Button>
                        <Button variant="secondary" onClick={() => setConfirmBulk(null)} dataButton="bulk-remove-cancel">
                            {t('common.cancel')}
                        </Button>
                    </div>
                </div>
            ) : confirmRemove ? (
                <div role="alert" style={{ display: 'grid', gap: 14 }}>
                    <p style={{ margin: 0, fontSize: 15, color: 'var(--fg)' }}>
                        <bdi>
                            {isPastedGroup(p)
                                ? t('network.remove_pasted_confirm')
                                : t('network.remove_publisher_confirm').replace('{name}', p.displayName)}
                        </bdi>
                    </p>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <Button variant="danger" onClick={onRemove} dataButton="remove-confirm">
                            {t('network.remove')}
                        </Button>
                        <Button variant="secondary" onClick={() => setConfirmRemove(false)} dataButton="remove-cancel">
                            {t('common.cancel')}
                        </Button>
                    </div>
                </div>
            ) : (
                <div style={{ display: 'grid', gap: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ flex: 1 }}>
                            {inUse || action !== 'connect' ? (
                                <Button
                                    block
                                    variant="secondary"
                                    disabled={rowActionDisabled(action, pendingId)}
                                    onClick={() => void onDisconnect()}
                                    dataButton="file-connect"
                                >
                                    {t(rowActionLabelKey(action === 'connect' ? 'disconnect' : action))}
                                </Button>
                            ) : connectingFile ? (
                                // Daal is choosing among this file's ways:
                                // the press can be taken back.
                                <Button block variant="secondary" onClick={() => void onDisconnect()} dataButton="file-connect">
                                    {t('conn.cancel_action')}
                                </Button>
                            ) : (
                                <Button
                                    block
                                    disabled={!best || pendingId !== null}
                                    // Daal chooses among this file's ways:
                                    // not a choice of one, so no pin. A
                                    // file whose ways are all connected
                                    // only by hand (a pasted WireGuard
                                    // file) has nothing to choose among:
                                    // its one way is connected as before.
                                    onClick={() => {
                                        if (!best) return;
                                        const auto = autoRoutesOf(routes);
                                        if (auto.length === 0) void onConnectRoute(best.routeId);
                                        else void onConnectFile(auto.map((r) => r.routeId));
                                    }}
                                    dataButton="file-connect"
                                >
                                    {t('network.connect_file')}
                                </Button>
                            )}
                        </div>
                        <OverflowMenu label={t('ui.more')} items={items} dataButton="file-more" />
                    </div>
                    {(pendingHere || (connectingFile && !inUse)) && (
                        <div style={{ fontSize: 13, color: 'var(--muted)' }}>{t('conn.headline_connecting')}</div>
                    )}
                    <div>
                        <div
                            style={{
                                display: 'flex',
                                alignItems: 'baseline',
                                justifyContent: 'space-between',
                                gap: 12,
                                fontSize: 12,
                                fontWeight: 600,
                                color: 'var(--muted)',
                                marginBlockEnd: 2,
                            }}
                        >
                            <span>{t('files.sheet.ways')}</span>
                            {here && <span style={{ fontWeight: 500 }}>{here}</span>}
                        </div>
                        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                            {routes.map((r, i) => {
                                const st = rowState(r.routeId, activeRouteId, pendingId, verifying);
                                const ws = wayState(r, st, nowMs);
                                return (
                                    <WayRow
                                        key={r.routeId}
                                        t={t}
                                        locale={locale}
                                        r={r}
                                        title={titles.get(r.routeId) ?? { title: r.routeId }}
                                        state={ws}
                                        open={openWay === r.routeId}
                                        onToggle={() => setOpenWay((w) => (w === r.routeId ? null : r.routeId))}
                                        pinned={r.routeId === pinnedId}
                                        chosenByDaal={r.routeId === autoRouteId}
                                        busy={pendingId !== null}
                                        otherConnected={activeRouteId !== null && activeRouteId !== r.routeId}
                                        // Connecting a way from this page IS
                                        // choosing it: it is pinned once the
                                        // engine reports it connected
                                        // (pinAfterTap), as before.
                                        onUseOnly={() => void onConnectRoute(r.routeId)}
                                        onBackToAuto={onBackToAuto}
                                        last={i === routes.length - 1}
                                        dev={
                                            dev ? (
                                                <span data-dev style={{ display: 'flex', gap: 4, flexWrap: 'wrap', paddingBlockEnd: 8 }}>
                                                    <code dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', flexBasis: '100%' }}>
                                                        {rowMetaText(t, r, {
                                                            stateLabelKey: rowStateLabelKey(st),
                                                            isAuto: r.routeId === autoRouteId,
                                                            isPinned: r.routeId === pinnedId,
                                                        })}{' '}
                                                        · {r.routeId}
                                                    </code>
                                                    <RouteActionButton
                                                        t={t}
                                                        routeId={r.routeId}
                                                        activeRouteId={activeRouteId}
                                                        pendingId={pendingId}
                                                        verifying={verifying}
                                                        onConnectRoute={onConnectRoute}
                                                        onDisconnect={onDisconnect}
                                                    />
                                                    <Button size="sm" variant="secondary" disabled={pendingId !== null} onClick={() => void onCool(r.routeId)}>
                                                        {t('network.cool_15m')}
                                                    </Button>
                                                    <Button size="sm" variant="secondary" onClick={() => onBudget(r)}>
                                                        {t('network.cap')}
                                                    </Button>
                                                </span>
                                            ) : undefined
                                        }
                                    />
                                );
                            })}
                        </ul>
                    </div>
                    <BackupLine t={t} list={backupRoutes} />
                    {dev && (
                        <div data-dev style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            {p.cells.flatMap((c) => c.families).map((f) => (
                                <FamilyChipView key={f.viaCdn ? `${f.family}#cdn` : f.family} t={t} chip={f} />
                            ))}
                        </div>
                    )}
                </div>
            )}
        </Sheet>
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

function FamilyChipView({
    t,
    chip,
}: {
    t: (k: string) => string;
    chip: FamilyChip;
}) {
    const [open, setOpen] = useState(false);
    const locale = effectiveLocale();
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
    // The Cloudflare route's chip is named and explained as that route;
    // a family without a Network help line falls back to its own
    // `family.<k>.about` (Hysteria 2's dated Iran caveat).
    const famK = chip.family.replace(/-/g, '_');
    const pick = (...keys: string[]) => {
        for (const k of keys) {
            const v = t(k);
            if (v !== k) return v;
        }
        return '';
    };
    const famHelp = chip.viaCdn
        ? pick('route.label.ws_cdn.help', `network.family.${famK}.help`, `family.${famK}.about`)
        : pick(`network.family.${famK}.help`, `family.${famK}.about`);
    const chipName = chip.viaCdn ? pick('route.label.ws_cdn') || chip.family : chip.family;
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
    const about = cooled
        ? `${t('network.cooled')}${chip.lastErrorTag ? ` · ${chip.lastErrorTag}` : ''}`
        : unsupported
        ? `${t('network.family.unsupported.help')}${famHelp ? ` ${famHelp}` : ''}`
        : exp
        ? famHelp || t('network.family.experimental.help')
        : famHelp;
    // The old "· 87%" on the chip face: a score, not a success rate.
    // It is kept, said as what it is, in the text a tap opens.
    const score = unsupported ? undefined : chipScoreText(t, locale, chip.healthPct);
    const detail = [about, score].filter(Boolean).join(' ') || undefined;
    const here = unsupported ? undefined : chipHereText(t, locale, chip.here);

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
            title={detail ? `${chipName} · ${detail}` : chipName}
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
                cursor: detail ? 'pointer' : 'default',
                textAlign: 'start',
            }}
        >
            {cooled && '🚨 '}
            {unsupported && !cooled && '⛔ '}
            {exp && !cooled && '⚡ '}
            {chipName} · {chip.count}
            {unsupported ? ` · ${t('network.family.unsupported')}` : here ? ` · ${here}` : ''}
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

