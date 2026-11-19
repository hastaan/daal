// The main screen's decisions, in one place and with no React in them.
//
// ConnectionPage draws; this file decides WHAT: the state shown, what a
// tap on the main control does, which sentence is the headline, and
// which panel sits under it. The page used to make these decisions
// inline, where no test could reach them — every test was one level
// below, on the helpers, so the defect this screen was rebuilt to remove
// (a tap that navigates to a list instead of connecting) could have
// come back with every test green. Now the page is `mainScreenView` for
// what it shows and `runMainTap` for what a tap does, and both are
// driven end to end by lib/mainScreen.test.ts against the harness
// contract.
import type {
    AutoStatus,
    AutoTried,
    ConnState,
    ConnectionSummary,
    RouteDisplayRow,
} from '../contract/D2Contract';
import {
    autoConnectedNoteKey,
    autoFailure,
    autoProgressText,
    autoTrying,
    autoVerdictActionText,
    autoVerdictKey,
    effectivePin,
    failureToShow,
    isHolding,
    mainTapLabelKey,
    mainTapPlan,
    restText,
    verdictWantsChooser,
    verdictWantsFile,
    type MainTapPlan,
    type PassFailure,
} from './autoConnect';
import {
    checkHeadlineKey,
    checkStateLabelKey,
    connectRefusedKey,
    retryableFailure,
    tapAction,
    tapLabelKey,
    type RouteCheck,
    type TapAction,
} from './routeCheck';

const HEADLINE_KEY: Record<ConnState, string> = {
    disconnected: 'conn.headline_disconnected',
    connecting: 'conn.headline_connecting',
    connected: 'conn.headline_connected',
    error: 'conn.headline_error',
};

const STATE_LABEL_KEY: Record<ConnState, string> = {
    disconnected: 'conn.disconnected',
    connecting: 'conn.connecting',
    connected: 'conn.state.routing', // "Connected · Routing" per design
    error: 'conn.error',
};

export interface MainScreenInput {
    t: (k: string) => string;
    locale: string;
    nowMs: number;
    /** The last connectionSummary read; null before the first. */
    conn: ConnectionSummary | null;
    /** The page's own optimistic state after a tap, if any. */
    optimistic: ConnState | null;
    /** A connect this page asked for has not come back yet. */
    connectInFlight: boolean;
    /** What the connect this page last started was. */
    intent: 'auto' | 'pinned' | null;
    /** An automatic connect whose call itself failed. */
    hostFailed: boolean;
    /** The stored pin, before it is checked against the route list. */
    pinnedRaw: string | null;
    /** The device's routes read strictly; `undefined` = not known. */
    routes: readonly RouteDisplayRow[] | undefined;
    /** This page has seen a connection up since it last saw none. */
    wasConnected: boolean;
    /** The last pass that tried something and found nothing
     *  (`rememberPassFailure`). */
    remembered: PassFailure | undefined;
}

/** The failure panel, when one is shown. */
export interface FailurePanel {
    verdict: string;
    tried: AutoTried[];
    /** "What to do", translated. */
    actionText: string;
    /** "You can try again in…", when the routes are resting. */
    restText: string | undefined;
    /** "Try again" would do nothing right now. */
    retryOff: boolean;
    /** "Try again" makes no sense for this verdict at all. */
    noRetry: boolean;
    wantsFile: boolean;
    wantsChooser: boolean;
}

export interface MainScreenView {
    /** The state the control and the label are drawn in. */
    state: ConnState;
    routeCheck: RouteCheck | undefined;
    auto: AutoStatus | undefined;
    /** The pin that still means something. */
    pinnedId: string | null;
    action: TapAction;
    plan: MainTapPlan;
    headline: string;
    stateLabel: string;
    tapLabel: string;
    /** An automatic connect found nothing, and that is the news. */
    failure: FailurePanel | undefined;
    /** The Android service holds the VPN closed and keeps retrying. */
    holding: boolean;
    /** The route the person chose failed its own connect. */
    pinnedFailed: boolean;
    noRoutes: boolean;
    needFile: boolean;
    showProgress: boolean;
    /** i18n key of the note under "You're connected.", if any. */
    connectedNoteKey: string | undefined;
    /** i18n key of the "the engine refused that" box, if any. */
    refusedKey: string | undefined;
    /** The engine itself is choosing the route that is running. */
    engineAuto: boolean;
}

export function mainScreenView(input: MainScreenInput): MainScreenView {
    const { t, locale, nowMs, conn, optimistic, routes } = input;
    // Optimistic overrides win until a poll lands a matching state.
    const polled: ConnState = optimistic ?? conn?.state ?? 'disconnected';
    // What the engine's connection check says, for the copy only. Not
    // applied over an optimistic state the poll has not confirmed yet.
    const routeCheck = optimistic ? undefined : conn?.routeCheck;
    // Not read over an optimistic "disconnected": the person just
    // cancelled, and the blob may say "trying" for one more poll.
    const auto = optimistic === 'disconnected' ? undefined : conn?.auto;
    const pinnedId = effectivePin(input.pinnedRaw, routes);
    const holding = !optimistic && isHolding(conn);
    // Holding is "connecting" to look at: Daal IS still trying.
    const state: ConnState = holding ? 'connecting' : polled;

    const action = tapAction(
        polled,
        routeCheck,
        input.connectInFlight || optimistic === 'connecting',
        conn?.routeCheckCategory,
    );
    const plan = mainTapPlan({ action, auto, pinnedRouteId: pinnedId, routes, holding });

    // An automatic connect that found no way that works, while that is
    // still the latest news. Not over the page's own optimistic state.
    const rawFailure: PassFailure | undefined = optimistic
        ? undefined
        : autoFailure(conn) ??
          (input.hostFailed && polled !== 'connected' ? { verdict: '', tried: [] } : undefined);
    let failure: FailurePanel | undefined;
    if (rawFailure) {
        const shown = failureToShow(rawFailure, input.remembered, routes, nowMs);
        // A pinned route is not what is resting: its own connect says so
        // if it is.
        const rest = pinnedId ? undefined : restText(t, locale, shown);
        failure = {
            verdict: shown.verdict,
            tried: shown.tried,
            actionText: autoVerdictActionText(t, locale, shown.verdict, routes, nowMs),
            restText: shown.verdict === 'all_cooling_down' ? undefined : rest,
            retryOff: !pinnedId && shown.retryOff,
            noRetry: !pinnedId && verdictWantsChooser(shown.verdict),
            wantsFile: verdictWantsFile(shown.verdict),
            wantsChooser: verdictWantsChooser(shown.verdict),
        };
    }

    const noRoutes = routes !== undefined && routes.length === 0;
    const needFile = plan.kind === 'add_file' && !failure && !holding;
    const showProgress =
        !holding &&
        state === 'connecting' &&
        (autoTrying(auto) || (optimistic === 'connecting' && input.intent === 'auto'));
    // The route the person chose failed its own connect and is resting
    // (not one of the two failures that rest nothing): the way forward
    // is to let Daal choose, and the page says so.
    const pinnedFailed =
        !!pinnedId &&
        !failure &&
        !holding &&
        polled === 'error' &&
        routeCheck === 'failed' &&
        !retryableFailure(conn?.routeCheckCategory);

    const headline = holding
        ? t('auto.holding.headline')
        : failure
        ? t(autoVerdictKey(failure.verdict))
        : showProgress
        ? input.wasConnected
            ? t('auto.moving')
            : autoProgressText(t, locale, auto)
        : needFile
        ? t('auto.need_file.headline')
        : pinnedFailed
        ? t('auto.pinned_failed')
        : t(checkHeadlineKey(state, routeCheck, conn?.routeCheckCategory) ?? HEADLINE_KEY[state]);
    const stateLabel = holding
        ? t('conn.state.lost')
        : failure
        ? t('auto.state.failed')
        : showProgress
        ? t('auto.state.trying')
        : t(checkStateLabelKey(state, routeCheck) ?? STATE_LABEL_KEY[state]);
    const tapLabel = t(mainTapLabelKey(plan, auto, tapLabelKey(action, polled, routeCheck), holding));

    const connectedNoteKey = state === 'connected' && !optimistic ? autoConnectedNoteKey(auto) : undefined;
    // The engine refused the last connect before trying anything. Shown
    // only while nothing is running, and not beside an automatic
    // failure: that has its own, fuller account.
    const refusedKey =
        conn?.connectRefused && !optimistic && !failure && !holding && (polled === 'disconnected' || polled === 'error')
            ? connectRefusedKey(conn.connectRefused)
            : undefined;

    return {
        state,
        routeCheck,
        auto,
        pinnedId,
        action,
        plan,
        headline,
        stateLabel,
        tapLabel,
        failure,
        holding,
        pinnedFailed,
        noRoutes,
        needFile,
        showProgress,
        connectedNoteKey,
        refusedKey,
        engineAuto: auto?.mode === true,
    };
}

/** What the page can do when the main control is tapped. */
export interface MainTapHandlers {
    disconnect(): unknown;
    addFile(): unknown;
    recovery(): unknown;
    connect(what: { kind: 'auto' } | { kind: 'pinned'; routeId: string }): unknown;
}

/** A tap on the main control. The ONE place the plan becomes an
 *  action: 'auto' connects — it never navigates anywhere. */
export function runMainTap(plan: MainTapPlan, h: MainTapHandlers): unknown {
    switch (plan.kind) {
        case 'disconnect':
            return h.disconnect();
        case 'add_file':
            // Nothing to connect with: never an empty list, never a
            // connect that can only fail. Straight to the add sheet.
            return h.addFile();
        case 'recovery':
            return h.recovery();
        case 'auto':
            return h.connect({ kind: 'auto' });
        case 'pinned':
            return h.connect({ kind: 'pinned', routeId: plan.routeId });
    }
}

/** What "Try again" in the failure panel connects: the route the person
 *  chose, else automatic. */
export function retryTarget(pinnedId: string | null): { kind: 'auto' } | { kind: 'pinned'; routeId: string } {
    return pinnedId ? { kind: 'pinned', routeId: pinnedId } : { kind: 'auto' };
}
