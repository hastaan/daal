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
import { connectedQualityKey } from './measured';
import { routeForDisplay } from './activeRoute';
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

/** How the bird is drawn (spec C2): grey with nothing to connect with,
 *  a breathing gold ring when ready, a spinning ring while connecting,
 *  green connected, amber slow or holding, red failed. */
export type HomeTone = 'none' | 'ready' | 'busy' | 'holding' | 'good' | 'slow' | 'bad';
/** The one gold button under the headline, when the state has one. */
export type HomePrimary = 'add_file' | 'try_again' | 'try_now' | 'let_daal_choose';
/** The one link under it, when the state has one. */
export type HomeLink = 'no_file_address' | 'add_new_file' | 'choose' | 'disconnect' | 'cancel';

export interface MainScreenView {
    /** The state the control and the label are drawn in. */
    state: ConnState;
    routeCheck: RouteCheck | undefined;
    auto: AutoStatus | undefined;
    /** The pin that still means something. */
    pinnedId: string | null;
    action: TapAction;
    plan: MainTapPlan;
    /** ONE short line, the same size in every state (spec C2). */
    headline: string;
    /** At most one line under it, or nothing. */
    line: string | undefined;
    /** The line is about the phone having no internet (a wifi-off icon). */
    lineNoInternet: boolean;
    tone: HomeTone;
    primary: HomePrimary | undefined;
    link: HomeLink | undefined;
    /** Connected, and the engine says the way is slow right now. */
    slow: boolean;
    /** The long sentence for this state (the engine's verdict, the
     *  progress "Trying way 2 of 4…"): the developer fold only. */
    detail: string;
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
    /** i18n key of the note under "You're connected.", if any. ONE
     *  line: what just happened (Daal moved to another way) when there
     *  is such news, otherwise how this way does here, when that helps
     *  (lib/measured.ts connectedQualityKey). */
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

    const detail = holding
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
    const slow = state === 'connected' && !optimistic && conn?.routeCheck === 'degraded';
    let tone: HomeTone;
    let headline: string;
    let line: string | undefined;
    let lineNoInternet = false;
    let primary: HomePrimary | undefined;
    let link: HomeLink | undefined;
    if (needFile) {
        tone = 'none';
        headline = t('auto.need_file.headline');
        primary = 'add_file';
        link = 'no_file_address';
    } else if (holding) {
        tone = 'holding';
        headline = t('auto.holding.headline');
        line = t('auto.holding.body');
        primary = 'try_now';
        link = 'disconnect';
    } else if (failure) {
        tone = 'bad';
        if (failure.verdict === 'network_down') {
            headline = t('conn.headline_no_internet');
            line = t('conn.no_internet.line');
            lineNoInternet = true;
        } else {
            headline = t('conn.headline_error');
            line = failure.restText ?? failure.actionText;
            // Never both: a file when there is nothing to connect with,
            // else choosing by hand when that is the way forward.
            link = failure.wantsFile || noRoutes ? 'add_new_file' : failure.wantsChooser ? 'choose' : undefined;
        }
        primary = failure.noRetry ? undefined : 'try_again';
    } else if (pinnedFailed) {
        tone = 'bad';
        headline = t('auto.pinned_failed');
        primary = 'let_daal_choose';
    } else if (state === 'error') {
        tone = 'bad';
        headline = t('conn.headline_error');
        const cat = routeCheck === 'failed' ? conn?.routeCheckCategory : undefined;
        line =
            cat === 'path_too_slow'
                ? t('conn.headline_too_slow')
                : cat === 'relay_no_egress'
                ? t('conn.headline_relay_no_internet')
                : undefined;
        primary = 'try_again';
    } else if (state === 'connecting') {
        const lost = routeCheck === 'failed' && !showProgress;
        tone = lost ? 'holding' : 'busy';
        headline = t(lost ? 'conn.headline_lost' : 'conn.headline_connecting');
        // The bird stops it too, but nobody should have to guess that.
        link = 'cancel';
    } else if (state === 'connected') {
        tone = slow ? 'slow' : 'good';
        headline = t('conn.headline_connected');
        const name = usingName(conn, t);
        line = name ? t('conn.using').replace('{name}', name) : undefined;
        // A quiet way out that is visible, beside the bird.
        link = 'disconnect';
    } else {
        tone = 'ready';
        headline = t('conn.headline_disconnected');
    }

    const tapLabel = t(mainTapLabelKey(plan, auto, tapLabelKey(action, polled, routeCheck), holding));

    // One line. News about what just happened (Daal moved) comes first
    // — except when the connection is slow NOW: "Daal moved to a faster
    // way." stays on the engine's record for as long as that way is up,
    // and under "Connected, but slow." it is stale news hiding the one
    // thing worth saying.
    const quality = connectedQualityKey(conn, routes === undefined ? undefined : routes.length > 1);
    const connectedNoteKey =
        state === 'connected' && !optimistic
            ? conn?.routeCheck === 'degraded'
                ? quality ?? autoConnectedNoteKey(auto)
                : autoConnectedNoteKey(auto) ?? quality
            : undefined;
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
        line,
        lineNoInternet,
        tone,
        primary,
        link,
        slow,
        detail,
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

/** The short name of the way in use, for "Using {name}": the file's
 *  publisher when the route has one, else the route's own name, else
 *  our words for a route whose details could not be read. */
export function usingName(conn: ConnectionSummary | null, t: (k: string) => string): string | undefined {
    if (!conn || conn.state !== 'connected') return undefined;
    const r = routeForDisplay(conn.activeRoute, t);
    if (!r) return undefined;
    return r.publisherName || r.routeNickname || undefined;
}

/** The badges under the headline (spec C2, at most two): Slow, then
 *  Manual (a way chosen by hand), then Lifeline (a mode other than
 *  normal). */
export type HomeBadge = 'slow' | 'manual' | 'lifeline';
export function homeBadges(
    view: Pick<MainScreenView, 'slow' | 'pinnedId' | 'needFile' | 'state' | 'engineAuto'>,
    mode: string | undefined,
): HomeBadge[] {
    if (view.needFile) return [];
    const out: HomeBadge[] = [];
    if (view.slow) out.push('slow');
    // Manual: a way the person chose, or a connection the engine is not
    // choosing for (it stays on that one way).
    if (view.pinnedId || (view.state === 'connected' && !view.engineAuto)) out.push('manual');
    if (mode && mode !== 'normal') out.push('lifeline');
    return out.slice(0, 2);
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

/** Whether a failed connect gets its "Details" fold (or, on a computer,
 *  the "What Daal tried" panel): only when something was tried. When
 *  the phone itself has no internet nothing was, and a fold that opens
 *  onto "Tried no ways" is noise (spec F.2, No internet). Developer
 *  mode keeps it for the verdict code. */
export function failureDetailsShown(tried: readonly unknown[], dev: boolean): boolean {
    return tried.length > 0 || dev;
}
