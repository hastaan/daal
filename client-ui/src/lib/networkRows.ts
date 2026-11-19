// What the Connections page shows per row, and what a tap is waiting for.
//
// Pure functions, so the rules can be tested without a webview (the
// pages are tested through helpers in this codebase).
import type { ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import { rowGradeSuffix } from './measured';
import { runningRouteId, summaryExtras } from './activeRoute';

// ---- the list body ---------------------------------------------------

/** What the body of the page is.
 *
 *    'loading'  nothing has been read yet and nothing has failed
 *    'failed'   the list could not be read and there is nothing to show
 *    'empty'    the list was read and is empty
 *    'list'     there are rows (possibly from before a failed re-read)
 *
 *  The page used to test `tree === null` alone, so a failed first read
 *  sat on "Loading…" for ever under a red banner. And an empty list
 *  left over from before a failed re-read is 'failed', not 'empty':
 *  "No publishers yet" is a claim about the phone that nobody has just
 *  verified. */
export type ListView = 'loading' | 'failed' | 'empty' | 'list';

export function listView(rows: readonly unknown[] | null, loadFailed: boolean): ListView {
    if (rows !== null && rows.length > 0) return 'list';
    if (loadFailed) return 'failed';
    return rows === null ? 'loading' : 'empty';
}

// ---- the line above the list -------------------------------------------

/** The sentence above the list about who is choosing the way, and —
 *  when the saved choice is not what is in force — a second line about
 *  the next connect.
 *
 *  The line used to follow the SAVED choice alone: with a way pinned
 *  earlier and the engine connected automatically on another one (the
 *  person pressed "Let Daal choose", or a pinned tap fell back to
 *  automatic) it said "You chose one way yourself. Daal uses only that
 *  one." over a connection Daal had chosen. What is true NOW comes
 *  from the engine; the saved choice is a statement about next time.
 *
 *    engine automatic (trying, or connected)   'network.auto.line'
 *        + a pin is saved                      next: 'network.pinned.next'
 *    connected by hand on the pinned way       'network.pinned.line'
 *    connected by hand on another way          'network.pinned.now'
 *        + next: the pin, or automatic
 *    nothing running                           the saved choice
 */
export interface ModeLine {
    lineKey: string;
    nextKey?: string;
}

export function connectionsModeLine(
    pinnedId: string | null,
    s: ConnectionSummary | null | undefined,
): ModeLine {
    const saved: ModeLine = { lineKey: pinnedId ? 'network.pinned.line' : 'network.auto.line' };
    if (!s) return saved;
    const auto = s.auto;
    if (auto?.mode === true && (auto.state === 'trying' || auto.state === 'connected')) {
        return { lineKey: 'network.auto.line', ...(pinnedId ? { nextKey: 'network.pinned.next' } : {}) };
    }
    const running = s.state === 'connected' ? runningRouteId(s) : null;
    if (running === null) return saved;
    if (pinnedId === running) return { lineKey: 'network.pinned.line' };
    return {
        lineKey: 'network.pinned.now',
        nextKey: pinnedId ? 'network.pinned.next' : 'network.auto.next',
    };
}

/** The words of that line, as the page draws them: the sentence about
 *  now, and — when there is one — the sentence about next time. */
export function modeLineTexts(t: (k: string) => string, line: ModeLine): { now: string; next?: string } {
    return { now: t(line.lineKey), ...(line.nextKey ? { next: t(line.nextKey) } : {}) };
}

// ---- one row ---------------------------------------------------------

/** The small line under a row's name, whole: the kind of connection,
 *  then — each only when it is true — "not supported", the row's state,
 *  who picked it, how it has done on this network (lib/measured.ts; an
 *  engine that sent no measurement gets no claim, and there is no
 *  number: the old "87%" was a score, not a success rate), resting,
 *  budget used up.
 *
 *  `inCooldown` / `budgetExhausted` are compared with `=== true` on
 *  purpose: undefined means the engine has not looked, which is not the
 *  same as "no". */
export function rowMetaText(
    t: (k: string) => string,
    r: RouteDisplayRow,
    o: { stateLabelKey?: string; isAuto?: boolean; isPinned?: boolean } = {},
): string {
    return [
        r.family,
        r.familyMaturity === 'unsupported' ? ` · ${t('network.family.unsupported')}` : '',
        o.stateLabelKey ? ` · ${t(o.stateLabelKey)}` : '',
        o.isAuto ? ` · ${t('network.auto.mark')}` : '',
        o.isPinned ? ` · ${t('network.pinned.mark')}` : '',
        rowGradeSuffix(t, r.measured),
        r.inCooldown === true ? ` · ${t('network.cooled')}` : '',
        r.budgetExhausted === true ? ` · ${t('network.budget_full')}` : '',
    ].join('');
}

/** 'checking'  the route the person just tapped, or the one the engine
 *              is still proving. Not connected yet.
 *  'connected' the route the engine has running and has proved.
 *  'lost'      the route the engine has running that has STOPPED
 *              carrying traffic; the engine keeps it up and retries.
 *              The Connection page says "Connection lost. Trying
 *              again…" for it; calling the row "connected" was a claim
 *              the engine had just withdrawn.
 *  'idle'      anything else. */
export type RowState = 'idle' | 'checking' | 'connected' | 'lost';

/** What the engine is doing with the route it has running. */
export type RunningPhase = 'steady' | 'verifying' | 'lost';

/** The phase of the running route, from one summary. */
export function runningPhase(s: ConnectionSummary): RunningPhase {
    if (s.state !== 'connecting') return 'steady';
    if (s.routeCheck === 'verifying') return 'verifying';
    if (s.routeCheck === 'failed' && s.routeRunning === true) return 'lost';
    return 'steady';
}

/** `activeId` is the route the engine reports as running (or null),
 *  `phase` what the engine is doing with that route (a boolean is
 *  accepted for "still proving it"), and `pendingId` the route tapped
 *  on this page whose answer has not come back yet.
 *
 *  During a switch from A to B this gives, in order:
 *    tap on B, engine still on A      A 'connected', B 'checking'
 *    engine reports B, still proving  A 'idle',      B 'checking'
 *    engine proved B                  A 'idle',      B 'connected'
 *    engine refused B                 A 'connected', B 'idle'
 *  The old row is never unmarked on the tap alone, and the new row is
 *  never marked connected before the engine says so. */
export function rowState(
    routeId: string,
    activeId: string | null,
    pendingId: string | null,
    phase: RunningPhase | boolean,
): RowState {
    if (routeId === pendingId) return 'checking';
    if (routeId === activeId) {
        if (phase === true || phase === 'verifying') return 'checking';
        return phase === 'lost' ? 'lost' : 'connected';
    }
    return 'idle';
}

/** i18n key of the word beside a row that is not idle. */
export function rowStateLabelKey(state: RowState): string | undefined {
    if (state === 'checking') return 'conn.checking';
    if (state === 'connected') return 'network.connected';
    if (state === 'lost') return 'conn.state.lost';
    return undefined;
}

/** What a tap on the row's button does. 'cancel' and 'disconnect' both
 *  stop the engine (that is how a check is cancelled — the same
 *  mechanism the Connection page uses, `tapAction` in routeCheck.ts);
 *  they differ in the word on the button.
 *
 *  `otherRouteRunning`: the row is the one just tapped and a DIFFERENT
 *  route is still running (a switch the engine has not acted on yet).
 *  Stopping the engine then also stops that working route, so the
 *  button must not read "Cancel" — a word that promises only the new
 *  attempt is abandoned. It reads "Disconnect", which is what it does. */
export type RowAction = 'connect' | 'cancel' | 'disconnect';

export function rowAction(state: RowState, otherRouteRunning = false): RowAction {
    if (state === 'checking') return otherRouteRunning ? 'disconnect' : 'cancel';
    if (state === 'connected' || state === 'lost') return 'disconnect';
    return 'connect';
}

/** Is a route other than `routeId` running while `routeId` is the tap
 *  still waiting for its answer? */
export function switchingAwayFromRunning(
    routeId: string,
    activeId: string | null,
    pendingId: string | null,
): boolean {
    return routeId === pendingId && activeId !== null && activeId !== routeId;
}

export function rowActionLabelKey(action: RowAction): string {
    if (action === 'cancel') return 'conn.cancel_action';
    if (action === 'disconnect') return 'network.disconnect';
    return 'network.connect';
}

/** A row's button is unavailable only when it would start a SECOND
 *  connect while one is still unanswered. Cancel and Disconnect are
 *  always available: being able to stop is the point. */
export function rowActionDisabled(action: RowAction, pendingId: string | null): boolean {
    return action === 'connect' && pendingId !== null;
}

// ---- a tap waiting for its answer --------------------------------------

/** How a tapped connect ended, as far as the engine has said. */
export type PendingOutcome = 'waiting' | 'connected' | 'refused' | 'failed' | 'timeout';

export interface PendingConnect {
    routeId: string;
    sinceMs: number;
    /** What the engine's blob ALREADY said about this route at the
     *  moment of the tap. `connect_refused` and a failed check both
     *  stand in the blob until the next connect reaches the engine, and
     *  on Android the connect call returns before that — so the first
     *  poll after a tap can still be showing the answer to an earlier
     *  one. The same answer is not taken as news until the grace period
     *  has passed. */
    baseline: PendingOutcome;
    /** The host has taken the connect (its call returned). Until then
     *  the person may still be looking at the system's VPN permission
     *  dialog, for as long as they like: "nothing is running" is then
     *  not an answer, and no clock runs. The page sets it where it
     *  re-stamps `sinceMs`. */
    accepted: boolean;
}

/** Two polls: long enough for the VPN service to have handed the new
 *  connect to the engine. */
export const PENDING_GRACE_MS = 4000;
/** Past this the page stops waiting and says so. Longer than the
 *  engine's own connection check. Counted from when the host accepted
 *  the connect. */
export const PENDING_TIMEOUT_MS = 90_000;
/** A tap after which the engine has nothing running, is checking
 *  nothing and names no reason for this long ended in nothing: the page
 *  says the connect did not work rather than "Checking…" for a minute
 *  and a half. Applies only once the host has accepted the connect
 *  (`accepted`), and is counted from then, so time spent on the
 *  system's VPN permission dialog neither counts nor triggers it. */
export const PENDING_IDLE_MS = 10_000;

/** What the blob says about a connect to `routeId`, ignoring time. */
export function pendingOutcomeNow(routeId: string, s: ConnectionSummary): PendingOutcome {
    const active = s.activeRoute?.routeId;
    if (active === routeId && s.state === 'connected') return 'connected';
    const extras = summaryExtras(s);
    if (s.connectRefused) {
        // An engine that does not say which route it refused is taken
        // to mean the last one asked for.
        const about = extras.connectRefusedRoute;
        if (about === undefined || about === routeId) return 'refused';
    }
    if (
        s.state === 'error' &&
        s.routeCheck === 'failed' &&
        (active === undefined || active === routeId)
    ) {
        return 'failed';
    }
    // The Android service's own record of a switch that did not take.
    // After a switch to a route that carries nothing the service goes
    // back to the old route, and the engine's blob then reads "the old
    // route is connected" with no trace of the one that failed: without
    // this the tapped row waited out the whole timeout in silence.
    if (extras.lastSwitch?.routeId === routeId) return extras.lastSwitch.outcome;
    return 'waiting';
}

export function startPending(
    routeId: string,
    nowMs: number,
    last: ConnectionSummary | null | undefined,
): PendingConnect {
    return {
        routeId,
        sinceMs: nowMs,
        baseline: last ? pendingOutcomeNow(routeId, last) : 'waiting',
        accepted: false,
    };
}

/** The host accepted the connect: the clocks start now. */
export function acceptPending(p: PendingConnect, nowMs: number): PendingConnect {
    return { ...p, sinceMs: nowMs, accepted: true };
}

export function resolvePending(
    p: PendingConnect,
    s: ConnectionSummary,
    nowMs: number,
): PendingOutcome {
    const now = pendingOutcomeNow(p.routeId, s);
    const age = nowMs - p.sinceMs;
    if (now === 'connected') return now;
    if (now === 'waiting') {
        // Not accepted yet: the connect call itself is still open (the
        // permission dialog, or a desktop connect that blocks for the
        // whole check) and will answer by returning or rejecting.
        if (!p.accepted) return 'waiting';
        if (age >= PENDING_TIMEOUT_MS) return 'timeout';
        const nothingRunning = s.state === 'disconnected' && s.routeRunning !== true;
        return nothingRunning && age >= PENDING_IDLE_MS ? 'failed' : 'waiting';
    }
    if (now === p.baseline && age < PENDING_GRACE_MS) return 'waiting';
    return now;
}

/** The route to pin after a tap on the Connections page ended, or
 *  `undefined` for none. A route picked by hand becomes "the one the
 *  main button connects" only when it is CONNECTED: a tap that failed,
 *  was refused, timed out or was cancelled chose nothing. */
export function pinAfterTap(routeId: string, outcome: PendingOutcome): string | undefined {
    return outcome === 'connected' && routeId ? routeId : undefined;
}

/** i18n key of the sentence for a tap that ended 'failed' or 'timeout'
 *  on the Connections page, or `undefined` to use the sentence the
 *  engine's own verdict selects (lib/routeCheck.ts connectFailedKey).
 *
 *  A switch that failed while another route stayed connected gets its
 *  own words: "Could not connect on this route" alone would leave the
 *  person wondering whether they are still protected. */
export function pendingFailureKey(
    routeId: string,
    outcome: PendingOutcome,
    s: ConnectionSummary,
): string | undefined {
    if (outcome === 'timeout') return 'network.connect_timeout';
    if (outcome !== 'failed') return undefined;
    const note = summaryExtras(s).lastSwitch;
    if (note?.routeId !== routeId) return undefined;
    return note.keptRouteId ? 'network.switch_failed_kept' : 'network.switch_failed_none';
}
