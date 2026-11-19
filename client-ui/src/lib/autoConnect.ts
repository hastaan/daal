// Automatic connect, as the pages read it.
//
// The engine owns the work: `engine_connect_auto` builds the candidate
// list, tries each route and keeps the first that carries traffic, and
// its diagnostics blob carries an `auto` block from memory saying where
// it is. Everything here is the reading of that block and the handful
// of decisions the main screen makes with it — pure functions, so the
// rules are tested without a webview (the pages are tested through
// helpers in this codebase).
//
// Two rules hold throughout:
//   * the engine's vocabulary (route ids, family names, result and
//     category codes) is never put in a sentence. It appears only in
//     the Details fold, for the person helping from the other end;
//   * a code this app does not know selects the GENERIC sentence. An
//     engine newer than the app must not be able to print a raw code.
import type {
    AutoConnectResult,
    AutoStatus,
    AutoTried,
    ConnState,
    ConnectionSummary,
    RouteDisplayRow,
} from '../contract/D2Contract';
import type { TapAction } from './routeCheck';
import { localDigits } from './measured';

// ---- reading the engine ------------------------------------------------

function str(v: unknown): string {
    return typeof v === 'string' ? v : '';
}

function count(v: unknown): number {
    return typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

function parseTried(v: unknown): AutoTried[] {
    if (!Array.isArray(v)) return [];
    const out: AutoTried[] = [];
    for (const raw of v) {
        if (!raw || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        const routeId = str(r.route_id);
        if (!routeId) continue;
        const refined = str(r.refined);
        const setupMs = count(r.setup_ms);
        const racedWith = str(r.raced_with);
        out.push({
            routeId,
            family: str(r.family),
            result: str(r.result),
            category: str(r.category),
            ...(refined ? { refined } : {}),
            ...(setupMs > 0 ? { setupMs } : {}),
            ...(racedWith ? { racedWith } : {}),
        });
    }
    return out;
}

/** `auto.racing`: the two routes being tried at this moment. Anything
 *  that is not a list of at least two different ids is "not racing" —
 *  one id alone is simply `trying`. Never more than two are kept: the
 *  engine never tries more at once, and a block that says otherwise is
 *  not something to repeat. */
function parseRacing(v: unknown): string[] {
    if (!Array.isArray(v)) return [];
    const ids: string[] = [];
    for (const x of v) {
        if (typeof x === 'string' && x !== '' && !ids.includes(x)) ids.push(x);
    }
    return ids.length >= 2 ? ids.slice(0, 2) : [];
}

/** Two routes are being tried at the same moment. */
export function autoRacing(auto: AutoStatus | undefined): boolean {
    return auto?.state === 'trying' && (auto.racing?.length ?? 0) >= 2;
}

/** The `auto` block of export_diagnostics. `undefined` when there is no
 *  block or its state is not one this app knows: "the engine said
 *  nothing", never a guess. */
export function parseAuto(v: unknown): AutoStatus | undefined {
    if (!v || typeof v !== 'object') return undefined;
    const a = v as Record<string, unknown>;
    const state = a.state;
    if (state !== 'idle' && state !== 'trying' && state !== 'connected' && state !== 'failed') {
        return undefined;
    }
    return {
        state,
        mode: a.mode === true,
        trying: str(a.trying),
        racing: parseRacing(a.racing),
        index: count(a.index),
        total: count(a.total),
        tried: parseTried(a.tried),
        verdict: str(a.verdict),
        routeId: str(a.route_id),
    };
}

/** The body `connect_auto` returns, where the host hands it back. Takes
 *  the JSON text or the already-parsed object; anything else is `null`
 *  ("the host did not say" — the diagnostics still will). */
export function parseAutoResult(v: unknown): AutoConnectResult | null {
    let o: unknown = v;
    if (typeof v === 'string') {
        try {
            o = JSON.parse(v);
        } catch {
            return null;
        }
    }
    if (!o || typeof o !== 'object') return null;
    const r = o as Record<string, unknown>;
    if (typeof r.connected !== 'boolean') return null;
    return {
        connected: r.connected,
        routeId: str(r.route_id),
        family: str(r.family),
        tried: parseTried(r.tried),
        verdict: str(r.verdict),
        candidates: count(r.candidates),
    };
}

/** The Android VPN service's note about an automatic connect that
 *  found nothing (`vpn_status.last_switch` with `auto: true`): the
 *  engine's verdict code, or the service's own when the engine could
 *  not be asked. `undefined` = no such note (desktop, an older service,
 *  a note about a switch by hand). */
export function parseAutoNote(vpnStatus: unknown): string | undefined {
    const raw = (vpnStatus as Record<string, unknown> | null | undefined)?.last_switch;
    if (!raw || typeof raw !== 'object') return undefined;
    const n = raw as Record<string, unknown>;
    if (n.auto !== true || n.outcome !== 'failed') return undefined;
    return str(n.reason);
}

/** `vpn_status.holding` (Android): the VPN interface is up with NOTHING
 *  behind it — the engine ran out of ways while the person was
 *  connected and the service is asking it again on a timer. Every other
 *  app on the phone is cut off meanwhile. Only a literal `true` counts:
 *  desktop, an older service and an unreadable answer are "not
 *  holding". */
export function parseHolding(vpnStatus: unknown): boolean {
    return (vpnStatus as Record<string, unknown> | null | undefined)?.holding === true;
}

/** The service is holding and that is the news: nothing is connected,
 *  and the engine is not in the middle of a pass (then the page shows
 *  the pass). */
export function isHolding(s: ConnectionSummary | null | undefined): boolean {
    return !!s && s.holding === true && s.state !== 'connected' && s.auto?.state !== 'trying';
}

// ---- the state the pages show ------------------------------------------

/** The connection state, given what the posture and the connection
 *  check say and what automatic connect is doing.
 *
 *  While the engine is working through its candidates the blob passes
 *  through every in-between reading: the route that just failed is torn
 *  down (`route_running` false with a failed check — which alone reads
 *  as 'error'), nothing is active for a moment ('disconnected'), the
 *  next one is still being proved. None of those is the truth while
 *  `auto.state` is 'trying': the truth is "connecting". This is also
 *  what keeps the page from flashing "disconnected" when the engine
 *  moves to another route by itself. */
export function stateWithAuto(state: ConnState, auto: AutoStatus | undefined): ConnState {
    if (auto?.state === 'trying') return 'connecting';
    // Every candidate was tried and none carried: nothing is running
    // and nothing will retry by itself. Only a reading of "nothing is
    // happening" is corrected — a connect by hand that is being checked
    // right now, or one that is up, is not overruled by an older
    // automatic attempt.
    if (auto?.state === 'failed' && state === 'disconnected') return 'error';
    return state;
}

/** True while automatic connect is working through its candidates. */
export function autoTrying(auto: AutoStatus | undefined): boolean {
    return auto?.state === 'trying';
}

/** An automatic connect that ended with nothing connected, while that
 *  is still the latest thing that happened: its verdict code and what
 *  was tried. `undefined` otherwise.
 *
 *  The engine's own block is the answer whenever the engine has one.
 *  On Android the VPN service also leaves a note when an automatic
 *  connect found nothing; it has a verdict and no list, and it NEVER
 *  EXPIRES (it lives until the next start or stop reaches the service).
 *  So it is read only where the engine cannot speak for itself: no
 *  `auto` block at all (a library without automatic connect), or the
 *  service's own "the engine could not be asked". When the engine's
 *  block says idle — it dropped its verdict because the routes may be
 *  tried again — the note is old news, and the page goes back to
 *  "Press to connect." Neither counts while something is connected or
 *  being tried. */
export function autoFailure(
    s: ConnectionSummary | null | undefined,
): { verdict: string; tried: AutoTried[] } | undefined {
    if (!s || (s.state !== 'error' && s.state !== 'disconnected')) return undefined;
    if (s.auto?.state === 'failed') return { verdict: s.auto.verdict, tried: s.auto.tried };
    if (s.autoFailedNote === undefined) return undefined;
    if (s.auto === undefined || (s.autoFailedNote === NOTE_UNAVAILABLE && s.auto.state === 'idle')) {
        return { verdict: s.autoFailedNote, tried: [] };
    }
    return undefined;
}

/** The service's verdict when the engine has no automatic connect to
 *  ask (SwitchPolicy.VERDICT_UNAVAILABLE). */
const NOTE_UNAVAILABLE = 'auto_unavailable';

/** The engine is in automatic mode and names `routeId` as the one up. */
export function autoIsUsing(auto: AutoStatus | undefined, routeId: string | null | undefined): boolean {
    return !!routeId && !!auto && auto.mode && auto.state === 'connected' && auto.routeId === routeId;
}

// ---- progress ----------------------------------------------------------

const digits = localDigits;

/** "Trying way 2 of 4…". No route id, no family: the sentence is for
 *  the person holding the phone. When the engine has not said how many
 *  there are (or the numbers make no sense) it says so without numbers
 *  rather than printing "0 of 0". */
export function autoProgressText(
    t: (k: string) => string,
    locale: string,
    auto: AutoStatus | undefined,
): string {
    // Two at once: still ONE sentence, and no "way 2 of 4" — which of
    // the two would that be? No route id, no kind of connection.
    if (autoRacing(auto)) return t('auto.trying_two');
    const total = auto?.total ?? 0;
    const index = auto?.index ?? 0;
    if (total < 1 || index < 1 || index > total) return t('auto.trying_plain');
    // One candidate: "way 1 of 1" is noise.
    if (total === 1) return t('auto.trying_plain');
    return t('auto.trying')
        .replace('{i}', digits(index, locale))
        .replace('{n}', digits(total, locale));
}

// ---- verdicts ----------------------------------------------------------

/** The verdict codes this app has a sentence for (contract 3 of the
 *  selection wave). '' and 'moved_on' are success codes and are not
 *  here: they have notes, below. */
export const FAILURE_VERDICTS = [
    'no_routes',
    'all_need_new_file',
    'all_expired_or_revoked',
    'all_cooling_down',
    'network_down',
    'udp_blocked_here',
    'relay_unreachable',
    'name_blocked',
    'address_blocked',
    'all_failed',
    // Beyond the contract's set, and one the engine is KNOWN to send:
    // routes exist and Daal may not pick any of them by itself (the
    // usual case: a single pasted link of a kind Daal only uses when
    // the person chooses it). The generic sentence — "Try again" — was a
    // dead end there; this one points at choosing by hand, which works.
    'none_usable',
] as const;

const KNOWN_FAILURE = new Set<string>(FAILURE_VERDICTS);

/** i18n key of the ONE sentence for a failed automatic connect. */
export function autoVerdictKey(verdict: string): string {
    return KNOWN_FAILURE.has(verdict) ? `auto.verdict.${verdict}` : 'auto.verdict.generic';
}

/** i18n key of what the person can do about it. */
export function autoVerdictActionKey(verdict: string): string {
    return KNOWN_FAILURE.has(verdict) ? `auto.verdict.${verdict}.do` : 'auto.verdict.generic.do';
}

/** For 'all_cooling_down': whole minutes until the first resting route
 *  may be tried again, when the route list says. `undefined` = the data
 *  does not have it (the sentence then says "in a few minutes"). */
export function cooldownMinutes(
    routes: readonly RouteDisplayRow[] | undefined,
    nowMs: number,
): number | undefined {
    let first: number | undefined;
    for (const r of routes ?? []) {
        const until = r.cooldownUntilUnixMs;
        if (r.inCooldown !== true || typeof until !== 'number' || until <= nowMs) continue;
        if (first === undefined || until < first) first = until;
    }
    if (first === undefined) return undefined;
    return Math.max(1, Math.ceil((first - nowMs) / 60_000));
}

/** The whole "what to do" line for a failed automatic connect. */
export function autoVerdictActionText(
    t: (k: string) => string,
    locale: string,
    verdict: string,
    routes: readonly RouteDisplayRow[] | undefined,
    nowMs: number,
): string {
    if (verdict === 'all_cooling_down') {
        const m = cooldownMinutes(routes, nowMs);
        if (m !== undefined) {
            return t('auto.verdict.all_cooling_down.do_in').replace('{n}', digits(m, locale));
        }
    }
    return t(autoVerdictActionKey(verdict));
}

/** Does this verdict mean "there is nothing here to connect with"? The
 *  page then offers "Add your file" beside "Try again". */
export function verdictWantsFile(verdict: string): boolean {
    return verdict === 'no_routes';
}

/** Does this verdict mean "Daal will not choose, but you can"? The
 *  page then offers "Choose one yourself" (it opens the chooser) and no
 *  "Try again": trying again gives the same answer for ever. */
export function verdictWantsChooser(verdict: string): boolean {
    return verdict === 'none_usable';
}

// ---- a failure, and the rest after it ----------------------------------

export interface PassFailure {
    verdict: string;
    tried: AutoTried[];
}

/** Every route on the device is resting right now (the list was read,
 *  is not empty, and each row has a cooldown that has not run out). */
export function allResting(routes: readonly RouteDisplayRow[] | undefined, nowMs: number): boolean {
    if (!routes || routes.length === 0) return false;
    return routes.every(
        (r) => r.inCooldown === true && typeof r.cooldownUntilUnixMs === 'number' && r.cooldownUntilUnixMs > nowMs,
    );
}

/** The failure worth REMEMBERING, given the one remembered so far and
 *  the latest reading: a pass that tried something and found nothing.
 *  'all_cooling_down' is not one — it is the engine saying "I did not
 *  try" — so it never replaces what was learned before it. Forgotten
 *  when something connects, or when the engine has nothing to report. */
export function rememberPassFailure(
    prev: PassFailure | undefined,
    s: ConnectionSummary | null | undefined,
): PassFailure | undefined {
    if (!s) return prev;
    if (s.state === 'connected' || s.auto?.state === 'connected') return undefined;
    if (s.auto?.state === 'trying') return prev;
    if (s.auto?.state !== 'failed') return undefined;
    if (s.auto.verdict === 'all_cooling_down' || s.auto.verdict === 'cancelled') return prev;
    return { verdict: s.auto.verdict, tried: s.auto.tried };
}

/** What the failure panel shows.
 *
 *  After a pass in which the routes ANSWERED and failed, the engine
 *  rests them, and the next pass answers 'all_cooling_down' without
 *  trying anything. Pressing "Try again" used to replace the one
 *  sentence the person could act on ("ask for a new file") with "Daal
 *  is giving them a rest", via a button that could not have done
 *  anything else. So:
 *
 *    - the sentence stays the one of the pass that actually tried
 *      (`remembered`), with the wait said under it;
 *    - "Try again" is off while every route is known to be resting and
 *      the list says for how long; when the list cannot say, it stays
 *      on (a press is then the only way to find out).
 */
export function failureToShow(
    current: PassFailure,
    remembered: PassFailure | undefined,
    routes: readonly RouteDisplayRow[] | undefined,
    nowMs: number,
): PassFailure & { resting: boolean; waitMinutes: number | undefined; retryOff: boolean } {
    const coolingVerdict = current.verdict === 'all_cooling_down';
    const resting = coolingVerdict || allResting(routes, nowMs);
    const shown = coolingVerdict && remembered ? remembered : current;
    const waitMinutes = resting ? cooldownMinutes(routes, nowMs) : undefined;
    return { ...shown, resting, waitMinutes, retryOff: resting && waitMinutes !== undefined };
}

/** The "you can try again in…" line under a failure whose routes are
 *  resting; `undefined` when they are not. */
export function restText(
    t: (k: string) => string,
    locale: string,
    view: { resting: boolean; waitMinutes: number | undefined },
): string | undefined {
    if (!view.resting) return undefined;
    return view.waitMinutes !== undefined
        ? t('auto.rest.wait_in').replace('{n}', digits(view.waitMinutes, locale))
        : t('auto.rest.wait');
}

/** A failed automatic pass as one comparable string, or `undefined`
 *  when the summary shows none. */
export function failureSignature(s: ConnectionSummary | null | undefined): string | undefined {
    if (!s || s.auto?.state !== 'failed') return undefined;
    return JSON.stringify([s.auto.verdict, s.auto.tried.map((x) => [x.routeId, x.result, x.category])]);
}

/** After an automatic start, is the summary just read still the OLD
 *  failure — so the page keeps its own "connecting" instead of flashing
 *  that failure back?
 *
 *  On Android the start call resolves as soon as the VPN service has
 *  been asked (`hostAnswered` false: it hands nothing back), a moment
 *  before the service reaches the engine; the blob read right then
 *  still carries the pass that failed before the tap. Where the host
 *  DID hand back a result (desktop: the call blocks until the pass is
 *  over) whatever the blob says is the new pass, identical or not. */
export function staleFailureAfterStart(
    hostAnswered: boolean,
    signatureAtTap: string | undefined,
    now: ConnectionSummary,
): boolean {
    if (hostAnswered || signatureAtTap === undefined) return false;
    return failureSignature(now) === signatureAtTap;
}

/** i18n key of the short note under "You're connected.", or
 *  `undefined` for nothing. Three things are worth a sentence once it
 *  works: Daal had to move past a way that failed, this network blocks
 *  some kinds of connection (no action needed — it is working), and
 *  Daal left a way that still worked for a faster one ('moved_faster':
 *  the person may have noticed a blink and should know it was on
 *  purpose). An unknown code says nothing: connected is connected. */
export function autoConnectedNoteKey(auto: AutoStatus | undefined): string | undefined {
    if (!auto || !auto.mode || auto.state !== 'connected') return undefined;
    if (auto.verdict === 'moved_faster') return 'auto.note.moved_faster';
    // The engine's verdict for a pass that CONNECTED after a failure is
    // 'moved_on'; that the way it moved past was stopped by this network
    // (and not by a dead server) is on that route's entry, `refined`.
    if (
        auto.verdict === 'udp_blocked_here' ||
        (auto.verdict === 'moved_on' && auto.tried.some((t) => t.refined === 'udp_blocked_here'))
    ) {
        return 'auto.note.udp_blocked_here';
    }
    if (auto.verdict === 'moved_on') return 'auto.note.moved_on';
    return undefined;
}

const KNOWN_RESULT = new Set(['carried', 'not_carrying', 'start_failed', 'refused', 'cancelled', 'stopped']);

/** i18n key of our words for one tried route's result (Details). */
export function autoResultKey(result: string): string {
    return KNOWN_RESULT.has(result) ? `auto.result.${result}` : 'auto.result.other';
}

// ---- the person's own choice -------------------------------------------

const PIN_KEY = 'daal.d2.connect.pinned_route';

/** The route the person chose by hand, or `null` for Automatic (the
 *  default). Kept on the platform side like the other UI preferences
 *  (lib/prefs.ts); the engine is told only through which connect call
 *  is made. */
export function getPinnedRoute(): string | null {
    try {
        const v = localStorage.getItem(PIN_KEY);
        return v ? v : null;
    } catch {
        return null;
    }
}

export function setPinnedRoute(routeId: string | null): void {
    try {
        if (routeId) localStorage.setItem(PIN_KEY, routeId);
        else localStorage.removeItem(PIN_KEY);
    } catch {
        /* no storage: the choice lasts as long as the page */
    }
}

/** The route was deleted: a pin on it is forgotten with it. */
export function forgetPinnedRoute(routeId: string): void {
    if (getPinnedRoute() === routeId) setPinnedRoute(null);
}

/** The pin that still means something. A pinned route that the device
 *  no longer holds (its file was removed, the store was reset) is no
 *  choice at all: back to Automatic, rather than a main button that can
 *  only fail. `routes` undefined = the list could not be read; the pin
 *  is then kept — nothing was learned. */
export function effectivePin(
    pinned: string | null,
    routes: readonly RouteDisplayRow[] | undefined,
): string | null {
    if (!pinned) return null;
    if (routes === undefined) return pinned;
    return routes.some((r) => r.routeId === pinned) ? pinned : null;
}

// ---- the main button ---------------------------------------------------

/** What a tap on the main control does.
 *
 *    'disconnect'  stop what is running (also cancels automatic connect
 *                  wherever it is — the engine abandons it at once; and
 *                  lets go of a VPN the service is holding closed)
 *    'recovery'    a connect by hand failed and its route is resting:
 *                  the sheet of other choices
 *    'add_file'    this device holds no route at all: the add sheet
 *    'auto'        connectAuto() — the default
 *    'pinned'      connect(routeId): the person chose that route
 */
export type MainTapPlan =
    | { kind: 'disconnect' }
    | { kind: 'recovery' }
    | { kind: 'add_file' }
    | { kind: 'auto' }
    | { kind: 'pinned'; routeId: string };

export function mainTapPlan(input: {
    /** `tapAction` of lib/routeCheck.ts for the current state. */
    action: TapAction;
    auto: AutoStatus | undefined;
    /** The effective pin (see `effectivePin`). */
    pinnedRouteId: string | null;
    /** The device's routes read strictly; `undefined` = not known. */
    routes: readonly RouteDisplayRow[] | undefined;
    /** The Android service is holding the VPN closed (`isHolding`). */
    holding?: boolean;
}): MainTapPlan {
    const { action, auto, pinnedRouteId, routes, holding } = input;
    // Stopping always wins: while the engine is trying candidates the
    // state between two of them can read as anything. And while the
    // service holds the VPN closed the phone has no internet at all:
    // the one thing the main control must be able to do is let go.
    if (action === 'disconnect' || autoTrying(auto) || holding) return { kind: 'disconnect' };
    if (routes !== undefined && routes.length === 0) return { kind: 'add_file' };
    if (pinnedRouteId) {
        // 'recovery' is for the pinned route's OWN failed connect (it
        // is resting; the sheet has the other choices). An error that
        // comes from an AUTOMATIC pass says nothing about the route the
        // person then chose: the tap connects it.
        return action === 'recovery' && auto?.state !== 'failed'
            ? { kind: 'recovery' }
            : { kind: 'pinned', routeId: pinnedRouteId };
    }
    // Automatic. After a failed attempt (by hand or automatic) the tap
    // simply tries again: the engine skips what is resting and says so
    // in its verdict.
    return { kind: 'auto' };
}

/** Starts the connect a plan asks for. Returns what the host handed
 *  back (automatic connect only, and only where the host does). */
export async function startConnect(
    contract: {
        connect(routeId: string): Promise<void>;
        connectAuto(): Promise<AutoConnectResult | null>;
    },
    plan: { kind: 'auto' } | { kind: 'pinned'; routeId: string },
): Promise<AutoConnectResult | null> {
    if (plan.kind === 'pinned') {
        await contract.connect(plan.routeId);
        return null;
    }
    return contract.connectAuto();
}

/** i18n key of the main button's accessible label. `otherwise` is
 *  the key lib/routeCheck.ts `tapLabelKey` gives for the same moment. */
export function mainTapLabelKey(
    plan: MainTapPlan,
    auto: AutoStatus | undefined,
    otherwise: string,
    holding = false,
): string {
    if (plan.kind === 'add_file') return 'auto.add_file';
    // Nothing was connected yet: "Cancel", not "Disconnect".
    if (plan.kind === 'disconnect' && autoTrying(auto)) return 'conn.cancel_action';
    if (plan.kind === 'disconnect' && holding) return 'conn.disconnect_action';
    return otherwise;
}
