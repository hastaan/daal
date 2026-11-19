// The engine's connection check, read once.
//
// `route_check` in the engine's diagnostics blob (core/abi/route_check.go,
// specs/engine-abi-v1.md) says whether the active route has actually
// carried a round trip:
//
//   ''          no route is active
//   'verifying' the engine has started and is still proving the route.
//               NOT connected — the engine dials the relay lazily, so
//               "started" says nothing about whether anything gets
//               through.
//   'ok'        proved
//   'degraded'  proved, but too slowly to call usable
//   'failed'    no round trip could be made
//
// 'failed' is two different things to the person holding the phone, and
// `route_running` in the same blob says which:
//
//   route_running false  the CONNECT failed. The engine tore the route
//                        down and put it in a cooldown; nothing is
//                        running and nothing will retry. The honest
//                        state is 'error' — "Could not connect on this
//                        route. Try another one."
//   route_running true   a route that WAS connected stopped carrying
//                        traffic. The engine keeps it up and re-checks
//                        it about every 30 s. 'connecting', with its own
//                        words — "Connection lost. Trying again…".
//
// Both leave the posture at Recovery, which alone maps to 'connecting';
// showing "Connecting…" for the first one was a promise the engine does
// not keep (review finding on the end-to-end rig: every blocked session
// ended there, on Android with no error at all).
//
// The posture alone cannot say "verifying": it does not advance until
// the proof has succeeded. A UI that showed Connected (or Disconnected)
// during those seconds would be showing something the engine has not
// concluded, so the check wins over the posture where it speaks.
import type { ConnState } from '../contract/D2Contract';

export type RouteCheck = 'verifying' | 'ok' | 'degraded' | 'failed';

/** Closed vocabulary; anything else (an older engine emits no field) is
 *  `undefined` — "the engine said nothing", never a guess. */
export function parseRouteCheck(v: unknown): RouteCheck | undefined {
    return v === 'verifying' || v === 'ok' || v === 'degraded' || v === 'failed'
        ? v
        : undefined;
}

/** `route_running` from the diagnostics blob: a boolean, or `undefined`
 *  when the engine did not say (an older engine emits no field). */
export function parseRouteRunning(v: unknown): boolean | undefined {
    return typeof v === 'boolean' ? v : undefined;
}

/** The connection state to show, given what the posture alone would say,
 *  what the connection check says, and whether the engine has a route
 *  running at all. */
export function connStateWithCheck(
    fromPosture: ConnState,
    check: RouteCheck | undefined,
    routeRunning?: boolean,
): ConnState {
    // Still proving the route: never "connected", whatever the posture
    // still reads from a previous route.
    if (check === 'verifying') return 'connecting';
    if (check === 'failed') {
        // The connect failed and the engine stopped: nothing is
        // connecting, whatever the Recovery posture maps to.
        if (routeRunning === false) return 'error';
        // A route that was connected and has stopped carrying traffic:
        // the engine keeps trying it.
        if (fromPosture === 'connected') return 'connecting';
    }
    return fromPosture;
}

/** i18n key of the headline that replaces the generic one for this
 *  state, or `undefined` to keep the generic one.
 *
 *  `category` is `route_check_category` from the same blob. Two failed
 *  connects are not the route's fault and say so instead of "try
 *  another one": a path that was moving and too slow to finish
 *  (`path_too_slow` — the route is not cooled down, trying again is the
 *  right advice), and a relay that answered and reaches nothing itself
 *  (`relay_no_egress` — only the person who runs it can fix that). Any
 *  other category, known or not, keeps the generic sentence: the
 *  category is a closed engine vocabulary, never text to display. */
export function checkHeadlineKey(
    state: ConnState,
    check: RouteCheck | undefined,
    category?: string,
): string | undefined {
    if (state === 'connecting' && check === 'verifying') return 'conn.headline_checking';
    if (state === 'connected' && check === 'degraded') return 'conn.headline_slow';
    if (state === 'error' && check === 'failed') {
        if (category === 'path_too_slow') return 'conn.headline_too_slow';
        if (category === 'relay_no_egress') return 'conn.headline_relay_no_internet';
        return 'conn.headline_route_failed';
    }
    if (state === 'connecting' && check === 'failed') return 'conn.headline_lost';
    return undefined;
}

/** i18n key of the short state label, same rule. */
export function checkStateLabelKey(
    state: ConnState,
    check: RouteCheck | undefined,
): string | undefined {
    if (state === 'connecting' && check === 'verifying') return 'conn.checking';
    if (state === 'connected' && check === 'degraded') return 'conn.state.slow';
    if (state === 'error' && check === 'failed') return 'conn.state.route_failed';
    if (state === 'connecting' && check === 'failed') return 'conn.state.lost';
    return undefined;
}

/** What a tap on the main button does.
 *
 *  The rule is about what is RUNNING, not about the word on the screen:
 *  whenever the engine has a route up — connected, still being checked,
 *  or lost and being retried — a tap stops it. It used to mean
 *  "connect" in the last two (the state is 'connecting'), which during
 *  a retry called connect for a route in its cooldown: refused, a
 *  recovery sheet, and no way to disconnect from this page at all
 *  (end-to-end rig finding CEN-5, remainder).
 *
 *  `inFlight` is the page's own knowledge that it asked for a connect
 *  and has not heard back: on the first poll after a tap the blob may
 *  not say 'verifying' yet, and a second tap must still cancel rather
 *  than start a second connect.
 *
 *  `category` is `route_check_category`. After a failed connect the
 *  button reads "Connect", and for most failures it opens the recovery
 *  sheet: the engine is resting the route, so the useful choices are
 *  the other ones. Two failures rest nothing (specs/failure-taxonomy-v1.md:
 *  `path_too_slow`, `relay_no_egress` — no cooldown) and their headline
 *  says so: "Try again in a moment", "ask whoever runs the server".
 *  The error does not clear by itself either, so the button is the only
 *  place to try again; there it connects the same route. If that fails
 *  too the page opens the recovery sheet itself.
 *
 *    'disconnect'  stop what is running (also cancels a check)
 *    'recovery'    nothing is running after a failed connect and the
 *                  route is being rested
 *    'connect'     nothing is running; start
 */
export type TapAction = 'connect' | 'disconnect' | 'recovery';

/** The failed-connect categories after which the engine rests nothing,
 *  so trying the same route again is what the headline advises. The
 *  same two that `checkHeadlineKey` gives their own sentence. */
export function retryableFailure(category: string | undefined): boolean {
    return category === 'path_too_slow' || category === 'relay_no_egress';
}

export function tapAction(
    state: ConnState,
    check: RouteCheck | undefined,
    inFlight = false,
    category?: string,
): TapAction {
    if (state === 'connected') return 'disconnect';
    if (state === 'error') {
        return check === 'failed' && retryableFailure(category) ? 'connect' : 'recovery';
    }
    if (state === 'connecting' && (inFlight || check === 'verifying' || check === 'failed')) {
        return 'disconnect';
    }
    return 'connect';
}

/** i18n key of the main button's label for that action: "Cancel" while
 *  a connect is still being checked (nothing was connected yet, so
 *  "Disconnect" would be the wrong word), "Disconnect" otherwise. */
export function tapLabelKey(action: TapAction, state: ConnState, check: RouteCheck | undefined): string {
    if (action !== 'disconnect') return 'conn.connect_action';
    if (state === 'connecting' && check !== 'failed') return 'conn.cancel_action';
    return 'conn.disconnect_action';
}

/** Why the engine refused the last connect before trying anything
 *  (`connect_refused` in the diagnostics blob — core/abi/route_check.go).
 *  A closed vocabulary; anything else is `undefined`. */
export type ConnectRefused = 'needs_new_file' | 'cooldown' | 'revoked' | 'expired' | 'other';

export function parseConnectRefused(v: unknown): ConnectRefused | undefined {
    return v === 'needs_new_file' || v === 'cooldown' || v === 'revoked' || v === 'expired' || v === 'other'
        ? v
        : undefined;
}

/** i18n key of the sentence for a refused connect. Every code has its
 *  own; an engine newer than this app that sends a code it does not
 *  know is parsed to `undefined` upstream and shows nothing. */
export function connectRefusedKey(code: ConnectRefused): string {
    switch (code) {
        case 'needs_new_file':
            return 'conn.refused.needs_new_file';
        case 'cooldown':
            return 'conn.refused.cooldown';
        case 'revoked':
        case 'expired':
            return 'conn.refused.no_longer_valid';
        default:
            return 'conn.refused.other';
    }
}

/** i18n key of the sentence for a Connect tap that ended in an error
 *  the engine did not name as a refusal.
 *
 *  The usual one: the route started and its connection check failed.
 *  The host's connect call then rejects with its own developer text
 *  (the desktop shell's is "engine call returned -1"), which is not a
 *  sentence for the person holding the phone and is English whatever
 *  the app's language. What happened is in the diagnostics: when the
 *  check reads 'failed', this is the same event the Connection page
 *  reports and gets the same words, chosen by the same category rule.
 *  Anything else — the summary could not be read, or it says nothing —
 *  gets a plain sentence of ours. The caught error's text is never
 *  shown. */
export function connectFailedKey(
    check: RouteCheck | undefined,
    category?: string,
): string {
    if (check === 'failed') {
        return checkHeadlineKey('error', 'failed', category) ?? 'conn.connect_failed';
    }
    return 'conn.connect_failed';
}

/** Which refused-connect sentence the routes page shows, if any.
 *
 *  Two sources, two rules:
 *
 *    `fromTap`   the refusal that answered a Connect tap made on this
 *                page. Always shown: the person pressed a button and
 *                must be told why nothing happened — also while another
 *                route is still connected. The engine refuses before it
 *                touches the running route, so "something is connected"
 *                is exactly the case where the tap would otherwise end
 *                in silence.
 *    `fromPoll`  the engine's standing `connect_refused`. It stays in
 *                the diagnostics until the next connect or disconnect,
 *                so while a route is running it is old news about some
 *                earlier attempt and is not shown.
 */
export function refusedToShow(
    fromPoll: ConnectRefused | undefined,
    fromTap: ConnectRefused | undefined,
    routeRunning: boolean,
): ConnectRefused | undefined {
    if (fromTap) return fromTap;
    return routeRunning ? undefined : fromPoll;
}
