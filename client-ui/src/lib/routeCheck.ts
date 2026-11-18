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
 *  state, or `undefined` to keep the generic one. */
export function checkHeadlineKey(
    state: ConnState,
    check: RouteCheck | undefined,
): string | undefined {
    if (state === 'connecting' && check === 'verifying') return 'conn.headline_checking';
    if (state === 'connected' && check === 'degraded') return 'conn.headline_slow';
    if (state === 'error' && check === 'failed') return 'conn.headline_route_failed';
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
