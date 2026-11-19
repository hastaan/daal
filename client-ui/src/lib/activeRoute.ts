// Which route is active — asked of the engine's memory, not of its store.
//
// The pages used to learn the active route only through two calls that
// read the route store: `diagnostics_explain` (its `pick` is filled only
// when the store can load the route) and `route_summary`. On the first
// phone pass the store stopped answering after a route switch while the
// tunnel kept carrying traffic, so the Connection page said "You're
// connected." over "No route selected" and the Connections page marked
// no row.
//
// `export_diagnostics` now carries `active_route` (and
// `active_route_family`) straight from engine memory. That is the first
// answer; the explain payload's `active_route` and `pick.route_id` are
// kept as fallbacks for an engine that predates the field.
import type { ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';

function nonEmpty(v: unknown): string | undefined {
    return typeof v === 'string' && v !== '' ? v : undefined;
}

/** The active route id, or `undefined` when no source names one.
 *  `diag` is the parsed export_diagnostics blob; `explain` the parsed
 *  diagnostics_explain payload, or null/undefined when that call failed
 *  or was not made. */
export function pickActiveRouteId(diag: unknown, explain?: unknown): string | undefined {
    const d = (diag ?? {}) as Record<string, unknown>;
    const fromMemory = nonEmpty(d.active_route);
    if (fromMemory) return fromMemory;
    const x = (explain ?? {}) as Record<string, unknown>;
    const fromExplain = nonEmpty(x.active_route);
    if (fromExplain) return fromExplain;
    const pick = (x.pick ?? {}) as Record<string, unknown>;
    return nonEmpty(pick.route_id);
}

/** True when the diagnostics blob itself names the active route, so the
 *  explain call (which reads AND writes the store) is not needed to
 *  find it. */
export function diagNamesActiveRoute(diag: unknown): boolean {
    return nonEmpty((diag as Record<string, unknown> | null | undefined)?.active_route) !== undefined;
}

/** A row that carries the id (and the family when the engine said it)
 *  and nothing else: what is left when the route's display details could
 *  not be read. Enough to mark the connected row and to never show "No
 *  route selected" over a working tunnel. */
export function idOnlyRoute(routeId: string, family?: unknown): RouteDisplayRow {
    return {
        routeId,
        publisherId: '',
        publisherName: '',
        routeNickname: '',
        trustClass: 'unknown',
        family: nonEmpty(family) ?? '',
    };
}

export function isIdOnlyRoute(r: RouteDisplayRow): boolean {
    return r.publisherName === '' && r.routeNickname === '';
}

/** The row to hand to a label that prints "publisher · nickname". An
 *  id-only row gets our own words there instead of an empty " · " or a
 *  raw id. Any other row is returned untouched. */
export function routeForDisplay(
    r: RouteDisplayRow | undefined,
    t: (k: string) => string,
): RouteDisplayRow | undefined {
    if (!r || !isIdOnlyRoute(r)) return r;
    return {
        ...r,
        publisherName: t('conn.route_unnamed'),
        routeNickname: t('conn.route_unnamed_detail'),
    };
}

/** The last route switch that did not take, as the Android VPN service
 *  reports it (`vpn_status.last_switch`). When the route asked for
 *  starts and carries nothing, the service reconnects the route that
 *  was working — and that reconnect erases the engine's own verdict
 *  about the route that failed. This note is the only copy left. */
export interface LastSwitch {
    /** The route that was asked for and did not come up. */
    routeId: string;
    /** The route still connected afterwards; `undefined` if none is. */
    keptRouteId?: string;
    outcome: 'refused' | 'failed';
    /** A closed engine code (refusal code or failure category), used
     *  only to choose between our own sentences. May be ''. */
    reason: string;
}

/** Reads `last_switch` out of a vpn_status answer. Anything that is not
 *  a well-formed note — an older service, the desktop shell, a failed
 *  call — is `undefined`: "nothing to say". */
export function parseLastSwitch(vpnStatus: unknown): LastSwitch | undefined {
    const raw = (vpnStatus as Record<string, unknown> | null | undefined)?.last_switch;
    if (!raw || typeof raw !== 'object') return undefined;
    const n = raw as Record<string, unknown>;
    const routeId = nonEmpty(n.route_id);
    if (!routeId) return undefined;
    if (n.outcome !== 'refused' && n.outcome !== 'failed') return undefined;
    return {
        routeId,
        keptRouteId: nonEmpty(n.kept_route_id),
        outcome: n.outcome,
        reason: typeof n.reason === 'string' ? n.reason : '',
    };
}

/** The engine's own record of the same thing (`switch_back` in the
 *  diagnostics blob), in the shape of the service's note. On desktop
 *  there is no service: after a switch to a route that carried nothing
 *  the engine goes back to the one that worked, the blob reads "the
 *  old route is connected", and without this the tapped row had no
 *  answer but the generic sentence. `failed_route` '' — and anything
 *  malformed — is `undefined`: "nothing to say".
 *
 *  `restored` false means the way back did not carry either: nothing is
 *  connected, so no route is named as kept. */
export function parseSwitchBack(switchBack: unknown): LastSwitch | undefined {
    if (!switchBack || typeof switchBack !== 'object') return undefined;
    const b = switchBack as Record<string, unknown>;
    const routeId = nonEmpty(b.failed_route);
    if (!routeId) return undefined;
    return {
        routeId,
        keptRouteId: b.restored === true ? nonEmpty(b.restored_route) : undefined,
        outcome: 'failed',
        reason: typeof b.category === 'string' ? b.category : '',
    };
}

/** ConnectionSummary plus what this wave added to the diagnostics blob.
 *  Kept beside the contract type rather than in it: the extra fields are
 *  optional, so a backend that does not send them (the browser harness)
 *  still satisfies the contract. */
export interface ConnectionSummaryPlus extends ConnectionSummary {
    /** The route the standing `connectRefused` is about
     *  (`connect_refused_route`). `undefined` = the engine did not say. */
    connectRefusedRoute?: string;
    /** The engine found its saved connections damaged at start and set
     *  them aside (`store_recovered`). */
    storeRecovered?: boolean;
    /** The last switch that did not take (Android only). */
    lastSwitch?: LastSwitch;
}

export function summaryExtras(s: ConnectionSummary | null | undefined): {
    connectRefusedRoute?: string;
    storeRecovered: boolean;
    lastSwitch?: LastSwitch;
} {
    const p = (s ?? {}) as ConnectionSummaryPlus;
    return {
        connectRefusedRoute: nonEmpty(p.connectRefusedRoute),
        storeRecovered: p.storeRecovered === true,
        lastSwitch: p.lastSwitch && nonEmpty(p.lastSwitch.routeId) ? p.lastSwitch : undefined,
    };
}

/** The route the engine has RUNNING, or null: connected, still being
 *  checked, or lost and being retried. A failed connect (state 'error')
 *  and a stopped engine run nothing. */
export function runningRouteId(s: ConnectionSummary): string | null {
    const running =
        s.state === 'connected' || (s.state === 'connecting' && s.routeRunning === true);
    return running ? s.activeRoute?.routeId ?? null : null;
}
