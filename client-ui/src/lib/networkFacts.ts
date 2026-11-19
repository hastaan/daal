// Who tells the engine about the network.
//
// On Android the VPN service watches the phone's networks while it runs
// and hands the engine the full fact: what kind of network, a stable
// opaque id for it, whether the system has confirmed it reaches the
// internet, whether it is metered. The webview knows almost nothing —
// a browser "online"/"offline" event, with no kind and no identity.
//
// If the webview reported its poor fact while the service is running,
// the engine would take "a network of unknown kind with no name" as a
// CHANGE of network: the per-network memory would switch to an empty
// bucket (every route "not tried here yet"), and what the service said
// about validated / metered would be gone until its next callback.
//
// So: the webview reports only where nobody better does — on desktop,
// and on Android while the service is not running.

import type { HostNetwork } from '../contract/D2Contract';

function tri(v: unknown): -1 | 0 | 1 {
    return v === 1 ? 1 : v === 0 ? 0 : -1;
}

/** The `network` block of the diagnostics blob. `undefined` when there
 *  is none (an engine that predates it). */
export function parseHostNetwork(v: unknown): HostNetwork | undefined {
    if (!v || typeof v !== 'object') return undefined;
    const n = v as Record<string, unknown>;
    return {
        fromHost: n.from_host === true,
        kind: typeof n.kind === 'string' && /^[a-z]{0,16}$/.test(n.kind) ? n.kind : '',
        validated: tri(n.validated),
        metered: tri(n.metered),
    };
}

/** Is the vpn service up, as far as `vpn_status` says? */
function serviceUp(vpnStatus: unknown): boolean {
    if (!vpnStatus || typeof vpnStatus !== 'object') return false;
    const s = vpnStatus as Record<string, unknown>;
    return s.running === true || s.connected === true || s.holding === true;
}

/** Is what the engine remembers about its routes filed under THE
 *  NETWORK THE DEVICE IS ON NOW — so that "Works well here" and "Not
 *  tried here yet" are true?
 *
 *  Only when the host has told the engine which network this is, and is
 *  still watching it:
 *
 *    - no host fact (`fromHost` false, or no block): the engine files
 *      what it learns under no network in particular. On Android that
 *      is every start of the app until the person connects — and its
 *      record there is EMPTY even on a network Daal has used a hundred
 *      times, so every row said "Not tried here yet". On desktop it is
 *      always (no shell reports the network there).
 *    - on Android the fact comes from the VPN service and only while it
 *      runs. After it stops the engine still holds the last network it
 *      was told about, and the phone may have moved since.
 *
 *  When this is false the pages show no grade at all — not a guess, and
 *  not "not tried". */
export function gradesAreForThisNetwork(input: {
    android: boolean;
    network: HostNetwork | undefined;
    vpnStatus: unknown;
}): boolean {
    if (input.network?.fromHost !== true) return false;
    if (input.network.kind === 'none') return false;
    return input.android ? serviceUp(input.vpnStatus) : true;
}

/** May the webview send its own network fact to the engine now?
 *
 *  `android`   this is the Android shell.
 *  `vpnStatus` the answer of `vpn_status`, or null when it could not be
 *              read.
 *
 *  On Android an unreadable status is "do not": the service may well be
 *  running, and staying silent costs nothing (the engine still checks
 *  the route on its own clock), while a poor fact over a rich one costs
 *  the memory of this network. `running` is read if a service sends it;
 *  `connected` and `holding` are what today's service sends, and each
 *  means it is up. */
export function webviewMayReportNetwork(input: { android: boolean; vpnStatus: unknown }): boolean {
    if (!input.android) return true;
    const v = input.vpnStatus;
    if (!v || typeof v !== 'object') return false;
    return !serviceUp(v);
}
