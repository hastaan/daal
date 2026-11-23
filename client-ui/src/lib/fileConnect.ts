// fileConnect — "Connect with this file" from the moment it is pressed
// until the engine has answered (round 3a).
//
// The button asks the engine to choose automatically among ONE file's
// ways (connectAutoWithin). On desktop the call blocks for the whole
// pass and hands the answer back. On Android it resolves as soon as the
// VPN service has started, long before the engine has tried anything;
// the answer then arrives in the `auto` block the page polls. Until one
// of the two has answered the sheet says "Connecting…" with Cancel, and
// a press never ends in silence: a pass that found nothing says why.
//
// The person's own pin (a way chosen by hand) is let go only once the
// file has CONNECTED: a failed, cancelled or refused connect leaves it
// as it was (the same rule as pinAfterTap for one way).

import type { AutoConnectResult, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import { failureSignature } from './autoConnect';
import { PENDING_IDLE_MS, PENDING_TIMEOUT_MS } from './networkRows';

export interface FileConnect {
    /** The file's ways the engine may choose among. */
    routeIds: readonly string[];
    /** When the host accepted the connect (its call returned); the
     *  clocks run from here. Before that the person may still be on the
     *  system's VPN permission dialog. */
    sinceMs: number;
    accepted: boolean;
    /** The failed pass the blob showed at the press (it stands until the
     *  next pass reaches the engine): not taken for this press's answer. */
    failureAtTap?: string;
    /** The engine has been seen trying since the press. */
    seenTrying: boolean;
}

export type FileConnectEnd =
    | { outcome: 'waiting'; next: FileConnect }
    | { outcome: 'connected'; routeId: string }
    | { outcome: 'failed'; verdict: string }
    | { outcome: 'cancelled' }
    | { outcome: 'timeout' };

/** The ways of a file the automatic connect may try: not the ones only
 *  ever connected by hand (a pasted WireGuard file). Empty: the file is
 *  connected through its one hand-picked way instead. */
export function autoRoutesOf(routes: readonly RouteDisplayRow[]): RouteDisplayRow[] {
    return routes.filter((r) => r.manualOnly !== true);
}

export function startFileConnect(
    routeIds: readonly string[],
    nowMs: number,
    last: ConnectionSummary | null | undefined,
): FileConnect {
    return { routeIds: [...routeIds], sinceMs: nowMs, accepted: false, failureAtTap: failureSignature(last), seenTrying: false };
}

/** The host took the connect (on Android: the VPN service started). */
export function acceptFileConnect(f: FileConnect, nowMs: number): FileConnect {
    return { ...f, sinceMs: nowMs, accepted: true };
}

/** The answer the host handed back (desktop), or null where it hands
 *  none (Android: read the poll with resolveFileConnect). */
export function fileConnectFromResult(res: AutoConnectResult | null): FileConnectEnd | null {
    if (!res) return null;
    if (res.connected && res.routeId) return { outcome: 'connected', routeId: res.routeId };
    if (res.verdict === 'cancelled') return { outcome: 'cancelled' };
    return { outcome: 'failed', verdict: res.verdict };
}

/** Is this file connect over, as far as this summary says? */
export function resolveFileConnect(f: FileConnect, s: ConnectionSummary, nowMs: number): FileConnectEnd {
    const ids = new Set(f.routeIds);
    const auto = s.auto;
    const active = s.activeRoute?.routeId;
    if (auto?.state === 'trying') {
        return { outcome: 'waiting', next: f.seenTrying ? f : { ...f, seenTrying: true } };
    }
    if (s.state === 'connected' && active && ids.has(active)) return { outcome: 'connected', routeId: active };
    const fresh = f.seenTrying || failureSignature(s) !== f.failureAtTap;
    if (auto?.state === 'failed' && fresh) {
        if (auto.verdict === 'cancelled') return { outcome: 'cancelled' };
        return { outcome: 'failed', verdict: auto.verdict };
    }
    if (f.seenTrying && auto?.state === 'connected' && active && !ids.has(active)) {
        // Nothing in the file carried; the engine put back the way the
        // person had (another file's) and keeps the pass's verdict.
        return { outcome: 'failed', verdict: auto.verdict };
    }
    if (f.seenTrying && (auto === undefined || auto.state === 'idle') && s.routeRunning !== true) {
        // The pass was stopped (a disconnect, a way picked by hand).
        return { outcome: 'cancelled' };
    }
    if (!f.accepted) return { outcome: 'waiting', next: f };
    const age = nowMs - f.sinceMs;
    if (age > PENDING_TIMEOUT_MS) return { outcome: 'timeout' };
    if (!f.seenTrying && age > PENDING_IDLE_MS && s.routeRunning !== true) {
        // Nothing ever started. A failed pass the blob shows is the
        // answer even when it looks like the one before the press.
        if (auto?.state === 'failed') return { outcome: 'failed', verdict: auto.verdict };
        return { outcome: 'timeout' };
    }
    return { outcome: 'waiting', next: f };
}
