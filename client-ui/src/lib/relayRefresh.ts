// relayRefresh — "Check for a new address": ask the engine to look for a
// newer signed relay file now (core/abi/relaypack_recover.go,
// engine_relaypack_refresh). The answer is one closed outcome word; the
// page turns it into one plain line.

import { invoke } from '@tauri-apps/api/core';

export type RefreshOutcome =
    | 'updated'
    | 'unchanged'
    | 'unreachable'
    | 'rejected'
    | 'tunnel_required'
    | 'rate_limited'
    | 'no_endpoints'
    | 'unknown_pack'
    | 'in_progress'
    | 'unavailable';

export interface RefreshAnswer {
    outcome: RefreshOutcome;
    retryAfterS: number;
}

const KNOWN: ReadonlySet<string> = new Set([
    'updated',
    'unchanged',
    'unreachable',
    'rejected',
    'tunnel_required',
    'rate_limited',
    'no_endpoints',
    'unknown_pack',
    'in_progress',
]);

export function parseRefresh(body: string): RefreshAnswer {
    try {
        const v = JSON.parse(body) as { outcome?: unknown; retry_after_s?: unknown };
        const o = typeof v.outcome === 'string' && KNOWN.has(v.outcome) ? (v.outcome as RefreshOutcome) : 'unavailable';
        const r = typeof v.retry_after_s === 'number' && v.retry_after_s > 0 ? Math.round(v.retry_after_s) : 0;
        return { outcome: o, retryAfterS: r };
    } catch {
        return { outcome: 'unavailable', retryAfterS: 0 };
    }
}

/** "" = every held relay file. Never throws: an old engine or a failed
 *  call is 'unavailable'. */
export async function checkForNewAddress(relayPackId = ''): Promise<RefreshAnswer> {
    try {
        return parseRefresh(await invoke<string>('relaypack_refresh', { relayPackId }));
    } catch {
        return { outcome: 'unavailable', retryAfterS: 0 };
    }
}

/** The i18n key and toast tone for an answer. */
export function refreshMessage(a: RefreshAnswer): { key: string; tone: 'good' | 'neutral' | 'bad' } {
    switch (a.outcome) {
        case 'updated':
            return { key: 'files.refresh.updated', tone: 'good' };
        case 'unchanged':
            return { key: 'files.refresh.unchanged', tone: 'neutral' };
        case 'tunnel_required':
            return { key: 'files.refresh.while_connected', tone: 'neutral' };
        case 'rate_limited':
        case 'in_progress':
            return { key: 'files.refresh.wait', tone: 'neutral' };
        case 'no_endpoints':
        case 'unknown_pack':
            return { key: 'files.refresh.no_channel', tone: 'neutral' };
        case 'rejected':
            return { key: 'files.refresh.rejected', tone: 'bad' };
        case 'unreachable':
            return { key: 'files.refresh.unreachable', tone: 'bad' };
        default:
            return { key: 'files.refresh.unavailable', tone: 'bad' };
    }
}
