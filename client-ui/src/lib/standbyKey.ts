// standbyKey — the recipient's "I was sent a code" field (optional
// add-ons, standby address; docs/optional-addons-plan.md §1.5, S7/S8).
// The engine checks the typed key against the signed commitment in the
// held file and keeps it only when it matches
// (engine_standby_key, specs/relaypack-v1.md `_standby`).
//
// NOT BUILT YET on the engine side: until lane L-ladder exports
// engine_standby_key the shell answers "not in this engine library",
// which this wrapper reports as 'unavailable'. The answer words are the
// engine lane's to extend; the page (lane L-ui) turns them into lines.

import { invoke } from '@tauri-apps/api/core';

export type StandbyKeyOutcome = 'accepted' | 'no_match' | 'malformed' | 'no_standby' | 'unavailable';

const KNOWN: ReadonlySet<string> = new Set(['accepted', 'no_match', 'malformed', 'no_standby']);

export function parseStandbyKey(body: string): StandbyKeyOutcome {
    try {
        const v = JSON.parse(body) as { outcome?: unknown };
        return typeof v.outcome === 'string' && KNOWN.has(v.outcome) ? (v.outcome as StandbyKeyOutcome) : 'unavailable';
    } catch {
        return 'unavailable';
    }
}

/** "" = every held relay file. Never throws: an engine without the call
 *  or a failed call is 'unavailable'. The key is never logged. */
export async function enterStandbyKey(key: string, relayPackId = ''): Promise<StandbyKeyOutcome> {
    try {
        return parseStandbyKey(await invoke<string>('recipient_standby_key', { relayPackId, key }));
    } catch {
        return 'unavailable';
    }
}
