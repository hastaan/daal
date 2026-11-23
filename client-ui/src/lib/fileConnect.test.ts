// lib/fileConnect.ts: when "Connect with this file" is over, as far as
// the engine has said (round 3a review).
import { describe, expect, it } from 'vitest';
import type { AutoStatus, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import {
    acceptFileConnect,
    autoRoutesOf,
    fileConnectFromResult,
    resolveFileConnect,
    startFileConnect,
} from './fileConnect';
import { PENDING_IDLE_MS, PENDING_TIMEOUT_MS } from './networkRows';

const IDLE: AutoStatus = { state: 'idle', mode: false, trying: '', index: 0, total: 0, tried: [], verdict: '', routeId: '' };
function summary(auto: Partial<AutoStatus>, over: Partial<ConnectionSummary> = {}): ConnectionSummary {
    return { state: 'disconnected', mode: 'normal', auto: { ...IDLE, ...auto }, ...over } as ConnectionSummary;
}
const ids = ['r1', 'r2'];

describe('the answer handed back (desktop)', () => {
    it('connected, failed with its verdict, cancelled, or none (Android)', () => {
        expect(fileConnectFromResult({ connected: true, routeId: 'r2', family: '', tried: [], verdict: '', candidates: 2 })).toEqual({ outcome: 'connected', routeId: 'r2' });
        expect(fileConnectFromResult({ connected: false, routeId: '', family: '', tried: [], verdict: 'all_failed', candidates: 2 })).toEqual({ outcome: 'failed', verdict: 'all_failed' });
        expect(fileConnectFromResult({ connected: false, routeId: '', family: '', tried: [], verdict: 'cancelled', candidates: 2 })).toEqual({ outcome: 'cancelled' });
        expect(fileConnectFromResult(null)).toBeNull();
    });
});

describe('the polled answer (Android)', () => {
    it('trying, then failed: the verdict of this pass', () => {
        let f = acceptFileConnect(startFileConnect(ids, 0, summary({})), 0);
        const w = resolveFileConnect(f, summary({ state: 'trying' }), 1000);
        expect(w.outcome).toBe('waiting');
        if (w.outcome === 'waiting') f = w.next;
        expect(f.seenTrying).toBe(true);
        expect(resolveFileConnect(f, summary({ state: 'failed', verdict: 'all_failed' }), 2000)).toEqual({ outcome: 'failed', verdict: 'all_failed' });
    });

    it('connected on a way of the file', () => {
        const f = acceptFileConnect(startFileConnect(ids, 0, null), 0);
        const s = summary({ state: 'connected', mode: true, routeId: 'r2' }, { state: 'connected', activeRoute: { routeId: 'r2' } as ConnectionSummary['activeRoute'] });
        expect(resolveFileConnect(f, s, 1000)).toEqual({ outcome: 'connected', routeId: 'r2' });
    });

    it("the failure from before the press is not this press's answer", () => {
        const before = summary({ state: 'failed', verdict: 'all_failed' });
        const f = acceptFileConnect(startFileConnect(ids, 0, before), 0);
        expect(resolveFileConnect(f, before, 1000).outcome).toBe('waiting');
        // ... unless nothing else ever happened.
        expect(resolveFileConnect(f, before, PENDING_IDLE_MS + 1)).toEqual({ outcome: 'failed', verdict: 'all_failed' });
    });

    it('nothing in the file carried and the engine put back the way of another file', () => {
        const f = { ...acceptFileConnect(startFileConnect(ids, 0, null), 0), seenTrying: true };
        const s = summary({ state: 'connected', mode: true, routeId: 'o1', verdict: 'all_failed' }, { state: 'connected', activeRoute: { routeId: 'o1' } as ConnectionSummary['activeRoute'] });
        expect(resolveFileConnect(f, s, 1000)).toEqual({ outcome: 'failed', verdict: 'all_failed' });
    });

    it('a pass stopped by someone else is cancelled; no clock before the host took the connect', () => {
        const f = { ...acceptFileConnect(startFileConnect(ids, 0, null), 0), seenTrying: true };
        expect(resolveFileConnect(f, summary({}), 1000)).toEqual({ outcome: 'cancelled' });
        const open = startFileConnect(ids, 0, null);
        expect(resolveFileConnect(open, summary({}), PENDING_TIMEOUT_MS + 1).outcome).toBe('waiting');
        expect(resolveFileConnect(acceptFileConnect(open, 0), summary({}), PENDING_TIMEOUT_MS + 1)).toEqual({ outcome: 'timeout' });
    });
});

describe('the ways the automatic connect may choose', () => {
    it('not the ones only ever connected by hand', () => {
        const r = (id: string, manualOnly?: boolean) => ({ routeId: id, manualOnly }) as RouteDisplayRow;
        expect(autoRoutesOf([r('a'), r('w', true)]).map((x) => x.routeId)).toEqual(['a']);
        expect(autoRoutesOf([r('w', true)])).toEqual([]);
    });
});
