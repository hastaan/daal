// The browser/stub backend's automatic connect: a small state machine
// shaped like the engine's, so the main screen can be driven (and its
// rules exercised) with no engine at all.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HarnessContract } from './harness';
import { autoFailure, autoProgressText, stateWithAuto } from '../lib/autoConnect';
import type { RouteDisplayRow } from '../contract/D2Contract';

const scenario = (id: string) => vi.stubGlobal('window', { location: { search: `?harness=${id}` } });

beforeEach(() => scenario('connection-disconnected'));
afterEach(() => vi.unstubAllGlobals());

describe('HarnessContract.connectAuto', () => {
    it('tries the usable routes in order, keeps the first that carries, and reports it the way the engine does', async () => {
        const c = new HarnessContract({ stepMs: 0 });
        expect((await c.connectionSummary()).state).toBe('disconnected');
        const r = await c.connectAuto();
        // The default route set: Rescue 03 (healthy) carries first time.
        expect(r).toMatchObject({ connected: true, routeId: 'pars-rescue-03', verdict: '' });
        const s = await c.connectionSummary();
        expect(s.state).toBe('connected');
        expect(s.activeRoute?.routeId).toBe('pars-rescue-03');
        expect(s.auto).toMatchObject({ state: 'connected', mode: true, routeId: 'pars-rescue-03' });
        // The resting route was never a candidate.
        expect(r?.tried.map((x) => x.routeId)).not.toContain('pars-rescue-01');
    });

    it('shows honest progress while it works, and "moved on" when the first way fails', async () => {
        const way = (id: string, healthPct?: number): RouteDisplayRow => ({
            routeId: id,
            publisherId: 'pub',
            publisherName: 'Pars',
            routeNickname: id,
            trustClass: 'trusted',
            family: 'vless-reality',
            healthPct,
        });
        const c = new HarnessContract({
            stepMs: 15,
            scenario: {
                id: 't',
                title: 't',
                screen: 'connection',
                connection: { state: 'disconnected', mode: 'normal' },
                // The first two do not work here; a resting one is skipped.
                availableRoutes: [way('r1', 10), way('r2', 20), { ...way('r3'), inCooldown: true }, way('r4')],
            },
        });
        const seen = new Set<string>();
        const pending = c.connectAuto();
        // Poll like the page does.
        for (let i = 0; i < 200; i++) {
            const s = await c.connectionSummary();
            if (s.auto?.state === 'trying') {
                seen.add(autoProgressText((k) => (k === 'auto.trying' ? 'way {i} of {n}' : k), 'en', s.auto));
                expect(stateWithAuto(s.state, s.auto)).toBe('connecting');
                expect(s.activeRoute?.routeId).toBe(s.auto.trying);
            }
            if (s.state === 'connected') break;
            await new Promise((r) => setTimeout(r, 2));
        }
        const r = await pending;
        expect([...seen]).toEqual(['way 1 of 3', 'way 2 of 3', 'way 3 of 3']);
        expect(r).toMatchObject({ connected: true, routeId: 'r4', verdict: 'moved_on', candidates: 3 });
        expect(r!.tried.map((x) => `${x.routeId}:${x.result}`)).toEqual(['r1:not_carrying', 'r2:not_carrying', 'r4:carried']);
        const s = await c.connectionSummary();
        expect(s.auto).toMatchObject({ state: 'connected', mode: true, routeId: 'r4', verdict: 'moved_on' });
    });

    it('with nothing imported: fails with "no_routes", and nothing is connected', async () => {
        scenario('connection-needs-route');
        const c = new HarnessContract({ stepMs: 0 });
        expect(await c.routesStrict()).toEqual([]);
        const r = await c.connectAuto();
        expect(r).toMatchObject({ connected: false, verdict: 'no_routes', candidates: 0 });
        const s = await c.connectionSummary();
        expect(s.state).toBe('error');
        expect(autoFailure(s)).toEqual({ verdict: 'no_routes', tried: [] });
    });

    it('disconnect cancels it promptly, mid-check', async () => {
        const c = new HarnessContract({ stepMs: 30 });
        const pending = c.connectAuto();
        await new Promise((r) => setTimeout(r, 5));
        expect((await c.connectionSummary()).auto?.state).toBe('trying');
        await c.disconnect();
        const s = await c.connectionSummary();
        expect(s.state).toBe('disconnected');
        expect(s.auto).toMatchObject({ state: 'idle', mode: false });
        const r = await pending;
        expect(r?.connected).toBe(false);
        expect(r?.tried[r.tried.length - 1].result).toBe('cancelled');
        // ...and the cancelled attempt did not overwrite the state.
        expect((await c.connectionSummary()).state).toBe('disconnected');
    });

    it('is a no-op that names the running route when already connected', async () => {
        const c = new HarnessContract({ stepMs: 0 });
        await c.connect('friend-may-6');
        const r = await c.connectAuto();
        expect(r).toMatchObject({ connected: true, routeId: 'friend-may-6', tried: [] });
        const s = await c.connectionSummary();
        expect(s.activeRoute?.routeId).toBe('friend-may-6');
        // ...and, like the engine, it is in charge of that route now.
        expect(s.auto).toMatchObject({ state: 'connected', mode: true, routeId: 'friend-may-6' });
    });

    it('a connect by hand ends automatic mode', async () => {
        const c = new HarnessContract({ stepMs: 0 });
        await c.connectAuto();
        await c.disconnect();
        await c.connect('friend-may-6');
        const s = await c.connectionSummary();
        expect(s.state).toBe('connected');
        expect(s.auto?.mode).toBe(false);
    });
});
