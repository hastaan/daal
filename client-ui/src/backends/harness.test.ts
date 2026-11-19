// The browser/stub backend's automatic connect: a small state machine
// shaped like the engine's, so the main screen can be driven (and its
// rules exercised) with no engine at all.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HarnessContract, harnessSteps } from './harness';
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

describe('HarnessContract: measurement and two ways at once', () => {
    const fresh = { grade: 'unknown' as const, samples: 0, carried: 0, failed: 0 };
    const way = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
        routeId: id,
        publisherId: 'pub',
        publisherName: 'Pars',
        routeNickname: id,
        trustClass: 'trusted',
        family: 'vless-reality',
        ...over,
    });
    const contract = (routes: RouteDisplayRow[], stepMs = 0) =>
        new HarnessContract({
            stepMs,
            scenario: { id: 't', title: 't', screen: 'connection', connection: { state: 'disconnected', mode: 'normal' }, availableRoutes: routes },
        });

    it('groups like the engine: the remembered way alone first, then two at a time, never more', () => {
        const good = way('good', { measured: { grade: 'good', setupMs: 300, samples: 3, carried: 3, failed: 0 } });
        const failing = way('bad', { measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } });
        const a = way('a', { measured: fresh });
        const b = way('b', { measured: fresh });
        const c = way('c', { measured: fresh });
        const ids = (steps: RouteDisplayRow[][]) => steps.map((s) => s.map((r) => r.routeId));
        expect(ids(harnessSteps([failing, a, good, b, c]))).toEqual([['good'], ['a', 'b'], ['c', 'bad']]);
        // Nothing remembered: pairs from the start, and a last one alone.
        expect(ids(harnessSteps([a, b, c]))).toEqual([['a', 'b'], ['c']]);
        for (const s of harnessSteps([failing, a, good, b, c])) expect(s.length).toBeLessThanOrEqual(2);
        // An engine that measures nothing: one after another.
        expect(ids(harnessSteps([way('x'), way('y')]))).toEqual([['x'], ['y']]);
    });

    it('on a network never seen: races in pairs, says so in `racing`, and the winner names what it was tried with', async () => {
        const c = contract(
            [
                way('r1', { measured: fresh, healthPct: 10 }),
                way('r2', { measured: fresh, healthPct: 10 }),
                way('r3', { measured: { ...fresh, setupMs: 900 } }),
                way('r4', { measured: { ...fresh, setupMs: 400 } }),
            ],
            15,
        );
        const seen: string[] = [];
        const pending = c.connectAuto();
        for (let i = 0; i < 200; i++) {
            const s = await c.connectionSummary();
            if (s.auto?.state === 'trying') {
                const pair = (s.auto.racing ?? []).join('+');
                if (seen[seen.length - 1] !== pair) seen.push(pair);
                expect(s.auto.trying).toBe(s.auto.racing?.[0]);
                expect(autoProgressText((k) => k, 'en', s.auto)).toBe('auto.trying_two');
            }
            if (s.state === 'connected') break;
            await new Promise((r) => setTimeout(r, 2));
        }
        const r = await pending;
        expect(seen).toEqual(['r1+r2', 'r3+r4']);
        expect(r).toMatchObject({ connected: true, routeId: 'r4', verdict: 'moved_on', candidates: 4 });
        expect(r!.tried).toEqual([
            { routeId: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply', racedWith: 'r2' },
            { routeId: 'r2', family: 'vless-reality', result: 'not_carrying', category: 'no_reply', racedWith: 'r1' },
            // Not needed: the other one answered first. The engine's word is
            // 'stopped'; 'cancelled' is the person's own cancel.
            { routeId: 'r3', family: 'vless-reality', result: 'stopped', category: '', racedWith: 'r4' },
            { routeId: 'r4', family: 'vless-reality', result: 'carried', category: '', setupMs: 400, racedWith: 'r3' },
        ]);
        // What was learned shows on the rows: the two that failed, the one that carried.
        const rows = (await c.routesStrict())!;
        expect(rows.map((x) => x.measured?.grade)).toEqual(['failing', 'failing', 'unknown', 'ok']);
        expect((await c.connectionSummary()).activeRoute?.measured).toMatchObject({ grade: 'ok', carried: 1, samples: 1 });
    });

    it('a partner that fails beside the way that connects is not "the first way did not work"', async () => {
        // r1 is the next way in the order; r2 is checked beside it and
        // fails. r1 worked at its first attempt: nothing was moved on from.
        const c = contract([way('r1', { measured: fresh }), way('r2', { measured: fresh, healthPct: 10 })]);
        const r = await c.connectAuto();
        expect(r).toMatchObject({ connected: true, routeId: 'r1', verdict: '' });
        expect(r!.tried.map((x) => `${x.routeId}:${x.result}`)).toEqual(['r2:not_carrying', 'r1:carried']);
        expect((await c.connectionSummary()).auto?.verdict).toBe('');
        // The other way round — the next way failed, its partner connected — is.
        const d = contract([way('r1', { measured: fresh, healthPct: 10 }), way('r2', { measured: fresh })]);
        expect(await d.connectAuto()).toMatchObject({ connected: true, routeId: 'r2', verdict: 'moved_on' });
        // What an attempt writes as `last` is what the real pipeline shows.
        expect((await d.routesStrict())![1].measured?.last).toMatch(/^\d{4}-\d\d-\d\d \d\dh UTC$/);
    });

    it('where a way is remembered: that one alone, no race at all', async () => {
        const c = contract([
            way('r1', { measured: fresh }),
            way('r2', { measured: { grade: 'good', setupMs: 300, samples: 5, carried: 5, failed: 0 } }),
            way('r3', { measured: fresh }),
        ]);
        const r = await c.connectAuto();
        expect(r).toMatchObject({ connected: true, routeId: 'r2', verdict: '' });
        expect(r!.tried).toEqual([{ routeId: 'r2', family: 'vless-reality', result: 'carried', category: '', setupMs: 300 }]);
        // One more sample does not flip a grade.
        expect((await c.routesStrict())![1].measured).toMatchObject({ grade: 'good', samples: 6, carried: 6 });
    });

    it('the canned scenarios of this wave exist and say what their titles say', async () => {
        const at = async (id: string) => {
            scenario(id);
            return new HarnessContract({ stepMs: 0 }).connectionSummary();
        };
        expect((await at('connection-auto-racing')).auto?.racing?.length).toBe(2);
        expect((await at('connection-moved-faster')).auto?.verdict).toBe('moved_faster');
        expect((await at('connection-network-down')).auto?.verdict).toBe('network_down');
        expect((await at('connection-connected-good')).activeRoute?.measured?.grade).toBe('good');
        expect((await at('connection-connected-slow')).routeCheck).toBe('degraded');
        scenario('routes-measured');
        const rows = await new HarnessContract({ stepMs: 0 }).availableRoutes();
        expect(rows.map((r) => r.measured?.grade)).toEqual(['good', 'slow', 'failing', 'unknown']);
    });
});
