// TauriContract against a scripted `invoke`.
//
// First phone pass: after a route switch the route store stopped
// answering while the tunnel kept carrying traffic. connectionSummary
// learned the active route only through store-backed calls inside a
// catch-all, so both pages lost it; listPublishers was all-or-nothing
// on subscription_list and turned a failed route list into "no
// publishers yet".
import { beforeEach, describe, expect, it, vi } from 'vitest';

type Handler = (args?: Record<string, unknown>) => unknown;
const handlers = new Map<string, Handler>();
const calls: string[] = [];
const callArgs: Array<[string, Record<string, unknown> | undefined]> = [];

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push(cmd);
        callArgs.push([cmd, args]);
        const h = handlers.get(cmd);
        // What the shell does for a failed engine call: reject with a
        // plain string.
        if (!h) throw 'engine call returned -1';
        return h(args);
    },
}));

import { TauriContract } from './tauri';
import { isIdOnlyRoute } from '../lib/activeRoute';

const diag = (over: Record<string, unknown>) => () =>
    JSON.stringify({ version: 't', mode: 'normal', posture: 'ImportedActive', route_count: 4, bucket: 'b', ...over });

const ROUTE = (id: string) => ({
    route_id: id,
    publisher_id: 'pub',
    publisher_name: 'Pars',
    route_nickname: `nick-${id}`,
    trust_class: 'trusted',
    family: 'vless-reality',
    in_cooldown: null,
    budget_exhausted: null,
    health_pct: null,
});

beforeEach(() => {
    handlers.clear();
    calls.length = 0;
    callArgs.length = 0;
});

describe('connectionSummary: the active route', () => {
    it('comes from export_diagnostics.active_route when every store-backed call fails', async () => {
        handlers.set(
            'export_diagnostics',
            diag({ active_route: 'r2', active_route_family: 'vless-reality', route_check: 'ok', route_running: true }),
        );
        // diagnostics_explain, route_summary, pointer_rotation_status: all reject.
        const s = await new TauriContract().connectionSummary();
        expect(s.state).toBe('connected');
        expect(s.activeRoute?.routeId).toBe('r2');
        expect(s.activeRoute?.family).toBe('vless-reality');
        expect(isIdOnlyRoute(s.activeRoute!)).toBe(true);
        // The blob named the route: the store-writing explain call is not made.
        expect(calls).not.toContain('diagnostics_explain');
    });

    it('uses the full row when route_summary answers', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r2' }));
        handlers.set('route_summary', (a) => JSON.stringify(ROUTE(String(a?.routeId))));
        const s = await new TauriContract().connectionSummary();
        expect(s.activeRoute?.routeId).toBe('r2');
        expect(s.activeRoute?.publisherName).toBe('Pars');
        expect(s.activeRoute?.routeNickname).toBe('nick-r2');
    });

    it("falls back to the explain payload's active_route, with no pick, for an older engine", async () => {
        handlers.set('export_diagnostics', diag({}));
        handlers.set('diagnostics_explain', () => JSON.stringify({ active_route: 'r3', failures: [] }));
        const s = await new TauriContract().connectionSummary();
        expect(s.activeRoute?.routeId).toBe('r3');
    });

    it('then to pick.route_id, still id-only when route_summary rejects', async () => {
        handlers.set('export_diagnostics', diag({ active_route: '' }));
        handlers.set('diagnostics_explain', () => JSON.stringify({ pick: { route_id: 'r4' } }));
        const s = await new TauriContract().connectionSummary();
        expect(s.activeRoute?.routeId).toBe('r4');
        expect(isIdOnlyRoute(s.activeRoute!)).toBe(true);
    });

    it('reports no route when nobody names one', async () => {
        handlers.set('export_diagnostics', diag({ posture: 'NoRoute', active_route: '' }));
        const s = await new TauriContract().connectionSummary();
        expect(s.activeRoute).toBeUndefined();
        expect(s.state).toBe('disconnected');
    });

    it('carries which route a refusal was about, and store_recovered', async () => {
        handlers.set(
            'export_diagnostics',
            diag({ active_route: 'r1', connect_refused: 'cooldown', connect_refused_route: 'r2', store_recovered: true }),
        );
        const s = await new TauriContract().connectionSummary();
        expect(s.connectRefused).toBe('cooldown');
        expect(s.connectRefusedRoute).toBe('r2');
        expect(s.storeRecovered).toBe(true);
        handlers.set('export_diagnostics', diag({}));
        const plain = await new TauriContract().connectionSummary();
        expect(plain.connectRefusedRoute).toBeUndefined();
        expect(plain.storeRecovered).toBe(false);
    });
});

describe('listPublishers', () => {
    it('still shows the routes when subscription_list fails', async () => {
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        handlers.set('export_diagnostics', diag({ skipped_families: [] }));
        handlers.set('available_routes', () => JSON.stringify({ routes: [ROUTE('r1'), ROUTE('r2')] }));
        const tree = await new TauriContract().listPublishers();
        const ids = tree.flatMap((p) => p.cells.flatMap((c) => c.routes.map((r) => r.routeId)));
        expect(ids.sort()).toEqual(['r1', 'r2']);
    });

    it('rejects — with the host\'s text — when the routes cannot be listed', async () => {
        handlers.set('export_diagnostics', diag({}));
        handlers.set('subscription_list', () => JSON.stringify({ subscriptions: [] }));
        await expect(new TauriContract().listPublishers()).rejects.toBe('engine call returned -1');
    });
});

describe('connectionSummary: a switch that did not take (Android)', () => {
    const asAndroid = () => vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0 (Linux; Android 15) wv' });

    it("carries the VPN service's last_switch note: the engine's blob has lost the verdict", async () => {
        asAndroid();
        try {
            // What the engine says after the service went back to r1.
            handlers.set('export_diagnostics', diag({ active_route: 'r1', route_check: 'ok', route_running: true }));
            handlers.set('plugin:daal-platform|vpn_status', () => ({
                connected: true,
                route_id: 'r1',
                platform: 'android',
                last_switch: { route_id: 'r2', kept_route_id: 'r1', outcome: 'failed', reason: 'timeout' },
            }));
            const s = await new TauriContract().connectionSummary();
            expect(s.activeRoute?.routeId).toBe('r1');
            expect(s.lastSwitch).toEqual({ routeId: 'r2', keptRouteId: 'r1', outcome: 'failed', reason: 'timeout' });
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it('a vpn_status that rejects costs nothing but the note', async () => {
        asAndroid();
        try {
            handlers.set('export_diagnostics', diag({ active_route: 'r1', route_check: 'ok', route_running: true }));
            const s = await new TauriContract().connectionSummary();
            expect(s.state).toBe('connected');
            expect(s.lastSwitch).toBeUndefined();
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it('is not asked for on the desktop', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r1' }));
        const s = await new TauriContract().connectionSummary();
        expect(calls).not.toContain('plugin:daal-platform|vpn_status');
        expect(s.lastSwitch).toBeUndefined();
    });
});

// ---- automatic connect (backlog PH-25) --------------------------------

describe('connectAuto', () => {
    const body = {
        connected: true,
        route_id: 'r2',
        family: 'websocket-tls',
        tried: [
            { route_id: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply' },
            { route_id: 'r2', family: 'websocket-tls', result: 'carried', category: '' },
        ],
        verdict: 'moved_on',
        candidates: 4,
    };

    it("desktop: invokes connect_auto, names no route, and hands back the engine's answer", async () => {
        handlers.set('connect_auto', () => JSON.stringify(body));
        const r = await new TauriContract().connectAuto();
        expect(callArgs).toEqual([['connect_auto', undefined]]);
        expect(r?.connected).toBe(true);
        expect(r?.routeId).toBe('r2');
        expect(r?.verdict).toBe('moved_on');
        expect(r?.tried.map((x) => x.result)).toEqual(['not_carrying', 'carried']);
    });

    it('nothing connected is an answer, not a rejection', async () => {
        handlers.set('connect_auto', () =>
            JSON.stringify({ connected: false, route_id: '', family: '', tried: [], verdict: 'network_down', candidates: 4 }),
        );
        const r = await new TauriContract().connectAuto();
        expect(r).toMatchObject({ connected: false, verdict: 'network_down' });
    });

    it('Android: starts the VPN service with an empty route id — the plugin\'s rule for "automatic"', async () => {
        vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0 (Linux; Android 15) wv' });
        try {
            handlers.set('plugin:daal-platform|vpn_start', () => ({ applied: true, platform: 'android' }));
            const r = await new TauriContract().connectAuto();
            expect(callArgs).toEqual([['plugin:daal-platform|vpn_start', { request: { routeId: '' } }]]);
            // The service was started; the answer comes through the diagnostics.
            expect(r).toBeNull();
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it('a connect by hand still names its route', async () => {
        handlers.set('connect', () => undefined);
        await new TauriContract().connect('r3');
        expect(callArgs).toEqual([['connect', { routeId: 'r3' }]]);
    });
});

describe('connectionSummary: following automatic connect', () => {
    const autoBlock = (over: Record<string, unknown>) => ({
        state: 'idle', mode: false, trying: '', index: 0, total: 0, tried: [], verdict: '', route_id: '', ...over,
    });

    it('carries the auto block, parsed', async () => {
        handlers.set(
            'export_diagnostics',
            diag({
                posture: 'Recovery',
                route_check: 'verifying',
                route_running: true,
                active_route: 'r2',
                auto: autoBlock({
                    state: 'trying', mode: true, trying: 'r2', index: 2, total: 4,
                    tried: [{ route_id: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply' }],
                }),
            }),
        );
        const s = await new TauriContract().connectionSummary();
        expect(s.state).toBe('connecting');
        expect(s.auto).toMatchObject({ state: 'trying', mode: true, trying: 'r2', index: 2, total: 4 });
        expect(s.auto?.tried).toEqual([{ routeId: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply' }]);
        expect(s.routeCountHint).toBe(4);
    });

    it('the engine moves from r1 to r2 by itself: never "disconnected" or "error" in between, and the route follows', async () => {
        const c = new TauriContract();
        const trying = autoBlock({ state: 'trying', mode: true, trying: 'r2', index: 2, total: 4 });
        const moments: Array<[Record<string, unknown>, string, string | undefined]> = [
            [{ posture: 'ImportedActive', route_check: 'ok', route_running: true, active_route: 'r1',
               auto: autoBlock({ state: 'connected', mode: true, route_id: 'r1' }) }, 'connected', 'r1'],
            // r1 stopped carrying and was torn down. Without the auto
            // block this blob reads 'error'.
            [{ posture: 'Recovery', route_check: 'failed', route_running: false, active_route: 'r1', auto: trying }, 'connecting', 'r2'],
            // Nothing active for a moment. Without it: 'disconnected'.
            [{ posture: 'NoRoute', route_check: '', route_running: false, active_route: '', auto: trying }, 'connecting', 'r2'],
            [{ posture: 'Recovery', route_check: 'verifying', route_running: true, active_route: 'r2', auto: trying }, 'connecting', 'r2'],
            [{ posture: 'ImportedActive', route_check: 'ok', route_running: true, active_route: 'r2',
               auto: autoBlock({ state: 'connected', mode: true, route_id: 'r2', verdict: 'moved_on' }) }, 'connected', 'r2'],
        ];
        const seen: Array<[string, string | undefined]> = [];
        for (const [blob] of moments) {
            handlers.set('export_diagnostics', diag(blob));
            const s = await c.connectionSummary();
            seen.push([s.state, s.activeRoute?.routeId]);
        }
        expect(seen).toEqual(moments.map(([, state, id]) => [state, id]));
    });

    it('a finished, failed automatic connect is an error with its verdict', async () => {
        handlers.set(
            'export_diagnostics',
            diag({ posture: 'NoRoute', route_running: false, active_route: '',
                   auto: autoBlock({ state: 'failed', verdict: 'relay_unreachable', total: 2 }) }),
        );
        const s = await new TauriContract().connectionSummary();
        expect(s.state).toBe('error');
        expect(s.auto?.verdict).toBe('relay_unreachable');
    });

    it('an engine with no auto block reads exactly as before', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r1', route_check: 'ok', route_running: true }));
        const s = await new TauriContract().connectionSummary();
        expect(s.state).toBe('connected');
        expect(s.auto).toBeUndefined();
        expect(s.autoFailedNote).toBeUndefined();
    });

    it("Android: carries the service's note about an automatic connect that found nothing", async () => {
        vi.stubGlobal('navigator', { userAgent: 'Mozilla/5.0 (Linux; Android 15) wv' });
        try {
            handlers.set('export_diagnostics', diag({ posture: 'NoRoute', active_route: '' }));
            handlers.set('plugin:daal-platform|vpn_status', () => ({
                connected: false, route_id: null, platform: 'android',
                last_switch: { route_id: '', kept_route_id: null, outcome: 'failed', reason: 'network_down', auto: true },
            }));
            const s = await new TauriContract().connectionSummary();
            expect(s.autoFailedNote).toBe('network_down');
            // Not a note about a switch by hand.
            expect(s.lastSwitch).toBeUndefined();
        } finally {
            vi.unstubAllGlobals();
        }
    });
});

describe('routesStrict', () => {
    it('lists the routes', async () => {
        handlers.set('available_routes', () => JSON.stringify({ routes: [ROUTE('r1'), ROUTE('r2')] }));
        expect((await new TauriContract().routesStrict())?.map((r) => r.routeId)).toEqual(['r1', 'r2']);
    });
    it('an empty list is empty; a list that could not be read is undefined — not empty', async () => {
        handlers.set('available_routes', () => JSON.stringify({ routes: [] }));
        expect(await new TauriContract().routesStrict()).toEqual([]);
        handlers.delete('available_routes');
        expect(await new TauriContract().routesStrict()).toBeUndefined();
    });
});

// ---- backlog PH-26 ----------------------------------------------------

describe('a route that no longer exists is not asked for on every poll', () => {
    const count = (cmd: string) => calls.filter((c) => c === cmd).length;

    it('asks once, confirms with the list, then stops', async () => {
        // After the store reset: the engine still names r9 from memory,
        // the store has no such row, and the list answers without it.
        handlers.set('export_diagnostics', diag({ active_route: 'r9', active_route_family: 'naive', route_check: 'ok', route_running: true }));
        handlers.set('available_routes', () => JSON.stringify({ routes: [ROUTE('r1')] }));
        const c = new TauriContract();
        for (let i = 0; i < 5; i++) {
            const s = await c.connectionSummary();
            // The page still has the id (and the family from memory).
            expect(s.activeRoute?.routeId).toBe('r9');
            expect(isIdOnlyRoute(s.activeRoute!)).toBe(true);
        }
        expect(count('route_summary')).toBe(1);
        expect(count('available_routes')).toBe(1);
    });

    it('asks again once the route set may have changed, and finds it', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r9' }));
        handlers.set('available_routes', () => JSON.stringify({ routes: [] }));
        const c = new TauriContract();
        await c.connectionSummary();
        await c.connectionSummary();
        expect(count('route_summary')).toBe(1);
        // The person adds their file again.
        handlers.set('import_sbp', () => '{"Kind":0}');
        handlers.set('route_summary', (a) => JSON.stringify(ROUTE(String(a?.routeId))));
        await c.importSbp('/tmp/x.sbp');
        const s = await c.connectionSummary();
        expect(count('route_summary')).toBe(2);
        expect(s.activeRoute?.routeNickname).toBe('nick-r9');
    });

    it('a list that shows the route (the QR lane imports outside this class) makes it askable again', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r9' }));
        handlers.set('available_routes', () => JSON.stringify({ routes: [] }));
        const c = new TauriContract();
        await c.connectionSummary();
        handlers.set('available_routes', () => JSON.stringify({ routes: [ROUTE('r9')] }));
        handlers.set('route_summary', (a) => JSON.stringify(ROUTE(String(a?.routeId))));
        await c.routesStrict();
        expect((await c.connectionSummary()).activeRoute?.publisherName).toBe('Pars');
    });

    it('a store that did not answer at all is not "gone": asked again, but not on every poll', async () => {
        vi.useFakeTimers();
        try {
            vi.setSystemTime(1_000_000);
            // route_summary AND available_routes reject.
            handlers.set('export_diagnostics', diag({ active_route: 'r2' }));
            const c = new TauriContract();
            await c.connectionSummary();
            await c.connectionSummary();
            expect(count('route_summary')).toBe(1);
            vi.setSystemTime(1_000_000 + 31_000);
            handlers.set('route_summary', (a) => JSON.stringify(ROUTE(String(a?.routeId))));
            const s = await c.connectionSummary();
            expect(count('route_summary')).toBe(2);
            expect(s.activeRoute?.routeNickname).toBe('nick-r2');
        } finally {
            vi.useRealTimers();
        }
    });

    it('a route that is there is asked for every time, as before', async () => {
        handlers.set('export_diagnostics', diag({ active_route: 'r2' }));
        handlers.set('route_summary', (a) => JSON.stringify(ROUTE(String(a?.routeId))));
        const c = new TauriContract();
        await c.connectionSummary();
        await c.connectionSummary();
        expect(count('route_summary')).toBe(2);
        expect(calls).not.toContain('available_routes');
    });
});

// The webview's own records (lib/localTraces.ts) go when the engine's do.
describe('wipe and delete forget what the webview wrote down', () => {
    const store = new Map<string, string>();
    const withStorage = () => {
        store.clear();
        vi.stubGlobal('localStorage', {
            getItem: (k: string) => store.get(k) ?? null,
            setItem: (k: string, v: string) => void store.set(k, v),
            removeItem: (k: string) => void store.delete(k),
        });
        store.set('daal.d2.import_origin', JSON.stringify({ aabbcc: 'file', ddeeff: 'paste' }));
        store.set('daal.d2.connect.pinned_route', 'r3');
    };
    it('panicWipe clears them BEFORE the engine is asked, so a failed or interrupted wipe still leaves none', async () => {
        withStorage();
        let seenAtCall = -1;
        handlers.set('panic_wipe', () => {
            seenAtCall = store.size;
            throw 'engine call returned -1';
        });
        await expect(new TauriContract().panicWipe()).rejects.toBeTruthy();
        expect(seenAtCall).toBe(0);
        expect(store.size).toBe(0);
        vi.unstubAllGlobals();
    });
    it('publisherDelete drops that fingerprint; routeDelete drops a pin on that route', async () => {
        withStorage();
        handlers.set('publisher_delete', () => 2);
        handlers.set('route_delete', () => undefined);
        const c = new TauriContract();
        await c.publisherDelete('AABBCC');
        expect(store.get('daal.d2.import_origin')).toBe(JSON.stringify({ ddeeff: 'paste' }));
        await c.routeDelete('r1');
        expect(store.get('daal.d2.connect.pinned_route')).toBe('r3');
        await c.routeDelete('r3');
        expect(store.has('daal.d2.connect.pinned_route')).toBe(false);
        vi.unstubAllGlobals();
    });
    it('a delete the engine refused forgets nothing', async () => {
        withStorage();
        // No handler: both calls reject.
        const c = new TauriContract();
        await expect(c.publisherDelete('aabbcc')).rejects.toBeTruthy();
        await expect(c.routeDelete('r3')).rejects.toBeTruthy();
        expect(store.get('daal.d2.import_origin')).toContain('aabbcc');
        expect(store.get('daal.d2.connect.pinned_route')).toBe('r3');
        vi.unstubAllGlobals();
    });
    it('vpn_status.holding reaches the summary', async () => {
        handlers.set('export_diagnostics', diag({ posture: 'Recovery', route_check: 'failed', route_running: false,
            auto: { state: 'failed', mode: true, verdict: 'all_failed', tried: [] } }));
        const s = await new TauriContract().connectionSummary();
        // Desktop (no Android bridge): never holding.
        expect(s.holding).toBe(false);
    });
});
