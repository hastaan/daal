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

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push(cmd);
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
