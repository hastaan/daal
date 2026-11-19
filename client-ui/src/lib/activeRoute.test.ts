// The active route is read from engine memory first; a failing route
// store must not erase it from the pages (first phone pass: "You're
// connected." over "No route selected").
import { describe, expect, it } from 'vitest';
import type { ConnectionSummary } from '../contract/D2Contract';
import {
    diagNamesActiveRoute,
    idOnlyRoute,
    isIdOnlyRoute,
    pickActiveRouteId,
    routeForDisplay,
    runningRouteId,
    summaryExtras,
} from './activeRoute';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';

describe('pickActiveRouteId', () => {
    it('prefers export_diagnostics.active_route over everything store-backed', () => {
        expect(
            pickActiveRouteId(
                { active_route: 'r2' },
                { active_route: 'r1', pick: { route_id: 'r1' } },
            ),
        ).toBe('r2');
    });
    it('needs no explain payload at all when the blob names the route', () => {
        expect(pickActiveRouteId({ active_route: 'r2' }, null)).toBe('r2');
        expect(diagNamesActiveRoute({ active_route: 'r2' })).toBe(true);
    });
    it("falls back to the explain payload's active_route, then pick.route_id", () => {
        expect(pickActiveRouteId({}, { active_route: 'r3', pick: { route_id: 'r9' } })).toBe('r3');
        // The store read failed inside DiagnosticsExplain: no pick, but
        // active_route is still there.
        expect(pickActiveRouteId({ active_route: '' }, { active_route: 'r3' })).toBe('r3');
        expect(pickActiveRouteId({}, { pick: { route_id: 'r4' } })).toBe('r4');
    });
    it('says nothing when nobody names a route', () => {
        expect(pickActiveRouteId({ active_route: '' }, { pick: { route_id: '' } })).toBeUndefined();
        expect(pickActiveRouteId(undefined, undefined)).toBeUndefined();
        expect(pickActiveRouteId({ active_route: 7 }, null)).toBeUndefined();
        expect(diagNamesActiveRoute({ active_route: '' })).toBe(false);
        expect(diagNamesActiveRoute({})).toBe(false);
    });
});

describe('id-only route', () => {
    const t = (k: string) => (en as Record<string, string>)[k] ?? k;
    it('carries the id and the family the engine gave, and claims nothing else', () => {
        const r = idOnlyRoute('r2', 'vless-reality');
        expect(r.routeId).toBe('r2');
        expect(r.family).toBe('vless-reality');
        expect(r.trustClass).toBe('unknown');
        expect(r.healthPct).toBeUndefined();
        expect(isIdOnlyRoute(r)).toBe(true);
        expect(idOnlyRoute('r2', undefined).family).toBe('');
    });
    it('is shown in our own words, not as an empty label or a raw id', () => {
        const shown = routeForDisplay(idOnlyRoute('r2'), t)!;
        expect(shown.routeId).toBe('r2');
        expect(shown.publisherName).toBe('Current connection');
        expect(shown.routeNickname).toBe('name not available');
    });
    it('leaves a fully-read route untouched, and no route as no route', () => {
        const full = { ...idOnlyRoute('r1'), publisherName: 'Pars', routeNickname: 'Rescue 03' };
        expect(routeForDisplay(full, t)).toBe(full);
        expect(routeForDisplay(undefined, t)).toBeUndefined();
    });
    it('has both languages for its words', () => {
        for (const k of ['conn.route_unnamed', 'conn.route_unnamed_detail']) {
            expect((en as Record<string, string>)[k], k).toBeTruthy();
            expect((fa as Record<string, string>)[k], k).toBeTruthy();
            expect((fa as Record<string, string>)[k]).not.toBe((en as Record<string, string>)[k]);
        }
    });
});

describe('runningRouteId / summaryExtras', () => {
    const base: ConnectionSummary = { state: 'connected', mode: 'normal', activeRoute: idOnlyRoute('r1') };
    it('is the route the engine has up: connected, being checked, or being retried', () => {
        expect(runningRouteId(base)).toBe('r1');
        expect(runningRouteId({ ...base, state: 'connecting', routeRunning: true })).toBe('r1');
        expect(runningRouteId({ ...base, state: 'connecting', routeRunning: false })).toBeNull();
        expect(runningRouteId({ ...base, state: 'error' })).toBeNull();
        expect(runningRouteId({ ...base, state: 'disconnected' })).toBeNull();
        expect(runningRouteId({ state: 'connected', mode: 'normal' })).toBeNull();
    });
    it('reads the extra fields, and a backend that sends none', () => {
        expect(summaryExtras(base)).toEqual({ connectRefusedRoute: undefined, storeRecovered: false });
        const plus = { ...base, connectRefusedRoute: 'r2', storeRecovered: true };
        expect(summaryExtras(plus)).toEqual({ connectRefusedRoute: 'r2', storeRecovered: true });
        expect(summaryExtras(null).storeRecovered).toBe(false);
    });
});
