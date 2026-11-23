// Round 3a: "Check the backup update routes" and "Connect with this
// file", below the page — the engine's words read into plain lines, the
// TauriContract calls (the check rides relaypack_refresh with a JSON
// request; the file's connect arms set_auto_scope, then connect_auto),
// and the harness doing the same without an engine.
import { beforeEach, describe, expect, it, vi } from 'vitest';

type Handler = (args?: Record<string, unknown>) => unknown;
const handlers = new Map<string, Handler>();
const callArgs: Array<[string, Record<string, unknown> | undefined]> = [];

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        callArgs.push([cmd, args]);
        const h = handlers.get(cmd);
        if (!h) throw 'engine call returned -1';
        return h(args);
    },
}));

import {
    backupNames,
    backupRoutesOf,
    CHECK_AGAIN_MS,
    keptAnswerFor,
    keptCheck,
    setKeptCheck,
    subscribeKeptCheck,
    canOfferCheck,
    drillLines,
    drillMessage,
    drillRequest,
    drillRouteOf,
    parseDrill,
} from './backupCheck';
import { TauriContract } from '../backends/tauri';
import { HarnessContract } from '../backends/harness';
import type { ConnectionSummary, PublisherTreeRow, RouteDisplayRow } from '../contract/D2Contract';
import type { Scenario } from '../harness/scenarios';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? k;

beforeEach(() => {
    handlers.clear();
    callArgs.length = 0;
});

const ANSWER = {
    outcome: 'unchanged',
    retry_after_s: 0,
    route_paused: false,
    packs: [{ relay_pack_id: 'rp-x', outcome: 'freshness_unreachable', kind: 'drill' }],
    drill: {
        github: { result: 'verified' },
        google: { result: 'nothing_new' },
        goproxy: { result: 'skipped', reason: 'budget' },
        jsdelivr: { result: 'failed' },
        dns: { result: 'skipped', reason: 'no_resolver' },
    },
};

describe("the engine's answer", () => {
    it('is read as closed words, per class', () => {
        const a = parseDrill(JSON.stringify(ANSWER));
        expect(a.outcome).toBe('unchanged');
        expect(a.classes?.github).toEqual({ result: 'verified', reason: '' });
        expect(a.classes?.dns).toEqual({ result: 'skipped', reason: 'no_resolver' });
    });

    it('anything else is "unavailable", never a guess', () => {
        expect(parseDrill('nope').outcome).toBe('unavailable');
        expect(parseDrill('{"outcome":"wonderful"}').outcome).toBe('unavailable');
        expect(parseDrill('null').outcome).toBe('unavailable');
        const odd = parseDrill(JSON.stringify({ outcome: 'unreachable', drill: { github: { result: 'magic' }, dns: { result: 'skipped', reason: 'x' } } }));
        expect(odd.classes?.github).toBeUndefined();
        expect(odd.classes?.dns).toEqual({ result: 'skipped', reason: '' });
    });

    it('the rate limit says how long', () => {
        const a = parseDrill('{"outcome":"rate_limited","retry_after_s":419.2}');
        expect(a).toEqual({ outcome: 'rate_limited', retryAfterS: 420 });
        expect(drillMessage(a).key).toBe('files.check.wait_until');
        expect(drillMessage({ outcome: 'rate_limited', retryAfterS: 0 }).key).toBe('files.check.wait');
    });

    it('the request names a route, not a pack', () => {
        expect(JSON.parse(drillRequest('test-r1'))).toEqual({ drill: true, route_id: 'test-r1' });
    });
});

describe('one line per route family', () => {
    it('GitHub, Google, Other mirrors (the one that was asked), DNS', () => {
        expect(drillLines(parseDrill(JSON.stringify(ANSWER)))).toEqual([
            { family: 'github', word: 'works' },
            { family: 'google', word: 'nothing_new' },
            { family: 'mirrors', word: 'no_answer' },
            { family: 'dns', word: 'not_here' },
        ]);
    });

    it('the better of the two mirrors is shown', () => {
        const a = parseDrill(JSON.stringify({ outcome: 'updated', drill: {
            github: { result: 'failed' },
            google: { result: 'reached' },
            goproxy: { result: 'verified' },
            jsdelivr: { result: 'skipped', reason: 'budget' },
            dns: { result: 'skipped', reason: 'no_resolver' },
        } }));
        expect(drillLines(a)).toEqual([
            { family: 'github', word: 'no_answer' },
            { family: 'google', word: 'works' },
            { family: 'mirrors', word: 'works' },
            { family: 'dns', word: 'not_here' },
        ]);
    });

    it('a family the file does not hold has no line', () => {
        const a = parseDrill(JSON.stringify({ outcome: 'unreachable', drill: {
            github: { result: 'skipped', reason: 'not_in_file' },
            google: { result: 'skipped', reason: 'not_in_file' },
            goproxy: { result: 'skipped', reason: 'not_in_file' },
            jsdelivr: { result: 'skipped', reason: 'not_in_file' },
            dns: { result: 'failed' },
        } }));
        expect(drillLines(a)).toEqual([{ family: 'dns', word: 'no_answer' }]);
        expect(drillLines({ outcome: 'rate_limited', retryAfterS: 60 })).toEqual([]);
    });

    it('a route that was not asked because a route was up has no line', () => {
        const up = { result: 'skipped', reason: 'route_up' };
        const a = parseDrill(JSON.stringify({ outcome: 'tunnel_required', drill: { github: up, google: up, goproxy: up, jsdelivr: up, dns: up } }));
        expect(drillLines(a)).toEqual([]);
    });

    it('"none answered" only when none did: a family that answered with nothing new changes the headline', () => {
        const answered = parseDrill(JSON.stringify({ outcome: 'unreachable', drill: {
            github: { result: 'nothing_new' },
            google: { result: 'nothing_new' },
            dns: { result: 'failed' },
        } }));
        expect(drillMessage(answered)).toEqual({ key: 'files.check.answered', tone: 'neutral' });
        const none = parseDrill(JSON.stringify({ outcome: 'unreachable', drill: {
            github: { result: 'failed' },
            dns: { result: 'failed' },
        } }));
        expect(drillMessage(none)).toEqual({ key: 'files.check.unreachable', tone: 'bad' });
        expect(EN['files.check.answered']).toBeTruthy();
        expect(FA['files.check.answered']).toBeTruthy();
    });

    it('every outcome has its own sentence, in both languages, with no jargon', () => {
        const outcomes = ['updated', 'unchanged', 'unreachable', 'no_endpoints', 'rejected', 'tunnel_required', 'rate_limited',
            'in_progress', 'not_available', 'unknown_pack', 'cancelled', 'unavailable'] as const;
        const keys = new Set<string>();
        for (const o of outcomes) keys.add(drillMessage({ outcome: o, retryAfterS: o === 'rate_limited' ? 60 : 0 }).key);
        keys.add('files.check.wait');
        for (const w of ['works', 'nothing_new', 'no_answer', 'not_here']) keys.add(`files.check.word.${w}`);
        for (const f of ['github', 'google', 'mirrors', 'dns']) keys.add(`files.check.family.${f}`);
        for (const k of ['files.check.action', 'files.check.title', 'files.check.running', 'files.backup.line']) keys.add(k);
        for (const k of keys) {
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toBeTruthy();
            for (const word of ['ladder', 'carrier', 'note', 'class', 'tag', 'epoch', 'A record']) {
                expect(EN[k].toLowerCase(), `${k}: ${word}`).not.toMatch(new RegExp(`\\b${word.toLowerCase()}\\b`));
            }
        }
        expect(EN['files.check.running']).toMatch(/two minutes/);
        expect(FA['files.check.running']).toMatch(/دو دقیقه/);
        expect(FA['files.check.wait_until']).toContain('{time}');
        expect(FA['files.backup.line']).toContain('{list}');
    });
});

function route(id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow {
    return { routeId: id, publisherId: 'p', publisherName: 'Test', routeNickname: id, trustClass: 'trusted', family: 'vless-reality', ...over };
}
function file(routes: RouteDisplayRow[]): PublisherTreeRow {
    return { publisherId: 'p', displayName: 'Test', trustLevel: 'trusted', sourceKind: 'file', revoked: false, routeCount: routes.length, cells: [{ cellIdFpHex: 'default', label: '', families: [], routes }] } as unknown as PublisherTreeRow;
}
const OFF = { state: 'disconnected', mode: 'normal', routeRunning: false } as unknown as ConnectionSummary;

describe("the file's backup routes", () => {
    const both = file([route('r1', { backupRoutes: ['dns', 'gittag'] }), route('r2', { backupRoutes: ['gittag', 'dns'] })]);
    const none = file([route('r1'), route('r2')]);

    it('are named in plain words, in a fixed order', () => {
        expect(backupRoutesOf(both)).toEqual(['gittag', 'dns']);
        expect(t('files.backup.line').replace('{list}', backupNames(t, backupRoutesOf(both)))).toBe('Backup update routes: GitHub, DNS');
        expect(backupRoutesOf(none)).toEqual([]);
        expect(drillRouteOf(both)).toBe('r1');
        expect(drillRouteOf(none)).toBeUndefined();
    });

    it('the check is offered only with backup routes and nothing up', () => {
        expect(canOfferCheck(both, OFF, null, null)).toBe(true);
        expect(canOfferCheck(none, OFF, null, null)).toBe(false);
        expect(canOfferCheck(both, { ...OFF, state: 'connected', routeRunning: true }, 'r1', null)).toBe(false);
        expect(canOfferCheck(both, OFF, null, 'r2')).toBe(false);
        expect(canOfferCheck(both, { ...OFF, state: 'connecting' }, null, null)).toBe(false);
        expect(canOfferCheck(both, { ...OFF, auto: { state: 'trying' } } as unknown as ConnectionSummary, null, null)).toBe(false);
        expect(canOfferCheck(both, null, null, null)).toBe(false);
    });
});

describe('the kept check', () => {
    const answer = { outcome: 'unchanged' as const, retryAfterS: 0, classes: { github: { result: 'verified' as const, reason: '' as const } } };

    it('keeps the last answer for 10 minutes, for its own file only', () => {
        const t0 = 1_000_000;
        const seen: number[] = [];
        const off = subscribeKeptCheck(() => seen.push(1));
        setKeptCheck({ fileName: 'A', running: false, startedAt: t0, answer, at: t0 + 60_000 });
        off();
        expect(seen).toEqual([1]);
        expect(keptCheck()?.fileName).toBe('A');
        expect(keptAnswerFor('A', t0 + 5 * 60_000, true)).not.toBeNull();
        expect(keptAnswerFor('B', t0 + 5 * 60_000, true)).toBeNull();
        expect(keptAnswerFor('A', t0 + CHECK_AGAIN_MS, true)).toBeNull();
        setKeptCheck(null);
    });

    it('an answer with no lines, or one after which the engine may not hold its stamp, is not used to skip the engine', () => {
        const t0 = 1_000_000;
        setKeptCheck({ fileName: 'A', running: false, startedAt: t0, answer: { outcome: 'tunnel_required', retryAfterS: 0, classes: {} }, at: t0 });
        expect(keptAnswerFor('A', t0 + 1000, false)).toBeNull();
        setKeptCheck({ fileName: 'A', running: false, startedAt: t0, answer: { ...answer, outcome: 'cancelled' }, at: t0 });
        expect(keptAnswerFor('A', t0 + 1000, true)).toBeNull();
        expect(keptAnswerFor('A', t0 + 1000, false)).not.toBeNull();
        setKeptCheck({ fileName: 'A', running: true, startedAt: t0 });
        expect(keptAnswerFor('A', t0 + 1000, false)).toBeNull();
        setKeptCheck(null);
    });
});

describe('TauriContract', () => {
    it('reads backup_routes off the summary rows, and nothing when absent', async () => {
        const raw = (id: string, extra: Record<string, unknown>) => ({
            route_id: id, publisher_id: 'p', publisher_name: 'Test', route_nickname: id, trust_class: 'trusted',
            family: 'vless-reality', in_cooldown: null, budget_exhausted: null, health_pct: null, ...extra,
        });
        handlers.set('available_routes', () => JSON.stringify({ routes: [
            raw('r1', { backup_routes: ['gittag', 'dns'] }),
            raw('r2', { backup_routes: ['dns', 'bogus'] }),
            raw('r3', {}),
        ] }));
        const rows = await new TauriContract().availableRoutes();
        expect(rows.map((r) => r.backupRoutes)).toEqual([['gittag', 'dns'], ['dns'], undefined]);
    });

    it('the check is relaypack_refresh with the JSON request', async () => {
        handlers.set('relaypack_refresh', () => JSON.stringify(ANSWER));
        const a = await new TauriContract().backupCheck('r1');
        expect(a.outcome).toBe('unchanged');
        expect(callArgs).toEqual([['relaypack_refresh', { relayPackId: '{"drill":true,"route_id":"r1"}' }]]);
    });

    it('a failed call is "unavailable", never a throw', async () => {
        const a = await new TauriContract().backupCheck('r1');
        expect(a).toEqual({ outcome: 'unavailable', retryAfterS: 0 });
    });

    it("Connect with this file arms the file's scope, then the automatic connect; never a connect by hand", async () => {
        handlers.set('set_auto_scope', () => 2);
        handlers.set('connect_auto', () => JSON.stringify({ connected: true, route_id: 'r2', family: 'vless-reality', tried: [], verdict: '', candidates: 2 }));
        const res = await new TauriContract().connectAutoWithin(['r1', 'r2']);
        expect(res?.routeId).toBe('r2');
        expect(callArgs.map(([c]) => c)).toEqual(['set_auto_scope', 'connect_auto']);
        expect(callArgs[0][1]).toEqual({ routeIds: ['r1', 'r2'] });
        expect(callArgs.some(([c]) => c === 'connect' || c === 'plugin:daal-platform|vpn_start')).toBe(false);
    });

    it('an engine without the scope still connects automatically, not by hand', async () => {
        handlers.set('set_auto_scope', () => {
            throw 'engine symbol missing: engine_set_auto_scope: not in this engine library';
        });
        handlers.set('connect_auto', () => JSON.stringify({ connected: true, route_id: 'r9', family: 'x', tried: [], verdict: '', candidates: 5 }));
        await new TauriContract().connectAutoWithin(['r1']);
        expect(callArgs.map(([c]) => c)).toEqual(['set_auto_scope', 'connect_auto']);
    });

    it('a failed arm is thrown and nothing connects', async () => {
        handlers.set('connect_auto', () => JSON.stringify({ connected: true, route_id: 'r9', family: 'x', tried: [], verdict: '', candidates: 5 }));
        // No set_auto_scope handler: the mock answers "engine call returned -1".
        await expect(new TauriContract().connectAutoWithin(['r1'])).rejects.toBeDefined();
        expect(callArgs.map(([c]) => c)).toEqual(['set_auto_scope']);
    });

    it('a connect that never reached the engine disarms the scope it armed', async () => {
        const armed: unknown[] = [];
        handlers.set('set_auto_scope', (a) => {
            armed.push(a?.routeIds);
            return 1;
        });
        handlers.set('connect_auto', () => {
            throw 'refused';
        });
        await expect(new TauriContract().connectAutoWithin(['r1'])).rejects.toBe('refused');
        expect(armed).toEqual([['r1'], []]);
    });

    it('the main connect disarms any scope first', async () => {
        const armed: unknown[] = [];
        handlers.set('set_auto_scope', (a) => {
            armed.push(a?.routeIds);
            return 0;
        });
        handlers.set('connect_auto', () => JSON.stringify({ connected: true, route_id: 'r9', family: 'x', tried: [], verdict: '', candidates: 5 }));
        await new TauriContract().connectAuto();
        expect(callArgs.map(([c]) => c)).toEqual(['set_auto_scope', 'connect_auto']);
        expect(armed).toEqual([[]]);
    });
});

describe('the harness', () => {
    const rows = [route('a1'), route('a2'), route('b1', { publisherName: 'Other', publisherId: 'q' })];
    const scenario = {
        id: 't', title: 't', screen: 'network',
        connection: { state: 'disconnected', mode: 'normal' },
        availableRoutes: rows,
        backupCheck: ANSWER,
    } as unknown as Scenario;

    it("connects automatically among the file's ways only, in automatic mode", async () => {
        const h = new HarnessContract({ stepMs: 1, scenario });
        const res = await h.connectAutoWithin(['b1']);
        expect(res?.routeId).toBe('b1');
        expect(res?.candidates).toBe(1);
        const s = await h.connectionSummary();
        expect(s.auto?.mode).toBe(true);
        expect(s.activeRoute?.routeId).toBe('b1');
        // The next plain connect is over every way again.
        await h.disconnect();
        expect((await h.connectAuto())?.candidates).toBe(3);
    });

    it("checks the backup routes with the scenario's answer, and refuses while connected", async () => {
        const h = new HarnessContract({ stepMs: 1, scenario });
        expect((await h.backupCheck('a1')).outcome).toBe('unchanged');
        await h.connect('a1');
        const busy = await h.backupCheck('a1');
        expect(busy.outcome).toBe('tunnel_required');
        expect(drillLines(busy).every((l) => l.word === 'not_here')).toBe(true);
    });
});
