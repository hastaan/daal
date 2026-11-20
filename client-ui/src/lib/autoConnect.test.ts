// Automatic connect as the main screen reads it (backlog PH-25).
//
// Second phone pass: a person with a valid file holding four routes
// pressed the main control and nothing connected — the page opened the
// Connections list, where they were left looking at protocol names. The
// main control now asks the engine to pick (connectAuto) unless the
// person pinned a route themselves; these are the rules it follows.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AutoStatus, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import {
    FAILURE_VERDICTS,
    autoConnectedNoteKey,
    autoFailure,
    autoIsUsing,
    autoProgressText,
    autoResultKey,
    autoVerdictActionKey,
    autoVerdictActionText,
    autoVerdictKey,
    cooldownMinutes,
    effectivePin,
    getPinnedRoute,
    mainTapLabelKey,
    mainTapPlan,
    parseAuto,
    parseAutoNote,
    parseAutoResult,
    setPinnedRoute,
    startConnect,
    stateWithAuto,
    verdictWantsFile,
} from './autoConnect';
import { connStateWithCheck, tapAction } from './routeCheck';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const tr = (d: Record<string, string>) => (k: string) => d[k] ?? k;

const route = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: id,
    trustClass: 'trusted',
    family: 'vless-reality',
    ...over,
});
const FOUR = [route('r1'), route('r2'), route('r3'), route('r4')];

const auto = (over: Partial<AutoStatus>): AutoStatus => ({
    state: 'idle',
    mode: false,
    trying: '',
    index: 0,
    total: 0,
    tried: [],
    verdict: '',
    routeId: '',
    ...over,
});

describe('parseAuto: the `auto` block of export_diagnostics', () => {
    it('reads the contract shape', () => {
        const a = parseAuto({
            state: 'trying',
            mode: true,
            trying: 'r2',
            index: 2,
            total: 4,
            tried: [{ route_id: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply' }],
            verdict: '',
            route_id: '',
        });
        expect(a).toEqual({
            state: 'trying',
            mode: true,
            trying: 'r2',
            // Nothing said about a second route: it is tried alone.
            racing: [],
            index: 2,
            total: 4,
            tried: [{ routeId: 'r1', family: 'vless-reality', result: 'not_carrying', category: 'no_reply' }],
            verdict: '',
            routeId: '',
        });
    });
    it('is undefined for an engine that sends no block, or a state this app does not know', () => {
        expect(parseAuto(undefined)).toBeUndefined();
        expect(parseAuto(null)).toBeUndefined();
        expect(parseAuto('trying')).toBeUndefined();
        expect(parseAuto({ state: 'warming_up', mode: true })).toBeUndefined();
    });
    it('tolerates missing and malformed fields without inventing any', () => {
        const a = parseAuto({ state: 'failed', tried: [null, { family: 'x' }, { route_id: 'r9' }], index: -3, total: 'four' });
        expect(a).toEqual(auto({ state: 'failed', racing: [], tried: [{ routeId: 'r9', family: '', result: '', category: '' }] }));
    });
});

describe('parseAutoResult: what connect_auto hands back', () => {
    it('reads the JSON text and the parsed object alike', () => {
        const body = {
            connected: true,
            route_id: 'r2',
            family: 'websocket-tls',
            tried: [
                { route_id: 'r1', family: 'vless-reality', result: 'not_carrying', category: '' },
                { route_id: 'r2', family: 'websocket-tls', result: 'carried', category: '' },
            ],
            verdict: 'moved_on',
            candidates: 4,
        };
        const want = {
            connected: true,
            routeId: 'r2',
            family: 'websocket-tls',
            tried: [
                { routeId: 'r1', family: 'vless-reality', result: 'not_carrying', category: '' },
                { routeId: 'r2', family: 'websocket-tls', result: 'carried', category: '' },
            ],
            verdict: 'moved_on',
            candidates: 4,
        };
        expect(parseAutoResult(JSON.stringify(body))).toEqual(want);
        expect(parseAutoResult(body)).toEqual(want);
    });
    it('is null for what is not an answer: Android\'s "started", nothing, junk', () => {
        expect(parseAutoResult('{"pending":true,"platform":"android"}')).toBeNull();
        expect(parseAutoResult(null)).toBeNull();
        expect(parseAutoResult(undefined)).toBeNull();
        expect(parseAutoResult('not json')).toBeNull();
    });
});

describe('parseAutoNote: the Android service on an automatic connect that found nothing', () => {
    it('reads the verdict of a note marked auto', () => {
        expect(
            parseAutoNote({ last_switch: { route_id: '', kept_route_id: null, outcome: 'failed', reason: 'network_down', auto: true } }),
        ).toBe('network_down');
    });
    it('ignores a note about a switch by hand, and everything else', () => {
        expect(parseAutoNote({ last_switch: { route_id: 'r2', outcome: 'failed', reason: 'x' } })).toBeUndefined();
        expect(parseAutoNote({ last_switch: null })).toBeUndefined();
        expect(parseAutoNote(null)).toBeUndefined();
    });
});

describe('stateWithAuto: the page follows the engine', () => {
    // D3. While connected automatically the running route stops
    // carrying and the engine moves to the next candidate by itself.
    // Between the two the blob reads, in turn: the old route failed and
    // torn down (which alone is "error"), nothing active
    // ("disconnected"), the new one being proved, the new one up. The
    // page must read connecting → connecting → connecting → connected.
    it('never shows "disconnected" or "error" while the engine is moving to another route', () => {
        const trying = auto({ state: 'trying', mode: true, trying: 'r2', index: 2, total: 4 });
        const moments: Array<[Parameters<typeof connStateWithCheck>, AutoStatus, string]> = [
            // r1 up and proved
            [['connected', 'ok', true], auto({ state: 'connected', mode: true, routeId: 'r1' }), 'connected'],
            // r1 stopped carrying; the engine has torn it down
            [['connecting', 'failed', false], trying, 'connecting'],
            // nothing active for a moment
            [['disconnected', undefined, false], trying, 'connecting'],
            // r2 started, being proved
            [['connecting', 'verifying', true], trying, 'connecting'],
            // r2 carried
            [['connected', 'ok', true], auto({ state: 'connected', mode: true, routeId: 'r2', verdict: 'moved_on' }), 'connected'],
        ];
        const seen = moments.map(([check, a]) => stateWithAuto(connStateWithCheck(...check), a));
        expect(seen).toEqual(moments.map((m) => m[2]));
        // The same blobs WITHOUT the auto block are what used to flash:
        expect(connStateWithCheck('connecting', 'failed', false)).toBe('error');
        expect(connStateWithCheck('disconnected', undefined, false)).toBe('disconnected');
    });
    it('reads a finished, failed automatic connect as an error, not as "press to connect"', () => {
        expect(stateWithAuto('disconnected', auto({ state: 'failed', verdict: 'all_failed' }))).toBe('error');
    });
    it('does not overrule a connect by hand that is up or being checked', () => {
        const stale = auto({ state: 'failed', verdict: 'all_failed' });
        expect(stateWithAuto('connected', stale)).toBe('connected');
        expect(stateWithAuto('connecting', stale)).toBe('connecting');
    });
    it('changes nothing for an engine with no auto block', () => {
        for (const s of ['disconnected', 'connecting', 'connected', 'error'] as const) {
            expect(stateWithAuto(s, undefined)).toBe(s);
            expect(stateWithAuto(s, auto({}))).toBe(s);
        }
    });
});

describe('the main control', () => {
    const idle = tapAction('disconnected', undefined);
    it('connects automatically when nothing is running and nothing is pinned', () => {
        expect(mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: null, routes: FOUR })).toEqual({ kind: 'auto' });
        // ...also when the route list could not be read: the engine
        // knows what it holds, and says "no_routes" if it holds nothing.
        expect(mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: null, routes: undefined })).toEqual({ kind: 'auto' });
    });
    it('connects the pinned route when the person chose one', () => {
        expect(mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: 'r3', routes: FOUR })).toEqual({
            kind: 'pinned',
            routeId: 'r3',
        });
    });
    it('opens the add sheet when the device holds no route at all — pinned or not', () => {
        expect(mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: null, routes: [] })).toEqual({ kind: 'add_file' });
        expect(mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: 'r3', routes: [] })).toEqual({ kind: 'add_file' });
    });
    it('stops whatever is running, and cancels automatic connect at any moment', () => {
        expect(mainTapPlan({ action: tapAction('connected', 'ok'), auto: undefined, pinnedRouteId: null, routes: FOUR }).kind).toBe('disconnect');
        // Between two candidates the state can read as anything —
        // here "error", for which the tap would otherwise be "recovery".
        const between = tapAction('error', 'failed');
        expect(between).toBe('recovery');
        expect(
            mainTapPlan({ action: between, auto: auto({ state: 'trying', mode: true }), pinnedRouteId: null, routes: FOUR }).kind,
        ).toBe('disconnect');
        // ...even with no routes listed (the store was reset under a
        // running tunnel): stopping wins over "add a file".
        expect(mainTapPlan({ action: tapAction('connected', 'ok'), auto: undefined, pinnedRouteId: null, routes: [] }).kind).toBe('disconnect');
    });
    it('after a failure: automatic simply tries again; a pinned route gets the sheet of other choices', () => {
        const failed = tapAction('error', 'failed');
        expect(mainTapPlan({ action: failed, auto: auto({ state: 'failed' }), pinnedRouteId: null, routes: FOUR })).toEqual({ kind: 'auto' });
        expect(mainTapPlan({ action: failed, auto: undefined, pinnedRouteId: 'r3', routes: FOUR })).toEqual({ kind: 'recovery' });
    });
    it('a lingering AUTOMATIC failure does not send a pinned tap to the recovery sheet: it connects the pin', () => {
        // Automatic failed (nothing running → 'error'), then the person
        // opened the chooser and picked r3. The error is not r3's.
        const failed = tapAction('error', 'failed');
        expect(failed).toBe('recovery');
        expect(
            mainTapPlan({ action: failed, auto: auto({ state: 'failed', verdict: 'none_usable' }), pinnedRouteId: 'r3', routes: FOUR }),
        ).toEqual({ kind: 'pinned', routeId: 'r3' });
        // The pinned route's OWN failed connect (a connect by hand ends
        // automatic mode: the block is idle) still gets the sheet.
        expect(mainTapPlan({ action: failed, auto: auto({ state: 'idle' }), pinnedRouteId: 'r3', routes: FOUR })).toEqual({ kind: 'recovery' });
    });
    it('while the service holds the VPN closed, the tap lets go of it', () => {
        const failed = tapAction('error', 'failed');
        const held = { action: failed, auto: auto({ state: 'failed', mode: true }), routes: FOUR, holding: true };
        expect(mainTapPlan({ ...held, pinnedRouteId: null })).toEqual({ kind: 'disconnect' });
        expect(mainTapPlan({ ...held, pinnedRouteId: 'r3' })).toEqual({ kind: 'disconnect' });
        expect(mainTapLabelKey({ kind: 'disconnect' }, held.auto, 'conn.connect_action', true)).toBe('conn.disconnect_action');
        // Not holding: unchanged.
        expect(mainTapPlan({ ...held, holding: false, pinnedRouteId: null })).toEqual({ kind: 'auto' });
    });

    it('main tap → connectAuto; pinned → connect(route)', async () => {
        const calls: string[] = [];
        const contract = {
            connect: async (id: string) => {
                calls.push(`connect:${id}`);
            },
            connectAuto: async () => {
                calls.push('connectAuto');
                return null;
            },
        };
        const tap = async (pinned: string | null) => {
            const plan = mainTapPlan({ action: idle, auto: undefined, pinnedRouteId: pinned, routes: FOUR });
            if (plan.kind === 'auto' || plan.kind === 'pinned') await startConnect(contract, plan);
        };
        await tap(null);
        expect(calls).toEqual(['connectAuto']);
        await tap('r3');
        expect(calls).toEqual(['connectAuto', 'connect:r3']);
    });

    it('labels the button: Cancel while trying, Add your file with nothing imported', () => {
        expect(mainTapLabelKey({ kind: 'disconnect' }, auto({ state: 'trying', mode: true }), 'conn.disconnect_action')).toBe('conn.cancel_action');
        expect(mainTapLabelKey({ kind: 'disconnect' }, auto({ state: 'connected', mode: true }), 'conn.disconnect_action')).toBe('conn.disconnect_action');
        expect(mainTapLabelKey({ kind: 'add_file' }, undefined, 'conn.connect_action')).toBe('auto.add_file');
        expect(mainTapLabelKey({ kind: 'auto' }, undefined, 'conn.connect_action')).toBe('conn.connect_action');
    });
});

describe('the pinned route', () => {
    const store = new Map<string, string>();
    beforeEach(() => {
        store.clear();
        vi.stubGlobal('localStorage', {
            getItem: (k: string) => store.get(k) ?? null,
            setItem: (k: string, v: string) => void store.set(k, v),
            removeItem: (k: string) => void store.delete(k),
        });
    });
    afterEach(() => vi.unstubAllGlobals());

    it('defaults to Automatic, is remembered, and is reversible', () => {
        expect(getPinnedRoute()).toBeNull();
        setPinnedRoute('r3');
        expect(getPinnedRoute()).toBe('r3');
        setPinnedRoute(null); // "Back to automatic"
        expect(getPinnedRoute()).toBeNull();
    });
    it('survives a platform with no storage (Automatic)', () => {
        vi.stubGlobal('localStorage', undefined);
        expect(getPinnedRoute()).toBeNull();
        expect(() => setPinnedRoute('r3')).not.toThrow();
    });
    it('a pin for a route the device no longer holds is no pin; an unread list proves nothing', () => {
        expect(effectivePin('r3', FOUR)).toBe('r3');
        expect(effectivePin('gone', FOUR)).toBeNull();
        expect(effectivePin('gone', undefined)).toBe('gone');
        expect(effectivePin(null, FOUR)).toBeNull();
    });
});

describe('progress: "Trying way 2 of 4…"', () => {
    const a = auto({ state: 'trying', mode: true, trying: 'r2', index: 2, total: 4 });
    it('is built from the auto block, in English and in Persian digits', () => {
        expect(autoProgressText(tr(EN), 'en', a)).toBe('Trying way 2 of 4…');
        const f = autoProgressText(tr(FA), 'fa', a);
        expect(f).toBe(FA['auto.trying'].replace('{i}', '۲').replace('{n}', '۴'));
        expect(f).not.toMatch(/[0-9{}]/);
    });
    it('names no route and no family', () => {
        const withFamily = { ...a, trying: 'r2-websocket-tls' };
        for (const [d, l] of [[EN, 'en'], [FA, 'fa']] as const) {
            const s = autoProgressText(tr(d), l, withFamily);
            expect(s).not.toContain('r2');
            expect(s).not.toContain('websocket');
        }
    });
    it('says it without numbers when the engine has not said how many, or there is only one', () => {
        expect(autoProgressText(tr(EN), 'en', auto({ state: 'trying' }))).toBe(EN['auto.trying_plain']);
        expect(autoProgressText(tr(EN), 'en', undefined)).toBe(EN['auto.trying_plain']);
        expect(autoProgressText(tr(EN), 'en', auto({ state: 'trying', index: 1, total: 1 }))).toBe(EN['auto.trying_plain']);
        expect(autoProgressText(tr(EN), 'en', auto({ state: 'trying', index: 5, total: 4 }))).toBe(EN['auto.trying_plain']);
    });
});

describe('verdicts: one plain sentence each, in both languages', () => {
    // Engine vocabulary that must never reach a sentence.
    const PROTOCOL = /vless|reality|websocket|\bws\b|naive|hysteria|tuic|shadowsocks|wireguard|\budp\b|\btcp\b|\btls\b|quic|\bsni\b|\bdns\b|sing-box|\.sbpx?/i;
    const RAW_CODE = /[a-z]+_[a-z_]+/; // a snake_case code leaking through

    it.each([...FAILURE_VERDICTS])('%s has its sentence and what to do, EN and FA', (code) => {
        for (const key of [autoVerdictKey(code), autoVerdictActionKey(code)]) {
            expect(key).toContain(code);
            for (const d of [EN, FA]) {
                const s = d[key];
                expect(s, key).toBeTruthy();
                expect(s).not.toMatch(PROTOCOL);
                expect(s).not.toMatch(RAW_CODE);
            }
            // Persian text, not the English copied across.
            expect(FA[key]).not.toBe(EN[key]);
            expect(FA[key]).toMatch(/[؀-ۿ]/);
        }
    });
    it('the contract examples say what they should', () => {
        expect(EN[autoVerdictKey('network_down')]).toBe('This phone has no internet right now.');
        // Silence alone cannot tell a dead server from a phone with no
        // working internet: the sentence names both, and the action
        // starts with the check that tells them apart — it does not
        // send the person for a new file they could not receive.
        expect(EN[autoVerdictKey('relay_unreachable')]).toContain('no working internet');
        expect(EN[autoVerdictActionKey('relay_unreachable')]).toMatch(/^If other apps work, ask for a new file\./);
        expect(EN[autoVerdictActionKey('relay_unreachable')]).toContain('ask for a new file');
        // No sentence promises that trying again "in a moment" helps:
        // after a pass that answered, the ways rest for minutes.
        for (const v of FAILURE_VERDICTS) {
            expect(EN[autoVerdictActionKey(v)], v).not.toMatch(/in a moment/);
        }
        // Nothing says "this network blocks…" on the strength of one
        // silent way: the server's own service being down looks the same.
        expect(EN[autoVerdictKey('udp_blocked_here')]).not.toMatch(/network blocks/);
        expect(EN['auto.note.udp_blocked_here']).not.toMatch(/network blocks/);
        expect(FA['auto.note.udp_blocked_here']).not.toContain('این شبکه جلوی');
        expect(FA[autoVerdictKey('udp_blocked_here')]).not.toContain('این شبکه جلوی');
        expect(EN[autoVerdictActionKey('all_failed')]).toContain('ask for a new file');
        expect(EN[autoVerdictActionKey('all_need_new_file')]).toContain('new one');
    });
    it('an unknown code gets the generic sentence — never the code', () => {
        for (const code of ['', 'quantum_interference', 'auto_unavailable', 'moved_on']) {
            expect(autoVerdictKey(code)).toBe('auto.verdict.generic');
            expect(autoVerdictActionKey(code)).toBe('auto.verdict.generic.do');
        }
        for (const d of [EN, FA]) {
            expect(d['auto.verdict.generic']).toBeTruthy();
            expect(d['auto.verdict.generic.do']).toBeTruthy();
        }
    });
    it('all_cooling_down says when to try again if the route list has it', () => {
        const now = 1_000_000;
        const rows = [
            route('r1', { inCooldown: true, cooldownUntilUnixMs: now + 7 * 60_000 }),
            route('r2', { inCooldown: true, cooldownUntilUnixMs: now + 3 * 60_000 + 1 }),
            route('r3', { inCooldown: false, cooldownUntilUnixMs: now + 60_000 }),
            route('r4', { inCooldown: true, cooldownUntilUnixMs: now - 5 }),
        ];
        expect(cooldownMinutes(rows, now)).toBe(4);
        expect(autoVerdictActionText(tr(EN), 'en', 'all_cooling_down', rows, now)).toBe('Try again in about 4 min.');
        expect(autoVerdictActionText(tr(FA), 'fa', 'all_cooling_down', rows, now)).toContain('۴');
        // No time in the data: no number is made up.
        expect(cooldownMinutes(FOUR, now)).toBeUndefined();
        expect(autoVerdictActionText(tr(EN), 'en', 'all_cooling_down', FOUR, now)).toBe(EN['auto.verdict.all_cooling_down.do']);
        expect(autoVerdictActionText(tr(EN), 'en', 'all_cooling_down', undefined, now)).toBe(EN['auto.verdict.all_cooling_down.do']);
    });
    it('only "nothing imported" asks for a file', () => {
        expect(verdictWantsFile('no_routes')).toBe(true);
        expect(verdictWantsFile('all_failed')).toBe(false);
    });
    it('connected: a note only for moving on and for a network that blocks some ways', () => {
        const up = (verdict: string) => auto({ state: 'connected', mode: true, routeId: 'r2', verdict });
        expect(autoConnectedNoteKey(up(''))).toBeUndefined();
        expect(autoConnectedNoteKey(up('moved_on'))).toBe('auto.note.moved_on');
        expect(autoConnectedNoteKey(up('udp_blocked_here'))).toBe('auto.note.udp_blocked_here');
        expect(autoConnectedNoteKey(up('something_new'))).toBeUndefined();
        // What the engine really sends when a QUIC way was silent and
        // another way to the same server carried (worldbox op `auto`,
        // memory.udp): verdict 'moved_on', and the reason on the entry.
        const moved = parseAuto({
            state: 'connected',
            mode: true,
            route_id: 'r1',
            verdict: 'moved_on',
            tried: [
                { route_id: 'r4', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', refined: 'udp_blocked_here' },
                { route_id: 'r1', family: 'vless-reality', result: 'carried', category: '', refined: '' },
            ],
        });
        expect(moved?.tried[0].refined).toBe('udp_blocked_here');
        expect(moved?.tried[1]).toEqual({ routeId: 'r1', family: 'vless-reality', result: 'carried', category: '' });
        expect(autoConnectedNoteKey(moved)).toBe('auto.note.udp_blocked_here');
        // A dead server beside it is not "this network blocks some ways".
        const dead = parseAuto({
            state: 'connected',
            mode: true,
            route_id: 'r1',
            verdict: 'moved_on',
            tried: [{ route_id: 'r4', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', refined: 'relay_unreachable' }],
        });
        expect(autoConnectedNoteKey(dead)).toBe('auto.note.moved_on');
        // A route connected by hand says nothing about automatic.
        expect(autoConnectedNoteKey(auto({ state: 'connected', mode: false, verdict: 'moved_on' }))).toBeUndefined();
        expect(EN['auto.note.moved_on']).toBe('Connected. The first way did not work here, so Daal used another.');
        for (const k of ['auto.note.moved_on', 'auto.note.udp_blocked_here']) {
            expect(FA[k]).toMatch(/[؀-ۿ]/);
            expect(EN[k]).not.toMatch(PROTOCOL);
            expect(FA[k]).not.toMatch(PROTOCOL);
        }
    });
    it('every result of a tried route has our words; an unknown one too', () => {
        for (const r of ['carried', 'not_carrying', 'start_failed', 'refused', 'cancelled', 'stopped']) {
            expect(EN[autoResultKey(r)]).toBeTruthy();
            expect(FA[autoResultKey(r)]).toBeTruthy();
        }
        // A check that was stopped because another route answered first
        // (the engine's racing) has its own words, not "no result".
        expect(autoResultKey('stopped')).toBe('auto.result.stopped');
        expect(autoResultKey('exploded')).toBe('auto.result.other');
        expect(EN['auto.result.other']).toBeTruthy();
    });
});

describe('autoFailure: is a failed automatic connect the latest news?', () => {
    const base: ConnectionSummary = { state: 'error', mode: 'normal' };
    const tried = [{ routeId: 'r1', family: 'naive', result: 'start_failed', category: 'tcp_connect_timeout' }];
    it("takes the engine's block first", () => {
        expect(autoFailure({ ...base, auto: auto({ state: 'failed', verdict: 'relay_unreachable', tried }) })).toEqual({
            verdict: 'relay_unreachable',
            tried,
        });
    });
    it("falls back to the Android service's note only where the engine cannot speak for itself", () => {
        // A library with no automatic connect: no block at all.
        expect(autoFailure({ ...base, state: 'disconnected', autoFailedNote: 'auto_unavailable' })).toEqual({
            verdict: 'auto_unavailable',
            tried: [],
        });
        expect(autoFailure({ ...base, state: 'disconnected', autoFailedNote: 'all_failed' })).toEqual({
            verdict: 'all_failed',
            tried: [],
        });
        // The engine has a block but could not be asked this time.
        expect(
            autoFailure({ ...base, state: 'disconnected', autoFailedNote: 'auto_unavailable', auto: auto({ state: 'idle' }) }),
        ).toEqual({ verdict: 'auto_unavailable', tried: [] });
    });
    it("the service's note does not outlive the engine's own verdict", () => {
        // The cooldowns ran out; the engine dropped its verdict (idle).
        // The service still holds the note it wrote when the pass
        // failed — it is cleared only by the next start or stop.
        const later: ConnectionSummary = {
            ...base,
            state: 'disconnected',
            autoFailedNote: 'all_cooling_down',
            auto: auto({ state: 'idle' }),
        };
        expect(autoFailure(later)).toBeUndefined();
    });
    it('says nothing while something is connected or being tried', () => {
        const failed = auto({ state: 'failed', verdict: 'all_failed' });
        expect(autoFailure({ ...base, state: 'connected', auto: failed })).toBeUndefined();
        expect(autoFailure({ ...base, state: 'connecting', auto: failed })).toBeUndefined();
        expect(autoFailure({ ...base, state: 'connecting', autoFailedNote: 'network_down', auto: auto({ state: 'trying', mode: true }) })).toBeUndefined();
        expect(autoFailure({ ...base })).toBeUndefined();
        expect(autoFailure(null)).toBeUndefined();
    });
});

describe('autoIsUsing: which row the Connections page marks', () => {
    it('only the route automatic connect has up, in automatic mode', () => {
        const up = auto({ state: 'connected', mode: true, routeId: 'r2' });
        expect(autoIsUsing(up, 'r2')).toBe(true);
        expect(autoIsUsing(up, 'r1')).toBe(false);
        expect(autoIsUsing(auto({ state: 'connected', mode: false, routeId: 'r2' }), 'r2')).toBe(false);
        expect(autoIsUsing(undefined, 'r2')).toBe(false);
        expect(autoIsUsing(up, null)).toBe(false);
    });
});

// ---- review of the selection wave (2026-11-19) -------------------------

import {
    allResting,
    failureSignature,
    failureToShow,
    forgetPinnedRoute,
    isHolding,
    parseHolding,
    rememberPassFailure,
    restText,
    staleFailureAfterStart,
    verdictWantsChooser,
} from './autoConnect';

describe('none_usable: routes exist and Daal may not choose any of them by itself', () => {
    it('has its own sentence and action in both languages, not the generic "Try again"', () => {
        expect(FAILURE_VERDICTS).toContain('none_usable');
        expect(autoVerdictKey('none_usable')).toBe('auto.verdict.none_usable');
        for (const d of [EN, FA]) {
            expect(d['auto.verdict.none_usable']).toBeTruthy();
            expect(d['auto.verdict.none_usable.do']).toBeTruthy();
            expect(d['auto.choose_yourself']).toBeTruthy();
        }
        expect(EN['auto.verdict.none_usable.do']).toBe('You can choose one yourself.');
        expect(verdictWantsChooser('none_usable')).toBe(true);
        expect(verdictWantsChooser('all_failed')).toBe(false);
    });
});

describe('after a pass that failed: the rest', () => {
    const now = 1_000_000;
    const resting = (id: string, min: number) => route(id, { inCooldown: true, cooldownUntilUnixMs: now + min * 60_000 });
    const passed = { verdict: 'all_failed', tried: [{ routeId: 'r1', family: 'naive', result: 'not_carrying', category: 'tcp_reset' }] };
    const cooling = { verdict: 'all_cooling_down', tried: [] };

    it('"the ways are resting" never replaces the sentence of the pass that tried', () => {
        const rows = [resting('r1', 28), resting('r2', 4)];
        const v = failureToShow(cooling, passed, rows, now);
        expect(v.verdict).toBe('all_failed');
        expect(v.tried).toEqual(passed.tried);
        expect(v.resting).toBe(true);
        expect(v.waitMinutes).toBe(4);
        // The button could do nothing: off, and the wait is said.
        expect(v.retryOff).toBe(true);
        expect(restText(tr(EN), 'en', v)).toBe('You can try again in about 4 min.');
        expect(restText(tr(FA), 'fa', v)).toContain('۴');
    });
    it('right after the pass, before any press: every way resting already switches Try again off', () => {
        const v = failureToShow(passed, undefined, [resting('r1', 28), resting('r2', 30)], now);
        expect(v.verdict).toBe('all_failed');
        expect(v.retryOff).toBe(true);
        expect(v.waitMinutes).toBe(28);
        // One way not resting: a press can do something.
        const some = failureToShow(passed, undefined, [resting('r1', 28), route('r2')], now);
        expect(some.resting).toBe(false);
        expect(some.retryOff).toBe(false);
        expect(restText(tr(EN), 'en', some)).toBeUndefined();
    });
    it('when the list cannot say how long, Try again stays on and the wait is said without a number', () => {
        const v = failureToShow(cooling, passed, undefined, now);
        expect(v.resting).toBe(true);
        expect(v.retryOff).toBe(false);
        expect(restText(tr(EN), 'en', v)).toBe('You can try again in a few minutes.');
        // Nothing remembered: the engine's own sentence is all there is.
        expect(failureToShow(cooling, undefined, undefined, now).verdict).toBe('all_cooling_down');
        expect(allResting([], now)).toBe(false);
        expect(allResting(undefined, now)).toBe(false);
    });
    it('remembers the last pass that tried something, until something connects', () => {
        const s = (over: Partial<ConnectionSummary>): ConnectionSummary => ({ state: 'error', mode: 'normal', ...over });
        let mem = rememberPassFailure(undefined, s({ auto: auto({ state: 'failed', verdict: 'all_failed', tried: passed.tried }) }));
        expect(mem).toEqual(passed);
        // "Resting" is the engine not trying: it is not a new failure.
        mem = rememberPassFailure(mem, s({ auto: auto({ state: 'failed', verdict: 'all_cooling_down' }) }));
        expect(mem).toEqual(passed);
        mem = rememberPassFailure(mem, s({ state: 'connecting', auto: auto({ state: 'trying', mode: true }) }));
        expect(mem).toEqual(passed);
        expect(rememberPassFailure(mem, s({ state: 'connected', auto: auto({ state: 'connected', mode: true }) }))).toBeUndefined();
        expect(rememberPassFailure(mem, s({ state: 'disconnected', auto: auto({ state: 'idle' }) }))).toBeUndefined();
        expect(rememberPassFailure(mem, null)).toEqual(passed);
    });
});

describe('Android: "Try again" does not flash the failure it is replacing', () => {
    const failed = (verdict: string): ConnectionSummary => ({
        state: 'error',
        mode: 'normal',
        auto: auto({ state: 'failed', verdict, tried: [{ routeId: 'r1', family: 'naive', result: 'not_carrying', category: 'tcp_reset' }] }),
    });
    it('the same failed block right after the start call is the OLD one', () => {
        const before = failureSignature(failed('all_failed'));
        expect(before).toBeTruthy();
        // Android: the call resolved ("service started"), handing nothing back.
        expect(staleFailureAfterStart(false, before, failed('all_failed'))).toBe(true);
        // A different block is the new pass's answer.
        expect(staleFailureAfterStart(false, before, failed('relay_unreachable'))).toBe(false);
        // The engine has begun: not stale.
        expect(staleFailureAfterStart(false, before, { state: 'connecting', mode: 'normal', auto: auto({ state: 'trying', mode: true }) })).toBe(false);
    });
    it('where the host hands back the result (desktop), the block is the new pass even when identical', () => {
        const before = failureSignature(failed('all_failed'));
        expect(staleFailureAfterStart(true, before, failed('all_failed'))).toBe(false);
        // No failure was on screen at the tap: nothing can be stale.
        expect(staleFailureAfterStart(false, undefined, failed('all_failed'))).toBe(false);
    });
});

describe('Android: the service holding the VPN closed', () => {
    it('reads vpn_status.holding strictly', () => {
        expect(parseHolding({ connected: false, auto: true, holding: true })).toBe(true);
        expect(parseHolding({ connected: false, auto: true })).toBe(false);
        expect(parseHolding({ holding: 'yes' })).toBe(false);
        expect(parseHolding(null)).toBe(false);
    });
    it('is the news only while nothing is connected and the engine is not mid-pass', () => {
        const s = (over: Partial<ConnectionSummary>): ConnectionSummary => ({ state: 'error', mode: 'normal', holding: true, ...over });
        expect(isHolding(s({ auto: auto({ state: 'failed', mode: true, verdict: 'all_failed' }) }))).toBe(true);
        expect(isHolding(s({ state: 'connecting', auto: auto({ state: 'trying', mode: true }) }))).toBe(false);
        expect(isHolding(s({ state: 'connected' }))).toBe(false);
        expect(isHolding(s({ holding: false }))).toBe(false);
        expect(isHolding(null)).toBe(false);
    });
});

describe('a deleted route takes its pin with it', () => {
    const store = new Map<string, string>();
    beforeEach(() => {
        store.clear();
        vi.stubGlobal('localStorage', {
            getItem: (k: string) => store.get(k) ?? null,
            setItem: (k: string, v: string) => void store.set(k, v),
            removeItem: (k: string) => void store.delete(k),
        });
    });
    afterEach(() => vi.unstubAllGlobals());
    it('forgets the pin on that route and no other', () => {
        setPinnedRoute('r3');
        forgetPinnedRoute('r1');
        expect(getPinnedRoute()).toBe('r3');
        forgetPinnedRoute('r3');
        expect(getPinnedRoute()).toBeNull();
        expect(store.size).toBe(0);
    });
});
