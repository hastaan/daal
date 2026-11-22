// The measuring wave, as the pages read it: the per-route `measured`
// block, the grade in plain words, the one line about quality under
// "You're connected.", two ways tried at once, a move for speed, the
// Connections page line that follows the engine (AC-24), the engine's
// own record of a switch that went back (AC-23), and who may tell the
// engine about the network.
import { describe, expect, it } from 'vitest';
import type { AutoStatus, ConnectionSummary, Measured, RouteDisplayRow } from '../contract/D2Contract';
import {
    anyMeasured,
    chipHereText,
    chipScoreText,
    connectedQualityKey,
    familyHere,
    gradeKey,
    measuredCode,
    measuredWords,
    parseMeasured,
    rowForThisNetwork,
    rowGradeSuffix,
} from './measured';
import {
    autoConnectedNoteKey,
    autoProgressText,
    autoRacing,
    autoVerdictKey,
    parseAuto,
    parseAutoResult,
} from './autoConnect';
import { mainScreenView, type MainScreenInput } from './mainScreen';
import { connectionsModeLine, modeLineTexts, pendingFailureKey, pendingOutcomeNow, rowMetaText, rowStateLabelKey } from './networkRows';
import { parseSwitchBack, type ConnectionSummaryPlus } from './activeRoute';
import { gradesAreForThisNetwork, parseHostNetwork, webviewMayReportNetwork } from './networkFacts';
import { buildPublisherTree } from '../contract/derive_tree';
import networkPageSource from '../d2pages/NetworkPage.tsx?raw';
import connectionPageSource from '../d2pages/ConnectionPage.tsx?raw';
import legacyEn from '../i18n/en.json';
import legacyFa from '../i18n/fa.json';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const EN = { ...(legacyEn as object), ...(en as object) } as Record<string, string>;
const FA = { ...(legacyFa as object), ...(fa as object) } as Record<string, string>;
const t = (k: string) => EN[k] ?? k;
const tFa = (k: string) => FA[k] ?? k;

const m = (grade: Measured['grade'], over: Partial<Measured> = {}): Measured => ({
    grade,
    samples: 0,
    carried: 0,
    failed: 0,
    ...over,
});
const way = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: id,
    trustClass: 'trusted',
    family: 'vless-reality',
    ...over,
});
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
const conn = (over: Partial<ConnectionSummaryPlus>): ConnectionSummary =>
    ({ state: 'disconnected', mode: 'normal', ...over }) as ConnectionSummary;

/** Words that must never reach a sentence on the main path. */
const ENGINE_WORDS = /vless|reality|hysteria|tuic|trojan|websocket|naive|shadowsocks|wireguard|\btcp\b|\budp\b|\bms\b|_/i;

describe('parseMeasured: the engine\'s block', () => {
    it('reads the contract fields', () => {
        expect(
            parseMeasured({ grade: 'good', setup_ms: 318.6, samples: 9, carried: 8, failed: 1, last: '2026-11-19T10' }),
        ).toEqual({ grade: 'good', setupMs: 318, samples: 9, carried: 8, failed: 1, last: '2026-11-19T10' });
    });
    it('a route never tried here has a grade and no time', () => {
        expect(parseMeasured({ grade: 'unknown', setup_ms: 0, samples: 0, carried: 0, failed: 0, last: '' })).toEqual({
            grade: 'unknown',
            samples: 0,
            carried: 0,
            failed: 0,
        });
    });
    it('no block, or a grade this app does not know, is "the engine said nothing" — never a guess', () => {
        expect(parseMeasured(undefined)).toBeUndefined();
        expect(parseMeasured(null)).toBeUndefined();
        expect(parseMeasured('good')).toBeUndefined();
        expect(parseMeasured({ grade: 'excellent', samples: 3 })).toBeUndefined();
        expect(parseMeasured({ samples: 3 })).toBeUndefined();
    });
    it('nonsense numbers are zero, and a `last` that is not a time bucket is dropped', () => {
        const r = parseMeasured({ grade: 'ok', setup_ms: -5, samples: 'many', carried: NaN, failed: 2, last: '<b>x</b>' });
        expect(r).toEqual({ grade: 'ok', samples: 0, carried: 0, failed: 2 });
        // The engine sends Unix seconds (the start of an hour). Raw, that
        // is a ten-digit number with no label in the Details line.
        expect(parseMeasured({ grade: 'ok', last: 1795082400 })?.last).toBe('2026-11-19 10h UTC');
        expect(measuredCode('r1', 'vless-reality', parseMeasured({ grade: 'good', setup_ms: 320, samples: 9, carried: 9, failed: 0, last: 1795082400 }))).toBe(
            'r1 · vless-reality · good · 320 ms · n=9 · ok=9 · fail=0 · 2026-11-19 10h UTC',
        );
        // Not a time this app can have seen: dropped, not printed.
        expect(parseMeasured({ grade: 'ok', last: 12 })?.last).toBeUndefined();
        expect(parseMeasured({ grade: 'ok', last: 1795082400000 })?.last).toBeUndefined();
    });
});

describe('the grade in plain words', () => {
    it('each grade has its phrase; "unknown" is "Not tried here yet"', () => {
        expect(t(gradeKey(m('good'))!)).toBe('Works well here');
        expect(t(gradeKey(m('ok'))!)).toBe('Works here');
        expect(t(gradeKey(m('slow'))!)).toBe('Slow here');
        expect(t(gradeKey(m('failing'))!)).toBe('Did not work here last time');
        expect(t(gradeKey(m('unknown'))!)).toBe('Not tried here yet');
    });
    it('nothing is said when the engine said nothing', () => {
        expect(gradeKey(undefined)).toBeUndefined();
    });
    it('the phrases carry no number, no code and no kind of connection, in either language', () => {
        const keys = Object.keys(EN).filter((k) => /^measure\.(grade|connected)\./.test(k));
        expect(keys.length).toBe(9);
        for (const k of keys) {
            expect(EN[k], k).not.toMatch(/[0-9]/);
            expect(EN[k], k).not.toMatch(ENGINE_WORDS);
            expect(FA[k], k).not.toMatch(/[0-9۰-۹]/);
            expect(FA[k], k).not.toMatch(/[A-Za-z_]/);
        }
    });
});

describe('the one line about quality under "You\'re connected."', () => {
    const up = (over: Partial<ConnectionSummary>) => conn({ state: 'connected', routeCheck: 'ok', ...over });
    it('good: "Works well here."', () => {
        expect(connectedQualityKey(up({ activeRoute: way('r1', { measured: m('good') }) }))).toBe('measure.connected.good');
    });
    it('"works", never tried, failed before, or nothing measured: no line — connected is connected', () => {
        for (const g of ['ok', 'unknown', 'failing'] as const) {
            expect(connectedQualityKey(up({ activeRoute: way('r1', { measured: m(g) }) })), g).toBeUndefined();
        }
        expect(connectedQualityKey(up({ activeRoute: way('r1') }))).toBeUndefined();
    });
    const inCharge = auto({ state: 'connected', mode: true, routeId: 'r1' });
    it('slow NOW in automatic mode, with another way to go to: promises the switch; on a way picked by hand it does not', () => {
        const slow = way('r1', { measured: m('slow') });
        expect(connectedQualityKey(up({ routeCheck: 'degraded', activeRoute: slow, auto: inCharge }), true)).toBe('measure.connected.slow_auto');
        expect(connectedQualityKey(up({ routeCheck: 'degraded', activeRoute: slow, auto: auto({}) }), true)).toBe('measure.connected.slow_own');
        expect(connectedQualityKey(up({ activeRoute: slow }), true)).toBe('measure.connected.slow_own');
        expect(t('measure.connected.slow_auto')).toContain('will switch');
        expect(t('measure.connected.slow_own')).not.toContain('switch');
        expect(t('measure.connected.slow')).toBe('Slow here.');
        expect(tFa('measure.connected.slow')).not.toBe(t('measure.connected.slow'));
    });
    it('no promise where the engine will not look for a faster way', () => {
        const slow = way('r1', { measured: m('slow') });
        const degraded = (over: Partial<ConnectionSummary> = {}) => up({ routeCheck: 'degraded', activeRoute: slow, auto: inCharge, ...over });
        // On a network the host calls metered the engine starts no probe by itself.
        expect(connectedQualityKey(degraded({ network: { fromHost: true, kind: 'cellular', validated: 1, metered: 1 } }), true)).toBe('measure.connected.slow');
        expect(connectedQualityKey(degraded({ network: { fromHost: true, kind: 'wifi', validated: 1, metered: 0 } }), true)).toBe('measure.connected.slow_auto');
        expect(connectedQualityKey(degraded({ network: { fromHost: true, kind: 'wifi', validated: 1, metered: -1 } }), true)).toBe('measure.connected.slow_auto');
        // One way in the file, or the list not known: nothing to move to.
        expect(connectedQualityKey(degraded(), false)).toBe('measure.connected.slow');
        expect(connectedQualityKey(degraded())).toBe('measure.connected.slow');
        // Graded slow from old samples while the check says fine NOW: the
        // engine starts nothing on a grade.
        expect(connectedQualityKey(up({ routeCheck: 'ok', activeRoute: slow, auto: inCharge }), true)).toBe('measure.connected.slow');
    });
    it('the engine\'s own "slow" check counts even for a route graded good', () => {
        expect(
            connectedQualityKey(
                up({
                    routeCheck: 'degraded',
                    activeRoute: way('r1', { measured: m('good') }),
                    auto: auto({ state: 'connected', mode: true, routeId: 'r1' }),
                }),
                true,
            ),
        ).toBe('measure.connected.slow_auto');
    });
    it('nothing while not connected', () => {
        expect(connectedQualityKey(conn({ state: 'connecting', activeRoute: way('r1', { measured: m('good') }) }))).toBeUndefined();
        expect(connectedQualityKey(null)).toBeUndefined();
    });
});

describe('two ways tried at once', () => {
    const racing = parseAuto({ state: 'trying', mode: true, trying: 'r2', racing: ['r2', 'r4'], index: 2, total: 4, tried: [] });
    it('`racing` is read; "trying" stays the first of the pair', () => {
        expect(racing?.racing).toEqual(['r2', 'r4']);
        expect(racing?.trying).toBe('r2');
        expect(autoRacing(racing)).toBe(true);
    });
    it('one id, the same id twice, or junk is not a race; more than two is never repeated', () => {
        const p = (r: unknown) => parseAuto({ state: 'trying', mode: true, trying: 'r2', racing: r, index: 2, total: 4 });
        expect(p(['r2'])?.racing).toEqual([]);
        expect(p(['r2', 'r2'])?.racing).toEqual([]);
        expect(p('r2,r4')?.racing).toEqual([]);
        expect(p([1, null, 'r2'])?.racing).toEqual([]);
        expect(p(undefined)?.racing).toEqual([]);
        expect(p(['r1', 'r2', 'r3'])?.racing).toEqual(['r1', 'r2']);
        expect(autoRacing(p(['r2']))).toBe(false);
    });
    it('is ONE sentence, with no "way 2 of 4", no id and no kind of connection', () => {
        expect(autoProgressText(t, 'en', racing)).toBe('Trying two ways at once…');
        expect(autoProgressText(tFa, 'fa', racing)).toBe(FA['auto.trying_two']);
        expect(autoProgressText(t, 'en', racing)).not.toMatch(/[0-9]|r2|r4/);
        expect(EN['auto.trying_two']).not.toMatch(ENGINE_WORDS);
        // One at a time is said as before.
        expect(autoProgressText(t, 'en', { ...racing!, racing: [] })).toBe('Trying way 2 of 4…');
    });
    it('a block left over from a race does not make a finished pass "racing"', () => {
        expect(autoRacing(auto({ state: 'connected', mode: true, racing: ['r2', 'r4'] }))).toBe(false);
    });
    it('tried[] carries this attempt\'s time and what it was tried with — in the block and in the returned body', () => {
        const tried = [
            { route_id: 'r2', family: 'vless-reality', result: 'carried', category: '', setup_ms: 412.4, raced_with: 'r4' },
            { route_id: 'r4', family: 'hysteria2', result: 'cancelled', category: '', setup_ms: 0, raced_with: 'r2' },
            { route_id: 'r1', family: 'tuic', result: 'not_carrying', category: 'udp_no_reply', raced_with: '' },
        ];
        const want = [
            { routeId: 'r2', family: 'vless-reality', result: 'carried', category: '', setupMs: 412, racedWith: 'r4' },
            { routeId: 'r4', family: 'hysteria2', result: 'cancelled', category: '', racedWith: 'r2' },
            { routeId: 'r1', family: 'tuic', result: 'not_carrying', category: 'udp_no_reply' },
        ];
        expect(parseAuto({ state: 'connected', mode: true, tried })?.tried).toEqual(want);
        expect(parseAutoResult({ connected: true, route_id: 'r2', tried })?.tried).toEqual(want);
    });
});

describe('a move for speed, and the phone being offline', () => {
    it('"moved_faster" has its own short note', () => {
        const a = auto({ state: 'connected', mode: true, routeId: 'r2', verdict: 'moved_faster' });
        expect(autoConnectedNoteKey(a)).toBe('auto.note.moved_faster');
        expect(t('auto.note.moved_faster')).toBe('Daal moved to a faster way.');
        expect(tFa('auto.note.moved_faster')).toMatch(/[؀-ۿ]/);
        // Not in manual mode, and not once the pass is no longer "connected".
        expect(autoConnectedNoteKey({ ...a, mode: false })).toBeUndefined();
    });
    it('"network_down" says the phone has no internet, and what to check', () => {
        expect(t(autoVerdictKey('network_down'))).toBe('This phone has no internet right now.');
        expect(t('auto.verdict.network_down.do')).toContain('Wi-Fi');
    });
});

describe('mainScreenView: one line under the headline', () => {
    const input = (c: ConnectionSummary, routes: RouteDisplayRow[]): MainScreenInput => ({
        t,
        locale: 'en',
        nowMs: 1_000_000,
        conn: c,
        optimistic: null,
        connectInFlight: false,
        intent: null,
        hostFailed: false,
        pinnedRaw: null,
        routes,
        wasConnected: false,
        remembered: undefined,
    });
    const good = way('r1', { measured: m('good', { setupMs: 300, samples: 4, carried: 4 }) });
    const slow = way('r2', { measured: m('slow', { setupMs: 2900, samples: 4, carried: 4 }) });
    it('connected on a way that works well here: "Works well here."', () => {
        const v = mainScreenView(
            input(conn({ state: 'connected', routeCheck: 'ok', activeRoute: good, auto: auto({ state: 'connected', mode: true, routeId: 'r1' }) }), [good, slow]),
        );
        expect(v.headline).toBe('Connected');
        // How the way does here is for the person helping (developer fold).
        expect(t(v.connectedNoteKey!)).toBe('Works well here.');
    });
    it('news about a move comes first: there is still only ONE line', () => {
        const moved = mainScreenView(
            input(
                conn({
                    state: 'connected',
                    routeCheck: 'ok',
                    activeRoute: good,
                    auto: auto({ state: 'connected', mode: true, routeId: 'r1', verdict: 'moved_faster' }),
                }),
                [good, slow],
            ),
        );
        expect(moved.connectedNoteKey).toBe('auto.note.moved_faster');
    });
    it('…but not over a connection that is slow NOW: the move is old news, and the line says it is slow', () => {
        const movedThenSlow = conn({
            state: 'connected',
            routeCheck: 'degraded',
            activeRoute: good,
            auto: auto({ state: 'connected', mode: true, routeId: 'r1', verdict: 'moved_faster' }),
        });
        expect(autoConnectedNoteKey(movedThenSlow.auto)).toBe('auto.note.moved_faster');
        const v = mainScreenView(input(movedThenSlow, [good, slow]));
        expect(v.detail).toBe('Connected, but slow.');
        expect(v.headline).toBe('Connected');
        expect(v.slow).toBe(true);
        expect(v.connectedNoteKey).toBe('measure.connected.slow_auto');
        // With one way only there is no promise either.
        expect(mainScreenView(input(movedThenSlow, [good])).connectedNoteKey).toBe('measure.connected.slow');
    });
    it('slow: the headline says so and the line says what Daal will do', () => {
        const v = mainScreenView(
            input(
                conn({ state: 'connected', routeCheck: 'degraded', activeRoute: slow, auto: auto({ state: 'connected', mode: true, routeId: 'r2' }) }),
                [good, slow],
            ),
        );
        expect(v.detail).toBe('Connected, but slow.');
        expect(v.slow).toBe(true);
        expect(t(v.connectedNoteKey!)).toBe('Slow here. Daal will switch if it finds a faster way.');
    });
    it('while two ways are tried at once the headline is that one sentence, and the tap is Cancel', () => {
        const v = mainScreenView(
            input(
                conn({
                    state: 'connecting',
                    routeRunning: true,
                    routeCheck: 'verifying',
                    activeRoute: good,
                    auto: auto({ state: 'trying', mode: true, trying: 'r1', racing: ['r1', 'r2'], index: 1, total: 2 }),
                }),
                [good, slow],
            ),
        );
        expect(v.detail).toBe('Trying two ways at once…');
        expect(v.headline).toBe('Connecting…');
        expect(v.plan.kind).toBe('disconnect');
        expect(v.connectedNoteKey).toBeUndefined();
    });
    it('the phone has no internet: that sentence, what to check, and "Try again"', () => {
        const v = mainScreenView(
            input(conn({ state: 'error', routeRunning: false, auto: auto({ state: 'failed', verdict: 'network_down', total: 2 }) }), [good, slow]),
        );
        expect(v.detail).toBe('This phone has no internet right now.');
        expect(v.headline).toBe('No internet');
        expect(v.line).toBe('Check Wi-Fi or mobile data.');
        expect(v.failure?.actionText).toBe('Check your Wi-Fi or mobile data, then try again.');
        expect(v.failure?.noRetry).toBe(false);
        expect(v.failure?.retryOff).toBe(false);
    });
});

describe('Details: the numbers, for the person helping', () => {
    const full = m('slow', { setupMs: 2900, samples: 4, carried: 3, failed: 1, last: '2026-11-18T21' });
    it('our words', () => {
        expect(measuredWords(t, 'en', full)).toBe('connects in about 2900 ms · tried 4, worked 3, failed 1');
        expect(measuredWords(t, 'en', m('unknown'))).toBe('');
        expect(measuredWords(t, 'en', m('failing', { samples: 2, failed: 2 }))).toBe('tried 2, worked 0, failed 2');
        expect(measuredWords(tFa, 'fa', full)).toContain('۲۹۰۰');
        expect(measuredWords(tFa, 'fa', full)).not.toMatch(/[0-9]/);
    });
    it('the engine\'s words, in one line', () => {
        expect(measuredCode('r2', 'websocket-tls', full)).toBe('r2 · websocket-tls · slow · 2900 ms · n=4 · ok=3 · fail=1 · 2026-11-18T21');
        expect(measuredCode('r4', 'trojan', m('unknown'))).toBe('r4 · trojan · unknown · n=0 · ok=0 · fail=0');
        expect(measuredCode('r4', 'trojan', undefined)).toBe('r4 · trojan');
    });
    it('offered only when some route was measured', () => {
        expect(anyMeasured(undefined)).toBe(false);
        expect(anyMeasured([way('r1')])).toBe(false);
        expect(anyMeasured([way('r1'), way('r2', { measured: m('unknown') })])).toBe(true);
    });
});

describe('family chips on the Connections page', () => {
    const routes = [
        way('a', { family: 'vless-reality', measured: m('good'), healthPct: 80 }),
        way('b', { family: 'vless-reality', measured: m('failing'), healthPct: 40 }),
        way('c', { family: 'vless-reality', measured: m('unknown') }),
        way('d', { family: 'hysteria2', measured: m('unknown') }),
        way('e', { family: 'trojan' }),
    ];
    it('count the routes tried here and those that worked — a count, not a percentage', () => {
        expect(familyHere(routes.slice(0, 3))).toEqual({ worked: 1, tried: 2 });
        expect(familyHere([routes[3]])).toEqual({ worked: 0, tried: 0 });
        expect(familyHere([routes[4]])).toBeUndefined();
        expect(chipHereText(t, 'en', { worked: 1, tried: 2 })).toBe('1 of 2 tried worked here');
        expect(chipHereText(tFa, 'fa', { worked: 1, tried: 2 })).toBe('از ۲ راهِ امتحان‌شده، ۱ راه اینجا کار کرد');
        expect(chipHereText(t, 'en', { worked: 0, tried: 0 })).toBe('Not tried here yet');
        expect(chipHereText(t, 'en', undefined)).toBeUndefined();
    });
    it('reach the chip through the tree', () => {
        const chips = buildPublisherTree(routes, [], [], () => '')[0].cells[0].families;
        const by = (f: string) => chips.find((c) => c.family === f)!;
        expect(by('vless-reality').here).toEqual({ worked: 1, tried: 2 });
        expect(by('hysteria2').here).toEqual({ worked: 0, tried: 0 });
        expect(by('trojan').here).toBeUndefined();
    });
    it('the old percentage is said as what it is: a score, not a success rate', () => {
        expect(chipScoreText(t, 'en', 60)).toBe(
            'Score 60 out of 100. It goes down after failures in a row and while a way is resting. It is not a success rate.',
        );
        expect(chipScoreText(t, 'en', 60)).not.toContain('%');
        expect(chipScoreText(t, 'en', undefined)).toBeUndefined();
    });
});

describe('AC-24: the line above the list follows the engine, not the saved choice', () => {
    const up = (id: string, a?: AutoStatus) => conn({ state: 'connected', routeRunning: true, activeRoute: way(id), auto: a });
    const autoUp = (id: string) => auto({ state: 'connected', mode: true, routeId: id });
    it('a way saved earlier, Daal connected automatically on another: "Daal is choosing", and the saved choice is about next time', () => {
        const line = connectionsModeLine('r1', up('r3', autoUp('r3')));
        expect(line).toEqual({ lineKey: 'network.auto.line', nextKey: 'network.pinned.next' });
        expect(t(line.lineKey)).toBe('Daal is choosing the way to connect automatically.');
        expect(t(line.nextKey!)).toContain('next time');
    });
    it('also while Daal is still trying', () => {
        expect(
            connectionsModeLine('r1', conn({ state: 'connecting', auto: auto({ state: 'trying', mode: true, trying: 'r2' }) })).lineKey,
        ).toBe('network.auto.line');
    });
    it('automatic and nothing saved: one line', () => {
        expect(connectionsModeLine(null, up('r3', autoUp('r3')))).toEqual({ lineKey: 'network.auto.line' });
    });
    it('connected by hand on the saved way: "You chose one way yourself"', () => {
        expect(connectionsModeLine('r1', up('r1', auto({})))).toEqual({ lineKey: 'network.pinned.line' });
        // An engine with no `auto` block connects only by hand.
        expect(connectionsModeLine('r1', up('r1'))).toEqual({ lineKey: 'network.pinned.line' });
    });
    it('connected by hand, and the saved choice says otherwise: what is true now, then next time', () => {
        expect(connectionsModeLine(null, up('r2', auto({})))).toEqual({
            lineKey: 'network.pinned.now',
            nextKey: 'network.auto.next',
        });
        expect(connectionsModeLine('r1', up('r2', auto({})))).toEqual({
            lineKey: 'network.pinned.now',
            nextKey: 'network.pinned.next',
        });
    });
    it('nothing running: the saved choice is the whole truth', () => {
        expect(connectionsModeLine('r1', conn({}))).toEqual({ lineKey: 'network.pinned.line' });
        expect(connectionsModeLine(null, conn({}))).toEqual({ lineKey: 'network.auto.line' });
        expect(connectionsModeLine('r1', null)).toEqual({ lineKey: 'network.pinned.line' });
        // A failed automatic pass is not "Daal is choosing".
        expect(connectionsModeLine('r1', conn({ state: 'error', auto: auto({ state: 'failed', mode: false }) }))).toEqual({
            lineKey: 'network.pinned.line',
        });
    });
});

describe('AC-23: the engine\'s own record of a switch that went back', () => {
    const back = { failed_route: 'r2', failed_family: 'hysteria2', category: 'udp_no_reply', restored_route: 'r1', restored: true };
    it('is read into the same note the Android service leaves', () => {
        expect(parseSwitchBack(back)).toEqual({ routeId: 'r2', keptRouteId: 'r1', outcome: 'failed', reason: 'udp_no_reply' });
    });
    it('a way back that did not carry names no kept route', () => {
        expect(parseSwitchBack({ ...back, restored: false })?.keptRouteId).toBeUndefined();
    });
    it('nothing to report is nothing', () => {
        expect(parseSwitchBack({ ...back, failed_route: '' })).toBeUndefined();
        expect(parseSwitchBack(undefined)).toBeUndefined();
        expect(parseSwitchBack('r2')).toBeUndefined();
    });
    it('gives the tapped row its answer and its sentence while the old route is connected again', () => {
        const s = conn({ state: 'connected', routeCheck: 'ok', activeRoute: way('r1'), lastSwitch: parseSwitchBack(back) });
        expect(pendingOutcomeNow('r2', s)).toBe('failed');
        expect(pendingFailureKey('r2', 'failed', s)).toBe('network.switch_failed_kept');
        // Without the record the blob has no trace of the failed switch.
        const bare = conn({ state: 'connected', routeCheck: 'ok', activeRoute: way('r1') });
        expect(pendingOutcomeNow('r2', bare)).toBe('waiting');
        expect(pendingFailureKey('r2', 'failed', bare)).toBeUndefined();
    });
});

describe('who tells the engine about the network', () => {
    it('desktop: the webview does', () => {
        expect(webviewMayReportNetwork({ android: false, vpnStatus: null })).toBe(true);
    });
    it('Android, service not running: the webview does', () => {
        expect(webviewMayReportNetwork({ android: true, vpnStatus: { connected: false, holding: false, platform: 'android' } })).toBe(true);
    });
    it('Android, service up (connected, holding, or saying it runs): the webview stays silent', () => {
        expect(webviewMayReportNetwork({ android: true, vpnStatus: { connected: true } })).toBe(false);
        expect(webviewMayReportNetwork({ android: true, vpnStatus: { connected: false, holding: true } })).toBe(false);
        expect(webviewMayReportNetwork({ android: true, vpnStatus: { connected: false, running: true } })).toBe(false);
    });
    it('Android, status unreadable: silent — a poor fact must not replace a rich one', () => {
        expect(webviewMayReportNetwork({ android: true, vpnStatus: null })).toBe(false);
        expect(webviewMayReportNetwork({ android: true, vpnStatus: 'up' })).toBe(false);
    });
});

// The pages themselves are not rendered in a test (no DOM in this
// repo), so — like connectThreading.test.ts pins the hosts — the
// drawing is pinned on its source: the decisions above are the ones
// the pages actually call, and the old claims are gone.
describe('the pages use these decisions', () => {
    const code = (src: string) =>
        src
            .split('\n')
            .filter((l) => !/^\s*(\/\/|\*|\/\*|\{\/\*)/.test(l))
            .join('\n');
    const network = code(networkPageSource);
    const connection = code(connectionPageSource);
    it('Files page: the developer line of a way says the grade, chips the count; no percentage and no "not measured yet"', () => {
        // The way's engine line (developer mode) is ONE call, for the way
        // being drawn; what it says is tested on its output below.
        expect(network).toMatch(/\{rowMetaText\(t, r, \{\s*stateLabelKey: rowStateLabelKey\(st\),\s*isAuto: r\.routeId === autoRouteId,\s*isPinned: r\.routeId === pinnedId,\s*\}\)\}/);
        expect(network).not.toContain('gradeKey(');
        expect(network).toContain('chipHereText(t, locale, chip.here)');
        expect(network).not.toContain("t('network.unmeasured')");
        expect(network).not.toMatch(/healthPct\}%/);
    });
    it('Connections page: the line above the list is connectionsModeLine, not the saved choice alone', () => {
        expect(network).toContain('const modeTexts = modeLineTexts(t, connectionsModeLine(pinnedId, summaryNow));');
        expect(network).toContain('{modeTexts.now}');
        expect(network).toMatch(/\{modeTexts\.next && \(\s*<span data-next[^>]*>\s*\{modeTexts\.next\}/);
        expect(network).not.toContain('t(modeLine.');
        expect(network).not.toMatch(/t\(pinnedId \? 'network\.pinned\.line'/);
    });
    it('main screen: the Details fold is there, and only when something was measured', () => {
        expect(connection).toMatch(/routes && anyMeasured\(routes\) && \(\s*<MeasuredDetails/);
    });
});

// What the Connections page draws for a row and above the list, on its
// OUTPUT (the page calls exactly these: pinned above).
describe('a row\'s line and the line above the list', () => {
    it('the row says the grade of ITS route in plain words, after the state and who picked it', () => {
        const good = way('r1', { measured: m('good', { setupMs: 300, samples: 4, carried: 4 }) });
        const failing = way('r2', { family: 'hysteria2', measured: m('failing', { samples: 2, failed: 2 }), inCooldown: true });
        const connected = rowStateLabelKey('connected')!;
        expect(rowMetaText(t, good, { stateLabelKey: connected, isAuto: true })).toBe(
            `vless-reality · ${t(connected)} · ${t('network.auto.mark')} · Works well here`,
        );
        expect(rowMetaText(t, failing, { isPinned: true })).toBe(
            `hysteria2 · ${t('network.pinned.mark')} · Did not work here last time · ${t('network.cooled')}`,
        );
        expect(rowMetaText(tFa, good)).toBe(`vless-reality · ${tFa('measure.grade.good')}`);
    });
    it('a row the engine sent no measurement for claims nothing — no number, no "not tried"', () => {
        const line = rowMetaText(t, way('r3', { healthPct: 87, inCooldown: undefined, budgetExhausted: undefined }));
        expect(line).toBe('vless-reality');
        expect(rowMetaText(t, way('r3', { familyMaturity: 'unsupported', budgetExhausted: true }))).toBe(
            `vless-reality · ${t('network.family.unsupported')} · ${t('network.budget_full')}`,
        );
    });
    it('the line above the list is what is true NOW, then what happens next time', () => {
        const pinnedButAuto = connectionsModeLine('r9', conn({ state: 'connected', auto: auto({ state: 'connected', mode: true, routeId: 'r1' }) }));
        expect(modeLineTexts(t, pinnedButAuto)).toEqual({ now: t('network.auto.line'), next: t('network.pinned.next') });
        expect(modeLineTexts(t, connectionsModeLine('r9', null))).toEqual({ now: t('network.pinned.line') });
        expect(modeLineTexts(t, connectionsModeLine(null, null))).toEqual({ now: t('network.auto.line') });
        expect(t('network.auto.line')).not.toBe(t('network.pinned.line'));
    });
});

// "Here" is only said when the engine knows where here is.
describe('grades are shown only for the network the device is on now', () => {
    const told = parseHostNetwork({ from_host: true, kind: 'wifi', validated: 1, metered: 0 });
    it('reads the engine\'s network block; nonsense is "not known"', () => {
        expect(told).toEqual({ fromHost: true, kind: 'wifi', validated: 1, metered: 0 });
        expect(parseHostNetwork({ from_host: false, kind: '', validated: -1, metered: -1 })).toEqual({ fromHost: false, kind: '', validated: -1, metered: -1 });
        expect(parseHostNetwork({ from_host: 'yes', kind: '<b>', validated: 7, metered: null })).toEqual({ fromHost: false, kind: '', validated: -1, metered: -1 });
        expect(parseHostNetwork(undefined)).toBeUndefined();
    });
    it('no host fact: no claim about "here" — on a phone that is every start of the app until the service runs', () => {
        expect(gradesAreForThisNetwork({ android: true, network: undefined, vpnStatus: { connected: true } })).toBe(false);
        expect(gradesAreForThisNetwork({ android: true, network: parseHostNetwork({ from_host: false }), vpnStatus: { connected: true } })).toBe(false);
        expect(gradesAreForThisNetwork({ android: false, network: parseHostNetwork({ from_host: false }), vpnStatus: null })).toBe(false);
    });
    it('on Android the fact is the service\'s, and only while it runs', () => {
        expect(gradesAreForThisNetwork({ android: true, network: told, vpnStatus: { connected: true } })).toBe(true);
        expect(gradesAreForThisNetwork({ android: true, network: told, vpnStatus: { connected: false, holding: true } })).toBe(true);
        expect(gradesAreForThisNetwork({ android: true, network: told, vpnStatus: { connected: false, holding: false } })).toBe(false);
        expect(gradesAreForThisNetwork({ android: true, network: told, vpnStatus: null })).toBe(false);
        // A host that reports elsewhere (none does today) is taken at its word.
        expect(gradesAreForThisNetwork({ android: false, network: told, vpnStatus: null })).toBe(true);
        // "No network" is not a network to have grades on.
        expect(gradesAreForThisNetwork({ android: true, network: parseHostNetwork({ from_host: true, kind: 'none', validated: 0, metered: -1 }), vpnStatus: { holding: true } })).toBe(false);
    });
    it('a row then goes out without its block, and every reading of it claims nothing', () => {
        const row = way('r1', { measured: m('unknown') });
        const stripped = rowForThisNetwork(row, false);
        expect(stripped.measured).toBeUndefined();
        expect('measured' in stripped).toBe(false);
        expect(stripped.routeId).toBe('r1');
        expect(rowForThisNetwork(row, true)).toBe(row);
        expect(gradeKey(stripped.measured)).toBeUndefined();
        expect(rowGradeSuffix(t, stripped.measured)).toBe('');
        expect(rowGradeSuffix(t, row.measured)).toBe(' · Not tried here yet');
        expect(anyMeasured([stripped])).toBe(false);
        expect(familyHere([stripped])).toBeUndefined();
    });
});
