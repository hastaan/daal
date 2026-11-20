// What Home says about the connection: each fact only when the engine
// sent it, never a comparison that did not run, never an engine token.
import { describe, expect, it } from 'vitest';
import type { AutoStatus, AutoTried, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import {
    connectedFacts,
    networkFact,
    qualityFact,
    rateText,
    readyKinds,
    readyLine,
    secondsText,
    speedFact,
    triedReason,
    triedRows,
    wayRows,
    whyFact,
} from './homeFacts';
import { familyLabel } from './familyName';
import legacyEn from '../i18n/en.json';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const EN = { ...(legacyEn as object), ...(en as object) } as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? k;
const tf = (k: string) => FA[k] ?? k;

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
    state: 'connected',
    mode: true,
    trying: '',
    index: 1,
    total: 3,
    tried: [],
    verdict: '',
    routeId: 'r1',
    ...over,
});
const carried = (id: string, over: Partial<AutoTried> = {}): AutoTried => ({ routeId: id, family: 'vless-reality', result: 'carried', category: '', ...over });
const up = (over: Partial<ConnectionSummary> = {}): ConnectionSummary => ({
    state: 'connected',
    mode: 'normal',
    routeCheck: 'ok',
    activeRoute: way('r1'),
    ...over,
});

describe('family names', () => {
    it('reads a known token, and says nothing for anything else', () => {
        expect(familyLabel(t, 'vless-reality')).toBe('VLESS Reality');
        expect(familyLabel(t, 'hysteria2')).toBe('Hysteria 2');
        expect(familyLabel(t, 'tor-bridge')).toBe('Tor bridge');
        expect(familyLabel(t, 'pars')).toBeUndefined();
        expect(familyLabel(t, '')).toBeUndefined();
        expect(familyLabel(t, undefined)).toBeUndefined();
    });
    it('every known family has a name in both languages', () => {
        for (const f of ['vless-reality', 'websocket-tls', 'naive', 'hysteria2', 'tuic', 'anytls', 'shadowsocks', 'wireguard', 'tor-bridge']) {
            expect(familyLabel(t, f), f).toBeTruthy();
            expect(familyLabel(tf, f), f).toBeTruthy();
        }
    });
});

describe('nothing the engine did not send', () => {
    it('a bare connected summary gives no rows at all', () => {
        const facts = connectedFacts({ t, locale: 'en', conn: { state: 'connected', mode: 'normal' }, throughput: null, pinnedId: null });
        expect(facts).toEqual({});
    });
    it('not connected: no facts, whatever the summary holds', () => {
        const conn = up({ state: 'connecting', pointerValidDays: 9, network: { fromHost: true, kind: 'wifi', validated: 1, metered: 0 } });
        expect(connectedFacts({ t, locale: 'en', conn, throughput: { upBytesPerSec: 1, downBytesPerSec: 1, windowMs: 1000 }, pinnedId: null })).toEqual({});
    });
    it('speed: null is "nobody counts" (no row); no row either until a byte has moved', () => {
        expect(speedFact('en', up(), { upBytesPerSec: null, downBytesPerSec: null, windowMs: 1000 })).toBeUndefined();
        expect(speedFact('en', up(), null)).toBeUndefined();
        expect(speedFact('en', up(), { upBytesPerSec: 0, downBytesPerSec: 0, windowMs: 1000 })).toBeUndefined();
        expect(speedFact('en', up(), { upBytesPerSec: 0, downBytesPerSec: 2048, windowMs: 1000 })).toEqual({ down: '2.0 KB/s', up: '0 B/s' });
    });
    it('network: only what the host told the engine', () => {
        expect(networkFact(t, up())).toBeUndefined();
        expect(networkFact(t, up({ network: { fromHost: false, kind: 'wifi', validated: 1, metered: 0 } }))).toBeUndefined();
        expect(networkFact(t, up({ network: { fromHost: true, kind: '', validated: -1, metered: -1 } }))).toBeUndefined();
        expect(networkFact(t, up({ network: { fromHost: true, kind: 'none', validated: 0, metered: -1 } }))).toBeUndefined();
        expect(networkFact(t, up({ network: { fromHost: true, kind: 'wifi', validated: 1, metered: 0 } }))).toEqual({
            kind: 'wifi',
            text: 'Wi-Fi',
            metered: false,
        });
        expect(networkFact(t, up({ network: { fromHost: true, kind: 'cellular', validated: 1, metered: 1 } }))?.text).toBe('Mobile data · metered');
        expect(networkFact(tf, up({ network: { fromHost: true, kind: 'cellular', validated: 1, metered: -1 } }))?.text).toBe('اینترنت همراه');
    });
    it('quality: the live check, else the grade here; nothing while checking', () => {
        expect(qualityFact(t, 'en', up({ routeCheck: 'verifying' }))).toBeUndefined();
        expect(qualityFact(t, 'en', up({ routeCheck: undefined }))).toBeUndefined();
        expect(qualityFact(t, 'en', up())).toEqual({ tone: 'good', label: 'Good' });
        expect(qualityFact(t, 'en', up({ routeCheck: 'degraded' }))?.tone).toBe('warn');
        // No live check: the grade here, in its own words ("here").
        const graded = up({ routeCheck: undefined, activeRoute: way('r1', { measured: { grade: 'slow', setupMs: 5200, samples: 3, carried: 3, failed: 0 } }) });
        expect(qualityFact(t, 'en', graded)).toEqual({ tone: 'warn', label: 'Slow here', setup: 'usually 5.2 s to connect' });
        const gradedGood = up({ routeCheck: undefined, activeRoute: way('r1', { measured: { grade: 'good', samples: 3, carried: 3, failed: 0 } }) });
        expect(qualityFact(t, 'en', gradedGood)).toEqual({ tone: 'good', label: 'Works well here' });
        // The live check says ok: an old "slow" grade does not overrule it.
        const liveOk = up({ routeCheck: 'ok', activeRoute: way('r1', { measured: { grade: 'slow', samples: 3, carried: 3, failed: 0 } }) });
        expect(qualityFact(t, 'en', liveOk)).toMatchObject({ tone: 'good', label: 'Good' });
        // This connect's own time beats the smoothed one.
        const timed = up({ auto: auto({ tried: [carried('r1', { setupMs: 640 })] }) });
        expect(qualityFact(t, 'en', timed)?.setup).toBe('connected in 0.6 s');
        expect(qualityFact(tf, 'fa', timed)?.setup).toBe('در ۰٫۶ ثانیه وصل شد');
        // After a connect by hand (mode false) an older pass's time is stale.
        const byHand = up({
            activeRoute: way('r1', { measured: { grade: 'good', setupMs: 300, samples: 3, carried: 3, failed: 0 } }),
            auto: auto({ mode: false, tried: [carried('r1', { setupMs: 640 })] }),
        });
        expect(qualityFact(t, 'en', byHand)?.setup).toBe('usually 0.3 s to connect');
    });
    it('no "valid for" row: the pointer expiry is not about this connection', () => {
        const facts = connectedFacts({ t, locale: 'en', conn: up({ pointerValidDays: 2 }), throughput: null, pinnedId: null });
        expect(Object.keys(facts)).not.toContain('valid');
    });
});

describe('why this way: only what the engine\'s own record shows', () => {
    it('no automatic record and no pin: nothing (never "worked best")', () => {
        expect(whyFact(t, 'en', up(), null)).toBeUndefined();
    });
    it('the person chose it', () => {
        expect(whyFact(t, 'en', up(), 'r1')?.token).toBe('picked');
        // A pin on another way says nothing about this one.
        expect(whyFact(t, 'en', up(), 'r2')).toBeUndefined();
    });
    it('moved for speed', () => {
        expect(whyFact(t, 'en', up({ auto: auto({ verdict: 'moved_faster', tried: [carried('r1')] }) }), null)?.text).toBe(
            'Daal moved here because it is faster',
        );
    });
    it('answered first of two tried at once', () => {
        const a = auto({ tried: [carried('r1', { racedWith: 'r2' }), { routeId: 'r2', family: 'tuic', result: 'stopped', category: '', racedWith: 'r1' }] });
        expect(whyFact(t, 'en', up({ auto: a }), null)?.token).toBe('won_race');
    });
    it('others did not get through: by kind for one, a count for more', () => {
        const one = auto({ verdict: 'moved_on', tried: [{ routeId: 'r2', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' }, carried('r1')] });
        expect(whyFact(t, 'en', up({ auto: one }), null)?.text).toBe('Hysteria 2 did not get through here, so Daal used this one');
        const unnamed = auto({ tried: [{ routeId: 'r2', family: 'mystery', result: 'start_failed', category: '' }, carried('r1')] });
        expect(whyFact(t, 'en', up({ auto: unnamed }), null)?.text).toBe('Another way did not get through here, so Daal used this one');
        const two = auto({
            tried: [
                { routeId: 'r2', family: 'hysteria2', result: 'not_carrying', category: '' },
                { routeId: 'r3', family: 'tuic', result: 'start_failed', category: '' },
                carried('r1'),
            ],
        });
        expect(whyFact(tf, 'fa', up({ auto: two }), null)?.text).toContain('۲');
    });
    it('worked here before: only when the engine says it put it first for that (`why`)', () => {
        const good = (why?: string) =>
            up({
                activeRoute: way('r1', { measured: { grade: 'good', setupMs: 300, samples: 5, carried: 5, failed: 0 } }),
                auto: auto({ tried: [carried('r1', why ? { why } : {})] }),
            });
        expect(whyFact(t, 'en', good('carried_here'), null)?.token).toBe('worked_here');
        // A good grade alone is not the engine's reason: 'ranked' is no
        // claim about this network.
        expect(whyFact(t, 'en', good('ranked'), null)?.token).toBe('first_try');
        expect(whyFact(t, 'en', good(), null)?.token).toBe('first_try');
    });
    it('ways the engine refused (never dialled) did not "fail here"', () => {
        const a = auto({
            tried: [
                { routeId: 'r2', family: 'tuic', result: 'refused', category: '' },
                { routeId: 'r3', family: 'masque', result: 'refused', category: '' },
                carried('r1'),
            ],
        });
        const w = whyFact(t, 'en', up({ auto: a }), null);
        expect(w?.token).toBe('first_try');
        expect(w?.token).not.toBe('after_failed');
        // Stopped and cancelled say nothing either.
        const b = auto({ tried: [{ routeId: 'r2', family: 'tuic', result: 'cancelled', category: '' }, carried('r1', { why: 'carried_here' })] });
        expect(whyFact(t, 'en', up({ auto: b }), null)?.token).toBe('worked_here');
    });
    it('the way that was up stopped: switched from one kind to the other', () => {
        const a = auto({
            verdict: 'moved_on',
            tried: [
                { routeId: 'r2', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', why: 'was_connected' },
                carried('r1'),
            ],
        });
        const w = whyFact(t, 'en', up({ auto: a, activeRoute: way('r1', { family: 'websocket-tls' }) }), null);
        expect(w).toEqual({ token: 'switched', text: 'Hysteria 2 stopped working, so Daal switched to WebSocket TLS' });
    });
});

describe('what was tried, in plain words', () => {
    it('the refined reason first, then the category, then the result', () => {
        expect(triedReason(t, { routeId: 'r', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', refined: 'udp_blocked_here' })).toBe(
            'This network seems to stop this kind',
        );
        expect(triedReason(t, { routeId: 'r', family: 'x', result: 'start_failed', category: 'tcp_connect_timeout' })).toBe('The server did not answer');
        expect(triedReason(t, { routeId: 'r', family: 'x', result: 'start_failed', category: 'brand_new_code' })).toBe('could not start');
        expect(triedReason(t, carried('r'))).toBe('Worked');
    });
    it('rows by kind and name, never an engine token', () => {
        const rows = triedRows(
            t,
            [
                { routeId: 'r1', family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout' },
                { routeId: 'r2', family: 'odd-thing', result: 'refused', category: '' },
            ],
            [way('r1', { routeNickname: 'Rescue 03' })],
        );
        expect(rows.map((r) => [r.family, r.name, r.glyph])).toEqual([
            ['VLESS Reality', 'Rescue 03', 'bad'],
            ['Other kind', undefined, 'off'],
        ]);
        expect(JSON.stringify(rows)).not.toMatch(/vless-reality|odd-thing|tcp_connect_timeout/);
    });
});

describe('what was tried: a red cross only for a real failure', () => {
    it('stopped, cancelled and refused are not "bad"', () => {
        const rows = triedRows(
            t,
            [
                carried('r1'),
                { routeId: 'r2', family: 'tuic', result: 'stopped', category: '' },
                { routeId: 'r3', family: 'tuic', result: 'cancelled', category: '' },
                { routeId: 'r4', family: 'masque', result: 'refused', category: '' },
                { routeId: 'r5', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
            ],
            undefined,
        );
        expect(rows.map((r) => r.glyph)).toEqual(['ok', 'none', 'none', 'off', 'bad']);
    });
});

describe('the Details fold: every way once', () => {
    const NOW = 1_000_000;
    it('one row per way, one state, one line; never "r1", a date or a short code', () => {
        const rows = wayRows({
            t,
            locale: 'en',
            routes: [
                way('r1', { routeNickname: 'Rescue 03', measured: { grade: 'good', samples: 1, carried: 1, failed: 0 }, healthPct: 96 }),
                way('r2', { family: 'hysteria2', routeNickname: 'May 6', measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } }),
                way('r3', { family: 'wireguard', routeNickname: 'K3F', familyMaturity: 'unsupported' }),
                way('r4', { family: 'naive', routeNickname: 'r4' }),
            ],
            activeId: 'r1',
            why: {
                active: way('r1'),
                reasonText: '',
                skipped: null,
                skippedFamilies: [{ family: 'hysteria2', ladderStep: 2, untilUnixMs: NOW + 8 * 60_000 + 1 }],
                decisionId: 'd',
            },
            scores: new Map([['r2', 28]]),
            nowMs: NOW,
        });
        expect(rows.map((r) => [r.family, r.name, r.state, r.status, r.scorePct])).toEqual([
            ['VLESS Reality', 'Rescue 03', 'ok', 'In use now', 96],
            ['Hysteria 2', undefined, 'warn', 'Resting: tries again in about 9 min', 28],
            ['WireGuard', undefined, 'off', 'Not in this version', undefined],
            ['Naive', undefined, 'none', undefined, undefined],
        ]);
    });
    it('a way that failed in this pass says how; a skip says why, from the engine\'s token', () => {
        const rows = wayRows({
            t,
            locale: 'en',
            routes: [way('r1'), way('r2', { family: 'hysteria2' }), way('r3', { family: 'naive' })],
            activeId: 'r1',
            tried: [{ routeId: 'r2', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', refined: 'udp_blocked_here' }, carried('r1')],
            why: {
                active: way('r1'),
                reasonText: '',
                skipped: [{ route: way('r3'), reason: 'recent failure', reasonToken: 'recent_failure' }],
                decisionId: 'd',
            },
            nowMs: NOW,
        });
        expect(rows.map((r) => [r.state, r.status])).toEqual([
            ['ok', 'In use now'],
            ['bad', 'This network seems to stop this kind'],
            ['none', 'Left out: it failed a short while ago'],
        ]);
    });
});

describe('ready: what automatic connect will try, in its order', () => {
    it('experimental kinds are not counted as ready, and are marked', () => {
        const routes = [
            way('r1', { family: 'masque', familyMaturity: 'experimental' }),
            way('r2', { family: 'hysteria2', measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } }),
            way('r3', { family: 'websocket-tls', measured: { grade: 'good', setupMs: 600, samples: 3, carried: 3, failed: 0 } }),
            way('r4', { family: 'naive' }),
        ];
        expect(readyLine(t, 'en', routes)).toBe('3 ways ready · WebSocket TLS worked here before');
        const k = readyKinds(t, routes, 4, NOW_READY);
        expect(k.tags.map((x) => [x.name, x.mark, x.experimental])).toEqual([
            ['WebSocket TLS', 'good', false],
            ['Naive', 'none', false],
            ['Hysteria 2', 'bad', false],
            ['MASQUE', 'none', true],
        ]);
        expect(k.names).toEqual(['WebSocket TLS', 'Naive', 'Hysteria 2', 'MASQUE']);
    });
});
const NOW_READY = 1_000_000;

describe('numbers as people read them', () => {
    it('rates and seconds, in Persian digits in Persian', () => {
        expect(rateText(318 * 1024, 'en')).toBe('318 KB/s');
        expect(rateText(2.4 * 1024 * 1024, 'en')).toBe('2.4 MB/s');
        expect(rateText(12 * 1024, 'en')).toBe('12 KB/s');
        expect(rateText(318 * 1024, 'fa')).toBe('۳۱۸ KB/s');
        expect(rateText(2.4 * 1024 * 1024, 'fa')).toBe('۲٫۴ MB/s');
        expect(secondsText(310, 'en')).toBe('0.3');
        expect(secondsText(12_400, 'en')).toBe('12');
    });
});
