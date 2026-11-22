import { describe, expect, it } from 'vitest';
import type { PublisherTreeRow, RouteDisplayRow } from '../contract/D2Contract';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import {
    familyAbout,
    familyName,
    familyTags,
    fileBadge,
    fileGlyph,
    fileState,
    healthTone,
    maturityBadgeKey,
    meaningfulNickname,
    restingUntilMs,
    setupText,
    waysCountText,
    wayGlyph,
    wayState,
    wayStateKey,
    wayTitles,
} from './fileFacts';
import type { RowState } from './networkRows';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? k;
const tFa = (k: string) => FA[k] ?? k;
const NOW = 1_800_000_000_000;

const route = (id: string, family: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'p',
    publisherName: 'Test',
    routeNickname: id,
    trustClass: 'trusted',
    family,
    familyMaturity: 'stable',
    ...over,
});
const file = (routes: RouteDisplayRow[], revoked = false): Pick<PublisherTreeRow, 'cells' | 'revoked'> => ({
    revoked,
    cells: [{ cellIdFpHex: 'default', label: '', families: [], routes }],
});
const idle = (): RowState => 'idle';

describe('family names', () => {
    it('reads the shared names, and never prints a token it does not know', () => {
        expect(familyName(t, 'vless-reality')).toBe('VLESS Reality');
        expect(familyName(t, 'hysteria2')).toBe('Hysteria 2');
        expect(familyName(t, 'websocket-tls')).toBe('WebSocket TLS');
        expect(familyName(t, 'tor-bridge')).toBe('Tor bridge');
        expect(familyName(t, '<script>')).toBe(EN['files.fam.unknown']);
        expect(familyName(tFa, 'tuic')).toBe('TUIC');
    });
    it('has a plain paragraph for every kind a relay mints', () => {
        for (const f of ['vless-reality', 'websocket-tls', 'naive', 'hysteria2', 'tuic', 'anytls', 'shadowsocks', 'wireguard']) {
            expect(familyAbout(t, f)).toBeTruthy();
            expect(familyAbout(tFa, f)).toBeTruthy();
        }
        expect(familyAbout(t, 'nonsense')).toBeUndefined();
    });
});

describe('way titles', () => {
    it('hides the names a relay makes up, keeps the ones a person wrote', () => {
        for (const n of ['r1', 'R4', 'route-1', 'route_12', 'way 3', '2', '', 'vless-reality', 'VLESS Reality']) {
            expect(meaningfulNickname({ routeNickname: n, family: 'vless-reality', routeId: 'x' }, 'VLESS Reality')).toBeUndefined();
        }
        expect(meaningfulNickname({ routeNickname: 'x', family: 'naive', routeId: 'x' })).toBeUndefined();
        expect(meaningfulNickname({ routeNickname: 'Rescue 03', family: 'naive', routeId: 'x' })).toBe('Rescue 03');
        expect(meaningfulNickname({ routeNickname: 'Old WG', family: 'wireguard', routeId: 'x' })).toBe('Old WG');
    });
    it('numbers two ways of one kind and leaves a single one alone', () => {
        const titles = wayTitles(t, [
            route('r1', 'vless-reality'),
            route('r2', 'hysteria2'),
            route('r3', 'vless-reality', { routeNickname: 'Backup' }),
        ]);
        expect(titles.get('r1')).toEqual({ title: 'VLESS Reality · 1' });
        expect(titles.get('r2')).toEqual({ title: 'Hysteria 2' });
        expect(titles.get('r3')).toEqual({ title: 'VLESS Reality · 2', nickname: 'Backup' });
        const faTitles = wayTitles(tFa, [route('r1', 'naive'), route('r2', 'naive')], 'fa');
        expect(faTitles.get('r2')?.title).toBe('Naive · ۲');
    });
});

describe('one way', () => {
    it('says what is running first, then what this build cannot do, then rest, then the grade here', () => {
        const r = route('a', 'naive', { measured: { grade: 'good', samples: 1, carried: 1, failed: 0 } });
        expect(wayState(r, 'connected', NOW)).toBe('in_use');
        expect(wayState(r, 'checking', NOW)).toBe('checking');
        expect(wayState(r, 'lost', NOW)).toBe('checking');
        expect(wayState({ ...r, familyMaturity: 'unsupported' }, 'idle', NOW)).toBe('unsupported');
        expect(wayState({ ...r, inCooldown: true, cooldownUntilUnixMs: NOW + 1 }, 'idle', NOW)).toBe('resting');
        expect(wayState({ ...r, inCooldown: true, cooldownUntilUnixMs: NOW - 1 }, 'idle', NOW)).toBe('good');
        expect(wayState(r, 'idle', NOW)).toBe('good');
        expect(wayState({ ...r, measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 } }, 'idle', NOW)).toBe('untried');
    });
    it('claims nothing about here without a measured block', () => {
        const bare = route('a', 'naive');
        expect(wayState(bare, 'idle', NOW)).toBe('none');
        expect(wayStateKey('none')).toBeUndefined();
        expect(wayGlyph('none')).toBe('none');
        expect(wayState({ ...bare, proven: true }, 'idle', NOW)).toBe('proven');
        // "Worked before" is not a green tick: it may have been elsewhere.
        expect(wayGlyph('proven')).toBe('none');
    });
    it('every state has words in both languages', () => {
        for (const s of ['in_use', 'checking', 'unsupported', 'resting', 'good', 'ok', 'slow', 'failing', 'untried', 'proven'] as const) {
            const k = wayStateKey(s)!;
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toBeTruthy();
        }
    });
    it('writes the setup time in seconds, never 0.0', () => {
        expect(setupText(t, 'en', 380)).toBe('0.4 s');
        expect(setupText(t, 'en', 20)).toBe('0.1 s');
        expect(setupText(t, 'en', 12_400)).toBe('12 s');
        expect(setupText(tFa, 'fa', 2600)).toBe('۲٫۶ ثانیه');
        expect(setupText(t, 'en', undefined)).toBeUndefined();
        expect(setupText(t, 'en', 0)).toBeUndefined();
    });
    it('has a meter only for a score the engine sent', () => {
        expect(healthTone(undefined)).toBeUndefined();
        expect(healthTone(Number.NaN)).toBeUndefined();
        expect(healthTone(0)).toBe('bad');
        expect(healthTone(55)).toBe('warn');
        expect(healthTone(90)).toBe('good');
    });
    it('marks experimental and unsupported kinds only', () => {
        expect(maturityBadgeKey({ familyMaturity: 'experimental' })).toBe('files.way.experimental');
        expect(maturityBadgeKey({ familyMaturity: 'unsupported' })).toBe('files.way.unsupported_short');
        expect(maturityBadgeKey({ familyMaturity: 'stable' })).toBeUndefined();
        expect(maturityBadgeKey({})).toBeUndefined();
    });
});

describe('one file', () => {
    const good = route('g', 'vless-reality', { measured: { grade: 'good', samples: 2, carried: 2, failed: 0 } });
    const fail = route('f', 'hysteria2', { measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } });
    const untried = route('u', 'tuic', { measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 } });
    const resting = route('z', 'naive', { inCooldown: true, cooldownUntilUnixMs: NOW + 60_000 });
    const unsupported = route('w', 'wireguard', { familyMaturity: 'unsupported' });

    it('in use beats everything but a revoked file', () => {
        expect(fileState(file([good, fail]), 'f', idle, NOW)).toBe('in_use');
        expect(fileState(file([good]), 'g', () => 'checking', NOW)).toBe('checking');
        expect(fileState(file([good], true), 'g', idle, NOW)).toBe('revoked');
    });
    it('works here only from a grade on this network', () => {
        expect(fileState(file([good, fail]), null, idle, NOW)).toBe('works');
        expect(fileState(file([route('p', 'naive', { proven: true })]), null, idle, NOW)).toBe('proven');
        expect(fileState(file([route('n', 'naive')]), null, idle, NOW)).toBe('none');
    });
    it('"Not working here" only when every usable way failed here', () => {
        expect(fileState(file([fail, unsupported]), null, idle, NOW)).toBe('failing');
        expect(fileState(file([fail, untried]), null, idle, NOW)).toBe('some_failed');
        expect(fileState(file([untried]), null, idle, NOW)).toBe('untried');
    });
    it('resting and unsupported', () => {
        expect(fileState(file([resting, unsupported]), null, idle, NOW)).toBe('resting');
        expect(fileState(file([unsupported]), null, idle, NOW)).toBe('unsupported');
        expect(restingUntilMs([resting, good], NOW)).toBe(NOW + 60_000);
        expect(restingUntilMs([good], NOW)).toBeUndefined();
    });
    it('a green disc only for in use or works here', () => {
        expect(fileGlyph('in_use')).toBe('ok');
        expect(fileGlyph('works')).toBe('ok');
        for (const s of ['proven', 'untried', 'none'] as const) expect(fileGlyph(s)).toBe('none');
        expect(fileGlyph('failing')).toBe('bad');
        expect(fileBadge('none')).toBeUndefined();
        for (const s of ['revoked', 'checking', 'in_use', 'works', 'resting', 'failing', 'some_failed', 'untried', 'unsupported', 'proven'] as const) {
            const b = fileBadge(s)!;
            expect(EN[b.key], b.key).toBeTruthy();
            expect(FA[b.key], b.key).toBeTruthy();
        }
    });
    it('lists each kind once, with a count and a mark for here', () => {
        const tags = familyTags(t, [good, route('g2', 'vless-reality'), fail, untried, unsupported, resting], null, NOW);
        expect(tags.map((x) => [x.name, x.count, x.mark])).toEqual([
            ['VLESS Reality', 2, 'good'],
            ['Hysteria 2', 1, 'bad'],
            ['TUIC', 1, 'none'],
            ['WireGuard', 1, 'off'],
            ['Naive', 1, 'warn'],
        ]);
        // The kind of the way in use is marked good even with no grade.
        expect(familyTags(t, [untried], 'u', NOW)[0].mark).toBe('good');
    });
    it('counts ways in words', () => {
        expect(waysCountText(t, 'en', 4)).toBe('4 ways');
        expect(waysCountText(t, 'en', 1)).toBe('1 way');
        expect(waysCountText(tFa, 'fa', 4)).toBe('۴ راه');
    });
});
