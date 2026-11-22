import { describe, expect, it, vi } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({ invoke: async () => { throw new Error('no shell'); } }));

const { checksFor, failedIds, failingHere, isPastedRoute, readSurvey, readSurveyBlock, surveyEnded } = await import('./pasteSurvey');
import type { RouteDisplayRow } from '../contract/D2Contract';

const block = (results: Array<[string, string]>, state = 'done') => ({
    state,
    trigger: 'user',
    total: results.length,
    done: results.length,
    results: results.map(([route_id, result]) => ({ route_id, result })),
});

const route = (routeId: string, extra: Partial<RouteDisplayRow> = {}): RouteDisplayRow =>
    ({ routeId, publisherId: 'p', publisherName: '', routeNickname: '', trustClass: 'tofu_friend', family: 'vless-reality', ...extra }) as RouteDisplayRow;

describe('reading the survey', () => {
    it('one verdict per route; a route with several variants worked if any carried', () => {
        const r = readSurveyBlock(
            block([
                ['a', 'carried'],
                ['b', 'not_carrying'],
                ['c', 'when_used'],
                ['d', 'skipped'],
                ['e', 'start_failed'],
                ['f', 'cancelled'],
                ['g', 'not_carrying'],
                ['g', 'carried'],
                ['h', 'skipped'],
                ['h', 'not_carrying'],
            ]),
        )!;
        expect(Object.fromEntries(r.results)).toEqual({
            a: 'works',
            b: 'failed',
            c: 'when_used',
            d: 'unchecked',
            e: 'unchecked',
            f: 'unchecked',
            g: 'works',
            h: 'failed',
        });
    });

    it('not a survey block: null', () => {
        expect(readSurveyBlock(null)).toBeNull();
        expect(readSurveyBlock({ state: 'bogus' })).toBeNull();
    });

    it('no shell: null, never a throw', async () => {
        await expect(readSurvey()).resolves.toBeNull();
    });

    it('ended means done or stopped', () => {
        expect(surveyEnded(readSurveyBlock(block([], 'done'))!.report)).toBe(true);
        expect(surveyEnded(readSurveyBlock(block([], 'stopped'))!.report)).toBe(true);
        expect(surveyEnded(readSurveyBlock(block([], 'checking'))!.report)).toBe(false);
        expect(surveyEnded(null)).toBe(false);
    });
});

describe('what a bulk removal may take', () => {
    it('only ids that were checked and failed; a route checked when used is never failed', () => {
        const read = readSurveyBlock(block([['a', 'not_carrying'], ['b', 'carried'], ['w', 'not_carrying']]));
        const checks = checksFor(['a', 'b', 'c', 'w'], read, [route('w', { checkedWhenUsed: true })]);
        expect(Object.fromEntries(checks)).toEqual({ a: 'failed', b: 'works', c: 'unchecked', w: 'when_used' });
        expect(failedIds(checks)).toEqual(['a']);
    });

    it('with no survey nothing is failed', () => {
        expect(failedIds(checksFor(['a', 'b'], null))).toEqual([]);
    });
});

describe('the Files page: ways that do not work here', () => {
    const failing = { grade: 'failing' as const, samples: 2, carried: 0, failed: 2 };
    it('the survey\'s failures and this network\'s remembered failures', () => {
        const read = readSurveyBlock(block([['pasted-1', 'not_carrying'], ['pasted-2', 'carried']]));
        const routes = [
            route('pasted-1'),
            route('pasted-2', { measured: failing }),
            route('pasted-3', { measured: failing }),
            route('pasted-4'),
        ];
        expect(failingHere(routes, read, null)).toEqual(['pasted-1', 'pasted-3']);
    });

    it('never the way in use, one checked when used, or one that ever carried here', () => {
        const read = readSurveyBlock(block([['a', 'not_carrying'], ['b', 'not_carrying'], ['c', 'not_carrying']]));
        const routes = [
            route('a'),
            route('b', { checkedWhenUsed: true }),
            route('c', { measured: { grade: 'slow', samples: 3, carried: 1, failed: 2 } }),
        ];
        expect(failingHere(routes, read, 'a')).toEqual([]);
    });

    it('a pasted link\'s route id', () => {
        expect(isPastedRoute('pasted-20261122T101010Z')).toBe(true);
        expect(isPastedRoute('maman/vless-1')).toBe(false);
    });
});
