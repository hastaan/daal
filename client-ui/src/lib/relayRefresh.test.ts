import { describe, expect, it } from 'vitest';
import { parseRefresh, refreshMessage } from './relayRefresh';

describe('check for a new address', () => {
    it('reads the engine outcome and retry hint', () => {
        expect(parseRefresh('{"outcome":"updated","retry_after_s":0}')).toEqual({ outcome: 'updated', retryAfterS: 0 });
        expect(parseRefresh('{"outcome":"rate_limited","retry_after_s":42.4}')).toEqual({ outcome: 'rate_limited', retryAfterS: 42 });
    });
    it('an unknown word or bad JSON is "unavailable", never a success', () => {
        expect(parseRefresh('{"outcome":"wat"}').outcome).toBe('unavailable');
        expect(parseRefresh('nope').outcome).toBe('unavailable');
    });
    it('every outcome has a line; only "updated" is good news', () => {
        for (const o of ['updated', 'unchanged', 'unreachable', 'rejected', 'tunnel_required', 'rate_limited', 'no_endpoints', 'unknown_pack', 'in_progress', 'unavailable'] as const) {
            const m = refreshMessage({ outcome: o, retryAfterS: 0 });
            expect(m.key).toMatch(/^files\.refresh\./);
            expect(m.tone === 'good').toBe(o === 'updated');
        }
    });
});
