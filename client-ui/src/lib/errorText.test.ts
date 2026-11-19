// A rejected Tauri command is a plain string. The pages read
// `(e as Error).message || 'unknown'` off it, and the first phone pass
// showed a red banner holding the one word "unknown".
import { describe, expect, it } from 'vitest';
import { errorText } from './errorText';

describe('errorText', () => {
    it('keeps a rejected plain string — the case that read "unknown"', () => {
        expect(errorText('engine call returned -1')).toBe('engine call returned -1');
    });
    it('reads an Error', () => {
        expect(errorText(new Error('boom'))).toBe('boom');
        expect(errorText(new TypeError(''))).toBe('TypeError');
    });
    it('reads an object the host rejected with', () => {
        expect(errorText({ message: 'no such route' })).toBe('no such route');
        expect(errorText({ error: 'store closed' })).toBe('store closed');
        expect(errorText({ code: -1 })).toBe('code -1');
        expect(errorText({ kind: 'Io', path: 'x' })).toBe('{"kind":"Io","path":"x"}');
    });
    it('never returns nothing, and never "[object Object]"', () => {
        const circular: Record<string, unknown> = {};
        circular.self = circular;
        for (const v of [undefined, null, '', '   ', {}, circular, 0, false]) {
            const s = errorText(v);
            expect(s.length).toBeGreaterThan(0);
            expect(s).not.toBe('[object Object]');
        }
    });
});
