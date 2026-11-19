// A failed engine start keeps the app alive (first phone pass, lane C);
// the pages must then SAY the app could not start instead of drawing an
// ordinary "not connected".
import { describe, expect, it } from 'vitest';
import {
    engineStartProblem,
    isEngineUnavailable,
    parseEngineStatus,
    publisherBootFailureKey,
    tapAllowedWithStartProblem,
} from './engineStart';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';

const down = {
    engine_ready: false,
    engine_error: 'open secrets.key: permission denied',
    publisher_store_ready: true,
    publisher_store_error: null,
};
const up = { engine_ready: true, engine_error: null, publisher_store_ready: true, publisher_store_error: null };

describe('engine_status', () => {
    it('an engine that did not start is a problem, with the reason kept for Details', () => {
        const p = engineStartProblem(parseEngineStatus(down));
        expect(p).toEqual({ detail: 'open secrets.key: permission denied' });
    });
    it('a started engine is no problem', () => {
        expect(engineStartProblem(parseEngineStatus(up))).toBeNull();
        // …even if an older call was rejected before it came up.
        expect(engineStartProblem(parseEngineStatus(up), 'engine_unavailable: x')).toBeNull();
    });
    it('no answer (older shell, browser harness) accuses nobody', () => {
        expect(parseEngineStatus(null)).toBeUndefined();
        expect(parseEngineStatus({})).toBeUndefined();
        expect(engineStartProblem(undefined)).toBeNull();
        expect(engineStartProblem(undefined, 'engine call returned -1')).toBeNull();
    });
    it('a rejected command with the contract prefix is enough on its own', () => {
        expect(isEngineUnavailable('engine_unavailable: route store: disk full')).toBe(true);
        expect(isEngineUnavailable(new Error('engine_unavailable: x'))).toBe(true);
        expect(isEngineUnavailable('engine call returned -1')).toBe(false);
        expect(engineStartProblem(undefined, 'engine_unavailable: route store: disk full')).toEqual({
            detail: 'route store: disk full',
        });
    });
});

describe('the main button while Daal could not start', () => {
    it('does not start a connect that can only fail; stopping is still allowed', () => {
        const p = { detail: 'x' };
        expect(tapAllowedWithStartProblem(p, 'connect')).toBe(false);
        expect(tapAllowedWithStartProblem(p, 'recovery')).toBe(false);
        expect(tapAllowedWithStartProblem(p, 'disconnect')).toBe(true);
        expect(tapAllowedWithStartProblem(null, 'connect')).toBe(true);
    });
});

describe('the publisher tab when its list could not be read at start', () => {
    it('does not offer "try again" for a start problem', () => {
        const storeDown = parseEngineStatus({ ...up, publisher_store_ready: false, publisher_store_error: 'x' });
        expect(publisherBootFailureKey('anything', storeDown)).toBe('pub.boot.unavailable');
        expect(publisherBootFailureKey('anything', parseEngineStatus(down))).toBe('pub.boot.unavailable');
        // Tauri's own text for a command whose state was never registered.
        expect(
            publisherBootFailureKey('state not managed for field `store` on command `wizard_list_operators`. You must call `.manage()` before using this command', undefined),
        ).toBe('pub.boot.unavailable');
        expect(publisherBootFailureKey('engine_unavailable: x', undefined)).toBe('pub.boot.unavailable');
    });
    it('keeps the ordinary sentence for anything else', () => {
        expect(publisherBootFailureKey('database is locked', parseEngineStatus(up))).toBe('pub.fail.generic');
    });
});

describe('the words', () => {
    it('exist in both languages and name no internals', () => {
        const e = en as Record<string, string>;
        const f = fa as Record<string, string>;
        for (const k of ['engine.start_failed.title', 'engine.start_failed.body', 'pub.boot.unavailable']) {
            expect(e[k], k).toBeTruthy();
            expect(f[k], k).toBeTruthy();
            expect(f[k], k).not.toBe(e[k]);
            expect(e[k], k).not.toMatch(/engine|database|store|sqlite|state/i);
        }
    });
});
