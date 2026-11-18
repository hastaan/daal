// The connection check must win over the posture: a route the engine is
// still proving is never shown as connected (end-to-end rig finding
// CEN-1 — "Connected" used to mean "the engine started").
import { describe, expect, it } from 'vitest';
import {
    checkHeadlineKey,
    checkStateLabelKey,
    connStateWithCheck,
    parseRouteCheck,
    parseRouteRunning,
} from './routeCheck';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

describe('parseRouteCheck', () => {
    it('accepts the closed vocabulary and nothing else', () => {
        for (const v of ['verifying', 'ok', 'degraded', 'failed']) {
            expect(parseRouteCheck(v)).toBe(v);
        }
        for (const v of ['', undefined, null, 'Connected', 'VERIFYING', 3]) {
            expect(parseRouteCheck(v)).toBeUndefined();
        }
    });
});

describe('parseRouteRunning', () => {
    it('is a boolean or nothing', () => {
        expect(parseRouteRunning(true)).toBe(true);
        expect(parseRouteRunning(false)).toBe(false);
        // An older engine emits no field: "the engine did not say",
        // never "nothing is running".
        for (const v of [undefined, null, '', 'false', 0, 1]) {
            expect(parseRouteRunning(v)).toBeUndefined();
        }
    });
});

describe('connStateWithCheck', () => {
    it('never shows a route that is still being checked as connected', () => {
        // The posture can still read an active state from the route
        // this connect replaced, or NoRoute on a first connect.
        expect(connStateWithCheck('connected', 'verifying')).toBe('connecting');
        expect(connStateWithCheck('disconnected', 'verifying')).toBe('connecting');
    });
    it('does not show a route that stopped carrying traffic as connected', () => {
        expect(connStateWithCheck('connected', 'failed')).toBe('connecting');
    });
    it('leaves the posture alone when the check agrees or is silent', () => {
        expect(connStateWithCheck('connected', 'ok')).toBe('connected');
        expect(connStateWithCheck('connected', 'degraded')).toBe('connected');
        expect(connStateWithCheck('connected', undefined)).toBe('connected');
        expect(connStateWithCheck('disconnected', undefined)).toBe('disconnected');
    });
    // What the engine reports after a connect that failed: posture
    // Recovery (-> 'connecting'), route_check 'failed', and nothing
    // running — the route was torn down and put in a cooldown, and the
    // engine never picks another. This used to read "Connecting…" for
    // good; on Android, where the connect call itself resolves early,
    // with no error anywhere.
    it('shows a failed connect as an error, not as connecting', () => {
        expect(connStateWithCheck('connecting', 'failed', false)).toBe('error');
        // Whatever the posture still reads.
        expect(connStateWithCheck('connected', 'failed', false)).toBe('error');
        expect(connStateWithCheck('disconnected', 'failed', false)).toBe('error');
    });
    // A connected route that stopped carrying: same posture, same
    // check, but the engine keeps it up and re-checks it.
    it('shows a lost connection the engine is retrying as connecting', () => {
        expect(connStateWithCheck('connecting', 'failed', true)).toBe('connecting');
        expect(connStateWithCheck('connected', 'failed', true)).toBe('connecting');
    });
    it('claims nothing new when the engine does not say what is running', () => {
        expect(connStateWithCheck('connecting', 'failed', undefined)).toBe('connecting');
        expect(connStateWithCheck('connecting', 'failed')).toBe('connecting');
    });
    it('only a failed check turns a stopped engine into an error', () => {
        expect(connStateWithCheck('disconnected', undefined, false)).toBe('disconnected');
        expect(connStateWithCheck('connecting', 'verifying', false)).toBe('connecting');
    });
});

describe('copy', () => {
    it('says "checking" while verifying and "slow" when degraded', () => {
        expect(checkHeadlineKey('connecting', 'verifying')).toBe('conn.headline_checking');
        expect(checkStateLabelKey('connecting', 'verifying')).toBe('conn.checking');
        expect(checkHeadlineKey('connected', 'degraded')).toBe('conn.headline_slow');
        expect(checkStateLabelKey('connected', 'degraded')).toBe('conn.state.slow');
        expect(checkHeadlineKey('connected', 'ok')).toBeUndefined();
        expect(checkHeadlineKey('connecting', undefined)).toBeUndefined();
        expect(checkStateLabelKey('disconnected', undefined)).toBeUndefined();
    });
    it('tells a failed connect from a lost connection, in both languages', () => {
        const failed = connStateWithCheck('connecting', 'failed', false);
        const lost = connStateWithCheck('connecting', 'failed', true);
        const e = en as Record<string, string>;
        const f = fa as Record<string, string>;

        const failedHead = checkHeadlineKey(failed, 'failed')!;
        const lostHead = checkHeadlineKey(lost, 'failed')!;
        expect(failedHead).toBe('conn.headline_route_failed');
        expect(lostHead).toBe('conn.headline_lost');
        expect(checkStateLabelKey(failed, 'failed')).toBe('conn.state.route_failed');
        expect(checkStateLabelKey(lost, 'failed')).toBe('conn.state.lost');

        // Neither is the generic "Connecting…", and they differ.
        for (const dict of [e, f]) {
            expect(dict[failedHead]).not.toBe(dict['conn.headline_connecting']);
            expect(dict[lostHead]).not.toBe(dict['conn.headline_connecting']);
            expect(dict[failedHead]).not.toBe(dict[lostHead]);
        }
        expect(e[failedHead]).toBe('Could not connect on this route. Try another one.');
        expect(e[lostHead]).toBe('Connection lost. Trying again…');
    });
    it('has every key in English and Persian', () => {
        const keys = [
            'conn.headline_checking',
            'conn.checking',
            'conn.headline_slow',
            'conn.state.slow',
            'conn.headline_route_failed',
            'conn.headline_lost',
            'conn.state.route_failed',
            'conn.state.lost',
        ];
        for (const k of keys) {
            expect((en as Record<string, string>)[k], `en ${k}`).toBeTruthy();
            expect((fa as Record<string, string>)[k], `fa ${k}`).toBeTruthy();
        }
    });
});
