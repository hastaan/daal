// The connection check must win over the posture: a route the engine is
// still proving is never shown as connected (end-to-end rig finding
// CEN-1 — "Connected" used to mean "the engine started").
import { describe, expect, it } from 'vitest';
import {
    checkHeadlineKey,
    checkStateLabelKey,
    connectFailedKey,
    connectRefusedKey,
    connStateWithCheck,
    parseConnectRefused,
    parseRouteCheck,
    parseRouteRunning,
    refusedToShow,
    tapAction,
    tapLabelKey,
} from './routeCheck';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import networkPageSource from '../d2pages/NetworkPage.tsx?raw';

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
        expect(e[lostHead]).toBe('Reconnecting…');
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

// Backlog TW-7 (the rig's CEN-5 remainder): while a lost connection is
// being retried the page is in the 'connecting' state, where a tap used
// to mean "connect" — refused by the route's cooldown, with no way to
// disconnect at all.
describe('tapAction — a tap stops whatever is running', () => {
    it('disconnects a lost connection that is being retried', () => {
        const lost = connStateWithCheck('connecting', 'failed', true);
        expect(lost).toBe('connecting');
        expect(tapAction(lost, 'failed')).toBe('disconnect');
        expect(tapLabelKey(tapAction(lost, 'failed'), lost, 'failed')).toBe('conn.disconnect_action');
    });
    it('cancels a connect that is still being checked', () => {
        expect(tapAction('connecting', 'verifying')).toBe('disconnect');
        // Nothing was connected yet: the word is Cancel.
        expect(tapLabelKey('disconnect', 'connecting', 'verifying')).toBe('conn.cancel_action');
    });
    it('cancels a connect the page itself has in flight, before the engine says so', () => {
        expect(tapAction('connecting', undefined, true)).toBe('disconnect');
        expect(tapLabelKey('disconnect', 'connecting', undefined)).toBe('conn.cancel_action');
    });
    it('disconnects when connected, slow or not', () => {
        expect(tapAction('connected', 'ok')).toBe('disconnect');
        expect(tapAction('connected', 'degraded')).toBe('disconnect');
        expect(tapLabelKey('disconnect', 'connected', 'ok')).toBe('conn.disconnect_action');
    });
    it('opens recovery after a failed connect and connects from rest', () => {
        const failed = connStateWithCheck('connecting', 'failed', false);
        expect(tapAction(failed, 'failed')).toBe('recovery');
        expect(tapAction('disconnected', undefined)).toBe('connect');
        // 'connecting' with nothing known to be running is not a reason
        // to send a disconnect.
        expect(tapAction('connecting', undefined)).toBe('connect');
        expect(tapLabelKey('connect', 'disconnected', undefined)).toBe('conn.connect_action');
    });
});

// "Try again in a moment" needs a button that tries again: the engine
// rests nothing after these two failures and the error never clears by
// itself, and the button under that headline reads "Connect".
describe('tapAction — a failed connect the engine does not rest can be retried', () => {
    const failed = connStateWithCheck('connecting', 'failed', false);
    it('connects the same route again after "too slow" and "the server has no internet"', () => {
        expect(failed).toBe('error');
        for (const category of ['path_too_slow', 'relay_no_egress']) {
            expect(checkHeadlineKey(failed, 'failed', category)).not.toBe('conn.headline_route_failed');
            const action = tapAction(failed, 'failed', false, category);
            expect(action, category).toBe('connect');
            expect(tapLabelKey(action, failed, 'failed')).toBe('conn.connect_action');
        }
    });
    it('still opens recovery for a failure that rests the route, or an unknown one', () => {
        expect(tapAction(failed, 'failed', false, 'tcp_connect_timeout')).toBe('recovery');
        expect(tapAction(failed, 'failed', false, 'something_new')).toBe('recovery');
        expect(tapAction(failed, 'failed', false, undefined)).toBe('recovery');
        // An error that is not a failed connect check (the summary could
        // not be read) is not a reason to connect, whatever category a
        // stale blob still carries.
        expect(tapAction('error', undefined, false, 'path_too_slow')).toBe('recovery');
    });
    it('a retry in flight is cancelled by a second tap, as any connect is', () => {
        expect(tapAction('connecting', undefined, true, 'path_too_slow')).toBe('disconnect');
    });
});

describe('failed connects that are not the route\'s fault', () => {
    it('says "too slow" and "the server has no internet" instead of "try another one"', () => {
        expect(checkHeadlineKey('error', 'failed', 'path_too_slow')).toBe('conn.headline_too_slow');
        expect(checkHeadlineKey('error', 'failed', 'relay_no_egress')).toBe('conn.headline_relay_no_internet');
        expect(checkHeadlineKey('error', 'failed', 'tcp_connect_timeout')).toBe('conn.headline_route_failed');
        // A category this app has never heard of is not displayed and
        // not guessed at.
        expect(checkHeadlineKey('error', 'failed', '<b>anything</b>')).toBe('conn.headline_route_failed');
        expect(checkHeadlineKey('error', 'failed')).toBe('conn.headline_route_failed');
    });
});

describe('connect_refused', () => {
    it('is a closed vocabulary', () => {
        for (const v of ['needs_new_file', 'cooldown', 'revoked', 'expired', 'other']) {
            expect(parseConnectRefused(v)).toBe(v);
        }
        for (const v of ['', undefined, null, 'NEEDS_NEW_FILE', 'route r1 has no signed endpoint', 7]) {
            expect(parseConnectRefused(v)).toBeUndefined();
        }
    });
    it('tells a person with an old file to ask for a new one, in both languages', () => {
        const key = connectRefusedKey('needs_new_file');
        expect(key).toBe('conn.refused.needs_new_file');
        expect((en as Record<string, string>)[key]).toBe(
            'This file was made by an older version of Daal. Ask the person who gave it to you for a new one.',
        );
        expect((fa as Record<string, string>)[key]).toBeTruthy();
        expect((fa as Record<string, string>)[key]).not.toBe((en as Record<string, string>)[key]);
    });
    it('has copy for every code and every new key, en and fa', () => {
        const keys = [
            ...(['needs_new_file', 'cooldown', 'revoked', 'expired', 'other'] as const).map(connectRefusedKey),
            'conn.cancel_action',
            'conn.headline_too_slow',
            'conn.headline_relay_no_internet',
        ];
        for (const k of keys) {
            expect((en as Record<string, string>)[k], `en ${k}`).toBeTruthy();
            expect((fa as Record<string, string>)[k], `fa ${k}`).toBeTruthy();
        }
    });
});

// Review finding on the routes page: connected on route A, tap Connect
// on route B that the engine refuses (old file, cooling down, revoked,
// expired). The engine leaves A up, so the page still has an active
// route — and the sentence was hidden behind "nothing is active". The
// button went Connecting… -> Connect and the page said nothing.
describe('refusedToShow', () => {
    it('answers a tap on this page even while another route is connected', () => {
        for (const code of ['needs_new_file', 'cooldown', 'revoked', 'expired', 'other'] as const) {
            expect(refusedToShow(code, code, true)).toBe(code);
            // The poll may not have caught up, or may have been cleared.
            expect(refusedToShow(undefined, code, true)).toBe(code);
            expect(refusedToShow(undefined, code, false)).toBe(code);
        }
    });
    it('the tap wins over an older refusal still in the diagnostics', () => {
        expect(refusedToShow('cooldown', 'needs_new_file', false)).toBe('needs_new_file');
    });
    it('shows the engine\'s standing refusal only when nothing is running', () => {
        // Android: the connect call returns before the engine decides,
        // so the poll is the only way the reason arrives.
        expect(refusedToShow('cooldown', undefined, false)).toBe('cooldown');
        // Old news about an earlier attempt while a route works.
        expect(refusedToShow('cooldown', undefined, true)).toBeUndefined();
        expect(refusedToShow(undefined, undefined, false)).toBeUndefined();
    });
});

// Review finding on the routes page: tap Connect on a blocked route.
// The route starts, its connection check fails, and the desktop shell
// rejects the call with "engine call returned -1". That is not a
// refusal, so the page put the raw string in its red banner — English
// developer text in a Persian app, with no next step — while the
// Connection page had the right sentence for the same event.
describe('connectFailedKey', () => {
    it('a failed connection check gets the Connection page\'s sentence, by the same category rule', () => {
        expect(connectFailedKey('failed')).toBe('conn.headline_route_failed');
        expect(connectFailedKey('failed', 'tcp_connect_timeout')).toBe('conn.headline_route_failed');
        expect(connectFailedKey('failed', 'path_too_slow')).toBe('conn.headline_too_slow');
        expect(connectFailedKey('failed', 'relay_no_egress')).toBe('conn.headline_relay_no_internet');
        for (const cat of [undefined, 'path_too_slow', 'relay_no_egress', '<b>x</b>']) {
            expect(connectFailedKey('failed', cat)).toBe(checkHeadlineKey('error', 'failed', cat));
        }
    });
    it('anything else gets a plain sentence of ours, never nothing', () => {
        // The summary could not be read, or the engine said nothing.
        for (const check of [undefined, 'verifying', 'ok', 'degraded'] as const) {
            expect(connectFailedKey(check)).toBe('conn.connect_failed');
            expect(connectFailedKey(check, 'path_too_slow')).toBe('conn.connect_failed');
        }
    });
    it('every sentence it can choose exists in both languages', () => {
        const keys = [
            connectFailedKey(undefined),
            connectFailedKey('failed'),
            connectFailedKey('failed', 'path_too_slow'),
            connectFailedKey('failed', 'relay_no_egress'),
        ];
        for (const k of keys) {
            expect((en as Record<string, string>)[k], k).toBeTruthy();
            expect((fa as Record<string, string>)[k], k).toBeTruthy();
            expect((fa as Record<string, string>)[k], k).not.toBe((en as Record<string, string>)[k]);
        }
    });
    it('the routes page shows that sentence, not the caught error\'s text', () => {
        // The page is pinned on its source (the way
        // connectThreading.test.ts pins the hosts): the Connect handler
        // runs from its header to the next row callback.
        const i = networkPageSource.indexOf('const onConnectRoute = async');
        const j = networkPageSource.indexOf('const pendingId =');
        expect(i).toBeGreaterThanOrEqual(0);
        expect(j).toBeGreaterThan(i);
        const handler = networkPageSource
            .slice(i, j)
            .split('\n')
            .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
            .join('\n');
        expect(handler).toContain('connectFailedKey(');
        expect(handler).not.toMatch(/\.message\b/);
        expect(handler).not.toMatch(/String\(e\)/);
        // The caught error's text goes one place only: the `detail` that
        // the page folds under "Details". The sentence is always a key.
        expect(handler.match(/errorText\(/g)).toHaveLength(1);
        expect(handler).toMatch(/detail: errorText\(e\)/);
        // ...either the one for a switch that went back to the route
        // that was connected (a key too: lib/networkRows.ts), or the
        // engine's verdict.
        expect(handler).toMatch(/key: wentBackKey \?\? connectFailedKey\(/);
        expect(handler).toMatch(/const wentBackKey = summary \? pendingFailureKey\(/);
    });
});
