// The network test's state machine and its words (lib/netTest.ts).
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import {
    ABORT_REASONS,
    NETWORK_LABELS,
    REFUSAL_CODES,
    SEAL_REFUSALS,
    SUMMARY_KEYS,
    abortKey,
    canRunAgain,
    fill,
    parseSeal,
    parseStart,
    parseStatus,
    progress,
    refusalKey,
    resultLines,
    rowShown,
    sealRefusalKey,
    viewOf,
} from './netTest';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;

const IDLE = {
    state: 'idle',
    plan: { steps: 23, minutes: 4, consent_version: 1, names: ['www.google.com', 'github.com', 3, ''], public_resolver: '1.1.1.1' },
    has_test_relay: true,
    publisher_id: 'pars-relays',
};

describe('status', () => {
    it('reads the three shapes the engine answers', () => {
        const idle = parseStatus(JSON.stringify(IDLE));
        expect(idle).toEqual({
            kind: 'idle',
            plan: { steps: 23, minutes: 4, consentVersion: 1, names: ['www.google.com', 'github.com'], publicResolver: '1.1.1.1' },
            offered: true,
            publisherId: 'pars-relays',
        });
        expect(parseStatus('{"state":"running","step":7,"of":23}')).toEqual({ kind: 'running', step: 7, of: 23 });
        const done = parseStatus({
            state: 'done',
            complete: true,
            abort_reason: '',
            net_kind: 'wifi',
            summary: ['netTest.summary.relayConnects', 'netTest.summary.fromTheFuture', 7, 'netTest.summary.privacy'],
            has_test_relay: false,
        });
        expect(done).toMatchObject({
            kind: 'result',
            complete: true,
            netKind: 'wifi',
            // A key this app has no words for is dropped, never shown.
            summary: ['netTest.summary.relayConnects', 'netTest.summary.privacy'],
        });
        expect(parseStatus({ state: 'aborted', complete: false, abort_reason: 'vpn_active', summary: [] })).toMatchObject({
            kind: 'result',
            complete: false,
            abortReason: 'vpn_active',
        });
    });

    it('anything else is "unavailable": the page offers nothing', () => {
        for (const raw of ['', 'not json', '[]', '{"state":"weird"}', null, 42]) {
            expect(parseStatus(raw)).toEqual({ kind: 'unavailable' });
        }
    });

    it('the row shows for a held test relay, a running test or a kept report, and only then', () => {
        expect(rowShown(parseStatus(IDLE))).toBe(true);
        expect(rowShown(parseStatus({ ...IDLE, has_test_relay: false }))).toBe(false);
        expect(rowShown(parseStatus({ state: 'running', step: 1, of: 23 }))).toBe(true);
        // A report kept from before stays sendable even when the test
        // file is gone.
        expect(rowShown(parseStatus({ state: 'done', complete: true, summary: [], has_test_relay: false }))).toBe(true);
        expect(rowShown({ kind: 'unavailable' })).toBe(false);
    });

    it('the view follows the status', () => {
        expect(viewOf(null)).toBe('loading');
        expect(viewOf(parseStatus(IDLE))).toBe('consent');
        expect(viewOf(parseStatus({ ...IDLE, has_test_relay: false }))).toBe('unavailable');
        expect(viewOf(parseStatus({ state: 'running', step: 3, of: 23 }))).toBe('running');
        expect(viewOf(parseStatus({ state: 'aborted', summary: [] }))).toBe('result');
    });

    it('a kept result can be run again only with a test relay held and a plan', () => {
        const kept = parseStatus({
            state: 'aborted',
            summary: [],
            has_test_relay: true,
            plan: IDLE.plan,
            report: { schema_version: 2, run: { complete: false } },
        });
        expect(canRunAgain(kept)).toBe(true);
        expect(viewOf(kept, true)).toBe('consent');
        expect(viewOf(kept, false)).toBe('result');
        expect(kept.kind === 'result' && kept.plan?.names).toEqual(['www.google.com', 'github.com']);
        expect(kept.kind === 'result' && kept.reportJson).toContain('"schema_version": 2');
        // An older engine (no plan) or no test relay held: the result stays.
        const old = parseStatus({ state: 'aborted', summary: [], has_test_relay: true });
        expect(canRunAgain(old)).toBe(false);
        expect(viewOf(old, true)).toBe('result');
        expect(canRunAgain(parseStatus({ state: 'done', summary: [], has_test_relay: false, plan: IDLE.plan }))).toBe(false);
        expect(canRunAgain(parseStatus(IDLE))).toBe(false);
    });

    it('progress is bounded', () => {
        expect(progress({ kind: 'running', step: 0, of: 23 })).toBe(0);
        expect(progress({ kind: 'running', step: 23, of: 23 })).toBe(1);
        const odd = parseStatus({ state: 'running', step: 99, of: 0 });
        expect(odd.kind === 'running' && progress(odd)).toBe(1);
    });
});

describe('start, seal', () => {
    it('reads a start and its refusal', () => {
        expect(parseStart('{"started":true}')).toEqual({ started: true });
        expect(parseStart('{"started":false,"refused":"rate_limited","retry_after_min":214}')).toEqual({
            started: false,
            refused: 'rate_limited',
            retryAfterMin: 214,
        });
        expect(parseStart('{"started":false,"refused":"vpn_active"}')).toEqual({ started: false, refused: 'vpn_active' });
        expect(parseStart('nope')).toEqual({ started: false, refused: '' });
    });

    it('reads a seal and its refusal', () => {
        expect(parseSeal('{"sealed":true,"path":"/x/net-ab12cd34.dat","file_name":"net-ab12cd34.dat","bytes":9}')).toEqual({
            sealed: true,
            fileName: 'net-ab12cd34.dat',
        });
        expect(parseSeal('{"sealed":false,"refused":"no_result"}')).toEqual({ sealed: false, refused: 'no_result' });
    });
});

describe('every closed code has a plain line, in English and Persian', () => {
    const keys = [
        ...SUMMARY_KEYS,
        ...REFUSAL_CODES.map(refusalKey),
        refusalKey('from_the_future'),
        ...ABORT_REASONS.map((r) => abortKey(r, false)),
        abortKey('from_the_future', false),
        ...SEAL_REFUSALS.map(sealRefusalKey),
        sealRefusalKey('from_the_future'),
        ...NETWORK_LABELS.map((l) => `netTest.label.${l}`),
    ];
    it.each(keys)('%s', (k) => {
        expect(EN[k], `en ${k}`).toBeTruthy();
        expect(FA[k], `fa ${k}`).toBeTruthy();
        // The same placeholders in both.
        const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(',');
        expect(ph(FA[k])).toBe(ph(EN[k]));
    });

    it('an unknown refusal or reason gets the general line, never the code', () => {
        expect(refusalKey('x')).toBe('netTest.refused.other');
        expect(abortKey('x', false)).toBe('netTest.aborted.other');
        expect(sealRefusalKey('x')).toBe('netTest.send.failed');
    });
});

describe('the result card', () => {
    it('a complete run, or one with no reason, says no "stopped because"', () => {
        expect(abortKey('', true)).toBe('');
        expect(abortKey('', false)).toBe('');
        expect(abortKey('vpn_active', false)).toBe('netTest.aborted.vpn_active');
    });

    it('the privacy line is kept for beside Send; "incomplete" goes when the reason is said', () => {
        const s = parseStatus({
            state: 'aborted',
            complete: false,
            abort_reason: 'network_changed',
            summary: ['netTest.summary.googleGithubOpen', 'netTest.summary.incomplete', 'netTest.summary.privacy'],
        });
        expect(s.kind).toBe('result');
        if (s.kind !== 'result') return;
        expect(resultLines(s)).toEqual(['netTest.summary.googleGithubOpen']);
        const blackout = parseStatus({
            state: 'aborted',
            complete: false,
            abort_reason: '',
            summary: ['netTest.summary.blackout', 'netTest.summary.incomplete', 'netTest.summary.privacy'],
        });
        if (blackout.kind !== 'result') throw new Error('not a result');
        expect(resultLines(blackout)).toEqual(['netTest.summary.blackout', 'netTest.summary.incomplete']);
    });

    it('fill puts in the values and leaves unknown placeholders', () => {
        expect(fill('Try again in {n} minutes, {name}. {x}', { n: 5, name: 'Pars' })).toBe('Try again in 5 minutes, Pars. {x}');
    });
});
