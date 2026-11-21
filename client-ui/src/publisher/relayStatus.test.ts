// The badge on a relay must not contradict what was measured.
//
// On the first real-phone pass the relay card showed a green "LIVE"
// directly above "Setup state — not a live health check." Both came
// from the same recorded field. Green ("Working") now needs a health
// check that said so; a recorded state is never green (spec C7.1).
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import listSource from './RelayListPage.tsx?raw';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import { relayLook, relayUnfinished } from './relayStatus';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const STATES = ['provisioned', 'pre-provision', 'decommissioned', 'rebuild_failed', 'something-new'];
const op = (status: string, has_signed_sbp = true) => ({ status, has_signed_sbp });

describe('relayLook', () => {
    it('a recorded state is never green', () => {
        for (const s of STATES) {
            for (const signed of [true, false]) {
                const b = relayLook(op(s, signed), null);
                expect(b.recordedOnly, s).toBe(true);
                expect(b.tone, s).not.toBe('good');
                expect(EN[b.labelKey], `en ${s}`).toBeTruthy();
                expect(FA[b.labelKey], `fa ${s}`).toBeTruthy();
            }
        }
    });

    it('a finished relay nobody checked reads "Not checked"', () => {
        expect(EN[relayLook(op('provisioned'), null).labelKey]).toBe('Not checked');
        expect(EN[relayLook(op('provisioned'), { overall: 'unknown' }).labelKey]).toBe('Not checked');
    });

    it('green is reserved for a check that said "working"; partly and not working say so', () => {
        expect(relayLook(op('provisioned'), { overall: 'working' })).toMatchObject({ tone: 'good', icon: 'ok' });
        expect(EN[relayLook(op('provisioned'), { overall: 'working' }).labelKey]).toBe('Working');
        expect(relayLook(op('provisioned'), { overall: 'partly' }).tone).toBe('warn');
        expect(relayLook(op('provisioned'), { overall: 'not_working' }).tone).toBe('bad');
        // A check cannot make an unfinished, gone or retired relay green.
        for (const s of STATES.filter((x) => x !== 'provisioned')) {
            expect(relayLook(op(s), { overall: 'working' }).tone, s).not.toBe('good');
        }
        expect(relayLook(op('provisioned', false), { overall: 'working' }).tone).not.toBe('good');
    });

    it('an unfinished relay says "may cost money", in full (MUST KEEP 1)', () => {
        const b = relayLook(op('pre-provision', false), null);
        expect(b.wrap).toBe(true);
        expect(EN[b.labelKey]).toMatch(/may cost money/);
        expect(relayUnfinished(op('provisioned', false))).toBe(true);
        expect(relayUnfinished(op('decommissioned', false))).toBe(false);
    });

    it('both screens take the badge from relayLook and from nothing else', () => {
        for (const src of [listSource, pageSource]) {
            expect(src).toContain('relayLook(');
            expect(/statusTone|statusKey|relayBadge\(/.test(src)).toBe(false);
            expect(/\{operator\.status\}/.test(src)).toBe(false);
            expect(/status === 'provisioned'\s*\?\s*'good'/.test(src)).toBe(false);
        }
        // The old caption under a recorded badge is gone with the badge.
        expect(listSource.includes('pub.relays.status.disclaimer')).toBe(false);
    });
});
