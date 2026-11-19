// The badge on a relay must not contradict its caption.
//
// On the first real-phone pass the relay card showed a green "LIVE"
// directly above "Setup state — not a live health check." Both came
// from the same recorded field. A badge drawn from the recorded state
// now names that state and is never green; "Live" needs a check that
// has just succeeded.
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import listSource from './RelayListPage.tsx?raw';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import { relayBadge } from './relayStatus';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const STATES = ['provisioned', 'pre-provision', 'decommissioned', 'rebuild_failed', 'something-new'];

describe('relayBadge', () => {
    it('a recorded state is never green and never says live', () => {
        for (const s of STATES) {
            const b = relayBadge(s);
            expect(b.recordedOnly, s).toBe(true);
            expect(b.tone, s).not.toBe('good');
            expect(b.labelKey, s).not.toBe('pub.relays.status.live');
            expect(EN[b.labelKey], `en ${s}`).toBeTruthy();
            expect(FA[b.labelKey], `fa ${s}`).toBeTruthy();
            expect(EN[b.labelKey], `en ${s}`).not.toMatch(/\blive\b/i);
        }
    });

    it('a finished relay reads "Set up"', () => {
        expect(EN[relayBadge('provisioned').labelKey]).toBe('Set up');
    });

    it('live, in green, is reserved for a check that just succeeded', () => {
        const b = relayBadge('provisioned', true);
        expect(b).toEqual({ tone: 'good', labelKey: 'pub.relays.status.live', recordedOnly: false });
        expect(EN[b.labelKey]).toMatch(/live/i);
        expect(FA[b.labelKey]).toBeTruthy();
        // A check cannot make an unfinished or removed relay live.
        for (const s of STATES.filter((x) => x !== 'provisioned')) {
            expect(relayBadge(s, true).tone, s).not.toBe('good');
        }
    });

    it('the caption is shown exactly when the badge is only the recorded state', () => {
        // One value drives both, in the list…
        const gate = listSource.indexOf('badge.recordedOnly');
        const caption = listSource.indexOf("t('pub.relays.status.disclaimer')");
        expect(gate).toBeGreaterThan(0);
        expect(caption - gate).toBeGreaterThan(0);
        expect(caption - gate).toBeLessThan(900);
        // (the only place the caption is rendered)
        expect(listSource.split('pub.relays.status.disclaimer').length).toBe(2);
        // …and neither screen derives a tone or a label any other way.
        for (const src of [listSource, pageSource]) {
            expect(/statusTone|statusKey/.test(src)).toBe(false);
            expect(/\{operator\.status\}/.test(src)).toBe(false);
            expect(/status === 'provisioned'\s*\?\s*'good'/.test(src)).toBe(false);
        }
        expect(EN['pub.relays.status.disclaimer']).not.toMatch(/setup state/i);
    });
});
