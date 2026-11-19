// A failure is told in plain words; the raw error is kept, not shown as
// the sentence.
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import { explainFailure, failureBlock, failureKey } from './failureText';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? k;

describe('failureKey', () => {
    it.each([
        ['context deadline exceeded', 'pub.fail.unreachable'],
        ['dial tcp 203.0.113.7:8443: connection refused', 'pub.fail.unreachable'],
        ['read: i/o timeout', 'pub.fail.unreachable'],
        ['E_HELPER_IP_STALE: allowlist', 'pub.helper_ip.stale'],
        ['E_RELAY_TOO_OLD: no rotate-tls verb', 'pub.rotate.too_old'],
        ['E_RELAY_KEYS_CHANGED: reality key', 'pub.relay_keys_changed'],
        ['E_CUSTODY_LOCKED: locked', 'pub.fail.locked'],
        ['some error nobody classified', 'pub.fail.generic'],
        ['', 'pub.fail.generic'],
    ])('%s → %s', (raw, key) => {
        expect(failureKey(raw)).toBe(key);
        expect(failureKey(new Error(raw))).toBe(key);
    });

    it('has a sentence for every explanation, in English and Persian', () => {
        for (const k of [
            'pub.fail.unreachable',
            'pub.fail.locked',
            'pub.fail.generic',
            'pub.helper_ip.stale',
            'pub.rotate.too_old',
            'pub.relay_keys_changed',
        ]) {
            expect(EN[k], `en ${k}`).toBeTruthy();
            expect(FA[k], `fa ${k}`).toBeTruthy();
        }
    });
});

describe('explainFailure', () => {
    it('never uses the raw error as the sentence', () => {
        const f = explainFailure(t, 'E_WHATEVER: context deadline exceeded (os error 110)');
        expect(f.message).toBe(EN['pub.fail.unreachable']);
        expect(f.message).not.toMatch(/E_|deadline|os error/);
        expect(f.detail).toBe('E_WHATEVER: context deadline exceeded (os error 110)');
    });

    it('survives a thrown value that is not a string or an Error', () => {
        expect(explainFailure(t, undefined)).toEqual({ message: EN['pub.fail.generic'], detail: '' });
        expect(explainFailure(t, { code: 7 }).message).toBe(EN['pub.fail.generic']);
    });

    it('as a block: plain words, a blank line, then the raw text', () => {
        expect(failureBlock(t, 'boom')).toBe(`${EN['pub.fail.generic']}\n\nboom`);
        expect(failureBlock(t, null)).toBe(EN['pub.fail.generic']);
    });
});
