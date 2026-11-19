// Backlog PH-27 (last part): a file chosen with the file picker was
// labelled "pasted" on the Connections page.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { importOriginOf, recordImportOrigin, sourceBadgeKey } from './importOrigin';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const store = new Map<string, string>();
beforeEach(() => {
    store.clear();
    vi.stubGlobal('localStorage', {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
    });
});
afterEach(() => vi.unstubAllGlobals());

describe('import origin', () => {
    it('remembers the lane per publisher, whatever the case of the fingerprint', () => {
        recordImportOrigin('AABBCC', 'file');
        recordImportOrigin('ddeeff', 'paste');
        expect(importOriginOf('aabbcc')).toBe('file');
        expect(importOriginOf('DDEEFF')).toBe('paste');
        expect(importOriginOf('unknown')).toBeUndefined();
        // The latest import wins.
        recordImportOrigin('aabbcc', 'scan');
        expect(importOriginOf('aabbcc')).toBe('scan');
    });
    it('records nothing without a fingerprint, and survives no storage or damaged storage', () => {
        recordImportOrigin('', 'file');
        recordImportOrigin(undefined, 'file');
        expect(store.size).toBe(0);
        store.set('daal.d2.import_origin', '{not json');
        expect(importOriginOf('aabbcc')).toBeUndefined();
        vi.stubGlobal('localStorage', undefined);
        expect(() => recordImportOrigin('aabbcc', 'file')).not.toThrow();
        expect(importOriginOf('aabbcc')).toBeUndefined();
    });
});

describe('the badge', () => {
    it('a file import is "from a file" — whatever the trust class guessed', () => {
        // The phone-pass row: the guess fell through to 'pasted'.
        expect(sourceBadgeKey('pasted', 'file')).toBe('network.badge.file');
        expect(sourceBadgeKey('sbp', 'file')).toBe('network.badge.file');
        expect(sourceBadgeKey('pasted', 'sealed_file')).toBe('network.badge.sealed');
    });
    it('"pasted" only when it WAS pasted; with nothing recorded, only what is certain', () => {
        expect(sourceBadgeKey('pasted', 'paste')).toBe('network.badge.pasted');
        expect(sourceBadgeKey('pasted', undefined)).toBe('network.badge.added');
        expect(sourceBadgeKey('pasted', 'scan')).toBe('network.badge.scanned');
    });
    it('subscriptions keep their badge; the signature guesses stand when nothing is recorded', () => {
        expect(sourceBadgeKey('subscription', 'file')).toBe('network.badge.subscription');
        expect(sourceBadgeKey('mixed', 'paste')).toBe('network.badge.mixed');
        expect(sourceBadgeKey('sbpx', undefined)).toBe('network.badge.sealed');
        expect(sourceBadgeKey('sbp', undefined)).toBe('network.badge.signed');
    });
    it('every badge has words in both languages', () => {
        const kinds = ['sbpx', 'sbp', 'subscription', 'pasted', 'mixed'] as const;
        const origins = [undefined, 'file', 'sealed_file', 'paste', 'scan'] as const;
        for (const k of kinds) {
            for (const o of origins) {
                const key = sourceBadgeKey(k, o);
                expect((en as Record<string, string>)[key], key).toBeTruthy();
                expect((fa as Record<string, string>)[key], key).toMatch(/[؀-ۿ]/);
            }
        }
    });
});
