import { beforeEach, describe, expect, it } from 'vitest';
import {
    markStoreResetNoticeSeen,
    resetStoreNoticeMemoryForTest,
    storeResetNoticeDue,
} from './storeNotice';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';

function fakeStore() {
    const m = new Map<string, string>();
    return {
        getItem: (k: string) => m.get(k) ?? null,
        setItem: (k: string, v: string) => void m.set(k, v),
    };
}

describe('the "saved connections were reset" notice', () => {
    beforeEach(() => resetStoreNoticeMemoryForTest());

    it('is not shown unless the engine reports store_recovered', () => {
        expect(storeResetNoticeDue(false, fakeStore())).toBe(false);
    });
    it('is shown on every poll until read, then never again in this run', () => {
        const store = fakeStore();
        expect(storeResetNoticeDue(true, store)).toBe(true);
        expect(storeResetNoticeDue(true, store)).toBe(true);
        markStoreResetNoticeSeen(store);
        expect(storeResetNoticeDue(true, store)).toBe(false);
        // Another page (a fresh module state, the same storage).
        resetStoreNoticeMemoryForTest();
        expect(storeResetNoticeDue(true, store)).toBe(false);
    });
    it('still shows once, then stops, in a webview with no storage', () => {
        expect(storeResetNoticeDue(true, undefined)).toBe(true);
        markStoreResetNoticeSeen(undefined);
        expect(storeResetNoticeDue(true, undefined)).toBe(false);
    });
    it('survives a storage that throws', () => {
        const broken = {
            getItem: () => { throw new Error('denied'); },
            setItem: () => { throw new Error('denied'); },
        };
        expect(storeResetNoticeDue(true, broken)).toBe(true);
        markStoreResetNoticeSeen(broken);
        expect(storeResetNoticeDue(true, broken)).toBe(false);
    });
    it('says it in plain words, in both languages, and tells the person what to do', () => {
        const e = en as Record<string, string>;
        const f = fa as Record<string, string>;
        for (const k of ['store.reset.title', 'store.reset.body', 'store.reset.dismiss']) {
            expect(e[k], k).toBeTruthy();
            expect(f[k], k).toBeTruthy();
            expect(f[k]).not.toBe(e[k]);
        }
        expect(e['store.reset.body']).toContain('Add your file again');
        expect(e['store.reset.title'] + e['store.reset.body']).not.toMatch(/sqlite|database|store|corrupt/i);
    });
});
