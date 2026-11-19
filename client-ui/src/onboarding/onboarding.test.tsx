/// <reference types="vite/client" />
// First run, as a person meets it (seen stale on a phone 2026-11-19:
// "an SSH key", "read these four words" with no words, a source-URL
// box). Language first, then who you are; a helper gets one honest
// page and lands on Publisher.
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { Prefs } from '../lib/prefs';
import { WELCOME_LANGUAGES } from './Onboarding';
import source from './Onboarding.tsx?raw';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';

describe('first run', () => {
    beforeEach(() => {
        const store = new Map<string, string>();
        vi.stubGlobal('localStorage', {
            getItem: (k: string) => store.get(k) ?? null,
            setItem: (k: string, v: string) => void store.set(k, v),
            removeItem: (k: string) => void store.delete(k),
        });
    });

    it('offers Farsi and English, each in its own script, Farsi first', () => {
        expect(WELCOME_LANGUAGES.map((l) => l.locale)).toEqual(['fa', 'en']);
        expect(WELCOME_LANGUAGES[0].label).toBe('فارسی');
        expect(WELCOME_LANGUAGES[1].label).toBe('English');
    });

    it('the helper page asks for nothing technical, in both languages', () => {
        const e = (en as Record<string, string>)['onboarding.p2.body'];
        const f = (fa as Record<string, string>)['onboarding.p2.body'];
        for (const text of [e, f]) {
            expect(text).not.toMatch(/SSH|VPS/i);
            expect(text.length).toBeGreaterThan(40);
        }
        expect(f).not.toBe(e);
    });

    it('no longer shows the pages of the old design', () => {
        for (const key of ['onboarding.r3', 'onboarding.r4', 'onboarding.p4', 'onboarding.r2']) {
            expect(source).not.toContain(key);
        }
    });

    it('a helper lands on Publisher once, and only once', () => {
        expect(Prefs.takeFirstSection()).toBeNull();
        Prefs.setFirstSection('publisher');
        expect(Prefs.takeFirstSection()).toBe('publisher');
        expect(Prefs.takeFirstSection()).toBeNull();
    });
});
