/// <reference types="vite/client" />
// First run, as a person meets it (seen stale on a phone 2026-11-19:
// "an SSH key", "read these four words" with no words, a source-URL
// box). Language first, then who you are; a helper gets one honest
// page and lands on Publisher.
import { describe, expect, it, beforeEach, vi } from 'vitest';
import { Prefs } from '../lib/prefs';
import { WELCOME_LANGUAGES, chooseLane } from './Onboarding';
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

    it('a helper goes straight to Publisher: no intro page, no "not sure" card', () => {
        // The cost is said by the relay wizard's first step
        // (wiz.step.cloud.line, PUBLISHER lane), where the money is spent.
        for (const key of ['onboarding.p2', 'onboarding.branch.unsure', "setScreen('P2')"]) {
            expect(source).not.toContain(key);
        }
        expect((en as Record<string, string>)['onboarding.branch.publisher']).toBe("I'm helping family connect");
        expect((fa as Record<string, string>)['onboarding.branch.publisher']).toMatch(/[؀-ۿ]/);
    });

    it('"I\'m helping family connect" turns Publisher on and opens it first; "I want to connect" does not', () => {
        chooseLane('publisher');
        expect(Prefs.lane()).toBe('publisher');
        expect(Prefs.publisherEnabled()).toBe(true);
        expect(Prefs.onboardingCompleted()).toBe(true);
        expect(Prefs.takeFirstSection()).toBe('publisher');
    });

    it('"I want to connect" finishes onboarding and opens nothing else first', () => {
        chooseLane('recipient');
        expect(Prefs.lane()).toBe('recipient');
        expect(Prefs.onboardingCompleted()).toBe(true);
        expect(Prefs.takeFirstSection()).toBeNull();
    });

    it('the welcome screen: tapping a language goes on at once, and has no corner toggle', () => {
        // Each language button sets the language and moves to "Who is this for?".
        expect(source).toMatch(/setLocale\(l\.locale\);\s*setScreen\('B'\);/);
        expect(source).not.toContain("lang.fa')");
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
