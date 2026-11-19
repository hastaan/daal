// The strings of the selection wave live in client-shared/i18n (the
// source tools/sync-i18n.mjs copies from on build) and are mirrored
// into src/i18n/d2. A string added to only one side ships on a dev run
// and vanishes on the next build — or the other way round.
import { describe, expect, it } from 'vitest';
import srcEn from '../../../client-shared/i18n/d2-extra.en.json';
import srcFa from '../../../client-shared/i18n/d2-extra.fa.json';
import mirrorEn from '../i18n/d2/d2-extra.en.json';
import mirrorFa from '../i18n/d2/d2-extra.fa.json';
import { translate } from './i18n';

const EN = srcEn as Record<string, string>;
const FA = srcFa as Record<string, string>;
const OURS = /^(auto\.|network\.auto\.|network\.pinned\.|network\.badge\.|add\.lede\.|add\.paste_help\.|add\.file\.sealed)/;

describe('selection-wave strings', () => {
    it('the mirror the app bundles is the source of truth, byte for byte', () => {
        expect(mirrorEn).toEqual(srcEn);
        expect(mirrorFa).toEqual(srcFa);
    });
    it('every one exists in English and in Persian, and the Persian is Persian', () => {
        const keys = Object.keys(EN).filter((k) => OURS.test(k));
        expect(keys.length).toBeGreaterThan(60);
        for (const k of keys) {
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toBeTruthy();
            expect(FA[k], k).toMatch(/[؀-ۿ]/);
        }
        // ...and nothing Persian-only.
        for (const k of Object.keys(FA).filter((k) => OURS.test(k))) expect(EN[k], k).toBeTruthy();
    });
    it('placeholders survive translation', () => {
        for (const k of Object.keys(EN).filter((k) => OURS.test(k))) {
            const ph = (s: string) => (s.match(/\{[a-z]+\}/g) ?? []).sort().join(',');
            expect(ph(FA[k]), k).toBe(ph(EN[k]));
        }
    });
    it('reach the app through translate()', () => {
        expect(translate('en', 'auto.chooser.automatic')).toBe('Automatic');
        expect(translate('fa', 'auto.chooser.back')).toBe(FA['auto.chooser.back']);
        expect(translate('en', 'add.paste_placeholder')).toBe('Paste what you were sent');
    });
});
