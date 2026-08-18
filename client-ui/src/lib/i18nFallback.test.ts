// Regression guard for the empty-value fallback in `translate`.
//
// `onboarding.fa.json` ships 119 keys whose values are all "" and
// `mobile.fa.json` 100 of 104. `translate` used to test `!= null`,
// which an empty string passes, so those keys rendered as NOTHING for
// a Farsi user while the English build looked perfect. Nothing reads
// them today, but the catalogues are loaded, so the bug was one t()
// call away — and it is invisible to English-speaking review.
import { describe, expect, it } from 'vitest';
import { translate } from './i18n';
import onboardingFa from '../i18n/d2/onboarding.fa.json';
import onboardingEn from '../i18n/d2/onboarding.en.json';

describe('translate() empty-value fallback', () => {
    it('the fixture this guards is real: onboarding.fa is entirely empty', () => {
        const vals = Object.values(onboardingFa as Record<string, string>);
        expect(vals.length).toBeGreaterThan(0);
        expect(vals.every((v) => v === '')).toBe(true);
    });

    it('falls back to English rather than rendering empty', () => {
        const key = 'cap.p.name.note';
        const en = (onboardingEn as Record<string, string>)[key];
        expect(en).toBeTruthy();
        // The FA catalogue has this key present-but-empty.
        expect((onboardingFa as Record<string, string>)[key]).toBe('');
        expect(translate('fa', key)).toBe(en);
    });

    it('still returns the bare key when neither catalogue has it', () => {
        expect(translate('fa', 'no.such.key.anywhere')).toBe('no.such.key.anywhere');
    });

    it('a real Farsi translation is still preferred over English', () => {
        // Shipped onboarding copy lives in the legacy fa.json.
        const fa = translate('fa', 'onboarding.welcome.title');
        expect(fa).toBe('به دال خوش آمدید');
        expect(fa).not.toBe(translate('en', 'onboarding.welcome.title'));
    });
});
