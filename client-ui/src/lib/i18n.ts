import legacyEn from '../i18n/en.json';
import legacyFa from '../i18n/fa.json';
// Catalogs mirrored from client-shared/i18n/ via tools/sync-i18n.mjs.
// Only `npm run build` invokes it (package.json "build"); `npm run dev`
// is bare `vite` and does NOT sync — run the mjs by hand after editing a
// shared catalog. Note that the legacy pair imported just above
// (../i18n/{en,fa}.json) is NOT mirrored from anywhere; it is edited in
// place.
import desktopEn from '../i18n/d2/desktop.en.json';
import desktopFa from '../i18n/d2/desktop.fa.json';
import onboardingEn from '../i18n/d2/onboarding.en.json';
import onboardingFa from '../i18n/d2/onboarding.fa.json';
import d2ExtraEn from '../i18n/d2/d2-extra.en.json';
import d2ExtraFa from '../i18n/d2/d2-extra.fa.json';

export type Locale = 'en' | 'fa';
export type LocalePref = 'system' | 'en' | 'fa';

const dictionaries: Record<Locale, Record<string, string>> = {
    en: {
        ...(legacyEn as Record<string, string>),
        ...(desktopEn as Record<string, string>),
        ...(onboardingEn as Record<string, string>),
        ...(d2ExtraEn as Record<string, string>),
    },
    fa: {
        ...(legacyFa as Record<string, string>),
        ...(desktopFa as Record<string, string>),
        ...(onboardingFa as Record<string, string>),
        ...(d2ExtraFa as Record<string, string>),
    },
};

const LOCALE_PREF_KEY = 'daal.locale_pref';

export function detectSystemLocale(): Locale {
    const lang = (navigator.language || 'en').toLowerCase();
    return lang.startsWith('fa') ? 'fa' : 'en';
}

/** @deprecated kept for legacy call sites; prefer effectiveLocale(). */
export function detectLocale(): Locale {
    return effectiveLocale();
}

export function getLocalePref(): LocalePref {
    try {
        const v = localStorage.getItem(LOCALE_PREF_KEY);
        if (v === 'en' || v === 'fa' || v === 'system') return v;
    } catch { /* localStorage unavailable */ }
    return 'system';
}

export function setLocalePref(p: LocalePref): void {
    try { localStorage.setItem(LOCALE_PREF_KEY, p); } catch { /* */ }
}

/** Returns the locale that should actually be applied to the UI. */
export function effectiveLocale(): Locale {
    const pref = getLocalePref();
    if (pref === 'system') return detectSystemLocale();
    return pref;
}

export function applyDir(locale: Locale): void {
    document.documentElement.dir = locale === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = locale;
}

/** Translate a key. Falls back to the EN dictionary then to the key
 *  itself, so missing FA strings degrade to English rather than to
 *  the bare key.
 *
 *  AN EMPTY VALUE COUNTS AS MISSING. This used to test `!= null`, which
 *  an empty string passes — so a key that was present-but-untranslated
 *  rendered as nothing at all, and the English fallback the line above
 *  promises was skipped exactly when it was needed. That is not
 *  hypothetical: `client-shared/i18n/onboarding.fa.json` carries 119
 *  keys whose values are all `""`, and `mobile.fa.json` 100 of 104.
 *  Nothing reads those keys today (they are design catalogues, and the
 *  shipped onboarding copy lives in the legacy `fa.json`), so no screen
 *  is blank right now — but the failure mode was one `t()` call away,
 *  and it fails INVISIBLY in the language the project exists to serve:
 *  English review looks perfect while Farsi renders empty. Fail to
 *  English instead, which is wrong but readable. */
export function translate(locale: Locale, key: string): string {
    const dict = dictionaries[locale];
    const hit = dict[key];
    if (hit != null && hit !== '') return hit;
    const en = dictionaries.en[key];
    if (locale === 'fa' && en != null && en !== '') return en;
    return key;
}

const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];

/** Convert ASCII 0-9 in a string to Persian digits. Non-digit
 *  characters pass through. */
export function toFaDigits(s: string): string {
    return s.replace(/[0-9]/g, (d) => FA_DIGITS[Number(d)]);
}
