// format — dates, times and "2 hours ago" in the reader's own language.
//
// Persian gets the Persian calendar and Persian digits («۱۷ آبان ۱۴۰۵»),
// English gets "8 Nov 2026" (no US month/day order to misread). Every
// result comes back wrapped in Unicode isolates (U+2068 … U+2069), so a
// date or a number dropped into a sentence of the other direction keeps
// its own order instead of being shuffled by the bidi algorithm.
//
// If the web view's Intl cannot do it, the fallback is an ISO date
// (yyyy-mm-dd), still isolated, with Persian digits in Persian.

import { toFaDigits, translate } from './i18n';
import type { Locale } from './i18n';

const FSI = '⁨';
const PDI = '⁩';

/** Wrap `s` in first-strong isolate … pop-directional-isolate. */
export function isolate(s: string): string {
    return `${FSI}${s}${PDI}`;
}

/** The separator between facts on one line. In Persian a middle dot
 *  next to Persian digits reads as the digit zero («۴ راه · ۵۲» looks
 *  like «۴ راه ۰ ۵۲»), so Persian gets its own comma. */
export function sep(): string {
    try {
        const el = document.documentElement;
        const lang = (el.getAttribute('lang') ?? '').toLowerCase();
        if (lang.startsWith('fa') || el.getAttribute('dir') === 'rtl') return '، ';
    } catch {
        /* no document (tests): English */
    }
    return ' · ';
}

/** A Date from a Date or from Unix SECONDS. */
function toDate(v: number | Date): Date {
    return v instanceof Date ? v : new Date(v * 1000);
}

function pad(n: number): string {
    return n < 10 ? `0${n}` : String(n);
}

function isoDay(d: Date): string {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function digits(locale: Locale, s: string): string {
    return locale === 'fa' ? toFaDigits(s) : s;
}

const DATE_LOCALE: Record<Locale, string> = {
    en: 'en-GB',
    fa: 'fa-IR-u-ca-persian',
};

/**
 * A calendar date: "8 Nov 2026" / «۱۷ آبان ۱۴۰۵». With `dayTime`, the
 * time follows: "8 Nov 2026, 09:59". `value` is a Date or Unix seconds.
 */
export function formatDate(locale: Locale, value: number | Date, style: 'day' | 'dayTime' = 'day'): string {
    const d = toDate(value);
    if (Number.isNaN(d.getTime())) return isolate('');
    try {
        const opts: Intl.DateTimeFormatOptions =
            style === 'dayTime'
                ? { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }
                : { day: 'numeric', month: 'short', year: 'numeric' };
        return isolate(new Intl.DateTimeFormat(DATE_LOCALE[locale], opts).format(d));
    } catch {
        const day = isoDay(d);
        const s = style === 'dayTime' ? `${day} ${pad(d.getHours())}:${pad(d.getMinutes())}` : day;
        return isolate(digits(locale, s));
    }
}

/** Hours and minutes, 24-hour: "09:59" / «۰۹:۵۹». `value` is a Date or Unix seconds. */
export function formatTime(locale: Locale, value: number | Date): string {
    const d = toDate(value);
    if (Number.isNaN(d.getTime())) return isolate('');
    try {
        return isolate(
            new Intl.DateTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', {
                hour: '2-digit',
                minute: '2-digit',
                hour12: false,
            }).format(d),
        );
    } catch {
        return isolate(digits(locale, `${pad(d.getHours())}:${pad(d.getMinutes())}`));
    }
}

const UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ['year', 365 * 24 * 3600],
    ['month', 30 * 24 * 3600],
    ['week', 7 * 24 * 3600],
    ['day', 24 * 3600],
    ['hour', 3600],
    ['minute', 60],
];

const UNIT_FALLBACK: Record<Locale, Record<string, string>> = {
    en: { year: 'y', month: 'mo', week: 'w', day: 'd', hour: 'h', minute: 'min' },
    fa: { year: 'سال', month: 'ماه', week: 'هفته', day: 'روز', hour: 'ساعت', minute: 'دقیقه' },
};

/**
 * How long ago, from an elapsed time in MILLISECONDS (now − then):
 * "2 hours ago" / «۲ ساعت پیش». Under a minute it returns `justNow`
 * (by default the `ui.just_now` string), isolated. A negative or invalid duration
 * counts as just now.
 */
export function formatAgo(locale: Locale, ms: number, justNow = translate(locale, 'ui.just_now')): string {
    const secs = Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
    if (secs < 60) return isolate(justNow);
    let unit: Intl.RelativeTimeFormatUnit = 'minute';
    let n = Math.floor(secs / 60);
    for (const [u, size] of UNITS) {
        if (secs >= size) {
            unit = u;
            n = Math.floor(secs / size);
            break;
        }
    }
    try {
        const rtf = new Intl.RelativeTimeFormat(locale === 'fa' ? 'fa-IR' : 'en-GB', { numeric: 'always', style: 'long' });
        return isolate(rtf.format(-n, unit));
    } catch {
        const word = UNIT_FALLBACK[locale][unit] ?? unit;
        return isolate(locale === 'fa' ? `${toFaDigits(String(n))} ${word} پیش` : `${n} ${word} ago`);
    }
}
