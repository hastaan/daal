import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatAgo, formatDate, formatTime, isolate } from './format';

const FSI = '⁨';
const PDI = '⁩';
const bare = (s: string) => {
    expect(s.startsWith(FSI) && s.endsWith(PDI), `isolated: ${JSON.stringify(s)}`).toBe(true);
    return s.slice(1, -1);
};

// Local time, so the test does not depend on the machine's time zone.
const NOV8 = new Date(2026, 10, 8, 9, 59);

afterEach(() => {
    vi.restoreAllMocks();
});

describe('isolate', () => {
    it('wraps in first-strong isolate … pop-directional isolate', () => {
        expect(isolate('daal1 qm3n')).toBe(`${FSI}daal1 qm3n${PDI}`);
    });
});

describe('formatDate', () => {
    it('English: day month year, no US order', () => {
        expect(bare(formatDate('en', NOV8))).toBe('8 Nov 2026');
    });
    it('Persian: Persian calendar and Persian digits', () => {
        expect(bare(formatDate('fa', NOV8))).toBe('۱۷ آبان ۱۴۰۵');
    });
    it('takes Unix seconds as well as a Date', () => {
        expect(formatDate('en', NOV8.getTime() / 1000)).toBe(formatDate('en', NOV8));
    });
    it('with the time', () => {
        expect(bare(formatDate('en', NOV8, 'dayTime'))).toBe('8 Nov 2026, 09:59');
        const fa = bare(formatDate('fa', NOV8, 'dayTime'));
        expect(fa).toContain('۱۷ آبان ۱۴۰۵');
        expect(fa).toContain('۰۹:۵۹');
        expect(fa).not.toMatch(/[0-9]/);
    });
    it('falls back to an ISO day, isolated, with Persian digits in Persian, when Intl throws', () => {
        vi.spyOn(Intl, 'DateTimeFormat').mockImplementation(() => {
            throw new RangeError('no calendar');
        });
        expect(formatDate('en', NOV8)).toBe(isolate('2026-11-08'));
        expect(formatDate('fa', NOV8)).toBe(isolate('۲۰۲۶-۱۱-۰۸'));
        expect(formatTime('fa', NOV8)).toBe(isolate('۰۹:۵۹'));
    });
});

describe('formatTime', () => {
    it('hours and minutes, 24-hour', () => {
        expect(bare(formatTime('en', NOV8))).toBe('09:59');
        expect(bare(formatTime('fa', NOV8))).toBe('۰۹:۵۹');
    });
});

describe('formatAgo', () => {
    const MIN = 60_000;
    const HOUR = 60 * MIN;
    it('under a minute is "just now", from the ui.just_now string or the caller', () => {
        expect(bare(formatAgo('en', 5_000))).toBe('just now');
        expect(bare(formatAgo('fa', 59_000))).toBe('همین الان');
        expect(bare(formatAgo('en', 1_000, 'now'))).toBe('now');
        expect(bare(formatAgo('en', -5 * HOUR))).toBe('just now');
        expect(bare(formatAgo('en', Number.NaN))).toBe('just now');
    });
    it('picks the largest whole unit', () => {
        expect(bare(formatAgo('en', 5 * MIN))).toBe('5 minutes ago');
        expect(bare(formatAgo('en', 2 * HOUR + 10 * MIN))).toBe('2 hours ago');
        expect(bare(formatAgo('en', 3 * 24 * HOUR))).toBe('3 days ago');
        expect(bare(formatAgo('en', 15 * 24 * HOUR))).toBe('2 weeks ago');
    });
    it('Persian reads «… پیش» with Persian digits', () => {
        expect(bare(formatAgo('fa', 2 * HOUR))).toBe('۲ ساعت پیش');
    });
    it('falls back to plain words when Intl.RelativeTimeFormat throws', () => {
        vi.spyOn(Intl, 'RelativeTimeFormat').mockImplementation(() => {
            throw new RangeError('old web view');
        });
        expect(bare(formatAgo('en', 2 * HOUR))).toBe('2 h ago');
        expect(bare(formatAgo('fa', 2 * HOUR))).toBe('۲ ساعت پیش');
    });
});
