// The harness catalog walks the app by `data-button` ids and i18n keys.
// When a screen renames a control, the scenario that taps it silently
// shows the wrong screen; this catches it before a capture does.
import { describe, expect, it } from 'vitest';
import { SCENARIOS, type DriveStep } from './scenarios';
import en from '../i18n/en.json';
import desktopEn from '../i18n/d2/desktop.en.json';
import onboardingEn from '../i18n/d2/onboarding.en.json';
import d2ExtraEn from '../i18n/d2/d2-extra.en.json';

const sources = import.meta.glob(['../**/*.tsx', '!../**/*.test.tsx', '!../harness/**', '!../test/**'], {
    query: '?raw',
    import: 'default',
    eager: true,
}) as Record<string, string>;
const all = Object.values(sources).join('\n');

const keys = new Set([
    ...Object.keys(en),
    ...Object.keys(desktopEn),
    ...Object.keys(onboardingEn),
    ...Object.keys(d2ExtraEn),
]);

// Ids built from a template in the source (`tab-${id}`, `nav-${id}`, …).
const TEMPLATED = /^(tab|nav|lang|dev|settle-keep|settle-removed|wizard-step|relay-only-more)-/;

function matchers(step: DriveStep): string[] {
    const one = 'click' in step ? step.click
        : 'type' in step ? step.type
        : 'waitFor' in step ? step.waitFor
        : 'scroll' in step ? step.scroll
        : 'freeze' in step && typeof step.freeze === 'string' ? step.freeze
        : null;
    return one ? one.split(' || ').map((m) => m.trim()) : [];
}

function stepsOf(s: (typeof SCENARIOS)[number]): DriveStep[] {
    return [...(s.steps ?? []), ...(s.fake?.steps ?? [])];
}

function idExists(id: string): boolean {
    if (TEMPLATED.test(id)) return true;
    const q = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(dataButton|data-button)=["{'\`]+${q}["'\`}]|\\bid: '${q}'`).test(all);
}

describe('harness scenarios', () => {
    it('ids are unique', () => {
        const ids = SCENARIOS.map((s) => s.id);
        expect(new Set(ids).size).toBe(ids.length);
    });

    it('every btn: target is a data-button some screen renders', () => {
        const missing: string[] = [];
        for (const s of SCENARIOS) {
            for (const step of stepsOf(s)) {
                for (const m of matchers(step)) {
                    if (m.startsWith('btn:') && !idExists(m.slice(4))) missing.push(`${s.id}: ${m}`);
                }
            }
        }
        expect(missing).toEqual([]);
    });

    it('every key: target is a string in the catalogs', () => {
        const missing: string[] = [];
        for (const s of SCENARIOS) {
            for (const step of stepsOf(s)) {
                for (const m of matchers(step)) {
                    if (m.startsWith('key:') && !keys.has(m.slice(4))) missing.push(`${s.id}: ${m}`);
                }
            }
        }
        expect(missing).toEqual([]);
    });

    it('a scenario lists its taps in one place: the fake shell, or its own steps', () => {
        for (const s of SCENARIOS) {
            if (s.steps?.length) expect(s.fake, s.id).toBeUndefined();
        }
    });

    it('covers the states this redesign added', () => {
        const ids = new Set(SCENARIOS.map((s) => s.id));
        for (const id of [
            'rcp-import-done',
            'rcp-file-done',
            'rcp-opened-file',
            'rcp-opened-text',
            'pub-person-send',
            'status-from-home',
            'connection-connected-dev',
            'settings-advanced-dev',
            'status-dev',
        ]) {
            expect(ids.has(id), id).toBe(true);
        }
        expect(SCENARIOS.filter((s) => s.dev).length).toBeGreaterThanOrEqual(5);
    });
});
