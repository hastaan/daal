// "Check all ways" on the routes card, and "Checked when used" for a
// way the engine can check only while connected on it
// (lib/routeSurvey.ts, core/abi/survey.go).
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { WayList } from './HomeFacts';
import { wayRows } from '../../lib/homeFacts';
import { parseSurvey, parseSurveyStart, surveyLine, surveyRunning } from '../../lib/routeSurvey';
import type { RouteDisplayRow } from '../../contract/D2Contract';
import { byAttr } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import legacyEn from '../../i18n/en.json';
import en from '../../i18n/d2/d2-extra.en.json';
import fa from '../../i18n/d2/d2-extra.fa.json';

const EN = { ...(legacyEn as object), ...(en as object) } as Record<string, string>;
const t = (k: string) => EN[k] ?? k;
const digits = (n: number) => String(n);

const way = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: id,
    trustClass: 'trusted',
    family: 'vless-reality',
    ...over,
});

const block = (over: Record<string, unknown> = {}) => ({
    state: 'checking',
    trigger: 'user',
    checking: ['r2'],
    total: 3,
    done: 1,
    seq: 4,
    stop_reason: '',
    results: [{ route_id: 'r3', family: 'hysteria2', result: 'carried', setup_ms: 300 }],
    ...over,
});

describe('routeSurvey', () => {
    it('reads the engine block, and nothing from an engine without one', () => {
        const r = parseSurvey(block())!;
        expect(r).toMatchObject({ state: 'checking', trigger: 'user', checking: ['r2'], total: 3, done: 1, seq: 4, carried: 1 });
        expect(parseSurvey(undefined)).toBeNull();
        expect(parseSurvey({ state: 'bogus' })).toBeNull();
        expect(parseSurveyStart('not json')).toEqual({ started: false, refused: 'unavailable', report: null });
        expect(parseSurveyStart(JSON.stringify({ ...block(), started: false, refused: 'busy' })).refused).toBe('busy');
    });
    it('says how far the person\'s check is, then how it ended — never for the engine\'s own', () => {
        expect(surveyLine(t, parseSurvey(block()), digits)).toBe('Checking ways… 1 of 3');
        expect(surveyLine(t, parseSurvey(block({ state: 'done', done: 3 })), digits)).toBe('All ways checked');
        expect(surveyLine(t, parseSurvey(block({ state: 'done', total: 0, done: 0 })), digits)).toBe('Every way was checked a moment ago');
        expect(surveyLine(t, parseSurvey(block({ state: 'stopped' })), digits)).toBe('The check stopped');
        expect(surveyLine(t, parseSurvey(block({ trigger: 'auto' })), digits)).toBeUndefined();
        expect(surveyRunning(parseSurvey(block({ trigger: 'auto' })))).toBe(false);
        expect(surveyRunning(parseSurvey(block({ state: 'waiting' })))).toBe(true);
    });
    it('has every string in English and Persian, and the Persian names the action without a gesture', () => {
        const FA = fa as Record<string, string>;
        for (const k of Object.keys(EN).filter((k) => k.startsWith('home.survey.') || k.startsWith('home.details.checked_when') || k === 'home.details.when_used_hint')) {
            expect(FA[k], k).toBeTruthy();
            expect(FA[k]).not.toMatch(/بزنید|ضربه|لمس کنید/);
        }
        expect(FA['home.survey.check_all']).toBe('بررسی همهٔ راه‌ها');
        expect(FA['home.survey.checking']).toContain('{done}');
        expect(FA['home.survey.checking']).toContain('{total}');
    });
});

describe('WayList: Check all ways', () => {
    let rig: Rig;
    beforeAll(() => {
        rig = createRig();
    });
    afterEach(async () => {
        await rig.unmountAll();
    });

    it('a way the engine checks only when used says so instead of an empty score slot', () => {
        const rows = wayRows({
            t,
            locale: 'en',
            routes: [
                way('r1', { healthPct: 100 }),
                way('r2', { family: 'wireguard', checkedWhenUsed: true }),
                way('r3', { family: 'hysteria2', healthPct: 100 }),
                // Scored already: the score is what is shown.
                way('r4', { family: 'wireguard', checkedWhenUsed: true, healthPct: 80 }),
            ],
            activeId: 'r1',
            nowMs: 0,
        });
        expect(rows.map((r) => !!r.whenUsed)).toEqual([false, true, false, false]);
        const html = renderToStaticMarkup(<WayList t={t} locale="en" ways={rows} />);
        expect(html.match(/data-testid="way-when-used"/g)?.length).toBe(1);
        expect(html).toContain('Checked when used');
        expect(html.match(/\d%<\/span>/g)?.length).toBe(3); // three score bars
        expect(html).toContain('80%');
    });

    it('the way being checked says so; the button calls the engine and waits while it runs', async () => {
        const report = parseSurvey(block())!;
        const rows = wayRows({
            t,
            locale: 'en',
            routes: [way('r1'), way('r2', { family: 'hysteria2' }), way('r3', { family: 'naive' })],
            activeId: 'r1',
            checking: new Set(report.checking),
            nowMs: 0,
        });
        expect(rows[1].status).toBe('Checking…');

        const onCheck = vi.fn();
        const idle = await rig.mount(<WayList t={t} locale="en" ways={rows} check={{ onCheck, running: false }} />);
        const button = byAttr(idle.container, 'data-button', 'check-all-ways');
        expect(button).not.toBeNull();
        expect(button!.textContent).toBe('Check all ways');
        await rig.click(button);
        expect(onCheck).toHaveBeenCalledTimes(1);
        await idle.unmount();

        const busy = await rig.mount(
            <WayList t={t} locale="en" ways={rows} check={{ onCheck, running: true, line: surveyLine(t, report, digits) }} />,
        );
        const b2 = byAttr(busy.container, 'data-button', 'check-all-ways');
        await rig.click(b2);
        expect(onCheck).toHaveBeenCalledTimes(1);
        expect(byAttr(busy.container, 'data-testid', 'way-check-line')!.textContent).toBe('Checking ways… 1 of 3');
    });

    it('no button where nothing is offered', () => {
        const rows = wayRows({ t, locale: 'en', routes: [way('r1')], activeId: 'r1', nowMs: 0 });
        expect(renderToStaticMarkup(<WayList t={t} locale="en" ways={rows} />)).not.toContain('check-all-ways');
    });
});
