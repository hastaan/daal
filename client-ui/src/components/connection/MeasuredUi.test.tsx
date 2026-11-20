// The measuring wave's drawing, rendered to static markup (no DOM): the
// Details fold on the main screen, the tried list in the failure box,
// and the route-health rows.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import MeasuredDetails from './MeasuredDetails';
import AutoFailure, { triedCode } from './AutoFailure';
import { DensityProvider } from '../../design/DensityProvider';
import RouteHealthBars from './RouteHealthBars';
import type { RouteDisplayRow } from '../../contract/D2Contract';
import legacyEn from '../../i18n/en.json';
import legacyFa from '../../i18n/fa.json';
import en from '../../i18n/d2/d2-extra.en.json';
import fa from '../../i18n/d2/d2-extra.fa.json';

const dict = (a: unknown, b: unknown) => ({ ...(a as object), ...(b as object) }) as Record<string, string>;
const EN = dict(legacyEn, en);
const FA = dict(legacyFa, fa);
const tr = (d: Record<string, string>) => (k: string) => d[k] ?? k;

const way = (id: string, family: string, measured?: RouteDisplayRow['measured']): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: `Way ${id}`,
    trustClass: 'trusted',
    family,
    measured,
});
const ROUTES = [
    way('r1', 'vless-reality', { grade: 'good', setupMs: 320, samples: 9, carried: 9, failed: 0, last: '2026-11-19T10' }),
    way('r2', 'hysteria2', { grade: 'failing', samples: 3, carried: 0, failed: 3 }),
    way('r3', 'trojan', { grade: 'unknown', samples: 0, carried: 0, failed: 0 }),
    way('r4', 'tuic'),
];

describe('MeasuredDetails', () => {
    it('is a closed fold: the numbers and the kinds of connection are inside <details>', () => {
        const html = renderToStaticMarkup(<MeasuredDetails t={tr(EN)} locale="en" routes={ROUTES} />);
        expect(html.startsWith('<details')).toBe(true);
        expect(html).not.toContain('<details open');
        expect(html).toContain('How each way has done on this network');
    });
    it('lists each measured route: plain phrase, numbers in words, then the engine\'s line left-to-right', () => {
        const html = renderToStaticMarkup(<MeasuredDetails t={tr(EN)} locale="en" routes={ROUTES} />);
        expect(html).toContain('Works well here');
        expect(html).toContain('connects in about 320 ms · tried 9, worked 9, failed 0');
        expect(html).toContain('r1 · vless-reality · good · 320 ms · n=9 · ok=9 · fail=0 · 2026-11-19T10');
        expect(html).toContain('Did not work here last time');
        expect(html).toContain('Not tried here yet');
        expect(html).toMatch(/<code dir="ltr"/);
        // A route the engine sent no measurement for is not listed.
        expect(html).not.toContain('r4');
        expect(html).not.toContain('tuic');
    });
    it('says so when nothing was tried on this network yet', () => {
        const html = renderToStaticMarkup(<MeasuredDetails t={tr(EN)} locale="en" routes={[ROUTES[2]]} />);
        expect(html).toContain('Daal has not tried any way on this network yet.');
    });
    it('in Persian: Persian words and digits around a left-to-right code line', () => {
        const html = renderToStaticMarkup(<MeasuredDetails t={tr(FA)} locale="fa" routes={ROUTES} />);
        expect(html).toContain(FA['measure.grade.good']);
        expect(html).toContain('۳۲۰');
        expect(html).toContain('r1 · vless-reality · good');
    });
});

describe('AutoFailure: the tried list', () => {
    it('adds this attempt\'s time and what it was tried with — under Details only', () => {
        expect(triedCode({ routeId: 'r2', family: 'vless-reality', result: 'carried', category: '', setupMs: 412, racedWith: 'r4' })).toBe(
            'r2 · vless-reality · carried · 412 ms · with r4',
        );
        expect(triedCode({ routeId: 'r1', family: 'tuic', result: 'not_carrying', category: 'udp_no_reply' })).toBe(
            'r1 · tuic · not_carrying · udp_no_reply',
        );
        // Developer mode: the per-try line carries it; otherwise no route id at all.
        const html = (dev: boolean) =>
            renderToStaticMarkup(
                <DensityProvider>
                    <AutoFailure
                        t={tr(EN)}
                        verdict="all_failed"
                        defaultOpen
                        dev={dev}
                        tried={[{ routeId: 'r1', family: 'tuic', result: 'not_carrying', category: 'udp_no_reply', racedWith: 'r2' }]}
                    />
                </DensityProvider>,
            );
        expect(html(false)).not.toContain('r2');
        expect(html(true)).toContain('with r2');
    });
});

describe('RouteHealthBars', () => {
    it('says the grade in plain words where the engine measured, and "not tested yet" only where it said nothing', () => {
        const html = renderToStaticMarkup(
            <RouteHealthBars
                t={tr(EN)}
                locale="en"
                rows={[
                    { routeId: 'r1', label: 'Pars · r1', measured: ROUTES[1].measured },
                    { routeId: 'r4', label: 'Pars · r4' },
                ]}
            />,
        );
        expect(html).toContain('Did not work here last time');
        expect(html.match(/not tested yet/g)?.length).toBe(1);
    });
});
