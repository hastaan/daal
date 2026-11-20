// The Home facts card, its Details list, the ready chips and the Files
// pieces, rendered: what reaches the page is only what the engine sent,
// no engine id or "r1" reaches a person, and a state disc says what the
// engine saw.
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { HomeFactsCard, ReadyChips, TriedList, TryingSteps, WayList } from './HomeFacts';
import { FileCard, WayRow } from '../files/FileParts';
import { connectedFacts, triedRows, wayRows } from '../../lib/homeFacts';
import { familyTags, wayTitles } from '../../lib/fileFacts';
import type { FileState, WayState } from '../../lib/fileFacts';
import type { PublisherTreeRow, RouteDisplayRow } from '../../contract/D2Contract';
import { byAttr, byText } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import legacyEn from '../../i18n/en.json';
import en from '../../i18n/d2/d2-extra.en.json';

const EN = { ...(legacyEn as object), ...(en as object) } as Record<string, string>;
const t = (k: string) => EN[k] ?? k;

const way = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: id,
    trustClass: 'trusted',
    family: 'vless-reality',
    ...over,
});

describe('HomeFactsCard', () => {
    it('a bare connected summary draws no card at all', () => {
        const facts = connectedFacts({ t, locale: 'en', conn: { state: 'connected', mode: 'normal' }, throughput: null, pinnedId: null });
        expect(renderToStaticMarkup(<HomeFactsCard t={t} facts={facts} />)).toBe('');
    });
    it('draws the why line and the rows the engine sent, never a "valid for" row', () => {
        const facts = connectedFacts({
            t,
            locale: 'en',
            conn: {
                state: 'connected',
                mode: 'normal',
                routeCheck: 'ok',
                activeRoute: way('r1'),
                pointerValidDays: 2,
                network: { fromHost: true, kind: 'wifi', validated: 1, metered: 0 },
                auto: {
                    state: 'connected',
                    mode: true,
                    trying: '',
                    index: 1,
                    total: 2,
                    tried: [{ routeId: 'r1', family: 'vless-reality', result: 'carried', category: '', why: 'carried_here' }],
                    verdict: '',
                    routeId: 'r1',
                },
            },
            throughput: { upBytesPerSec: 1024, downBytesPerSec: 4096, windowMs: 1000 },
            pinnedId: null,
        });
        const html = renderToStaticMarkup(<HomeFactsCard t={t} facts={facts} />);
        expect(html).toContain('data-testid="home-facts"');
        expect(html).toContain('data-why="worked_here"');
        expect(html).toContain('data-testid="fact-network"');
        expect(html).toContain('data-testid="fact-speed"');
        expect(html).toContain('data-testid="fact-quality"');
        expect(html).not.toContain('fact-valid');
        expect(html).not.toContain('r1');
    });
});

describe('WayList (Details)', () => {
    it('one row per way, a disc per state, a score bar only where the engine has a score', () => {
        const rows = wayRows({
            t,
            locale: 'en',
            routes: [way('r1', { healthPct: 96 }), way('r2', { family: 'hysteria2', measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } })],
            activeId: 'r1',
            nowMs: 0,
        });
        const html = renderToStaticMarkup(<WayList t={t} locale="en" ways={rows} title="Ways on this phone" />);
        expect(html.match(/data-way-row=/g)?.length).toBe(2);
        expect(html).toContain('data-way-row="ok"');
        expect(html).toContain('data-way-row="bad"');
        expect(html).toContain('96%');
        expect(html).toContain('In use now');
        expect(html).not.toMatch(/>r[12]</);
    });
});

describe('ReadyChips', () => {
    it('each chip carries its state dot, and its label says "here"', () => {
        const html = renderToStaticMarkup(
            <ReadyChips
                t={t}
                kinds={[
                    { name: 'WebSocket TLS', mark: 'good', experimental: false },
                    { name: 'Hysteria 2', mark: 'bad', experimental: false },
                    { name: 'MASQUE', mark: 'none', experimental: true },
                ]}
                more={0}
                moreText=""
            />,
        );
        expect(html).toContain('data-testid="ready-kinds"');
        expect(html).toContain('aria-label="WebSocket TLS · Works here"');
        expect(html).toContain('aria-label="Hysteria 2 · Not working here"');
        expect(html).toContain('Experimental');
    });
});

describe('TriedList and TryingSteps', () => {
    it('a red cross only for a way that failed; a stopped one is a hollow ring', () => {
        const rows = triedRows(
            t,
            [
                { routeId: 'r1', family: 'vless-reality', result: 'carried', category: '' },
                { routeId: 'r2', family: 'tuic', result: 'stopped', category: '' },
                { routeId: 'r3', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
            ],
            undefined,
        );
        const html = renderToStaticMarkup(<TriedList rows={rows} />);
        expect(html).toContain('data-tried-glyph="ok"');
        expect(html).toContain('data-tried-glyph="none"');
        expect(html).toContain('data-tried-glyph="bad"');
        expect(html.match(/data-state="bad"/g)?.length).toBe(1);
    });
    it('steps only when the engine said where it is', () => {
        expect(renderToStaticMarkup(<TryingSteps fact={{ text: 'x' }} />)).toBe('');
        expect(renderToStaticMarkup(<TryingSteps fact={{ text: 'x', index: 2, total: 4 }} />)).toContain('data-testid="trying-steps"');
    });
});

const file = (routes: RouteDisplayRow[]): PublisherTreeRow =>
    ({
        publisherId: 'pub',
        displayName: 'Test',
        trustLevel: 'trusted',
        revoked: false,
        cells: [{ routes }],
    }) as unknown as PublisherTreeRow;

describe('FileCard', () => {
    const card = (state: FileState) =>
        renderToStaticMarkup(
            <FileCard
                t={t}
                locale="en"
                p={file([way('r1')])}
                state={state}
                summary="1 way"
                tags={familyTags(t, [way('r1')], null, 0)}
                last
                onOpen={() => {}}
            />,
        );
    it('a filled green disc only for the file in use; "works here" is the outline', () => {
        expect(card('in_use')).toMatch(/data-state="ok"(?! data-variant)/);
        expect(card('in_use')).not.toContain('data-variant="outline"');
        expect(card('works')).toContain('data-variant="outline"');
        expect(card('untried')).not.toContain('data-state="ok"');
        expect(card('untried')).toContain('data-state="none"');
    });
    it('family tags carry the "here" word in their label', () => {
        const html = renderToStaticMarkup(
            <FileCard
                t={t}
                locale="en"
                p={file([way('r1', { measured: { grade: 'good', samples: 1, carried: 1, failed: 0 } })])}
                state="works"
                summary="1 way"
                tags={familyTags(t, [way('r1', { measured: { grade: 'good', samples: 1, carried: 1, failed: 0 } })], null, 0)}
                last
                onOpen={() => {}}
            />,
        );
        expect(html).toContain('aria-label="VLESS Reality · Works here"');
    });
});

describe('WayRow', () => {
    let rig: Rig;
    beforeAll(() => {
        rig = createRig();
    });
    afterEach(async () => {
        await rig.unmountAll();
    });
    const r = way('r1', { routeNickname: 'r1', measured: { grade: 'good', setupMs: 400, samples: 3, carried: 3, failed: 0 } });
    const el = (state: WayState, over: Partial<Parameters<typeof WayRow>[0]> = {}) => (
        <WayRow
            t={t}
            locale="en"
            r={r}
            title={wayTitles(t, [r]).get('r1')!}
            state={state}
            open
            onToggle={() => {}}
            pinned={false}
            chosenByDaal={false}
            busy={false}
            onUseOnly={() => {}}
            onBackToAuto={() => {}}
            last
            {...over}
        />
    );
    it('no "Use only this way" for an unusable, resting or in-use way', () => {
        for (const s of ['unsupported', 'resting', 'in_use'] as WayState[]) {
            expect(renderToStaticMarkup(el(s))).not.toContain('data-button="way-use-only"');
        }
        expect(renderToStaticMarkup(el('good'))).toContain('data-button="way-use-only"');
    });
    it('never prints "r1" as a name, and no route id without developer tools', () => {
        const html = renderToStaticMarkup(el('good'));
        expect(html).not.toContain('Name in the file');
        expect(html).not.toMatch(/>r1</);
        const dev = renderToStaticMarkup(el('good', { dev: <code>r1</code> }));
        expect(dev).toContain('<code>r1</code>');
    });
    it('says it connects now when another way is up', () => {
        expect(renderToStaticMarkup(el('good', { otherConnected: true }))).toContain('Connect with only this way');
        expect(renderToStaticMarkup(el('good'))).toContain('Use only this way');
    });
    it('pinned: "Back to automatic", and it calls back', async () => {
        let back = 0;
        const m = await rig.mount(el('in_use', { pinned: true, onBackToAuto: () => back++ }));
        expect(byAttr(m.container, 'data-button', 'way-use-only')).toBeNull();
        await rig.click(byText(m.container, 'Back to automatic'));
        expect(back).toBe(1);
    });
});
