// The two pieces of the main screen that automatic connect added,
// rendered to static markup (no DOM): the chooser under the headline
// and the box shown when no way worked.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import WayChooser from './WayChooser';
import AutoFailure from './AutoFailure';
import { triedRows } from '../../lib/homeFacts';
import { DensityProvider } from '../../design/DensityProvider';
import type { RouteDisplayRow } from '../../contract/D2Contract';
import legacyEn from '../../i18n/en.json';
import legacyFa from '../../i18n/fa.json';
import en from '../../i18n/d2/d2-extra.en.json';
import fa from '../../i18n/d2/d2-extra.fa.json';

const dict = (a: unknown, b: unknown) => ({ ...(a as object), ...(b as object) }) as Record<string, string>;
const EN = dict(legacyEn, en);
const FA = dict(legacyFa, fa);
const tr = (d: Record<string, string>) => (k: string) => d[k] ?? k;

const FAMILIES = ['vless-reality', 'websocket-tls', 'naive', 'hysteria2'];
const ROUTES: RouteDisplayRow[] = FAMILIES.map((family, i) => ({
    routeId: `r${i + 1}`,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: `r${i + 1}`,
    trustClass: 'trusted',
    family,
}));
const noop = () => {};
const chooser = (over: Partial<Parameters<typeof WayChooser>[0]> = {}, d = EN) =>
    renderToStaticMarkup(
        <WayChooser
            t={tr(d)}
            pinned={null}
            routes={ROUTES}
            busy={false}
            open={false}
            onToggle={noop}
            onPick={noop}
            onBackToAuto={noop}
            onManage={noop}
            {...over}
        />,
    );

describe('WayChooser', () => {
    it('defaults to "Automatic — Daal chooses the best way", with no route list and no protocol name', () => {
        const html = chooser();
        expect(html).toContain('Automatic');
        expect(html).toContain('Daal chooses the best way');
        expect(html).not.toContain('Back to automatic');
        expect(html).not.toContain('No route selected');
        for (const f of FAMILIES) expect(html).not.toContain(f);
        // Folded: the routes are not listed.
        expect(html).not.toContain('WebSocket TLS');
    });
    it('opened: the routes are the ADVANCED choice, named by their kind, never by "r1" or a raw token', () => {
        const html = chooser({ open: true });
        expect(html).toContain('Choose one yourself (advanced)');
        expect(html.indexOf('Automatic')).toBeLessThan(html.indexOf('Choose one yourself (advanced)'));
        for (const r of ROUTES) expect(html).toContain(`>${EN[`network.family.${r.family.replace(/-/g, '_')}`]}<`);
        // The file each comes from is said under it; its "r1" is not.
        expect(html).toContain('>Pars<');
        for (const r of ROUTES) expect(html).not.toContain(`>${r.routeNickname}<`);
        for (const f of FAMILIES) expect(html).not.toContain(f);
        expect(html).toContain('Open my files');
        // Automatic is the selected one.
        expect(html).toMatch(/aria-checked="true"[^>]*>.*?Automatic/s);
    });
    it('a pinned route is said in words, with the way back right there — also folded', () => {
        const html = chooser({ pinned: ROUTES[2] });
        expect(html).toContain('Only this one: Pars · Naive');
        expect(html).toContain('You chose it yourself. Daal will not try the others.');
        expect(html).toContain('>Back to automatic<');
        expect(html).not.toContain('naive');
    });
    it('connected automatically: names no route on the main path, and says a new choice applies next time', () => {
        const html = chooser({ running: ROUTES[1], engineAuto: true, busy: true, open: false });
        expect(html).toContain('Automatic');
        // A person who chose nothing is shown no route name or id here.
        expect(html).not.toContain('Using now');
        expect(html).not.toContain('r2');
        expect(html).not.toContain('websocket');
        expect(chooser({ running: ROUTES[1], engineAuto: true, busy: true, open: true })).toContain(
            'Your choice is used the next time you connect.',
        );
    });
    it('connected automatically with a way picked meanwhile: the chip is what is true NOW, the pick is "next time"', () => {
        // The engine is choosing and is on r1; the person just picked r3.
        const html = chooser({ running: ROUTES[0], engineAuto: true, pinned: ROUTES[2], busy: true });
        const chip = html.slice(html.indexOf('<button'), html.indexOf('</button>'));
        expect(chip).toContain('Automatic');
        expect(chip).not.toContain('Only this one');
        expect(html).toContain('Daal chooses the best way');
        expect(html).not.toContain('Daal will not try the others');
        // Folded, and still visible.
        expect(html).toContain('From the next time you connect: only Pars · Naive');
    });
    it('connected on a way picked by hand, then "Back to automatic": still that way until the engine takes over', () => {
        const html = chooser({ running: ROUTES[2], engineAuto: false, pinned: null, busy: true });
        const chip = html.slice(html.indexOf('<button'), html.indexOf('</button>'));
        expect(chip).toContain('Only this one: Pars · Naive');
        expect(html).toContain('From the next time you connect: automatic');
        // The same pick, in force: nothing to add.
        const same = chooser({ running: ROUTES[2], engineAuto: false, pinned: ROUTES[2], busy: true });
        expect(same).toContain('Only this one: Pars · Naive');
        expect(same).not.toContain('From the next time');
    });
    it('the sheet: the selected radio is what is in force (the way held by hand), with one hint line and no "next time" lines', () => {
        // Connected on a way picked earlier, nothing saved: Home shows "Manual".
        const html = chooser({ bare: true, open: true, running: ROUTES[2], engineAuto: false, pinned: null, busy: true });
        expect(html).toMatch(/aria-checked="true"[^>]*>.*?Naive/s);
        expect(html).toMatch(/aria-checked="false"[^>]*>.*?Automatic/s);
        expect(html).not.toContain('From the next time');
        expect(html).not.toContain('Your choice is used the next time you connect.');
        expect(html.match(/data-note/g)?.length).toBe(1);
        expect(html).toContain('Daal won&#x27;t switch away from a way you pick.');
        // Connected automatically: Automatic is selected.
        expect(chooser({ bare: true, open: true, running: ROUTES[0], engineAuto: true, busy: true })).toMatch(
            /aria-checked="true"[^>]*>.*?Automatic/s,
        );
        // A pick saved while the engine chooses: selected, and its one line says when it applies.
        const saved = chooser({ bare: true, open: true, running: ROUTES[0], engineAuto: true, pinned: ROUTES[3], busy: true });
        expect(saved).toMatch(/aria-checked="true"[^>]*>.*?Hysteria 2/s);
        expect(saved).toContain('From the next time you connect: only Pars · Hysteria 2');
        expect(saved).not.toContain('Daal won&#x27;t switch');
    });
    it('offers no route list when the list could not be read', () => {
        const html = chooser({ routes: undefined, open: true });
        expect(html).toContain('Automatic');
        expect(html).not.toContain('advanced');
    });
    it('renders in Persian', () => {
        const html = chooser({ pinned: ROUTES[0], open: true }, FA);
        expect(html).toContain(FA['auto.chooser.back']);
        expect(html).toContain(FA['auto.chooser.automatic']);
        expect(html).not.toContain('Automatic');
        expect(html).not.toContain('Back to');
    });
});

describe('AutoFailure: the Details fold under a failed connect', () => {
    const tried = [
        { routeId: 'r1', family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout' },
        { routeId: 'r4', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
        { routeId: 'r5', family: 'naive', result: 'something_new', category: '' },
    ];
    const box = (over: Partial<Parameters<typeof AutoFailure>[0]> = {}, d = EN) =>
        renderToStaticMarkup(
            <DensityProvider>
                <AutoFailure t={tr(d)} tried={tried} verdict="relay_unreachable" defaultOpen {...over} />
            </DensityProvider>,
        );

    it('is closed at first: only its summary, "Details"', () => {
        const html = box({ defaultOpen: false });
        expect(html).toContain('>Details<');
        expect(html).not.toContain('Tried');
    });
    it('opened: how many ways were tried, and no engine words', () => {
        const html = box();
        expect(html).toContain('Tried 3 ways');
        for (const raw of ['r1', 'vless-reality', 'hysteria2', 'tcp_connect_timeout', 'udp_no_reply', 'relay_unreachable', 'start_failed']) {
            expect(html, raw).not.toContain(raw);
        }
        expect(box({ tried: tried.slice(0, 1) })).toContain('Tried 1 way');
    });
    it('in developer mode: each try as the engine names it, left-to-right, in order', () => {
        const html = box({ dev: true });
        for (const raw of ['r1', 'vless-reality', 'hysteria2', 'tcp_connect_timeout', 'udp_no_reply', 'relay_unreachable']) {
            expect(html, raw).toContain(raw);
        }
        expect(html).toMatch(/could not start.*started, but nothing got through.*no result/s);
        expect(html.indexOf('r1')).toBeLessThan(html.indexOf('r4'));
        expect(html).toMatch(/<code dir="ltr"/);
    });
    it('with nothing tried, it says so instead of an empty list', () => {
        const html = box({ tried: [], verdict: 'network_down', dev: true });
        expect(html).toContain('Daal did not get as far as trying anything.');
        expect(html).not.toContain('<ol');
    });
    it('with the rows the page passes: each try by kind, in plain words — still no engine token', () => {
        const rows = triedRows(tr(EN), tried, undefined);
        const html = box({ rows });
        expect(html).toContain('VLESS Reality');
        expect(html).toContain('Hysteria 2');
        expect(html).toContain('The server did not answer');
        for (const raw of ['vless-reality', 'hysteria2', 'tcp_connect_timeout', 'udp_no_reply', 'start_failed']) {
            expect(html, raw).not.toContain(raw);
        }
        const htmlFa = box({ locale: 'fa', rows: triedRows(tr(FA), tried, undefined) }, FA);
        expect(htmlFa).toContain(FA['home.tried.no_answer']);
    });
    it('renders in Persian, with Persian digits', () => {
        const html = box({ locale: 'fa' }, FA);
        expect(html).toContain(FA['ui.details']);
        expect(html).toContain('۳');
        expect(html).not.toMatch(/Tried|Details/);
        expect(html).not.toContain('vless');
    });
});
