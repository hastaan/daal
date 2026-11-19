// The two pieces of the main screen that automatic connect added,
// rendered to static markup (no DOM): the chooser under the headline
// and the box shown when no way worked.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import WayChooser from './WayChooser';
import AutoFailure from './AutoFailure';
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
        expect(html).not.toContain('Pars · r2');
    });
    it('opened: the routes are the ADVANCED choice, named without their protocol', () => {
        const html = chooser({ open: true });
        expect(html).toContain('Choose one yourself (advanced)');
        expect(html.indexOf('Automatic')).toBeLessThan(html.indexOf('Choose one yourself (advanced)'));
        for (const r of ROUTES) expect(html).toContain(`Pars · ${r.routeNickname}`);
        for (const f of FAMILIES) expect(html).not.toContain(f);
        expect(html).toContain('See all connections');
        // Automatic is the selected one.
        expect(html).toMatch(/aria-checked="true"[^>]*>.*?Automatic/s);
    });
    it('a pinned route is said in words, with the way back right there — also folded', () => {
        const html = chooser({ pinned: ROUTES[2] });
        expect(html).toContain('Only this one: Pars · r3');
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
        expect(html).toContain('From the next time you connect: only Pars · r3');
    });
    it('connected on a way picked by hand, then "Back to automatic": still that way until the engine takes over', () => {
        const html = chooser({ running: ROUTES[2], engineAuto: false, pinned: null, busy: true });
        const chip = html.slice(html.indexOf('<button'), html.indexOf('</button>'));
        expect(chip).toContain('Only this one: Pars · r3');
        expect(html).toContain('From the next time you connect: automatic');
        // The same pick, in force: nothing to add.
        const same = chooser({ running: ROUTES[2], engineAuto: false, pinned: ROUTES[2], busy: true });
        expect(same).toContain('Only this one: Pars · r3');
        expect(same).not.toContain('From the next time');
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

describe('AutoFailure', () => {
    const tried = [
        { routeId: 'r1', family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout' },
        { routeId: 'r4', family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
        { routeId: 'r5', family: 'naive', result: 'something_new', category: '' },
    ];
    const box = (over: Partial<Parameters<typeof AutoFailure>[0]> = {}, d = EN) =>
        renderToStaticMarkup(
            <AutoFailure
                t={tr(d)}
                actionText={tr(d)('auto.verdict.relay_unreachable.do')}
                tried={tried}
                verdict="relay_unreachable"
                onRetry={noop}
                {...over}
            />,
        );

    it('says what to do and offers Try again; ids, families and codes only under Details', () => {
        const html = box();
        const at = html.indexOf('<details');
        expect(at).toBeGreaterThan(0);
        const before = html.slice(0, at);
        const details = html.slice(at);
        expect(before).toContain('ask the person who gave you the file for a new one.');
        expect(before).toContain('>Try again<');
        for (const raw of ['r1', 'vless-reality', 'hysteria2', 'tcp_connect_timeout', 'udp_no_reply', 'relay_unreachable', 'start_failed']) {
            expect(before, raw).not.toContain(raw);
            expect(details, raw).toContain(raw);
        }
        // The per-route list, in order, each with our words for how it went.
        expect(details).toContain('>Details<');
        expect(details).toMatch(/could not start.*started, but nothing got through.*no result/s);
        expect(details.indexOf('r1')).toBeLessThan(details.indexOf('r4'));
        // Engine vocabulary is printed left-to-right, isolated from the sentence.
        expect(details).toMatch(/<code dir="ltr"/);
    });
    it('offers "Add your file" only when that is the way forward', () => {
        expect(box()).not.toContain('Add your file');
        expect(box({ onAddFile: noop, tried: [], verdict: 'no_routes' })).toContain('>Add your file<');
    });
    it('while the ways are resting: says the wait, and "Try again" is off', () => {
        const html = box({ restText: 'You can try again in about 4 min.', retryOff: true });
        expect(html).toContain('You can try again in about 4 min.');
        expect(html).toMatch(/<button[^>]*disabled=""[^>]*><span>Try again</);
        // Not resting: on.
        expect(box()).not.toMatch(/<button[^>]*disabled/);
    });
    it('"Daal will not choose": offers choosing by hand and no futile Try again', () => {
        const html = box({ onRetry: undefined, onChoose: noop, tried: [], verdict: 'none_usable' });
        expect(html).toContain('>Choose one yourself<');
        expect(html).not.toContain('>Try again<');
    });
    it('holding: the verdict moves into the box, with Try now and Disconnect', () => {
        const html = box({
            lead: EN['auto.verdict.relay_unreachable'],
            actionText: EN['auto.holding.body'],
            retryLabel: EN['auto.holding.try_now'],
            onDisconnect: noop,
        });
        const before = html.slice(0, html.indexOf('<details'));
        expect(before).toContain('Other apps on this phone have no internet');
        expect(before).toContain('Daal could not reach the server in your file.');
        expect(before).toContain('>Try now<');
        expect(before).toContain('>Disconnect<');
    });
    it('with nothing tried, Details says so instead of an empty list', () => {
        const html = box({ tried: [], verdict: 'network_down' });
        expect(html).toContain('Daal did not get as far as trying anything.');
        expect(html).not.toContain('<ol');
    });
    it('renders in Persian, engine vocabulary still only under Details', () => {
        const html = box({}, FA);
        const before = html.slice(0, html.indexOf('<details'));
        expect(before).toContain(FA['auto.verdict.relay_unreachable.do']);
        expect(before).toContain(FA['auto.try_again']);
        expect(before).not.toMatch(/Try again|Ask the person/);
        expect(before).not.toContain('vless');
    });
});
