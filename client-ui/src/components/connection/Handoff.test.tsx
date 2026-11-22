// The hand-off card (W1-B) and the Cloudflare route's name, rendered to
// static markup (no DOM).
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import AutoFailure from './AutoFailure';
import HandoffCard, { HANDOFF_APPS, bridgeText, handoffShown } from './HandoffCard';
import { routeLabel } from './WayChooser';
import { DensityProvider } from '../../design/DensityProvider';
import { familyLabel, familyName } from '../../lib/familyName';
import { familyAbout, familyTags, wayTitles } from '../../lib/fileFacts';
import { readyKinds, triedRows, usingLine } from '../../lib/homeFacts';
import { buildPublisherTree } from '../../contract/derive_tree';
import type { ConnectionSummary, RouteDisplayRow } from '../../contract/D2Contract';
import legacyEn from '../../i18n/en.json';
import legacyFa from '../../i18n/fa.json';
import en from '../../i18n/d2/d2-extra.en.json';
import fa from '../../i18n/d2/d2-extra.fa.json';

const dict = (a: unknown, b: unknown) => ({ ...(a as object), ...(b as object) }) as Record<string, string>;
const EN = dict(legacyEn, en);
const FA = dict(legacyFa, fa);
const tr = (d: Record<string, string>) => (k: string) => d[k] ?? k;

describe('HandoffCard: other apps that may work right now', () => {
    const card = (bridgeLines?: string[], d = EN) =>
        renderToStaticMarkup(
            <DensityProvider>
                <HandoffCard t={tr(d)} bridgeLines={bridgeLines} />
            </DensityProvider>,
        );

    it('names the three apps, one line each, and says they are not Daal', () => {
        const html = card();
        expect(html).toContain('Other apps that may work right now');
        expect(html).toContain("other organisations&#x27;");
        expect(html).toContain('not Daal');
        for (const n of ['Psiphon', 'Lantern', 'Orbot / Tor Browser']) expect(html).toContain(n);
        expect(html.match(/data-handoff=/g)).toHaveLength(3);
    });

    it('makes no user-count claim and no promise, in either language', () => {
        for (const d of [EN, FA]) {
            const keys = Object.keys(d).filter((k) => k.startsWith('handoff.'));
            expect(keys.length).toBeGreaterThan(10);
            for (const k of keys) {
                expect(d[k], k).not.toMatch(/million|users|people use|guarantee|will work|always works|[0-9۰-۹]{2,}/i);
            }
        }
    });

    it('links only to the projects\' own store pages and sites', () => {
        for (const a of HANDOFF_APPS) {
            for (const u of [a.phone, a.computer]) {
                expect(u).toMatch(/^https:\/\/(play\.google\.com\/store\/apps\/details\?id=|psiphon\.ca\/|lantern\.io\/|www\.torproject\.org\/)/);
            }
        }
    });

    it('has no bridge section without bridge lines, and never a copy button', () => {
        const html = card();
        expect(html).not.toContain('handoff-bridges');
        const withLines = card(['Bridge obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0']);
        expect(withLines).toContain('Your Tor bridges');
        expect(withLines).toContain('handoff-bridges-qr');
        expect(withLines.toLowerCase()).not.toContain('copy');
        // The lines themselves are never printed as text on the card.
        expect(withLines).not.toContain('192.0.2.1');
    });

    it('hands Orbot plain bridge lines, one per line', () => {
        expect(bridgeText(['Bridge obfs4 a b', '  ', 'webtunnel c d'])).toBe('obfs4 a b\nwebtunnel c d');
    });

    it('renders in Persian', () => {
        const html = card(['obfs4 a b'], FA);
        expect(html).toContain(FA['handoff.title']);
        expect(html).not.toMatch(/Other apps|Get it|Your Tor/);
    });
});

describe('AutoFailure shows the hand-off once Daal\'s ways ran out', () => {
    const tried = [{ routeId: 'r1', family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout' }];
    const box = (verdict: string, handoff?: boolean) =>
        renderToStaticMarkup(
            <DensityProvider>
                <AutoFailure t={tr(EN)} tried={tried} verdict={verdict} handoff={handoff} />
            </DensityProvider>,
        );
    it('after the ways failed', () => {
        for (const v of ['all_failed', 'relay_unreachable', 'name_blocked', 'address_blocked', 'udp_blocked_here', 'some_new_verdict']) {
            expect(handoffShown(v), v).toBe(true);
            expect(box(v), v).toContain('handoff-card');
        }
    });
    it('not when the phone has no internet, or a way can still be chosen by hand', () => {
        for (const v of ['network_down', 'none_usable', 'cancelled']) {
            expect(handoffShown(v), v).toBe(false);
            expect(box(v), v).not.toContain('handoff-card');
        }
        expect(box('all_failed', false)).not.toContain('handoff-card');
    });
});

describe('the Cloudflare route is named as one', () => {
    const route = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
        routeId: id,
        publisherId: 'pub',
        publisherName: 'Pars',
        routeNickname: id,
        trustClass: 'trusted',
        family: 'websocket-tls',
        ...over,
    });
    const direct = route('r1');
    const cdn = route('r2', { viaCdn: true });
    const t = tr(EN);

    it('in the name helpers', () => {
        expect(familyLabel(t, direct)).toBe('WebSocket TLS');
        expect(familyLabel(t, cdn)).toBe('WebSocket TLS · Cloudflare');
        expect(familyName(tr(FA), cdn)).toBe('WebSocket TLS · Cloudflare');
        // Only websocket-tls has a Cloudflare form.
        expect(familyLabel(t, { family: 'vless-reality', viaCdn: true })).toBe('VLESS Reality');
        // A catalog without the new key still names the family.
        expect(familyLabel((k) => (k === 'network.family.websocket_tls' ? 'WS' : k), cdn)).toBe('WS');
    });

    it('in the file card: its own title, not "· 2", and its one-line help', () => {
        const titles = wayTitles(t, [direct, cdn]);
        expect(titles.get('r1')?.title).toBe('WebSocket TLS');
        expect(titles.get('r2')?.title).toBe('WebSocket TLS · Cloudflare');
        expect(familyAbout(t, cdn)).toBe(EN['route.label.ws_cdn.help']);
        expect(familyAbout(t, cdn)).toMatch(/Cloudflare.*slower/);
        expect(familyAbout(t, direct)).not.toContain('Cloudflare');
        const tags = familyTags(t, [direct, cdn], null, 0);
        expect(tags.map((x) => x.name)).toEqual(['WebSocket TLS', 'WebSocket TLS · Cloudflare']);
    });

    it('in the chips, the routes card and the "connected with" line', () => {
        expect(readyKinds(t, [direct, cdn]).names).toEqual(['WebSocket TLS', 'WebSocket TLS · Cloudflare']);
        expect(routeLabel(t, cdn, [direct, cdn])).toBe('Pars · WebSocket TLS · Cloudflare');
        const conn = { state: 'connected', activeRoute: cdn } as unknown as ConnectionSummary;
        expect(usingLine(t, undefined, conn)).toContain('WebSocket TLS · Cloudflare');
        const rows = triedRows(t, [{ routeId: 'r2', family: 'websocket-tls', result: 'start_failed', category: '' }], [direct, cdn]);
        expect(rows[0].family).toBe('WebSocket TLS · Cloudflare');
        const tree = buildPublisherTree([direct, cdn], [], [], () => 'default');
        const chips = tree[0].cells[0].families;
        expect(chips.map((c) => [c.family, !!c.viaCdn, c.count])).toEqual([
            ['websocket-tls', false, 1],
            ['websocket-tls', true, 1],
        ]);
    });

    it('Hysteria 2 keeps its name and carries the dated Iran caveat', () => {
        expect(familyLabel(t, 'hysteria2')).toBe('Hysteria 2');
        expect(familyAbout(t, 'hysteria2')).toMatch(/November 2026.*often blocked or throttled in Iran/);
        expect(familyAbout(tr(FA), 'hysteria2')).toContain('آبان ۱۴۰۵');
    });
});
