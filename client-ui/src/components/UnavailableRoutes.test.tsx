// The import screens must SHOW which ways to connect a file left out
// (backlog TW-6: the verdict carried the list and the strings existed;
// no screen rendered them). Rendered to static markup — no DOM needed.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import UnavailableRoutes from './UnavailableRoutes';
import { parseVerdict } from '../lib/importVerdict';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';

const tr = (dict: unknown) => (k: string) => (dict as Record<string, string>)[k] ?? k;

const partial = parseVerdict(
    JSON.stringify({
        Kind: 0,
        RouteCount: 3,
        Unavailable: [
            { RouteID: 'r5', Family: 'tuic', Reason: 'not_offered' },
            { RouteID: 'r3', Family: 'naive', Reason: 'needs_new_file' },
        ],
    }),
);

describe('UnavailableRoutes', () => {
    it('lists every route the file left out, under a plain title', () => {
        const html = renderToStaticMarkup(<UnavailableRoutes t={tr(en)} verdict={partial} />);
        expect(html).toContain('Some ways to connect are not in this file');
        expect(html).toContain('tuic');
        expect(html).toContain('naive');
        expect(html.match(/<li/g)).toHaveLength(2);
        expect(html).toContain('Ask for a new file');
    });
    it('renders in Persian', () => {
        const html = renderToStaticMarkup(<UnavailableRoutes t={tr(fa)} verdict={partial} />);
        expect(html).toContain((fa as Record<string, string>)['add.unavailable.title']);
        expect(html).not.toContain('Some ways to connect');
    });
    it('renders nothing when the file gave everything it lists', () => {
        expect(renderToStaticMarkup(<UnavailableRoutes t={tr(en)} verdict={parseVerdict('{"Kind":0}')} />)).toBe('');
        expect(renderToStaticMarkup(<UnavailableRoutes t={tr(en)} verdict={null} />)).toBe('');
    });
    it('shows none of a hostile verdict\'s own text', () => {
        const hostile = parseVerdict(
            JSON.stringify({
                Kind: 0,
                Unavailable: [{ RouteID: 'r1', Family: 'call 555-0100', Reason: 'your phone is infected' }],
            }),
        );
        const html = renderToStaticMarkup(<UnavailableRoutes t={tr(en)} verdict={hostile} />);
        expect(html).not.toContain('555');
        expect(html).not.toContain('infected');
        expect(html).toContain('One way to connect');
    });
});
