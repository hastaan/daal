// The failure box: our own sentence, a Try again button, the raw text
// folded away. Rendered to static markup — no DOM needed.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { EngineStartNotice, FailureBox, StoreResetNotice } from './PageNotices';
import en from '../i18n/en.json';
import fa from '../i18n/fa.json';

const tr = (dict: unknown) => (k: string) => (dict as Record<string, string>)[k] ?? k;

describe('FailureBox', () => {
    it('shows the plain sentence and Try again; the raw text only under Details', () => {
        const t = tr(en);
        const html = renderToStaticMarkup(
            <FailureBox t={t} text={t('network.load_failed')} detail="engine call returned -1" onRetry={() => {}} />,
        );
        expect(html).toContain('Daal could not read your connections. Try again.');
        expect(html).toContain('>Try again</');
        expect(html).toMatch(/<details[^>]*><summary[^>]*>Details<\/summary>.*engine call returned -1.*<\/details>/);
        expect(html).not.toContain('unknown');
        expect(html).not.toContain('Loading');
    });
    it('has no button without a retry, and no fold without a detail', () => {
        const html = renderToStaticMarkup(<FailureBox t={tr(en)} text="x" />);
        expect(html).not.toContain('<button');
        expect(html).not.toContain('<details');
    });
    it('renders in Persian', () => {
        const t = tr(fa);
        const html = renderToStaticMarkup(
            <FailureBox t={t} text={t('network.load_failed')} detail="e" onRetry={() => {}} />,
        );
        expect(html).toContain((fa as Record<string, string>)['network.load_failed']);
        expect(html).toContain((fa as Record<string, string>)['network.try_again']);
        expect(html).not.toContain('Try again');
    });
});

describe('StoreResetNotice', () => {
    it('says what happened and what to do', () => {
        const html = renderToStaticMarkup(<StoreResetNotice t={tr(en)} onDismiss={() => {}} />);
        expect(html).toContain('Your saved connections were reset');
        expect(html).toContain('Add your file again');
        expect(html).toContain('<button');
    });
});

describe('EngineStartNotice', () => {
    it('says Daal could not start, in our words, with the reason only under Details and no "Try again"', () => {
        const html = renderToStaticMarkup(
            <EngineStartNotice t={tr(en)} detail="open secrets.key: permission denied" />,
        );
        expect(html).toContain('Daal could not start on this device');
        expect(html).toContain('Close Daal and open it again');
        expect(html).not.toContain('Try again');
        const beforeDetails = html.slice(0, html.indexOf('<details'));
        expect(beforeDetails).not.toContain('secrets.key');
        expect(html.slice(html.indexOf('<details'))).toContain('secrets.key');
    });
});
