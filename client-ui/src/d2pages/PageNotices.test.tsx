// The notices: our own sentence, one action, the raw text folded away
// behind "Details" (mounted only when opened). Rendered to static
// markup — no DOM needed — and opened in the miniDom rig.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { renderToStaticMarkup as ssr } from 'react-dom/server';
import type { ReactElement } from 'react';
import { DensityProvider } from '../design/DensityProvider';
import { EngineStartNotice, FailureBox, NoticeRow, StoreResetNotice } from './PageNotices';
import { byAttr } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';
import legacyEn from '../i18n/en.json';
import legacyFa from '../i18n/fa.json';
import d2En from '../i18n/d2/d2-extra.en.json';
import d2Fa from '../i18n/d2/d2-extra.fa.json';

vi.mock('@tauri-apps/api/core', () => ({ invoke: (cmd: string) => Promise.reject(`not mocked: ${cmd}`) }));

const EN = { ...(legacyEn as object), ...(d2En as object) } as Record<string, string>;
const FA = { ...(legacyFa as object), ...(d2Fa as object) } as Record<string, string>;
const renderToStaticMarkup = (el: ReactElement) => ssr(<DensityProvider>{el}</DensityProvider>);
const tr = (dict: Record<string, string>) => (k: string) => dict[k] ?? k;

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

describe('FailureBox', () => {
    it('shows the plain sentence and Try again; the raw text only once Details is opened', async () => {
        const t = tr(EN);
        const el = <FailureBox t={t} text={t('network.load_failed')} detail="engine call returned -1" onRetry={() => {}} />;
        const html = renderToStaticMarkup(el);
        expect(html).toContain('Daal could not read your connections. Try again.');
        expect(html).toContain('>Try again</');
        expect(html).toContain('>Details<');
        // Folded: the raw text is not on the surface.
        expect(html).not.toContain('engine call returned -1');
        const m = await rig.mount(el);
        await rig.click(byAttr(m.container, 'data-button', 'notice-details'));
        expect(m.container.textContent).toContain('engine call returned -1');
    });
    it('has no button without a retry, and no fold without a detail', () => {
        const html = renderToStaticMarkup(<FailureBox t={tr(EN)} text="x" />);
        expect(html).not.toContain('<button');
        expect(html).not.toContain('Details');
    });
    it('renders in Persian', () => {
        const t = tr(FA);
        const html = renderToStaticMarkup(<FailureBox t={t} text={t('network.load_failed')} detail="e" onRetry={() => {}} />);
        expect(html).toContain(FA['network.load_failed']);
        expect(html).toContain(FA['network.try_again']);
        expect(html).not.toContain('Try again');
    });
});

describe('StoreResetNotice', () => {
    it('says what happened on one line with its action; what to do next is behind Details', async () => {
        const el = <StoreResetNotice t={tr(EN)} onDismiss={() => {}} />;
        const html = renderToStaticMarkup(el);
        expect(html).toContain('Your saved connections were reset');
        expect(html).toContain('>OK<');
        const m = await rig.mount(el);
        await rig.click(byAttr(m.container, 'data-button', 'notice-details'));
        expect(m.container.textContent).toContain('Add your file again');
    });
});

describe('EngineStartNotice', () => {
    it('says Daal could not start, in our words, with the reason only under Details and no "Try again"', async () => {
        const el = <EngineStartNotice t={tr(EN)} detail="open secrets.key: permission denied" />;
        const html = renderToStaticMarkup(el);
        expect(html).toContain('Daal could not start on this device');
        expect(html).toContain('Close Daal and open it again');
        expect(html).not.toContain('Try again');
        expect(html).not.toContain('secrets.key');
        const m = await rig.mount(el);
        await rig.click(byAttr(m.container, 'data-button', 'notice-details'));
        expect(m.container.textContent).toContain('secrets.key');
    });
});

describe('NoticeRow', () => {
    it('is one row: icon, one line, its action', () => {
        const html = renderToStaticMarkup(<NoticeRow t={tr(EN)} text="This build cannot carry traffic" />);
        expect(html).toContain('role="alert"');
        expect(html).toContain('This build cannot carry traffic');
        expect(html).not.toContain('<button');
    });
});
