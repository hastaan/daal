// "Links for other apps": the sheet for one person.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all as allNodes, byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import type { ShareLinksResult } from '../wizardCommands';

const written: string[] = [];
let writeFails = false;
vi.mock('../../lib/clipboard', () => ({
    writeClipboardText: async (text: string) => {
        if (writeFails) throw new Error('the clipboard could not be written');
        written.push(text);
    },
    readClipboardText: async () => '',
}));
vi.mock('@tauri-apps/api/core', () => ({
    invoke: () => Promise.reject('not mocked'),
}));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
const secure: boolean[] = [];
beforeEach(async () => {
    written.length = 0;
    writeFails = false;
    secure.length = 0;
    const s = await import('../useSecureScreen');
    s.setSecureScreenSetterForTests(async (on) => {
        secure.push(on);
    });
});
afterEach(async () => {
    await rig.unmountAll();
    const s = await import('../useSecureScreen');
    s.setSecureScreenSetterForTests(null);
});

const { translate } = await import('../../lib/i18n');
const { ShareLinksSheet } = await import('./ShareLinksSheet');
const t = (k: string) => translate('en', k);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const all = (root: FakeNode, attr: string, v: string): FakeNode[] => allNodes(root, (n) => n.getAttribute(attr) === v);

const REALITY = 'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&pbk=k&sid=ab#Home';
const SS = 'ss://2022-blake3-aes-128-gcm:a%3Ab@1.2.3.4:8446#Home';
const RESULT: ShareLinksResult = {
    links: [
        { way: 'vless-reality', label: 'Home · REALITY', link: REALITY },
        { way: 'shadowsocks', label: 'Home · Shadowsocks', link: SS },
    ],
    left_out: [
        { way: 'naive', reason: 'needs_insecure' },
        { way: 'hysteria2', reason: 'missing_material' },
    ],
};
const flush = () => new Promise((r) => setTimeout(r, 0));

describe('Links for other apps', () => {
    it('shows one link, folds the others and the left-out ways away', async () => {
        const load = vi.fn(async () => RESULT);
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={load} />,
        );
        await flush();
        expect(load).toHaveBeenCalledWith(7, 3);
        expect(tid(m.container, 'share-links-warning')?.textContent).toBe(t('pub.links.warning').replace(/\{name\}/g, 'Bahar'));
        expect(tid(m.container, 'share-links-for-apps')?.textContent).toBe(t('pub.links.for_apps'));
        let rows = all(m.container, 'data-testid', 'share-link-row');
        expect(rows.map((r) => r.getAttribute('data-way'))).toEqual(['vless-reality']);
        // The first link needs no protocol title.
        expect(rows[0].textContent).not.toContain('Reality');
        expect(tid(m.container, 'share-links-left-out')).toBeNull();
        await rig.click(btn(m.container, 'share-links-more'));
        rows = all(m.container, 'data-testid', 'share-link-row');
        expect(rows.map((r) => r.getAttribute('data-way'))).toEqual(['vless-reality', 'shadowsocks']);
        // The link itself is never printed on the screen: only Copy / QR.
        expect(m.container.textContent).not.toContain('vless://');
        await rig.click(btn(m.container, 'share-links-left-out-toggle'));
        const left = tid(m.container, 'share-links-left-out')?.textContent ?? '';
        expect(left).toContain(`${t('network.family.naive')}: ${t('pub.links.why.needs_insecure')}`);
        expect(left).toContain(`${t('network.family.hysteria2')}: ${t('pub.links.why.missing_material')}`);
    });

    it('puts ways left out for one reason on one line', async () => {
        const result: ShareLinksResult = {
            links: [{ way: 'vless-reality', label: 'x', link: REALITY }],
            left_out: ['websocket-tls', 'naive', 'tuic', 'anytls'].map((way) => ({ way, reason: 'needs_insecure' })),
        };
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={async () => result} />,
        );
        await flush();
        expect(btn(m.container, 'share-links-more')).toBeNull();
        await rig.click(btn(m.container, 'share-links-left-out-toggle'));
        const lines = tid(m.container, 'share-links-left-out')?.childNodes ?? [];
        expect(lines).toHaveLength(1);
        expect(lines[0].textContent).toBe(
            `${['websocket_tls', 'naive', 'tuic', 'anytls'].map((f) => t(`network.family.${f}`)).join(', ')}: ${t('pub.links.why.needs_insecure')}`,
        );
    });

    it('marks the screen sensitive while it is open', async () => {
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={async () => RESULT} />,
        );
        await flush();
        expect(secure).toContain(true);
        await rig.unmountAll();
        await flush();
        expect(secure[secure.length - 1]).toBe(false);
        void m;
    });

    it('copies the link with the one clipboard helper', async () => {
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={async () => RESULT} />,
        );
        await flush();
        await rig.click(btn(m.container, 'share-links-more'));
        const copy = all(m.container, 'data-button', 'share-link-copy');
        await rig.click(copy[1]);
        await flush();
        expect(written).toEqual([SS]);
        expect(copy[1].textContent).toContain(t('pub.links.copied'));
    });

    it('says so when copying fails, without the link', async () => {
        writeFails = true;
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={async () => RESULT} />,
        );
        await flush();
        await rig.click(all(m.container, 'data-button', 'share-link-copy')[0]);
        await flush();
        expect(tid(m.container, 'share-link-copy-failed')?.textContent).toBe(t('pub.links.copy_failed'));
    });

    it('shows and hides a QR code for one link', async () => {
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={async () => RESULT} />,
        );
        await flush();
        expect(tid(m.container, 'share-link-qr')).toBeNull();
        const qr = all(m.container, 'data-button', 'share-link-qr')[0];
        await rig.click(qr);
        expect(tid(m.container, 'share-link-qr')).not.toBeNull();
        expect(all(m.container, 'data-testid', 'share-link-qr')).toHaveLength(1);
        await rig.click(qr);
        expect(tid(m.container, 'share-link-qr')).toBeNull();
    });

    it('a failure offers a retry and shows no detail', async () => {
        let n = 0;
        const load = vi.fn(async () => {
            n++;
            if (n === 1) throw new Error('vless://secret');
            return { links: [], left_out: [] };
        });
        const m = await rig.mount(
            <ShareLinksSheet t={t} operatorId={7} recipientId={3} name="Bahar" onClose={() => {}} load={load} />,
        );
        await flush();
        expect(tid(m.container, 'share-links-failed')?.textContent).toContain(t('pub.links.error'));
        expect(m.container.textContent).not.toContain('secret');
        await rig.click(btn(m.container, 'share-links-retry'));
        await flush();
        expect(tid(m.container, 'share-links-none')?.textContent).toBe(t('pub.links.none'));
    });

    it('every string has English and Persian', async () => {
        const keys = [
            'menu', 'title', 'warning', 'loading', 'error', 'retry', 'none', 'copy', 'copied', 'copy_failed',
            'qr_show', 'qr_hide', 'close', 'left_out', 'more', 'for_apps', 'why.needs_insecure', 'why.missing_material',
            'why.not_signed', 'why.shows_cdn_name', 'why.no_link_format', 'why.other',
        ].map((k) => `pub.links.${k}`);
        for (const k of keys) {
            expect(translate('en', k)).not.toBe(k);
            expect(translate('fa', k)).not.toBe(translate('en', k));
        }
        expect(translate('fa', 'pub.links.warning')).toContain('{name}');
    });
});
