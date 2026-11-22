// Wave 2 app leftovers in the add sheet, driven in the miniDom rig:
//   • one neutral title for a sheet that takes files, links and codes;
//   • the paste box takes the clipboard on its own ONLY when it holds
//     something Daal can add, never the phone's own Daal address, and
//     says nothing about what the person did not paste;
//   • in the paste list each item's own name sits at the far edge;
//   • a pasted WireGuard conf can be added, and says in one line that
//     Daal uses it only when the person picks it.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';

let clip = '';
const calls: string[] = [];

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string) => {
        if (cmd === 'platform_clipboard_read') {
            calls.push('clipboard');
            return clip;
        }
        throw new Error(`not mocked: ${cmd}`);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: async () => null }));

let nextId = 0;
const fake = {
    uriImport: async (text: string) => {
        calls.push(`uriImport:${text.split('\n')[0]}`);
        nextId++;
        return { raw: JSON.stringify({ Kind: 0, Fingerprint: 'self', RouteCount: 1 }) };
    },
    routesStrict: async () => Array.from({ length: nextId }, (_, i) => ({ routeId: `pasted-${i}` })),
    resolveTrustPrompt: async () => JSON.stringify({ Kind: 0 }),
    listPublishers: async () => [],
    importSbpBytes: async () => '',
    previewBundle: async () => ({}),
    importSbp: async () => '',
    subscriptionAdd: async () => 'sub',
};
vi.mock('../contract/ContractProvider', () => ({ useContract: () => fake }));

const React = await import('react');
const { default: AddSheet } = await import('./AddSheet');
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const d2En = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const d2Fa = (await import('../i18n/d2/d2-extra.fa.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...d2En };
const t = (k: string) => EN[k] ?? k;

const ADDRESS = `daal1q${'m3n8v2c5'.repeat(5)}`;
const VLESS = 'vless://00000000-0000-4000-8000-000000000001@a.example.org:443?security=reality&pbk=AAAA&sid=01#Server%201';
const TROJAN = 'trojan://pass@b.example.org:443?sni=b.example.org#B';
const CONF = `[Interface]
PrivateKey = aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd28=
Address = 10.0.0.2/32

[Peer]
PublicKey = d29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGU=
Endpoint = wg.example.org:51820
AllowedIPs = 0.0.0.0/0`;

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
beforeEach(() => {
    clip = '';
    calls.length = 0;
    nextId = 0;
});
afterEach(async () => {
    await rig.unmountAll();
});

const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const alerts = (root: FakeNode) => all(root, (n) => n.getAttribute('role') === 'alert');
const box = (root: FakeNode) => btn(root, 'paste-box') as unknown as { value: string } & FakeNode;

async function openPaste() {
    const m = await rig.mount(<AddSheet t={t} onClose={vi.fn()} onImported={vi.fn()} />);
    await rig.click(btn(m.container, 'add-paste'));
    await rig.settle(6);
    return m;
}

describe('the add sheet title', () => {
    it('names no kind of thing, in both languages', async () => {
        expect(d2En['add.title']).toBe('Add to Daal');
        expect(d2Fa['add.title']).toBe('افزودن به دال');
        const m = await rig.mount(<AddSheet t={t} onClose={vi.fn()} />);
        expect(m.container.textContent).toContain('Add to Daal');
        expect(m.container.textContent).not.toMatch(/Add my file|Add file/);
    });
});

describe('the paste box does not fill itself with what Daal cannot use', () => {
    it("the phone's own Daal address stays on the clipboard: an empty box and no error", async () => {
        clip = ADDRESS;
        const m = await openPaste();
        expect(calls).toContain('clipboard');
        expect(box(m.container).value ?? '').toBe('');
        expect(alerts(m.container)).toHaveLength(0);
        expect(m.container.textContent).not.toContain(t('add.multi.unknown_single'));
    });

    it('a sentence, a web page or a proxy for another app stays there too', async () => {
        for (const text of ['Salam! See you on Friday.', 'https://news.example.org/today', 'tg://proxy?server=p.example.org&port=443&secret=ee00ff']) {
            clip = text;
            const m = await openPaste();
            expect(box(m.container).value ?? '', text).toBe('');
            expect(alerts(m.container), text).toHaveLength(0);
            await m.unmount();
        }
    });

    it('a link Daal can add is taken, and waits for Add', async () => {
        clip = VLESS;
        const m = await openPaste();
        expect(box(m.container).value).toBe(VLESS);
        expect(btn(m.container, 'add-pasted')).toBeTruthy();
        expect(calls.filter((c) => c.startsWith('uriImport'))).toHaveLength(0);
    });

    it('the Paste button takes anything: then the person pasted it', async () => {
        clip = ADDRESS;
        const m = await openPaste();
        await rig.click(btn(m.container, 'paste-again'));
        await rig.settle(6);
        expect(box(m.container).value).toBe(ADDRESS);
        expect(m.container.textContent).toContain(t('add.multi.unknown_single'));
    });
});

describe('the paste list', () => {
    it("puts each item's own name at the far edge of its row, however short", async () => {
        const m = await rig.mount(<AddSheet t={t} onClose={vi.fn()} initialStep="paste" />);
        await rig.type(btn(m.container, 'paste-box'), `${VLESS}\n${TROJAN}`);
        const names = all(m.container, (n) => n.getAttribute('data-testid') === 'paste-item-name');
        expect(names.map((n) => n.textContent)).toEqual(['Server 1', 'B']);
        for (const n of names) {
            // It takes the rest of the line and ends it in the page's
            // direction, and it is the row's last part.
            expect(n.style.justifyContent).toBe('flex-end');
            expect(n.style.flex).toContain('1');
            expect(n.parentNode?.lastChild).toBe(n);
        }
    });

    it('a WireGuard conf is added with the rest and says it is used only when picked', async () => {
        const m = await rig.mount(<AddSheet t={t} onClose={vi.fn()} onImported={vi.fn()} initialStep="paste" />);
        await rig.type(btn(m.container, 'paste-box'), `${VLESS}\n${CONF}`);
        const line = byAttr(m.container, 'data-testid', 'paste-manual-only');
        expect(line?.textContent).toBe(t('add.multi.manual_only'));
        expect(byAttr(m.container, 'data-testid', 'paste-cannot-add')).toBeNull();
        // Its row names the server's host, never a key.
        expect(m.container.textContent).toContain('wg.example.org');
        expect(m.container.textContent).not.toContain('aGVsbG8');
        expect(btn(m.container, 'paste-add-all')?.textContent).toContain('2');
        await rig.click(btn(m.container, 'paste-add-all'));
        for (let i = 0; i < 10; i++) await React.act(async () => new Promise((r) => setTimeout(r, 5)));
        expect(calls).toContain('uriImport:[Interface]');
        // One link and one conf: no bulk check (a conf is never checked).
        expect(btn(m.container, 'paste-check')).toBeNull();
    });

    it('a conf on its own goes through the single flow with the same line', async () => {
        const m = await rig.mount(<AddSheet t={t} onClose={vi.fn()} initialStep="paste" />);
        await rig.type(btn(m.container, 'paste-box'), CONF);
        expect(byAttr(m.container, 'data-testid', 'paste-manual-only')?.textContent).toBe(t('add.multi.manual_only'));
        expect(btn(m.container, 'add-pasted')).toBeTruthy();
    });
});

describe('the words', () => {
    it('the check says it takes every one, and keeps the line for those it could not', () => {
        for (const cat of [d2En, d2Fa]) {
            for (const k of ['add.multi.manual_only', 'add.multi.keep_working.help', 'add.multi.unchecked', 'add.multi.unchecked_one', 'files.pasted.group', 'files.pasted.manual_only']) {
                expect(cat[k], k).toBeTruthy();
            }
            expect(cat['add.multi.unchecked']).toContain('{n}');
        }
        expect(d2En['add.multi.keep_working.help']).toMatch(/every one/);
        expect(d2Fa['add.multi.manual_only']).not.toMatch(/بزنید/);
    });
});
