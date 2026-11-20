// D3 / PA-25, rendered: real components, mounted with react-dom in a
// minimal fake DOM, answering the system Back through the app's one
// back stack. The fake history behaves like WryActivity: Back goes back
// in the webview while it can, otherwise the app is left.
import { afterEach, describe, expect, it, vi, beforeAll } from 'vitest';
import { byAttr, byText, all } from '../test/miniDom';
import type { FakeNode, FakeWindow } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';

// The shell is not here: every command is answered by `answer`.
const answer: { fn: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } = {
    fn: (cmd) => Promise.reject(`not mocked: ${cmd}`),
};
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => answer.fn(cmd, args),
}));
vi.mock('@tauri-apps/api/event', () => ({
    listen: async () => () => {},
}));

let rig: Rig;
let win: FakeWindow;
beforeAll(() => {
    rig = createRig();
    win = rig.win;
});
afterEach(async () => {
    await rig.unmountAll();
});
const mount = (el: React.ReactElement) => rig.mount(el);
const settle = (n?: number) => rig.settle(n);
const back = () => rig.back();
const click = (n: FakeNode | null | undefined) => rig.click(n);
const type = (n: FakeNode | null | undefined, v: string) => rig.type(n, v);

const en = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const t = (k: string) => en[k] ?? k;

describe('Back, rendered', () => {
    it('a sheet over a page: Back closes the sheet, then the page goes back, then the app is left', async () => {
        const React = await import('react');
        const { Sheet } = await import('../design/primitives');
        const { useBack } = await import('./useBack');
        const pageBacks: number[] = [];
        function Page() {
            const [open, setOpen] = React.useState(true);
            const [inner, setInner] = React.useState(true);
            useBack(inner, () => {
                pageBacks.push(1);
                setInner(false);
            }, 'page');
            return (
                <div data-page={inner ? 'inner' : 'top'}>
                    {open && (
                        <Sheet title="S" onClose={() => setOpen(false)}>
                            <span data-sheet="1">sheet</span>
                        </Sheet>
                    )}
                </div>
            );
        }
        const m = await mount(<Page />);
        expect(byAttr(m.container, 'data-sheet')).not.toBeNull();
        expect(win.history.depth).toBe(1);
        await back();
        expect(byAttr(m.container, 'data-sheet')).toBeNull();
        expect(byAttr(m.container, 'data-page', 'inner')).not.toBeNull();
        expect(pageBacks).toEqual([]);
        await back();
        expect(byAttr(m.container, 'data-page', 'top')).not.toBeNull();
        expect(win.history.depth).toBe(0);
        expect(win.history.appLeft).toBe(false);
        await back();
        expect(win.history.appLeft).toBe(true);
        win.history.appLeft = false;
        await m.unmount();
    });

    it('on a tablet or desktop the same Sheet is a centred dialog, and Back closes it too', async () => {
        const React = await import('react');
        const { Sheet } = await import('../design/primitives');
        win.innerWidth = 1400;
        try {
            function Host() {
                const [open, setOpen] = React.useState(true);
                return <div>{open && <Sheet title="S" onClose={() => setOpen(false)}><span data-sheet="1" /></Sheet>}</div>;
            }
            const m = await mount(<Host />);
            expect(byAttr(m.container, 'data-sheet')).not.toBeNull();
            await back();
            expect(byAttr(m.container, 'data-sheet')).toBeNull();
            expect(win.history.appLeft).toBe(false);
        } finally {
            win.innerWidth = 400;
        }
    });

    it('the per-person QR sheet: Back closes it and the page behind stays (PA-25)', async () => {
        const React = await import('react');
        const { QrSendSheet } = await import('../publisher/QrSendSheet');
        const { useBack } = await import('./useBack');
        answer.fn = () => new Promise(() => {}); // qrRender: still streaming
        let leftPage = 0;
        function RelayPage() {
            const [qr, setQr] = React.useState(true);
            useBack(true, () => (leftPage += 1), 'page');
            return (
                <div data-relay-page="1">
                    {qr && (
                        <QrSendSheet
                            t={t}
                            operatorId={1}
                            relayName="Bahar"
                            artifact="recipient:4"
                            onClose={() => setQr(false)}
                        />
                    )}
                </div>
            );
        }
        const m = await mount(<RelayPage />);
        expect(all(m.container, (n) => n.getAttribute?.('role') === 'dialog').length).toBe(1);
        await back();
        expect(all(m.container, (n) => n.getAttribute?.('role') === 'dialog').length).toBe(0);
        expect(byAttr(m.container, 'data-relay-page')).not.toBeNull();
        expect(leftPage).toBe(0);
        expect(win.history.appLeft).toBe(false);
        await m.unmount();
        expect(win.history.depth).toBe(0);
    });

    it('the delete sheet while it works: Back is refused and the sheet stays', async () => {
        const { RelayDestroySheet } = await import('../publisher/RelayListPage');
        let finish: (v: unknown) => void = () => {};
        const calls: unknown[] = [];
        answer.fn = (cmd, args) => {
            calls.push([cmd, args]);
            return new Promise((r) => (finish = r));
        };
        let closed = 0;
        const m = await mount(
            <RelayDestroySheet
                t={t}
                target={{ operatorId: 3, name: 'Bahar', where: '203.0.113.7' }}
                onClose={() => (closed += 1)}
            />,
        );
        const radios = all(m.container, (n) => n.getAttribute?.('role') === 'radio');
        await click(radios[1]); // delete the server
        // The card being chosen names the server it deletes.
        expect(radios[1].getAttribute('aria-checked')).toBe('true');
        expect(radios[1].textContent).toContain('203.0.113.7');
        const go = byAttr(m.container, 'data-button', 'destroy-confirm');
        // The button names the choice (C7.1).
        expect(go?.textContent).toBe(t('pub.relays.destroy.confirm.server_noaddr'));
        await click(go);
        expect(calls[0]).toEqual(['wizard_relay_destroy', { operatorId: 3, deleteServer: true, deleteOwnServer: false }]);
        await back(); // busy: refused
        expect(closed).toBe(0);
        expect(all(m.container, (n) => n.getAttribute?.('role') === 'dialog').length).toBe(1);
        expect(win.history.depth).toBe(1); // the sentinel came back
        finish({ server_deleted: true, ssh_key_deleted: true, firewall_deleted: true, local_removed: true, warnings: [] });
        await settle();
        await back(); // done: Back is the close
        expect(closed).toBe(1);
        await m.unmount();
    });

    it('the wizard: Back at step 2 goes to the key, then to the hosting companies; from there it returns to the list', async () => {
        const { default: PublisherWizard } = await import('../publisher/PublisherWizard');
        let rootBacks = 0;
        let cancels = 0;
        const m = await mount(
            <PublisherWizard
                t={t}
                onDone={() => {}}
                onCancel={() => (cancels += 1)}
                rootBack={() => (rootBacks += 1)}
            />,
        );
        const stepTitle = () => all(m.container, (n) => n.nodeName === 'H2')[0]?.textContent ?? '';
        // It opens on "Where should your relay live?"; Hetzner is chosen.
        const first = stepTitle();
        expect(first).toBe(t('wiz.host.title'));
        await click(byText(m.container, t('common.continue')));
        const key = stepTitle();
        expect(key).toBe(t('wiz.step.cloud.title'));
        await type(all(m.container, (n) => n.nodeName === 'INPUT' && n.getAttribute('type') === 'password')[0], 'tok');
        // "Next" is the primary button of the nav row.
        await click(byText(m.container, t('wiz.nav.next')));
        const second = stepTitle();
        expect(second).not.toBe(key);
        await back();
        expect(stepTitle()).toBe(key);
        await back();
        expect(stepTitle()).toBe(first);
        expect(rootBacks).toBe(0);
        await back();
        expect(rootBacks).toBe(1);
        // Back never cancels or cleans up.
        expect(cancels).toBe(0);
        await m.unmount();
    });

    it('a wizard that is the first screen of a fresh install takes no Back at step 1', async () => {
        const { default: PublisherWizard } = await import('../publisher/PublisherWizard');
        const m = await mount(<PublisherWizard t={t} onDone={() => {}} onCancel={() => {}} />);
        expect(win.history.depth).toBe(0);
        await m.unmount();
    });
});

describe('Back, rendered: the publisher pages', () => {
    const op = {
        id: 5,
        status: 'provisioned',
        provider: 'hetzner',
        region: 'fsn1',
        server_type: 'cx22',
        publisher_pub_hex: 'aa',
        created_at_unix: 1,
        nickname: 'Bahar',
        public_ip: '203.0.113.7',
        public_ipv6: '',
        server_id: '9',
        helper_ip: '198.51.100.2',
        last_provisioned_at_unix: 1,
        decommissioned_at_unix: 0,
        has_signed_sbp: true,
        signed_sbp_at_unix: 1,
        live_recipient_count: 0,
        total_recipient_count: 0,
        floating_ip_id: '',
        can_reserve_address: true,
        toolbox_profile: 'default',
        served_families: [],
    };

    const answerWith = (ops: unknown[]) => {
        answer.fn = (cmd) => {
            if (cmd === 'wizard_list_operators') return Promise.resolve(ops);
            if (cmd === 'publisher_custody_status')
                return Promise.resolve({ level: 'hardware', unlocked: true, ok: true, error: '', legacy_pending: false, legacy_aliases: [], has_existing_blob: true });
            return new Promise(() => {}); // everything else: still loading
        };
    };

    it('one finished relay: the tab opens it; Back returns to the relay list (C7.0)', async () => {
        answerWith([op]);
        const { default: PublisherPage } = await import('../d2pages/PublisherPage');
        const m = await mount(<PublisherPage t={t} />);
        // The relay page itself, with a back control to "Relays".
        expect(byAttr(m.container, 'data-testid', 'people')).not.toBeNull();
        const backBtn = byAttr(m.container, 'data-button', 'page-back');
        expect(backBtn?.getAttribute('aria-label')).toBe(t('pub.relays.title'));
        expect(win.history.depth).toBe(1);
        await back();
        expect(byAttr(m.container, 'data-testid', 'people')).toBeNull();
        expect(byAttr(m.container, 'data-button', 'relay-5')).not.toBeNull();
        // The list is a top-level page: nothing holds Back any more.
        expect(win.history.depth).toBe(0);
        // A tap on the row opens it again, and Back comes back.
        await click(byAttr(m.container, 'data-button', 'relay-5'));
        expect(byAttr(m.container, 'data-testid', 'people')).not.toBeNull();
        expect(win.history.depth).toBe(1);
        await back();
        expect(win.history.depth).toBe(0);
    });

    it('two relays: the list; none: the "set up a relay" empty state, never the wizard by itself', async () => {
        answerWith([op, { ...op, id: 6, nickname: 'Sahand' }]);
        const { default: PublisherPage } = await import('../d2pages/PublisherPage');
        const two = await mount(<PublisherPage t={t} />);
        expect(byAttr(two.container, 'data-button', 'relay-5')).not.toBeNull();
        expect(byAttr(two.container, 'data-button', 'relay-6')).not.toBeNull();
        expect(byAttr(two.container, 'data-testid', 'people')).toBeNull();
        await two.unmount();
        answerWith([]);
        const none = await mount(<PublisherPage t={t} />);
        expect(byAttr(none.container, 'data-empty-state')).not.toBeNull();
        expect(byAttr(none.container, 'data-button', 'new-relay')).not.toBeNull();
        expect(byAttr(none.container, 'data-button', 'restore-link')).not.toBeNull();
        expect(none.container.textContent).toContain(t('pub.relays.empty.line'));
    });

    it('one unfinished relay stays on the list, where it says it may cost money', async () => {
        answerWith([{ ...op, status: 'pre-provision', has_signed_sbp: false }]);
        const { default: PublisherPage } = await import('../d2pages/PublisherPage');
        const m = await mount(<PublisherPage t={t} />);
        expect(byAttr(m.container, 'data-button', 'relay-5')).not.toBeNull();
        expect(m.container.textContent).toContain(t('pub.relays.status.unfinished'));
    });
});
