// The build wizard with accounts that come first (owner, 2026-11-22):
//   - a connected hosting account skips the paste-key step, with a small
//     "use a different key" way out;
//   - «More protection (optional)» is a step before «Create my relay»:
//     three switches, all off, a missing account opens its sheet here;
//   - the chosen extras are turned on after the relay is built, with the
//     same calls the relay page's switches make, and a failure stays one
//     line with «Try again» on the relay page, never a failed relay.
// Driven in the app's live mode against a fake shell.
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import uiEn from '../i18n/en.json';
import { all, byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';

type Handler = (args: Record<string, unknown> | undefined) => unknown;
let handlers: Record<string, Handler> = {};
const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        const h = handlers[cmd];
        if (!h) throw `E_NOT_BUILT: ${cmd} is not mocked`;
        return h(args);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

const EN = { ...(uiEn as Record<string, string>), ...(en as Record<string, string>) };
const t = (k: string) => EN[k] ?? k;
const btn = (c: FakeNode, name: string) => byAttr(c, 'data-button', name);
const tid = (c: FakeNode, id: string) => byAttr(c, 'data-testid', id);
const cmds = () => calls.map((c) => c.cmd);
const inputs = (c: FakeNode) => all(c, (n) => n.nodeName === 'INPUT');

let rig: Rig;
const kept = new Map<string, string>();
beforeAll(() => {
    rig = createRig();
    // Live mode: the app is inside the shell.
    (globalThis as unknown as { window: Record<string, unknown> }).window.__TAURI_INTERNALS__ = {};
    Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: {
            getItem: (k: string) => kept.get(k) ?? null,
            setItem: (k: string, v: string) => void kept.set(k, String(v)),
            removeItem: (k: string) => void kept.delete(k),
        },
    });
});
afterAll(() => {
    delete (globalThis as unknown as { window: Record<string, unknown> }).window.__TAURI_INTERNALS__;
});

const X86 = { id: 'cpx12', description: 'CPX12', cpus: 1, memory_gb: 2, disk_gb: 40, monthly_eur: 14.36, hourly_eur: 0.023, location: 'fsn1', arch: 'x86' };

/** A shell with one connected Hetzner account and no relay yet. */
function shell(over: { hetzner?: boolean; cloudflare?: { connected: boolean; zone: string } } = {}) {
    const hz = over.hetzner ?? true;
    const cf = over.cloudflare ?? { connected: false, zone: '' };
    handlers = {
        wizard_hosting_account_status: () => ({
            hetzner: { connected: hz, account: hz },
            vultr: { connected: false, account: false },
        }),
        wizard_saved_cloud_token: () => (hz ? { operator_id: 0, nickname: '', account: true } : null),
        wizard_reuse_cloud_token: () => 7,
        wizard_store_cloud_token: () => 7,
        wizard_list_server_types: () => [X86],
        wizard_list_existing_servers: () => [],
        wizard_set_operator_nickname: () => null,
        wizard_addon_cdn_account: () => cf,
        wizard_get_helper_ip: () => '198.51.100.1',
        wizard_select_profile: () => null,
        wizard_publisher_keygen: () => ({ hex: 'aa'.repeat(16), en_words: 'a b c d', fa_words: 'ا ب پ ت' }),
        wizard_provision_run: () => null,
        wizard_sign_relaypack: () => ({ sbp_path: 'x', fingerprint_hex: 'aa', sbp_sha256: 'bb' }),
        wizard_produce_shared_sbp: () => ({ sbp_path: 'x', server: 's' }),
        wizard_addons_list: () => [],
    };
}

beforeEach(() => {
    calls.length = 0;
    kept.clear();
});
afterEach(async () => {
    await rig.unmountAll();
});

async function until(cond: () => boolean, what: string, rounds = 400) {
    for (let i = 0; i < rounds && !cond(); i++) await rig.settle(1);
    expect(cond(), what).toBe(true);
}

async function mountWizard(onDone: (id: number) => void = () => {}) {
    const { default: PublisherWizard } = await import('./PublisherWizard');
    return rig.mount(<PublisherWizard t={t} onDone={onDone} onCancel={() => {}} />);
}

describe('the hosting account in the wizard', () => {
    it('connected: no key to paste, Next copies the account key into the new relay', async () => {
        shell();
        const m = await mountWizard();
        await rig.click(btn(m.container, 'wiz-next')); // the hosting companies
        const using = tid(m.container, 'wizard-account-connected');
        expect(using?.textContent).toContain('Using your connected Hetzner Cloud account.');
        expect(tid(m.container, 'wizard-guide')).toBeNull();
        expect(inputs(m.container)).toHaveLength(0);
        expect(btn(m.container, 'use-other-key')?.textContent).toContain(EN['wiz.provider.account.other']);
        const next = btn(m.container, 'wiz-next')!;
        expect(next.getAttribute('disabled')).toBeNull();
        await rig.click(next);
        expect(cmds()).toContain('wizard_reuse_cloud_token');
        expect(cmds()).not.toContain('wizard_store_cloud_token');
        await until(() => tid(m.container, 'wizard-account-connected') == null, 'left the key step');
    });

    it('"use a different key" shows the paste step, and only a typed key goes on', async () => {
        shell();
        const m = await mountWizard();
        await rig.click(btn(m.container, 'wiz-next'));
        await rig.click(btn(m.container, 'use-other-key'));
        expect(tid(m.container, 'wizard-guide')).not.toBeNull();
        expect(tid(m.container, 'wizard-account-connected')).toBeNull();
        expect(btn(m.container, 'wiz-next')!.getAttribute('disabled')).not.toBeNull();
        await rig.type(inputs(m.container)[0], 'hcloud-other');
        await rig.click(btn(m.container, 'wiz-next'));
        const store = calls.find((c) => c.cmd === 'wizard_store_cloud_token');
        expect(store?.args).toMatchObject({ provider: 'hetzner', token: 'hcloud-other' });
        expect(cmds()).not.toContain('wizard_reuse_cloud_token');
    });

    it('not connected: the numbered guide and the key field, as before', async () => {
        shell({ hetzner: false });
        const m = await mountWizard();
        await rig.click(btn(m.container, 'wiz-next'));
        expect(tid(m.container, 'wizard-guide')).not.toBeNull();
        expect(tid(m.container, 'wizard-account-connected')).toBeNull();
        expect(inputs(m.container)).toHaveLength(1);
    });
});

/** From a fresh wizard to the «More protection» step. */
async function toExtras(m: { container: FakeNode }) {
    await rig.click(btn(m.container, 'wiz-next')); // companies → key
    await rig.click(btn(m.container, 'wiz-next')); // key → plan
    await until(() => btn(m.container, 'wiz-next')?.getAttribute('disabled') == null && tid(m.container, 'wizard-addons') == null && cmds().includes('wizard_list_server_types'), 'plan loaded');
    await until(() => btn(m.container, 'wiz-next')?.getAttribute('disabled') == null, 'a size chosen');
    expect(btn(m.container, 'wiz-next')!.textContent).toContain(EN['common.continue']);
    await rig.click(btn(m.container, 'wiz-next')); // plan → extras
    await until(() => tid(m.container, 'wizard-addons') != null, 'extras step');
}

describe('«More protection (optional)» while building', () => {
    it('is its own step before «Create my relay»: three switches, all off, with their cost', async () => {
        shell();
        const m = await mountWizard();
        await toExtras(m);
        const title = all(m.container, (n) => n.nodeName === 'H2')[0]?.textContent ?? '';
        expect(title).toBe(EN['wiz.step.extras.title']);
        for (const k of ['standby', 'cdn', 'google']) {
            expect(tid(m.container, `wizard-addon-${k}`)?.getAttribute('data-chosen'), k).toBe('false');
        }
        expect(tid(m.container, 'wizard-addon-standby-cost')?.textContent).toBe('€3 a month + VAT, on top of the relay');
        expect(tid(m.container, 'wizard-addon-cdn-cost')?.textContent).toContain(EN['pub.addons.needs.cloudflare']);
        expect(m.container.textContent).toContain(EN['pub.addons.wizard.intro']);
        expect(btn(m.container, 'wiz-next')!.textContent).toContain(EN['wiz.plan.next']);
        // Choosing rents nothing.
        await rig.click(btn(m.container, 'wizard-addon-standby-toggle'));
        expect(tid(m.container, 'wizard-addon-standby')?.getAttribute('data-chosen')).toBe('true');
        expect(cmds().filter((c) => c.startsWith('wizard_addon_') && c !== 'wizard_addon_cdn_account')).toEqual([]);
        expect(JSON.parse(kept.get('daal.wizard.addons.7') ?? '[]')).toEqual(['standby']);
    });

    it('a switch whose account is missing opens its sheet here, then comes back on', async () => {
        shell();
        handlers.wizard_addon_cdn_connect = () => ({ zones: ['example.com'], verdict: 'ok', stored: true });
        const m = await mountWizard();
        await toExtras(m);
        await rig.click(btn(m.container, 'wizard-addon-cdn-toggle'));
        expect(tid(m.container, 'cloudflare-sheet')).not.toBeNull();
        expect(tid(m.container, 'wizard-addon-cdn')?.getAttribute('data-chosen')).toBe('false');
        await rig.type(btn(m.container, 'cloudflare-token'), 'cf-token');
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'example.com' });
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeNull();
        expect(tid(m.container, 'wizard-addon-cdn')?.getAttribute('data-chosen')).toBe('true');
        // Google: the sheet, then «Sign in with Google» chooses it.
        await rig.click(btn(m.container, 'wizard-addon-google-toggle'));
        expect(tid(m.container, 'google-sheet')).not.toBeNull();
        await rig.click(btn(m.container, 'google-sign-in'));
        expect(tid(m.container, 'wizard-addon-google')?.getAttribute('data-chosen')).toBe('true');
        expect(cmds()).not.toContain('wizard_addon_google_sign_in');
        // Back keeps the choice; Next on the plan comes back to it.
        await rig.click(btn(m.container, 'wiz-back'));
        await rig.click(btn(m.container, 'wiz-next'));
        await until(() => tid(m.container, 'wizard-addons') != null, 'extras again');
        expect(tid(m.container, 'wizard-addon-cdn')?.getAttribute('data-chosen')).toBe('true');
    });

    it('the chosen extras are turned on after the relay is built; a failure is one line, not a failed relay', async () => {
        shell({ cloudflare: { connected: true, zone: 'example.com' } });
        handlers.wizard_addon_standby_add = () => ({ id: 1, kind: 'standby', state: 'ready' });
        handlers.wizard_addon_cdn_build = () => {
            throw 'E_CDN_TEST_FAILED: no answer through the edge';
        };
        const m = await mountWizard();
        await toExtras(m);
        await rig.click(btn(m.container, 'wizard-addon-standby-toggle'));
        await rig.click(btn(m.container, 'wizard-addon-cdn-toggle'));
        expect(cmds()).not.toContain('wizard_addon_standby_add');
        await rig.click(btn(m.container, 'wiz-next')); // «Create my relay»
        await until(() => tid(m.container, 'wizard-done') != null, 'relay built', 2000);
        await until(
            () => tid(m.container, 'wizard-addon-cdn-progress')?.getAttribute('data-state') === 'failed',
            'cdn settled',
        );

        // After the relay, never before it, and with the switches' calls.
        const order = cmds();
        const shared = order.indexOf('wizard_produce_shared_sbp');
        expect(shared).toBeGreaterThan(-1);
        expect(order.indexOf('wizard_addon_standby_add')).toBeGreaterThan(shared);
        expect(order.indexOf('wizard_addon_cdn_build')).toBeGreaterThan(order.indexOf('wizard_addon_standby_add'));
        expect(calls.find((c) => c.cmd === 'wizard_addon_standby_add')?.args).toEqual({ input: { operator_id: 7, mode: 'sealed' } });
        expect(calls.find((c) => c.cmd === 'wizard_addon_cdn_build')?.args).toEqual({ input: { operator_id: 7, zone: 'example.com' } });
        expect(cmds()).not.toContain('wizard_addon_google_sign_in');

        expect(tid(m.container, 'wizard-addon-standby-progress')?.getAttribute('data-state')).toBe('on');
        expect(tid(m.container, 'wizard-addon-cdn-failed')?.textContent).toContain(EN['pub.addons.err.E_CDN_TEST_FAILED']);
        expect(tid(m.container, 'wizard-addon-cdn-failed')?.textContent).toContain(EN['pub.addons.wizard.failed']);
        // The relay is done all the same.
        expect(btn(m.container, 'add-first-person')).not.toBeNull();
        // Applied once: the choice is gone, the failure is kept for the relay.
        expect(kept.get('daal.wizard.addons.7')).toBeUndefined();
        expect(Object.keys(JSON.parse(kept.get('daal.addons.failed.7') ?? '{}'))).toEqual(['cdn']);

        // The relay page shows it as one line with «Try again».
        await rig.unmountAll();
        const { AddonsSection } = await import('./addons/AddonsSection');
        const page = await rig.mount(
            <AddonsSection
                t={t}
                operatorId={7}
                accounts={{ hetzner: true, hetznerAccount: true, cloudflare: { connected: true, zone: 'example.com' }, google: null }}
            />,
        );
        const failed = tid(page.container, 'addon-cdn-failed');
        expect(failed?.textContent).toContain(EN['pub.addons.err.E_CDN_TEST_FAILED']);
        expect(btn(page.container, 'addon-cdn-retry')?.textContent).toContain(EN['pub.addons.try_again']);
        handlers.wizard_addon_cdn_build = () => ({ id: 2, kind: 'cdn', state: 'ready' });
        await rig.click(btn(page.container, 'addon-cdn-retry'));
        expect(tid(page.container, 'addon-cdn-failed')).toBeNull();
        expect(kept.get('daal.addons.failed.7')).toBeUndefined();
    });

    it('a build with nothing chosen turns nothing on', async () => {
        shell();
        const m = await mountWizard();
        await toExtras(m);
        await rig.click(btn(m.container, 'wiz-next'));
        await until(() => tid(m.container, 'wizard-done') != null, 'relay built', 2000);
        await rig.settle(10);
        expect(cmds().filter((c) => /^wizard_addon_(standby_add|cdn_build|google_sign_in)$/.test(c))).toEqual([]);
        expect(tid(m.container, 'wizard-addons-progress')).toBeNull();
    });
});
