// «More protection» on the relay page, and the Accounts page (owner
// review 2026-11-21: make it as plain as the Hetzner setup). Three rows,
// each a title, one line, its cost and a switch:
//   - a switch whose account is missing opens that account's sheet;
//   - a switch whose account is connected just runs;
//   - turning one off asks one sentence first;
//   - the standby code is hidden until a switch or «Details»;
//   - there is no open-standby or plain-fallback control anywhere.
// Driven through the real command wrappers against a fake shell.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import type { AddonRow } from './addonTypes';
import type { AccountsState } from './accounts';
import srcSection from './AddonsSection.tsx?raw';
import srcSheets from './AccountSheets.tsx?raw';
import srcPage from '../AccountsPage.tsx?raw';

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
vi.mock('@tauri-apps/api/event', () => ({
    listen: () => Promise.resolve(() => {}),
}));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
    // The Google choice is a per-phone preference (accounts.ts).
    const kept = new Map<string, string>();
    Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: {
            getItem: (k: string) => kept.get(k) ?? null,
            setItem: (k: string, v: string) => void kept.set(k, String(v)),
            removeItem: (k: string) => void kept.delete(k),
        },
    });
});
let ledger: AddonRow[] = [];
beforeEach(() => {
    handlers = { wizard_addons_list: () => ledger };
    calls.length = 0;
    ledger = [];
    localStorage.removeItem('daal.d2.accounts.google');
});
afterEach(async () => {
    await rig.unmountAll();
});

const { translate } = await import('../../lib/i18n');
const { AddonsSection } = await import('./AddonsSection');
const { default: AccountsPage } = await import('../AccountsPage');
const { Addons, classifyPublisherError } = await import('../wizardCommands');
const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const cmds = () => calls.map((c) => c.cmd);
const inputOf = (cmd: string) => (calls.find((c) => c.cmd === cmd)?.args as { input: Record<string, unknown> }).input;

const NONE: AccountsState = { hetzner: true, cloudflare: { connected: false, zone: '' }, google: null };
const ALL: AccountsState = { hetzner: true, cloudflare: { connected: true, zone: 'example.com' }, google: 'signin' };

function row(kind: AddonRow['kind'], state: AddonRow['state'], detail: Record<string, unknown> = {}): AddonRow {
    return {
        id: kind === 'standby' ? 7 : kind === 'cdn' ? 8 : 9,
        operator_id: 1,
        kind,
        state,
        provider_ids: {},
        monthly_cost_cents: kind === 'standby' ? 300 : 0,
        cost_currency: kind === 'standby' ? 'EUR' : '',
        has_secret: false,
        detail,
        created_at_unix: 1,
        updated_at_unix: 1,
    };
}

async function mountSection(accounts: AccountsState, t = en) {
    return rig.mount(<AddonsSection t={t} operatorId={1} accounts={accounts} />);
}

describe('«More protection»: three rows, read in five seconds', () => {
    it('each row is a title, one line, its cost and a switch, all off', async () => {
        const m = await mountSection(NONE);
        expect(m.container.textContent).toContain(en('pub.addons.title'));
        for (const kind of ['standby', 'cdn', 'google']) {
            const r = tid(m.container, `addon-${kind}`)!;
            expect(r.getAttribute('data-state')).toBe('off');
            expect(btn(r, `addon-${kind}-toggle`)?.getAttribute('aria-checked')).toBe('false');
        }
        expect(tid(m.container, 'addon-standby-cost')?.textContent).toBe('€3 a month + VAT');
        expect(tid(m.container, 'addon-cdn-cost')?.textContent).toBe('Domain about $10 a year · needs Cloudflare');
        expect(tid(m.container, 'addon-google-cost')?.textContent).toBe('Free · needs Google');
        // Nothing runs on open but reads.
        expect(cmds().filter((c) => c !== 'wizard_addons_list')).toEqual([]);
        // No Details until something is on.
        expect(tid(m.container, 'addons-details')).toBeNull();
    });

    it('in Persian', async () => {
        const m = await mountSection(NONE, fa);
        expect(m.container.textContent).toContain('محافظت بیشتر');
        expect(tid(m.container, 'addon-standby-cost')?.textContent).toBe('ماهی ۳ یورو + مالیات');
        expect(m.container.textContent).not.toContain('امکانات اختیاری');
    });

    it('with the accounts connected the "needs" goes away', async () => {
        const m = await mountSection(ALL);
        expect(tid(m.container, 'addon-cdn-cost')?.textContent).toBe(en('pub.addons.cdn.cost'));
        expect(tid(m.container, 'addon-google-cost')?.textContent).toBe(en('pub.addons.google.cost'));
    });
});

describe('a switch whose account is not connected opens Accounts', () => {
    it('Cloudflare: the sheet opens, nothing is built; once connected the switch carries on', async () => {
        handlers.wizard_addon_cdn_connect = () => ({ zones: ['example.com'], verdict: 'ok', stored: true });
        handlers.wizard_addon_cdn_build = () => row('cdn', 'ready', { name_hidden: true });
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeTruthy();
        expect(cmds()).not.toContain('wizard_addon_cdn_build');
        await rig.type(btn(m.container, 'cloudflare-token'), 'cf-token');
        ledger = [row('cdn', 'ready', { name_hidden: true })];
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(inputOf('wizard_addon_cdn_connect')).toEqual({ token: 'cf-token' });
        expect(inputOf('wizard_addon_cdn_build')).toEqual({ operator_id: 1, zone: 'example.com' });
        expect(tid(m.container, 'cloudflare-sheet')).toBeNull();
        expect(tid(m.container, 'addon-cdn')?.getAttribute('data-state')).toBe('ready');
        expect(tid(m.container, 'addon-cdn-status')?.textContent).toBe(en('pub.addons.state.on'));
    });

    it('Google: one tap on "Sign in with Google" records it and signs in for this relay', async () => {
        handlers.wizard_addon_google_sign_in = () => row('google', 'ready');
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        const sheet = tid(m.container, 'google-sheet')!;
        expect(sheet.textContent).toContain(en('pub.accounts.google.warn'));
        expect(cmds()).not.toContain('wizard_addon_google_sign_in');
        await rig.click(btn(m.container, 'google-sign-in'));
        expect(inputOf('wizard_addon_google_sign_in')).toEqual({ operator_id: 1 });
        expect(localStorage.getItem('daal.d2.accounts.google')).toBe('signin');
    });

    it('Google by hand: the small link records it, and the switch opens the script steps', async () => {
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        await rig.click(btn(m.container, 'google-by-hand'));
        expect(tid(m.container, 'google-hand-sheet')).toBeTruthy();
        expect(cmds()).not.toContain('wizard_addon_google_sign_in');
    });
});

describe('a switch whose account is connected just runs', () => {
    it('standby: one progress line, then On; always sealed', async () => {
        let finish: (r: AddonRow) => void = () => {};
        handlers.wizard_addon_standby_add = () => new Promise<AddonRow>((r) => (finish = r));
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-standby-toggle'));
        expect(inputOf('wizard_addon_standby_add')).toEqual({ operator_id: 1, mode: 'sealed' });
        expect(tid(m.container, 'addon-standby-status')?.textContent).toBe(en('pub.addons.state.running'));
        expect(btn(m.container, 'addon-standby-toggle')?.getAttribute('aria-checked')).toBe('true');
        ledger = [row('standby', 'ready', { mode: 'sealed' })];
        const React = await import('react');
        await React.act(async () => finish(ledger[0]));
        await rig.settle();
        expect(tid(m.container, 'addon-standby-status')?.textContent).toBe(en('pub.addons.state.on'));
        expect(tid(m.container, 'addon-standby-cost')?.textContent).toBe('€3 a month + VAT');
    });

    it('Cloudflare: builds on the connected domain without asking anything', async () => {
        handlers.wizard_addon_cdn_build = () => row('cdn', 'ready');
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeNull();
        expect(inputOf('wizard_addon_cdn_build')).toEqual({ operator_id: 1, zone: 'example.com' });
    });

    it('a failure is one plain line with Try again, the raw text only under Details', async () => {
        let n = 0;
        handlers.wizard_addon_standby_add = () => {
            n += 1;
            if (n === 1) throw 'E_STANDBY_LIMIT: resource_limit_exceeded';
            return row('standby', 'ready');
        };
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-standby-toggle'));
        const f = tid(m.container, 'addon-standby-failed')!;
        expect(byAttr(f, 'data-testid', 'addon-error')?.getAttribute('data-code')).toBe('E_STANDBY_LIMIT');
        expect(f.textContent).toContain(en('pub.addons.err.E_STANDBY_LIMIT'));
        ledger = [row('standby', 'ready')];
        await rig.click(btn(m.container, 'addon-standby-retry'));
        expect(n).toBe(2);
        expect(tid(m.container, 'addon-standby-failed')).toBeNull();
    });

    it('a Cloudflare key that went missing opens the Cloudflare sheet again', async () => {
        handlers.wizard_addon_cdn_build = () => {
            throw 'E_CDN_NO_TOKEN: no Cloudflare key is kept for this relay';
        };
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeTruthy();
    });

    it('a setup that stopped says so in one line, and Try again sets it up again', async () => {
        ledger = [row('cdn', 'building')];
        handlers.wizard_addon_cdn_build = () => row('cdn', 'ready');
        const m = await mountSection(ALL);
        expect(tid(m.container, 'addon-cdn-failed')?.textContent).toContain(en('pub.addons.state.building'));
        await rig.click(btn(m.container, 'addon-cdn-retry'));
        expect(cmds()).toContain('wizard_addon_cdn_build');
    });
});

describe('turning one off asks one sentence first', () => {
    it('Cloudflare: names that the domain keeps billing; No leaves it on', async () => {
        ledger = [row('cdn', 'ready')];
        handlers.wizard_addon_remove = () => ({ addon_id: 8, removed: true, still_billing: [], by_hand: [], warnings: [] });
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        expect(tid(m.container, 'confirm-body')?.textContent).toBe(en('pub.addons.off.cdn'));
        expect(en('pub.addons.off.cdn')).toMatch(/domain keeps billing/);
        await rig.click(btn(m.container, 'confirm-cancel'));
        expect(cmds()).not.toContain('wizard_addon_remove');
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        ledger = [];
        await rig.click(btn(m.container, 'confirm-yes'));
        expect(calls.find((c) => c.cmd === 'wizard_addon_remove')?.args).toEqual({ addonId: 8 });
        expect(tid(m.container, 'addon-cdn')?.getAttribute('data-state')).toBe('off');
    });

    it('standby: names that the address is given back and the charge stops', async () => {
        ledger = [row('standby', 'ready')];
        handlers.wizard_addon_remove = () => ({ addon_id: 7, removed: true, still_billing: [], by_hand: [], warnings: [] });
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-standby-toggle'));
        expect(tid(m.container, 'confirm-body')?.textContent).toBe(en('pub.addons.off.standby'));
        await rig.click(btn(m.container, 'confirm-yes'));
        expect(cmds()).toContain('wizard_addon_remove');
    });

    it('what is still billing afterwards is said', async () => {
        ledger = [row('cdn', 'ready')];
        handlers.wizard_addon_remove = () => ({ addon_id: 8, removed: true, still_billing: ['domain'], by_hand: [], warnings: [] });
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        ledger = [];
        await rig.click(btn(m.container, 'confirm-yes'));
        expect(tid(m.container, 'addon-cdn-billing')?.textContent).toBe(en('pub.addons.billing.domain'));
    });
});

describe('the standby code shows only when it matters', () => {
    it('hidden by default; «Details» shows it on request', async () => {
        ledger = [row('standby', 'ready', { mode: 'sealed' })];
        handlers.wizard_addon_standby_key = () => ({ key: '000G40 R40M3 0E209 185WP 03H2G' });
        const m = await mountSection(NONE);
        expect(tid(m.container, 'standby-key')).toBeNull();
        expect(m.container.textContent).not.toContain('000G40');
        expect(cmds()).not.toContain('wizard_addon_standby_key');
        expect(tid(m.container, 'addons-details')).toBeTruthy();
        await rig.click(btn(m.container, 'standby-show-key'));
        expect(tid(m.container, 'standby-key')?.textContent).toBe('000G40 R40M3 0E209 185WP 03H2G');
    });

    it('a switch to the standby asks first, then shows the code to send', async () => {
        ledger = [row('standby', 'ready')];
        handlers.wizard_addon_standby_promote = () => ({
            addon: row('standby', 'promoted'),
            key: '000G40 R40M3 0E209 185WP 03H2G',
            refresh_note_published: true,
            warnings: [],
        });
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'standby-switch'));
        expect(tid(m.container, 'confirm-body')?.textContent).toBe(en('pub.addons.standby.switch.body'));
        expect(tid(m.container, 'standby-key')).toBeNull();
        ledger = [row('standby', 'promoted')];
        await rig.click(btn(m.container, 'confirm-yes'));
        expect(tid(m.container, 'standby-key')?.textContent).toBe('000G40 R40M3 0E209 185WP 03H2G');
        expect(tid(m.container, 'addon-standby')?.getAttribute('data-state')).toBe('off');
    });

    it('«Details» says the name is hidden, and nothing else about ECH', async () => {
        ledger = [row('cdn', 'ready', { name_hidden: true, plain_fallback: false })];
        const m = await mountSection(ALL);
        expect(tid(m.container, 'cdn-name-hidden')?.textContent).toBe('Name is hidden ✓');
        expect(m.container.textContent).not.toMatch(/ECH|fallback|posture/i);
    });
});

describe('Daal decides: no open standby, no plain fallback', () => {
    it('no control for either exists, and nothing ever asks the shell for them', async () => {
        ledger = [row('standby', 'ready'), row('cdn', 'ready', { name_hidden: true }), row('google', 'ready')];
        const m = await mountSection(ALL);
        for (const b of ['standby-open', 'cdn-fallback']) expect(btn(m.container, b)).toBeNull();
        // Only the three row switches are switches.
        expect(all(m.container, (n) => n.getAttribute?.('role') === 'switch')).toHaveLength(3);
        expect(cmds()).not.toContain('wizard_addon_cdn_set_plain_fallback');
        for (const src of [srcSection, srcSheets, srcPage]) {
            expect(src).not.toMatch(/cdnSetPlainFallback|plain_fallback\s*:|mode:\s*'open'|E_STANDBY_OPEN_REFUSED/);
        }
        expect(srcSection).toMatch(/mode: 'sealed'/);
    });
});

describe('the Accounts page', () => {
    function shellWith(cf: { connected: boolean; zone: string }) {
        handlers.wizard_list_operators = () => [{ id: 1, status: 'provisioned', has_cloud_token: true, nickname: 'Home' }];
        handlers.wizard_addon_cdn_account = () => cf;
        handlers.wizard_saved_cloud_token = () => null;
    }

    it('lists Hetzner, Cloudflare, Google and the companies still being built', async () => {
        shellWith({ connected: false, zone: '' });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        const acc = (id: string) => byAttr(m.container, 'data-account', id)!;
        expect(acc('hetzner').getAttribute('data-connected')).toBe('true');
        expect(tid(m.container, 'account-hetzner-state')?.textContent).toBe('✓ Connected');
        expect(acc('cloudflare').getAttribute('data-connected')).toBe('false');
        expect(acc('google').getAttribute('data-connected')).toBe('false');
        for (const id of ['vultr', 'digitalocean', 'linode', 'custom']) {
            expect(acc(id).getAttribute('data-connected')).toBe('soon');
            expect(acc(id).textContent).toContain(en('wiz.host.soon'));
        }
    });

    it('Cloudflare: three numbered steps with the pre-filled key page, paste, then ✓ Connected: the one domain', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_addon_cdn_connect = () => ({ zones: ['example.com'], verdict: 'ok', stored: true });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        const steps = tid(m.container, 'cloudflare-steps')!;
        expect(all(steps, (n) => n.nodeName === 'LI')).toHaveLength(3);
        expect(btn(steps, 'cloudflare-token-page')).toBeTruthy();
        expect(m.container.textContent).toContain(en('pub.accounts.cf.sees'));
        await rig.type(btn(m.container, 'cloudflare-token'), '  cf-token ');
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'example.com' });
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(tid(m.container, 'cloudflare-connected')?.textContent).toBe('✓ Connected: example.com');
        // The key left the page.
        expect(btn(m.container, 'cloudflare-token')).toBeNull();
        await rig.click(btn(m.container, 'cloudflare-done'));
        expect(tid(m.container, 'account-cloudflare-state')?.textContent).toBe('✓ Connected: example.com');
    });

    it('a key that sees two domains is refused in one line, and kept nowhere', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_addon_cdn_connect = () => ({ zones: ['a.com', 'b.org'], verdict: 'too_broad', stored: false });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        await rig.type(btn(m.container, 'cloudflare-token'), 'broad');
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(tid(m.container, 'cloudflare-verdict')?.textContent).toBe(en('pub.accounts.cf.verdict.too_broad'));
        expect(tid(m.container, 'cloudflare-connected')).toBeNull();
    });

    it('Google: one step, Sign in with Google, the by-hand way only as a small link', async () => {
        shellWith({ connected: false, zone: '' });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-google-connect'));
        expect(all(tid(m.container, 'google-steps')!, (n) => n.nodeName === 'LI')).toHaveLength(1);
        expect(btn(m.container, 'google-sign-in')?.getAttribute('data-variant')).toBe('primary');
        expect(btn(m.container, 'google-by-hand')?.getAttribute('data-variant')).toBe('link');
        await rig.click(btn(m.container, 'google-sign-in'));
        // No relay here: the choice is recorded, the sign-in waits for a switch.
        expect(cmds()).not.toContain('wizard_addon_google_sign_in');
        expect(tid(m.container, 'account-google-state')?.textContent).toBe(en('pub.accounts.google.chosen.signin'));
    });

    it('in Persian it is «حساب‌ها»', async () => {
        shellWith({ connected: true, zone: 'example.com' });
        const m = await rig.mount(<AccountsPage t={fa} onBack={() => {}} backLabel="رله‌ها" />);
        expect(m.container.textContent).toContain('حساب‌ها');
        expect(tid(m.container, 'account-cloudflare-state')?.textContent).toBe('✓ وصل است: example.com');
    });
});

describe('the command surface', () => {
    it('the account commands reach their Tauri names', async () => {
        const cases: [Promise<unknown>, string][] = [
            [Addons.cdnConnect({ token: 'x' }), 'wizard_addon_cdn_connect'],
            [Addons.cdnAccount(), 'wizard_addon_cdn_account'],
            [Addons.cdnDisconnect(), 'wizard_addon_cdn_disconnect'],
        ];
        for (const [p, name] of cases) {
            const e = await p.then(() => 'resolved', (err: unknown) => err);
            expect(classifyPublisherError(e), name).toBe('E_NOT_BUILT');
        }
        expect(cmds()).toEqual(cases.map(([, n]) => n));
        expect(calls[0].args).toEqual({ input: { token: 'x' } });
    });
});
