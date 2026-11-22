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
import srcWizardAddons from './wizardAddons.ts?raw';
import srcWizardRows from './WizardAddons.tsx?raw';

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
    // Per-phone conveniences (wizardAddons.ts keeps a failed extra).
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
});
afterEach(async () => {
    await rig.unmountAll();
});

const { translate } = await import('../../lib/i18n');
const { AddonsSection } = await import('./AddonsSection');
const { default: AccountsPage } = await import('../AccountsPage');
const { Addons, Wizard, classifyPublisherError } = await import('../wizardCommands');
const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const cmds = () => calls.map((c) => c.cmd);
const inputOf = (cmd: string) => (calls.find((c) => c.cmd === cmd)?.args as { input: Record<string, unknown> }).input;

const NO_G = { connected: false, scriptMade: false, signIn: false };
const NONE: AccountsState = { hetzner: true, hetznerAccount: true, cloudflare: { connected: false, zone: '' }, google: NO_G };
const ALL: AccountsState = {
    hetzner: true,
    hetznerAccount: true,
    cloudflare: { connected: true, zone: 'example.com' },
    google: { connected: true, scriptMade: false, signIn: false },
};
const EXEC = 'https://script.google.com/macros/s/AKfycbx0123456789abcdefghijklmn/exec';
const G_ACCOUNT = (connected: boolean, sign_in = false) => ({ connected, script_made: false, url: connected ? EXEC : '', sign_in });

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

    it('Google: the sheet adds the one script by hand, checks it, then the switch takes a place in it', async () => {
        handlers.wizard_google_account_script = () => ({ code_gs: '// the script', manifest_json: '{}' });
        handlers.wizard_google_account_attach = () => G_ACCOUNT(true);
        handlers.wizard_addon_google_on = () => row('google', 'ready');
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        const sheet = tid(m.container, 'google-sheet')!;
        expect(sheet.textContent).toContain(en('pub.accounts.google.warn'));
        // Account, copy, paste in Apps Script, deploy, paste back.
        expect(all(tid(m.container, 'google-steps')!, (n) => n.nodeName === 'LI')).toHaveLength(5);
        // No OAuth clients in this build: no trace of signing in.
        expect(btn(m.container, 'google-sign-in')).toBeNull();
        expect(m.container.textContent).not.toContain(en('pub.accounts.google.sign_in'));
        expect(cmds()).not.toContain('wizard_addon_google_on');
        await rig.click(btn(m.container, 'google-copy-script'));
        expect(cmds()).toContain('wizard_google_account_script');
        expect(tid(m.container, 'google-script')).toBeTruthy();
        expect(btn(m.container, 'google-connect')?.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(m.container, 'google-url'), ` ${EXEC} `);
        ledger = [row('google', 'ready')];
        await rig.click(btn(m.container, 'google-connect'));
        expect(inputOf('wizard_google_account_attach')).toEqual({ url: EXEC });
        // Connected: the sheet closes and the switch carries on, with no
        // per-relay step in Google.
        expect(tid(m.container, 'google-sheet')).toBeNull();
        expect(inputOf('wizard_addon_google_on')).toEqual({ operator_id: 1 });
        expect(tid(m.container, 'addon-google-status')?.textContent).toBe(en('pub.addons.state.on'));
    });

    it('Google: an address the check refuses is one line, and nothing is turned on', async () => {
        handlers.wizard_google_account_attach = () => {
            throw 'E_GOOGLE_CHECK_FAILED: not_deployed: the answer is not from Daal\'s script';
        };
        const m = await mountSection(NONE);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        await rig.type(btn(m.container, 'google-url'), EXEC);
        await rig.click(btn(m.container, 'google-connect'));
        const e = tid(m.container, 'addon-error')!;
        expect(e.getAttribute('data-code')).toBe('E_GOOGLE_CHECK_FAILED');
        expect(e.textContent).toContain(en('pub.addons.google.reason.not_deployed'));
        expect(tid(m.container, 'google-connected')).toBeNull();
        expect(cmds()).not.toContain('wizard_addon_google_on');
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

    it('Google: takes a place in the connected script, no sheet, nothing asked', async () => {
        handlers.wizard_addon_google_on = () => row('google', 'ready');
        const m = await mountSection(ALL);
        ledger = [row('google', 'ready')];
        await rig.click(btn(m.container, 'addon-google-toggle'));
        expect(tid(m.container, 'google-sheet')).toBeNull();
        expect(inputOf('wizard_addon_google_on')).toEqual({ operator_id: 1 });
        expect(tid(m.container, 'addon-google-status')?.textContent).toBe(en('pub.addons.state.on'));
    });

    it('Google: a failed first update is one line and Try again; the raw words only under Details', async () => {
        let n = 0;
        handlers.wizard_addon_google_on = () => {
            n += 1;
            if (n === 1) throw 'E_GOOGLE_CHECK_FAILED: unreachable: front: dial 142.250.0.1:443: i/o timeout';
            return row('google', 'ready');
        };
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        const f = tid(m.container, 'addon-google-failed')!;
        const line = all(f, (x) => x.nodeName === 'P')[0];
        expect(line.textContent).toBe(`${en('pub.addons.err.E_GOOGLE_CHECK_FAILED')} ${en('pub.addons.google.reason.unreachable')}`);
        expect(line.textContent).not.toContain('i/o timeout');
        expect(f.textContent).toContain(en('pub.addons.details'));
        ledger = [row('google', 'ready')];
        await rig.click(btn(m.container, 'addon-google-retry'));
        expect(n).toBe(2);
        expect(tid(m.container, 'addon-google-failed')).toBeNull();
    });

    it('a Google account that went missing opens the Google sheet again', async () => {
        handlers.wizard_addon_google_on = () => {
            throw 'E_GOOGLE_NO_ACCOUNT: connect Google on the Accounts page first';
        };
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-google-toggle'));
        expect(tid(m.container, 'google-sheet')).toBeTruthy();
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

describe('Cloudflare on a zone without ECH, and on a relay with nobody yet', () => {
    it('ECH off: one line naming the zone and where to turn it on, never «Something went wrong»', async () => {
        handlers.wizard_addon_cdn_build = () => {
            throw 'E_CDN_NO_ECH: example.com: Cloudflare publishes no ECH config for this name';
        };
        const m = await mountSection(ALL);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        const f = tid(m.container, 'addon-cdn-failed')!;
        expect(byAttr(f, 'data-testid', 'addon-error')?.getAttribute('data-code')).toBe('E_CDN_NO_ECH');
        const line = f.textContent ?? '';
        expect(line).toContain("Cloudflare isn't hiding the site name for example.com yet (ECH is off).");
        expect(line).toContain('SSL/TLS → Edge Certificates');
        expect(line).not.toContain(en('pub.addons.err.other'));
        expect(line).not.toContain('{zone}');
    });

    it('in Persian it names the zone too, without «بزنید»', async () => {
        handlers.wizard_addon_cdn_build = () => {
            throw 'E_CDN_NO_ECH: example.com: no config';
        };
        const m = await mountSection(ALL, fa);
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        const line = tid(m.container, 'addon-cdn-failed')?.textContent ?? '';
        expect(line).toContain('example.com');
        expect(line).toContain('Encrypted ClientHello');
        expect(line).not.toContain('بزنید');
        expect(line).not.toContain('{zone}');
    });

    it('a door that waited opens on the next visit once someone is on the relay, and the row says On', async () => {
        ledger = [row('cdn', 'ready', { door_waits: true })];
        handlers.wizard_addon_cdn_posture = () => {
            ledger = [row('cdn', 'ready', { door_waits: false, name_hidden: true })];
            return { door_waits: false };
        };
        const m = await mountSection(ALL);
        await rig.settle();
        expect(inputOf('wizard_addon_cdn_posture')).toEqual({ operator_id: 1, test: true });
        expect(cmds().filter((c) => c === 'wizard_addon_cdn_posture')).toHaveLength(1);
        expect(tid(m.container, 'addon-cdn-waits')).toBeNull();
        expect(tid(m.container, 'addon-cdn-status')?.textContent).toContain(en('pub.addons.state.on'));
    });

    it('nobody on the relay yet: one plain line that it starts with the first person, not On and not a failure', async () => {
        const waiting = row('cdn', 'ready', { door_waits: true, name_hidden: null });
        handlers.wizard_addon_cdn_posture = () => ({ door_waits: true });
        handlers.wizard_addon_cdn_build = () => waiting;
        const m = await mountSection(ALL);
        ledger = [waiting];
        await rig.click(btn(m.container, 'addon-cdn-toggle'));
        expect(tid(m.container, 'addon-cdn-waits')?.textContent).toBe(en('pub.addons.cdn.waits_person'));
        expect(tid(m.container, 'addon-cdn-failed')).toBeNull();
        expect(tid(m.container, 'addon-cdn-status')).toBeNull();
        expect(btn(m.container, 'addon-cdn-toggle')?.getAttribute('aria-checked')).toBe('true');
    });

    it('the build wizard says the same when the extra turned on with nobody on the relay', async () => {
        const { WizardAddonsProgress } = await import('./WizardAddons');
        const { applyAddonChoices } = await import('./wizardAddons');
        const states: unknown[] = [];
        await applyAddonChoices(41, ['cdn'], {
            accounts: async () => ALL,
            onState: (_k, st) => states.push(st),
            run: async () => row('cdn', 'ready', { door_waits: true }),
        });
        expect(states.at(-1)).toEqual({ k: 'on', waitsForPerson: true });
        const m = await rig.mount(<WizardAddonsProgress t={en} progress={{ cdn: { k: 'on', waitsForPerson: true } }} onRetry={() => {}} />);
        expect(tid(m.container, 'wizard-addon-cdn-status')?.textContent).toBe(en('pub.addons.cdn.waits_person'));
        const fm = await rig.mount(<WizardAddonsProgress t={fa} progress={{ cdn: { k: 'on', waitsForPerson: true } }} onRetry={() => {}} />);
        expect(tid(fm.container, 'wizard-addon-cdn-status')?.textContent).toBe(fa('pub.addons.cdn.waits_person'));
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
        // Only the row switches are switches (the three extras, and the
        // two update-note carriers).
        expect(all(m.container, (n) => n.getAttribute?.('role') === 'switch')).toHaveLength(5);
        expect(cmds()).not.toContain('wizard_addon_cdn_set_plain_fallback');
        for (const src of [srcSection, srcSheets, srcPage, srcWizardAddons, srcWizardRows]) {
            expect(src).not.toMatch(/cdnSetPlainFallback|plain_fallback\s*:|mode:\s*'open'|E_STANDBY_OPEN_REFUSED/);
        }
        // The one call a switch (relay page or build wizard) makes.
        expect(srcWizardAddons).toMatch(/mode: 'sealed'/);
        expect(srcSection).toMatch(/runAddon\(/);
    });
});

describe('the Accounts page', () => {
    function shellWith(cf: { connected: boolean; zone: string }) {
        handlers.wizard_list_operators = () => [{ id: 1, status: 'provisioned', has_cloud_token: true, nickname: 'Home' }];
        handlers.wizard_addon_cdn_account = () => cf;
        handlers.wizard_saved_cloud_token = () => null;
        handlers.wizard_google_account = () => G_ACCOUNT(false);
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

    it('a key that sees two domains asks which one, and the one picked is the one checked and kept', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_addon_cdn_connect = (a) => {
            const input = (a?.input ?? {}) as { token?: string; zone?: string };
            if (!input.zone) return { zones: ['a.com', 'b.org'], verdict: 'pick_zone', stored: false };
            return { zones: ['a.com', 'b.org'], zone: input.zone, verdict: 'ok', stored: true };
        };
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        await rig.type(btn(m.container, 'cloudflare-token'), 'two-domains-key');
        await rig.click(btn(m.container, 'cloudflare-connect'));
        // Not refused: the domains to pick from, and the key stays until then.
        expect(tid(m.container, 'cloudflare-verdict')).toBeNull();
        expect(tid(m.container, 'cloudflare-pick')?.textContent).toContain(en('pub.accounts.cf.pick'));
        expect(btn(m.container, 'cloudflare-zone-a.com')?.getAttribute('aria-checked')).toBe('false');
        expect(btn(m.container, 'cloudflare-token')?.value).toBe('two-domains-key');
        expect(btn(m.container, 'cloudflare-connect')?.getAttribute('disabled')).not.toBeNull();
        expect(inputOf('wizard_addon_cdn_connect')).toEqual({ token: 'two-domains-key' });
        await rig.click(btn(m.container, 'cloudflare-zone-b.org'));
        expect(btn(m.container, 'cloudflare-zone-b.org')?.getAttribute('aria-checked')).toBe('true');
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'b.org' });
        await rig.click(btn(m.container, 'cloudflare-connect'));
        const sent = calls.filter((c) => c.cmd === 'wizard_addon_cdn_connect').map((c) => (c.args as { input: unknown }).input);
        expect(sent).toEqual([{ token: 'two-domains-key' }, { token: 'two-domains-key', zone: 'b.org' }]);
        expect(tid(m.container, 'cloudflare-connected')?.textContent).toBe('✓ Connected: b.org');
        expect(btn(m.container, 'cloudflare-token')).toBeNull();
        expect(tid(m.container, 'cloudflare-broad')).toBeNull();
    });

    it('a key that can do more is kept, with one muted line naming what more, then and later', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_addon_cdn_connect = () => ({
            zones: ['example.com'],
            zone: 'example.com',
            verdict: 'ok_broad',
            stored: true,
            extra: ['Account — Billing', 'Account — Workers Scripts'],
        });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        await rig.type(btn(m.container, 'cloudflare-token'), 'broad-key');
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'example.com', extra: ['Account — Billing', 'Account — Workers Scripts'] });
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(tid(m.container, 'cloudflare-connected')?.textContent).toBe('✓ Connected: example.com');
        const line = 'This key can do more than Daal needs (billing, running code (Workers)). It works, but a narrower key is safer if this phone is lost.';
        expect(tid(m.container, 'cloudflare-broad')?.textContent).toBe(line);
        expect(tid(m.container, 'cloudflare-verdict')).toBeNull();
        // Reopened from the Accounts page: still said.
        await rig.click(btn(m.container, 'cloudflare-done'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeNull();
        expect(tid(m.container, 'account-cloudflare-state')?.textContent).toBe('✓ Connected: example.com');
        await rig.click(btn(m.container, 'account-cloudflare'));
        expect(tid(m.container, 'cloudflare-connected')?.textContent).toBe('✓ Connected: example.com');
        expect(tid(m.container, 'cloudflare-broad')?.textContent).toBe(line);
    });

    it('a key short of a permission is refused, naming what it lacks, and kept nowhere', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_addon_cdn_connect = () => ({
            zones: ['example.com'],
            zone: 'example.com',
            verdict: 'missing_permission',
            stored: false,
            missing: ['Zone — DNS', 'Zone — Origin Rules'],
            extra: ['Account — Billing'],
        });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        await rig.type(btn(m.container, 'cloudflare-token'), 'short-key');
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(tid(m.container, 'cloudflare-verdict')?.textContent).toBe(
            'This key is missing what Daal needs: DNS (Edit), Origin Rules (Edit). Add it to the key in Cloudflare, or make the key again with «Make the key».',
        );
        expect(tid(m.container, 'cloudflare-connected')).toBeNull();
        expect(btn(m.container, 'cloudflare-token')?.value).toBe('');
    });

    it('Paste reads the phone\'s clipboard; when nothing comes back the field says so', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.platform_clipboard_read = () => '  cf-pasted-key \n';
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-cloudflare-connect'));
        await rig.click(btn(m.container, 'cloudflare-paste'));
        expect(btn(m.container, 'cloudflare-token')?.value).toBe('cf-pasted-key');
        expect(m.container.textContent).not.toContain(en('wiz.provider.token.paste_failed'));
        handlers.platform_clipboard_read = () => '';
        await rig.click(btn(m.container, 'cloudflare-paste'));
        expect(m.container.textContent).toContain(en('wiz.provider.token.paste_failed'));
    });

    it('Google: the script by hand in five steps, checked through Google, then ✓ Connected', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_google_account_script = () => ({ code_gs: '// the script', manifest_json: '{}' });
        handlers.wizard_google_account_attach = () => G_ACCOUNT(true);
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        expect(tid(m.container, 'account-google-state')?.textContent).toBe(en('pub.accounts.google.line'));
        await rig.click(btn(m.container, 'account-google-connect'));
        const steps = tid(m.container, 'google-steps')!;
        expect(all(steps, (n) => n.nodeName === 'LI')).toHaveLength(5);
        for (const b of ['google-signup', 'google-copy-script', 'google-open-editor']) expect(btn(steps, b), b).toBeTruthy();
        expect(steps.textContent).toContain('Execute as: Me');
        expect(steps.textContent).toContain('Who has access: Anyone');
        expect(btn(m.container, 'google-sign-in')).toBeNull();
        await rig.click(btn(m.container, 'google-copy-script'));
        expect(m.container.textContent).toContain(en('pub.accounts.google.hand.secret'));
        await rig.type(btn(m.container, 'google-url'), EXEC);
        handlers.wizard_google_account = () => G_ACCOUNT(true);
        await rig.click(btn(m.container, 'google-connect'));
        expect(tid(m.container, 'google-connected')?.textContent).toBe('✓ Connected');
        expect(m.container.textContent).toContain(en('pub.accounts.google.kept'));
        // The script (and its key) left the page.
        expect(tid(m.container, 'google-script')).toBeNull();
        // No relay was touched.
        expect(cmds()).not.toContain('wizard_addon_google_on');
        await rig.click(btn(m.container, 'google-done'));
        expect(tid(m.container, 'account-google-state')?.textContent).toBe('✓ Connected');
        expect(byAttr(m.container, 'data-account', 'google')?.getAttribute('data-connected')).toBe('true');
    });

    it('Google: «Sign in with Google» shows only in a build with the OAuth clients, as the same step', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_google_account = () => G_ACCOUNT(false, true);
        handlers.wizard_google_account_sign_in = () => G_ACCOUNT(true, true);
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-google-connect'));
        expect(tid(m.container, 'google-sign-in-block')?.textContent).toContain(en('pub.accounts.google.unverified'));
        await rig.click(btn(m.container, 'google-sign-in'));
        expect(cmds()).toContain('wizard_google_account_sign_in');
        expect(tid(m.container, 'google-connected')).toBeTruthy();
    });

    it('Google: Disconnect says the relays keep theirs and the script stays in Google', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_google_account = () => G_ACCOUNT(true);
        handlers.wizard_google_account_disconnect = () => null;
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        expect(tid(m.container, 'account-google-state')?.textContent).toBe('✓ Connected');
        await rig.click(btn(m.container, 'account-google'));
        const line = tid(m.container, 'google-disconnect-line')?.textContent ?? '';
        expect(line).toBe(en('pub.accounts.google.disconnect.line'));
        expect(line).toMatch(/stays in your Google account until you delete it/);
        expect(fa('pub.accounts.google.disconnect.line')).toContain('script.google.com');
        handlers.wizard_google_account = () => G_ACCOUNT(false);
        await rig.click(btn(m.container, 'google-disconnect'));
        expect(cmds()).toContain('wizard_google_account_disconnect');
        expect(tid(m.container, 'google-sheet')).toBeNull();
        expect(tid(m.container, 'account-google-state')?.textContent).toBe(en('pub.accounts.google.line'));
    });

    it('Google: a pasted address that is not a web app is one line', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_google_account_attach = () => {
            throw 'E_GOOGLE_BAD_ADDRESS: that is the test address (/dev); copy the web app address that ends in /exec';
        };
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-google-connect'));
        await rig.type(btn(m.container, 'google-url'), EXEC.replace('/exec', '/dev'));
        await rig.click(btn(m.container, 'google-connect'));
        expect(tid(m.container, 'addon-error')?.getAttribute('data-code')).toBe('E_GOOGLE_BAD_ADDRESS');
        expect(tid(m.container, 'google-connected')).toBeNull();
    });

    it('Google in Persian: «✓ وصل است», no «بزنید»', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_google_account = () => G_ACCOUNT(true);
        const m = await rig.mount(<AccountsPage t={fa} onBack={() => {}} backLabel="رله‌ها" />);
        expect(tid(m.container, 'account-google-state')?.textContent).toBe('✓ وصل است');
        await rig.click(btn(m.container, 'account-google'));
        expect(m.container.textContent).not.toContain('بزنید');
    });

    function hosting(st: { connected: boolean; account: boolean }) {
        handlers.wizard_hosting_account_status = () => ({ hetzner: st, vultr: { connected: false, account: false } });
    }

    it('Hetzner: connected with no relay, from three numbered steps and one paste', async () => {
        shellWith({ connected: false, zone: '' });
        handlers.wizard_list_operators = () => [];
        hosting({ connected: false, account: false });
        handlers.wizard_hosting_account_connect = () => ({ connected: true, account: true });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        const row = byAttr(m.container, 'data-account', 'hetzner')!;
        expect(row.getAttribute('data-connected')).toBe('false');
        // Connecting no longer starts a relay: it opens the sheet.
        await rig.click(btn(m.container, 'account-hetzner-connect'));
        const steps = tid(m.container, 'hetzner-steps')!;
        expect(all(steps, (n) => n.nodeName === 'LI')).toHaveLength(3);
        // The wizard's own words for the account and the key.
        expect(steps.textContent).toContain(en('wiz.guide.1'));
        expect(steps.textContent).toContain(en('wiz.guide.2'));
        expect(steps.textContent).toContain('Read & Write');
        for (const b of ['hetzner-signup', 'hetzner-project', 'hetzner-token-page']) expect(btn(steps, b), b).toBeTruthy();
        expect(btn(m.container, 'hetzner-connect')?.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(m.container, 'hetzner-token'), '  hcloud-key ');
        hosting({ connected: true, account: true });
        await rig.click(btn(m.container, 'hetzner-connect'));
        const call = calls.find((c) => c.cmd === 'wizard_hosting_account_connect');
        expect(call?.args).toEqual({ input: { provider: 'hetzner', token: '  hcloud-key ' } });
        expect(tid(m.container, 'hetzner-connected')?.textContent).toBe('✓ Connected');
        expect(btn(m.container, 'hetzner-token')).toBeNull();
        // No relay was started.
        expect(cmds()).not.toContain('wizard_store_cloud_token');
        expect(cmds()).not.toContain('wizard_reuse_cloud_token');
        await rig.click(btn(m.container, 'hetzner-done'));
        expect(tid(m.container, 'account-hetzner-state')?.textContent).toBe('✓ Connected');
    });

    it('Hetzner: a refused key is one line, and nothing is connected', async () => {
        shellWith({ connected: false, zone: '' });
        hosting({ connected: false, account: false });
        handlers.wizard_hosting_account_connect = () => {
            throw 'pricing: list-server-types: hetzner: 401 unauthorized';
        };
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-hetzner-connect'));
        await rig.type(btn(m.container, 'hetzner-token'), 'wrong');
        await rig.click(btn(m.container, 'hetzner-connect'));
        expect(tid(m.container, 'hetzner-refused')?.textContent).toBe(en('pub.accounts.hz.refused'));
        expect(tid(m.container, 'hetzner-connected')).toBeNull();
        expect(tid(m.container, 'addon-error')).toBeNull();
    });

    it('Hetzner: Disconnect says the relays keep working, and forgets only the account key', async () => {
        shellWith({ connected: false, zone: '' });
        hosting({ connected: true, account: true });
        handlers.wizard_hosting_account_disconnect = () => null;
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        expect(tid(m.container, 'account-hetzner-state')?.textContent).toBe('✓ Connected');
        await rig.click(btn(m.container, 'account-hetzner'));
        expect(tid(m.container, 'hetzner-disconnect-line')?.textContent).toBe(en('pub.accounts.hz.disconnect.line'));
        expect(en('pub.accounts.hz.disconnect.line')).toMatch(/does not stop your relays/);
        hosting({ connected: true, account: false });
        await rig.click(btn(m.container, 'hetzner-disconnect'));
        expect(calls.find((c) => c.cmd === 'wizard_hosting_account_disconnect')?.args).toEqual({ provider: 'hetzner' });
        expect(tid(m.container, 'hetzner-sheet')).toBeNull();
    });

    it('Hetzner held only by relays (an older phone): connected, nothing to disconnect', async () => {
        shellWith({ connected: false, zone: '' });
        hosting({ connected: true, account: false });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        await rig.click(btn(m.container, 'account-hetzner'));
        expect(tid(m.container, 'hetzner-connected')).not.toBeNull();
        expect(m.container.textContent).toContain(en('pub.accounts.hz.relay_only'));
        expect(btn(m.container, 'hetzner-disconnect')).toBeNull();
    });

    it('Hetzner in Persian: «اتصال», then «✓ وصل است»', async () => {
        shellWith({ connected: false, zone: '' });
        hosting({ connected: false, account: false });
        handlers.wizard_hosting_account_connect = () => ({ connected: true, account: true });
        const m = await rig.mount(<AccountsPage t={fa} onBack={() => {}} backLabel="رله‌ها" />);
        await rig.click(btn(m.container, 'account-hetzner-connect'));
        expect(btn(m.container, 'hetzner-connect')?.textContent).toBe('اتصال');
        await rig.type(btn(m.container, 'hetzner-token'), 'k');
        await rig.click(btn(m.container, 'hetzner-connect'));
        expect(tid(m.container, 'hetzner-connected')?.textContent).toBe('✓ وصل است');
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
            [Wizard.hostingAccountConnect('hetzner', 'k'), 'wizard_hosting_account_connect'],
            [Wizard.hostingAccountStatus(), 'wizard_hosting_account_status'],
            [Wizard.hostingAccountDisconnect('hetzner'), 'wizard_hosting_account_disconnect'],
            [Addons.googleAccount(), 'wizard_google_account'],
            [Addons.googleAccountScript(), 'wizard_google_account_script'],
            [Addons.googleAccountAttach({ url: 'u' }), 'wizard_google_account_attach'],
            [Addons.googleAccountSignIn(), 'wizard_google_account_sign_in'],
            [Addons.googleAccountDisconnect(), 'wizard_google_account_disconnect'],
            [Addons.googleOn({ operator_id: 1 }), 'wizard_addon_google_on'],
            [Addons.googleCheck({ operator_id: 1 }), 'wizard_addon_google_check'],
        ];
        for (const [p, name] of cases) {
            const e = await p.then(() => 'resolved', (err: unknown) => err);
            expect(classifyPublisherError(e), name).toBe('E_NOT_BUILT');
        }
        expect(cmds()).toEqual(cases.map(([, n]) => n));
        expect(calls[0].args).toEqual({ input: { token: 'x' } });
    });
});
