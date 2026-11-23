// The update notes on the publisher's phone: the GitHub account (paste a
// key, Daal checks it and says plainly what is wrong), and the relay's
// two switches, «Updates through GitHub» and «Updates through DNS»
// (each needs its account; turning one on does the rest; people who had
// a file are told once that they need a new one; a write that failed is
// a calm line). Driven through the real command wrappers against a fake
// shell.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import type { AddonRow } from './addonTypes';
import type { AccountsState } from './accounts';
import srcEn from '../../../../client-shared/i18n/d2-extra.en.json';
import srcFa from '../../../../client-shared/i18n/d2-extra.fa.json';

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
const { GithubSheet, githubTokenUrl } = await import('./AccountSheets');
const { default: AccountsPage } = await import('../AccountsPage');
const { addonNeed, runAddon, ADDON_ORDER } = await import('./wizardAddons');
const { hasStandby } = await import('../refile/refile');
const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);
const EN = srcEn as Record<string, string>;
const FA = srcFa as Record<string, string>;
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const cmds = () => calls.map((c) => c.cmd);
const inputOf = (cmd: string) => (calls.find((c) => c.cmd === cmd)?.args as { input: Record<string, unknown> }).input;

const NO_G = { connected: false, scriptMade: false, signIn: false };
const NONE: AccountsState = { hetzner: true, hetznerAccount: true, cloudflare: { connected: false, zone: '' }, google: NO_G };
const BOTH: AccountsState = {
    ...NONE,
    cloudflare: { connected: true, zone: 'example.com' },
    github: { connected: true, login: 'notes-family' },
};
const GH = { connected: true, login: 'notes-family', token_kind: 'fine_grained', extra: [], expires_at: '' };

function row(kind: AddonRow['kind'], state: AddonRow['state'], detail: Record<string, unknown> = {}): AddonRow {
    return {
        id: kind === 'gittag' ? 21 : 22,
        operator_id: 1,
        kind,
        state,
        provider_ids: {},
        monthly_cost_cents: 0,
        cost_currency: '',
        has_secret: kind === 'gittag',
        detail,
        created_at_unix: 1,
        updated_at_unix: 1,
    };
}

const now = () => Math.floor(Date.now() / 1000);

describe('Accounts → GitHub: paste a key, Daal checks it', () => {
    it('sits with Cloudflare and Google, three steps, the key page, one line of advice', async () => {
        handlers.wizard_list_operators = () => [{ id: 1, status: 'provisioned', has_cloud_token: true, nickname: 'Home' }];
        handlers.wizard_addon_cdn_account = () => ({ connected: false, zone: '' });
        handlers.wizard_google_account = () => ({ connected: false, script_made: false, url: '', sign_in: false });
        handlers.wizard_github_account = () => ({ connected: false, login: '', token_kind: '', extra: [], expires_at: '' });
        const m = await rig.mount(<AccountsPage t={en} onBack={() => {}} backLabel="Relays" />);
        const row = byAttr(m.container, 'data-account', 'github')!;
        expect(row.getAttribute('data-connected')).toBe('false');
        expect(tid(m.container, 'account-github-state')?.textContent).toBe(en('pub.accounts.github.line'));
        await rig.click(btn(m.container, 'account-github-connect'));
        const steps = tid(m.container, 'github-steps')!;
        expect(all(steps, (n) => n.nodeName === 'LI')).toHaveLength(3);
        expect(steps.textContent).toContain(en('pub.accounts.github.step.1'));
        expect(btn(m.container, 'github-token-page')).toBeTruthy();
        expect(githubTokenUrl()).toMatch(/^https:\/\/github\.com\/settings\/personal-access-tokens\/new\?/);
        expect(githubTokenUrl()).toContain('administration=write');
        expect(githubTokenUrl()).toContain('contents=write');
        expect(githubTokenUrl()).not.toMatch(/daal/i);
        // An account only for this, in one line.
        expect(EN['pub.accounts.github.step.1']).toMatch(/only for this/);
        expect(btn(m.container, 'github-connect')?.getAttribute('disabled')).not.toBeNull();
    });

    it('a working key is kept: «Connected as <name>», and the key leaves the page', async () => {
        handlers.wizard_github_connect = () => ({ verdict: 'ok', stored: true, login: 'notes-family', token_kind: 'fine_grained', expires_at: '2027-11-22T00:00:00Z' });
        let connected = '';
        const m = await rig.mount(<GithubSheet t={en} onClose={() => {}} onConnected={(l) => (connected = l)} />);
        await rig.type(btn(m.container, 'github-token'), 'github_pat_1');
        await rig.click(btn(m.container, 'github-connect'));
        expect(inputOf('wizard_github_connect')).toEqual({ token: 'github_pat_1' });
        expect(connected).toBe('notes-family');
        expect(tid(m.container, 'github-connected')?.textContent).toBe('✓ Connected as notes-family');
        expect(m.container.textContent).toContain(en('pub.accounts.github.kept'));
        // A key that stops working says when.
        expect(tid(m.container, 'github-expires')?.textContent).toContain('2027');
        expect(m.container.textContent).not.toContain('github_pat_1');
    });

    it('a key that cannot do the job is named in plain words and never kept', async () => {
        handlers.wizard_github_connect = () => ({ verdict: 'missing_permission', stored: false, missing: ['public_repo'] });
        let connected = false;
        const m = await rig.mount(<GithubSheet t={en} onClose={() => {}} onConnected={() => (connected = true)} />);
        await rig.type(btn(m.container, 'github-token'), 'ghp_short');
        await rig.click(btn(m.container, 'github-connect'));
        const v = tid(m.container, 'github-verdict')!;
        expect(v.getAttribute('data-verdict')).toBe('missing_permission');
        expect(v.textContent).toBe(
            en('pub.accounts.github.verdict.missing_permission').replace('{list}', en('pub.accounts.github.perm.public_repo')),
        );
        expect(connected).toBe(false);
        expect(tid(m.container, 'github-connected')).toBeNull();
        expect((btn(m.container, 'github-token') as unknown as { value: string }).value).toBe('');
        for (const verdict of ['invalid', 'rate_limited']) {
            handlers.wizard_github_connect = () => ({ verdict, stored: false });
            await rig.type(btn(m.container, 'github-token'), 'x');
            await rig.click(btn(m.container, 'github-connect'));
            expect(tid(m.container, 'github-verdict')?.textContent).toBe(en(`pub.accounts.github.verdict.${verdict}`));
        }
    });

    it('connected: Disconnect forgets the key and says the relays keep theirs', async () => {
        handlers.wizard_github_disconnect = () => null;
        let gone = false;
        const m = await rig.mount(
            <GithubSheet t={en} github={{ connected: true, login: 'notes-family' }} onClose={() => {}} onConnected={() => {}} onDisconnected={() => (gone = true)} />,
        );
        expect(tid(m.container, 'github-disconnect-line')?.textContent).toBe(en('pub.accounts.github.disconnect.line'));
        await rig.click(btn(m.container, 'github-disconnect'));
        expect(cmds()).toContain('wizard_github_disconnect');
        expect(gone).toBe(true);
    });

    it('connected: «Use a new key» takes a new key without disconnecting, from either caller', async () => {
        handlers.wizard_github_connect = () => ({ verdict: 'ok', stored: true, login: 'notes-family', token_kind: 'fine_grained' });
        // From a relay switch: no Disconnect, but a new key all the same.
        const m = await rig.mount(<GithubSheet t={en} github={{ connected: true, login: 'notes-family' }} onClose={() => {}} onConnected={() => {}} />);
        expect(btn(m.container, 'github-disconnect')).toBeNull();
        expect(btn(m.container, 'github-new-key')?.textContent).toBe(en('pub.accounts.github.new_key'));
        await rig.click(btn(m.container, 'github-new-key'));
        expect(btn(m.container, 'github-signup')).toBeNull();
        expect(btn(m.container, 'github-token-page')).toBeTruthy();
        await rig.type(btn(m.container, 'github-token'), 'github_pat_2');
        await rig.click(btn(m.container, 'github-connect'));
        expect(inputOf('wizard_github_connect')).toEqual({ token: 'github_pat_2' });
        expect(cmds()).not.toContain('wizard_github_disconnect');
        expect(tid(m.container, 'github-connected')).toBeTruthy();
    });
});

describe('the relay switches', () => {
    it('two more rows after the three: free, each naming the account it needs', async () => {
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={NONE} />);
        expect(tid(m.container, 'addon-gittag-cost')?.textContent).toBe('Free · needs GitHub');
        // No standby address yet: DNS, which carries only that, says so too.
        expect(tid(m.container, 'addon-dnsnote-cost')?.textContent).toBe(
            `${en('pub.addons.dnsnote.cost')} · needs Cloudflare · ${en('pub.addons.needs.standby')}`,
        );
        // DNS says what it carries, and for whom, in its one line.
        expect(tid(m.container, 'addon-dnsnote')?.textContent).toContain(en('pub.addons.dnsnote.line'));
        expect(EN['pub.addons.dnsnote.line']).toMatch(/only the standby address/);
        expect(EN['pub.addons.dnsnote.line']).toMatch(/one by one/);
        expect(ADDON_ORDER.slice(-2)).toEqual(['gittag', 'dnsnote']);
    });

    it('GitHub, not connected: the GitHub sheet; once connected the switch makes the repository', async () => {
        handlers.wizard_github_connect = () => ({ verdict: 'ok', stored: true, login: 'notes-family' });
        handlers.wizard_addon_gittag_on = () => row('gittag', 'ready', { last_ok_at_unix: now(), people_before: 0 });
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={NONE} />);
        await rig.click(btn(m.container, 'addon-gittag-toggle'));
        expect(tid(m.container, 'github-sheet')).toBeTruthy();
        expect(cmds()).not.toContain('wizard_addon_gittag_on');
        await rig.type(btn(m.container, 'github-token'), 'github_pat_2');
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now() })];
        await rig.click(btn(m.container, 'github-connect'));
        expect(tid(m.container, 'github-sheet')).toBeNull();
        expect(inputOf('wizard_addon_gittag_on')).toEqual({ operator_id: 1 });
        expect(tid(m.container, 'addon-gittag-status')?.textContent).toBe(en('pub.addons.state.on'));
        expect(tid(m.container, 'addon-gittag-note')?.getAttribute('data-note')).toBe('updated');
        // Nobody had a file: nothing to say about new files.
        expect(tid(m.container, 'addon-gittag-new-files')).toBeNull();
    });

    it('people who already had a file are told once, with «New files for everyone»', async () => {
        handlers.wizard_addon_dnsnote_on = () => row('dnsnote', 'ready', { last_ok_at_unix: now(), people_before: 2 });
        let opened = 0;
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} onNewFiles={() => opened++} />);
        ledger = [row('dnsnote', 'ready', { last_ok_at_unix: now(), people_before: 2 })];
        await rig.click(btn(m.container, 'addon-dnsnote-toggle'));
        expect(inputOf('wizard_addon_dnsnote_on')).toEqual({ operator_id: 1 });
        const n = tid(m.container, 'addon-dnsnote-new-files')!;
        expect(n.textContent).toContain(en('pub.addons.dnsnote.new_files'));
        await rig.click(btn(m.container, 'addon-dnsnote-new-files'));
        expect(opened).toBe(1);
        expect(btn(m.container, 'addon-dnsnote-new-files')?.textContent).toBe(en('pub.refile.menu'));
    });

    it('a page opened later still says people need new files (read from the row)', async () => {
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now(), people_before: 2 })];
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} onNewFiles={() => {}} />);
        expect(tid(m.container, 'addon-gittag-new-files')?.textContent).toContain(en('pub.addons.gittag.new_files'));
        // Once everyone has a new file the row says nothing more.
        await rig.unmountAll();
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now(), people_before: 0 })];
        const m2 = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} onNewFiles={() => {}} />);
        expect(tid(m2.container, 'addon-gittag-new-files')).toBeNull();
    });

    it('with a file for everyone: the notes do not reach it, and new files go person by person', async () => {
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now(), people_before: 2 })];
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} everyoneFile />);
        expect(tid(m.container, 'addon-gittag-not-everyone')?.textContent).toBe(en('pub.addons.notes.not_everyone'));
        expect(tid(m.container, 'addon-gittag-new-files')?.textContent).toContain(en('pub.addons.notes.new_files_each'));
        expect(btn(m.container, 'addon-gittag-new-files')).toBeNull();
    });

    it('DNS without a standby address says it needs one', async () => {
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        expect(tid(m.container, 'addon-dnsnote-cost')?.textContent).toContain(en('pub.addons.needs.standby'));
        await rig.unmountAll();
        ledger = [row('standby', 'ready', {})];
        const m2 = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        expect(tid(m2.container, 'addon-dnsnote-cost')?.textContent).not.toContain(en('pub.addons.needs.standby'));
    });

    it('a key GitHub refused is not «will try again»: it says so and offers a new key', async () => {
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now() - 86400, last_try_at_unix: now() - 60, last_error: 'e_gittag_refused' })];
        handlers.wizard_github_account = () => GH;
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        const note = tid(m.container, 'addon-gittag-note')!;
        expect(note.getAttribute('data-note')).toBe('act');
        expect(note.textContent).toContain(en('pub.addons.err.E_GITTAG_REFUSED'));
        await rig.click(btn(m.container, 'addon-gittag-fix-key'));
        expect(tid(m.container, 'github-sheet')).toBeTruthy();
        // The new-key mode: the key steps and field, not the account step.
        expect(btn(m.container, 'github-token')).toBeTruthy();
        expect(btn(m.container, 'github-signup')).toBeNull();
    });

    it('a switch GitHub refused for a permission names it and opens the sheet for a new key', async () => {
        handlers.wizard_addon_gittag_on = () => {
            throw 'E_GITTAG_REFUSED: missing_permission: Administration, Contents';
        };
        handlers.wizard_github_account = () => GH;
        handlers.wizard_list_operators = () => [];
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'example.com' });
        handlers.wizard_google_account = () => ({ connected: false });
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        await rig.click(btn(m.container, 'addon-gittag-toggle'));
        const failed = tid(m.container, 'addon-gittag-failed')!;
        expect(failed.textContent).toContain(
            en('pub.accounts.github.verdict.missing_permission').replace('{list}', 'Administration, Contents'),
        );
        expect(tid(m.container, 'github-sheet')).toBeTruthy();
        expect(btn(m.container, 'github-signup')).toBeNull();
    });

    it('DNS, Cloudflare not connected: the Cloudflare sheet, then the DNS switch (not the Cloudflare way in)', async () => {
        handlers.wizard_addon_cdn_connect = () => ({ zones: ['example.com'], zone: 'example.com', verdict: 'ok', stored: true });
        handlers.wizard_addon_dnsnote_on = () => row('dnsnote', 'ready', { last_ok_at_unix: now() });
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={NONE} />);
        await rig.click(btn(m.container, 'addon-dnsnote-toggle'));
        expect(tid(m.container, 'cloudflare-sheet')).toBeTruthy();
        await rig.type(btn(m.container, 'cloudflare-token'), 'cf');
        await rig.click(btn(m.container, 'cloudflare-connect'));
        expect(cmds()).toContain('wizard_addon_dnsnote_on');
        expect(cmds()).not.toContain('wizard_addon_cdn_build');
    });

    it('a write that failed is a calm line; the switch stays on', async () => {
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now() - 86400, last_try_at_unix: now() - 60, last_error: 'network' })];
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        expect(tid(m.container, 'addon-gittag-status')?.textContent).toBe(en('pub.addons.state.on'));
        const note = tid(m.container, 'addon-gittag-note')!;
        expect(note.getAttribute('data-note')).toBe('retry');
        expect(note.textContent).toBe(en('pub.addons.gittag.retry'));
        expect(tid(m.container, 'addon-gittag-failed')).toBeNull();
        expect(btn(m.container, 'addon-gittag-toggle')?.getAttribute('aria-checked')).toBe('true');
    });

    it('the last write that went through is said in the reader\'s words', async () => {
        ledger = [row('dnsnote', 'ready', { last_ok_at_unix: now() - 2 * 3600, last_try_at_unix: now() - 2 * 3600, last_error: '' })];
        const m = await rig.mount(<AddonsSection t={fa} operatorId={1} accounts={BOTH} />);
        const note = tid(m.container, 'addon-dnsnote-note')!;
        expect(note.textContent).toContain('آخرین به‌روزرسانی');
        expect(note.textContent).not.toMatch(/[0-9]/);
    });

    it('turning GitHub off says the repository stays, and the shell is asked to remove it', async () => {
        ledger = [row('gittag', 'ready', { last_ok_at_unix: now(), repo: 'k3j9q2mxw7aa' })];
        handlers.wizard_addon_remove = () => ({ addon_id: 21, removed: true, still_billing: [], by_hand: ['github_repository'], warnings: [] });
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        await rig.click(btn(m.container, 'addon-gittag-toggle'));
        expect(tid(m.container, 'confirm-body')?.textContent).toBe(en('pub.addons.gittag.off'));
        ledger = [];
        await rig.click(btn(m.container, 'confirm-yes'));
        expect(cmds()).toContain('wizard_addon_remove');
        expect(tid(m.container, 'addon-gittag-billing')?.textContent).toBe(
            en('pub.addons.gittag.repo_left').replace('{name}', 'k3j9q2mxw7aa'),
        );
        expect(tid(m.container, 'addon-gittag')?.getAttribute('data-state')).toBe('off');
    });

    it('a shell with the GitHub account gone opens the sheet again', async () => {
        handlers.wizard_addon_gittag_on = () => {
            throw 'E_GITHUB_NO_ACCOUNT: GitHub is not connected';
        };
        handlers.wizard_github_account = () => ({ connected: false });
        handlers.wizard_list_operators = () => [];
        handlers.wizard_addon_cdn_account = () => ({ connected: true, zone: 'example.com' });
        handlers.wizard_google_account = () => ({ connected: false });
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} accounts={BOTH} />);
        await rig.click(btn(m.container, 'addon-gittag-toggle'));
        expect(tid(m.container, 'github-sheet')).toBeTruthy();
    });
});

describe('the plumbing', () => {
    it('each switch needs its account, and turns on with one call', async () => {
        expect(addonNeed('gittag', NONE)).toBe('github');
        expect(addonNeed('dnsnote', NONE)).toBe('cloudflare');
        expect(addonNeed('dnsnote', { ...NONE, cloudflare: { connected: true, zone: '' } })).toBe('cloudflare');
        expect(addonNeed('gittag', BOTH)).toBe('ready');
        expect(addonNeed('dnsnote', BOTH)).toBe('ready');
        handlers.wizard_addon_gittag_on = () => row('gittag', 'ready');
        handlers.wizard_addon_dnsnote_on = () => row('dnsnote', 'ready');
        await runAddon('gittag', 4, BOTH);
        await runAddon('dnsnote', 4, BOTH);
        expect(inputOf('wizard_addon_gittag_on')).toEqual({ operator_id: 4 });
        expect(inputOf('wizard_addon_dnsnote_on')).toEqual({ operator_id: 4 });
    });

    it('a note switch that is on makes «New files for everyone» worth offering', () => {
        expect(hasStandby([row('gittag', 'ready')])).toBe(true);
        expect(hasStandby([row('dnsnote', 'building')])).toBe(false);
        expect(hasStandby([])).toBe(false);
    });

    it('the GitHub account is read with the others', async () => {
        handlers.wizard_hosting_account_status = () => ({ hetzner: { connected: true, account: true } });
        handlers.wizard_addon_cdn_account = () => ({ connected: false, zone: '' });
        handlers.wizard_google_account = () => ({ connected: false });
        handlers.wizard_github_account = () => ({ ...GH, extra: ['repo'], expires_at: '2027-01-01T00:00:00Z' });
        const { readAccounts } = await import('./accounts');
        const a = await readAccounts();
        expect(a.github).toEqual({ connected: true, login: 'notes-family', extra: ['repo'], expiresAt: '2027-01-01T00:00:00Z' });
        handlers.wizard_github_account = () => {
            throw 'unknown command';
        };
        expect((await readAccounts()).github?.connected).toBe(false);
    });

    it('the Persian names GitHub and DNS as they are, and says nothing narrated', () => {
        for (const k of Object.keys(EN).filter((k) => /^pub\.(accounts\.github|addons\.(gittag|dnsnote))\./.test(k))) {
            expect(FA[k], k).toBeTruthy();
            expect(FA[k], k).not.toMatch(/بزنید|[0-9]|[يك]/);
        }
        expect(FA['pub.addons.gittag.title']).toBe('به‌روزرسانی از راه GitHub');
        expect(FA['pub.accounts.github.key']).toBe('کلید دسترسی');
    });
});
