// The three add-on sheets (standby S8, Cloudflare B-7, Google G6), the
// relay delete report's add-on lines, the account check's standby line,
// the recipient's "I was sent a code" field, and every string they use,
// driven through the real command wrappers (wizardCommands.ts) against
// a fake shell.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import srcEn from '../../../../client-shared/i18n/d2-extra.en.json';
import srcFa from '../../../../client-shared/i18n/d2-extra.fa.json';
import type { AddonProgress, AddonRow } from './addonTypes';
import srcSection from './AddonsSection.tsx?raw';
import srcText from './addonText.ts?raw';
import srcUi from './addonUi.tsx?raw';
import srcErrors from './addonErrors.ts?raw';
import srcStandby from './StandbyCard.tsx?raw';
import srcCdn from './CdnCard.tsx?raw';
import srcGoogle from './GoogleCard.tsx?raw';
import srcOutcome from './AddonOutcomeLines.tsx?raw';
import srcCode from '../../components/StandbyCodeEntry.tsx?raw';
import srcAccount from '../AccountCheckSheet.tsx?raw';

type Handler = (args: Record<string, unknown> | undefined) => unknown;
let handlers: Record<string, Handler> = {};
const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let emit: ((p: AddonProgress) => void) | null = null;

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        const h = handlers[cmd];
        if (!h) throw `E_NOT_BUILT: ${cmd} is not mocked`;
        return h(args);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({
    listen: async (_name: string, cb: (e: { payload: AddonProgress }) => void) => {
        emit = (p) => cb({ payload: p });
        return () => {
            emit = null;
        };
    },
}));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
let clipboard = '';
beforeEach(() => {
    handlers = {};
    calls.length = 0;
    clipboard = '';
    (globalThis.navigator as unknown as { clipboard: unknown }).clipboard = {
        writeText: async (s: string) => {
            clipboard = s;
        },
    };
});
afterEach(async () => {
    await rig.unmountAll();
});

const { translate } = await import('../../lib/i18n');
const { StandbySheet } = await import('./StandbyCard');
const { CdnSheet, CDN_PERMISSIONS, cloudflareTokenUrl } = await import('./CdnCard');
const { GoogleSheet } = await import('./GoogleCard');
const { AddonOutcomeLines, addonOutcomeLine } = await import('./AddonOutcomeLines');
const errs = await import('./addonErrors');
const { addonItemLine } = await import('../AccountCheckSheet');
const { StandbyCodeEntry, normaliseCode } = await import('../../components/StandbyCodeEntry');
const { unavailableLines } = await import('../../lib/importVerdict');

const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);
const EN = srcEn as Record<string, string>;
const FA = srcFa as Record<string, string>;
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const inputOf = (c: { cmd: string; args?: Record<string, unknown> }) => (c.args as { input: Record<string, unknown> }).input;
const callsTo = (cmd: string) => calls.filter((c) => c.cmd === cmd);

function row(kind: AddonRow['kind'], state: AddonRow['state'], detail: Record<string, unknown> = {}): AddonRow {
    return {
        id: 7,
        operator_id: 1,
        kind,
        state,
        provider_ids: {},
        monthly_cost_cents: kind === 'standby' ? 300 : 0,
        cost_currency: kind === 'standby' ? 'EUR' : '',
        has_secret: kind === 'google',
        detail,
        created_at_unix: 1,
        updated_at_unix: 1,
    };
}

function sheet(
    Comp: typeof StandbySheet,
    rows: AddonRow[],
    t: (k: string) => string = en,
) {
    const onChanged = vi.fn();
    const onClose = vi.fn();
    return { el: <Comp t={t} operatorId={1} rows={rows} onClose={onClose} onChanged={onChanged} />, onChanged, onClose };
}

// ------------------------------------------------------------------ errors

describe('what a failure says', () => {
    it('reads every add-on code, and the shared ones, by their prefix only', () => {
        for (const c of errs.ADDON_ERROR_CODES) expect(errs.classifyAddonError(`${c}: tail`), c).toBe(c);
        expect(errs.classifyAddonError('E_GOOGLE_API_NOT_ENABLED: x')).toBe('E_GOOGLE_API_NOT_ENABLED');
        expect(errs.classifyAddonError('E_GOOGLE_API: x')).toBe('E_GOOGLE_API');
        expect(errs.classifyAddonError('E_DEPLOY_TOO_OLD: x')).toBe('E_DEPLOY_TOO_OLD');
        expect(errs.classifyAddonError('E_HELPER_IP_STALE: x')).toBe('E_HELPER_IP_MISSING');
        expect(errs.classifyAddonError('boom')).toBeNull();
        const e = errs.addonErrorText(en, 'E_STANDBY_LIMIT: resource_limit_exceeded');
        expect(e.line).toBe(en('pub.addons.err.E_STANDBY_LIMIT'));
        expect(e.detail).toContain('resource_limit_exceeded');
        expect(errs.addonErrorText(en, 'kaboom').line).toBe(en('pub.addons.err.other'));
        // The Google check's tail names its reason.
        const g = errs.addonErrorText(en, 'E_GOOGLE_CHECK_FAILED: not_deployed: the script did not answer');
        expect(g.line).toContain(en('pub.addons.err.E_GOOGLE_CHECK_FAILED'));
        expect(g.line).toContain(en('pub.addons.google.reason.not_deployed'));
    });

    it('money is in the reader\'s digits', () => {
        expect(errs.money(en, 300, 'EUR')).toBe('€3.00');
        expect(errs.money(fa, 300, 'EUR')).toBe('۳٫۰۰ یورو');
        expect(errs.money(en, 1050, 'USD')).toBe('$10.50');
        expect(errs.money(en, 100, 'chf')).toBe('1.00 CHF');
    });
});

// ------------------------------------------------------------------ standby

describe('the standby sheet', () => {
    it('off: today\'s price, when it stops, sealed by default; renting shows the steps, then the result', async () => {
        handlers.wizard_addon_standby_price = () => ({ monthly_cents: 300, currency: 'EUR', vat_included: false });
        handlers.wizard_addon_standby_add = async () => {
            for (const step of ['renting', 'attaching', 'checking', 'signing']) {
                emit?.({ operator_id: 1, kind: 'standby', step, state: 'ok', detail: '' });
            }
            emit?.({ operator_id: 2, kind: 'standby', step: 'renting', state: 'failed', detail: '' });
            emit?.({ operator_id: 1, kind: 'standby', step: 'standby_internal', state: 'ok', detail: '' });
            return row('standby', 'ready', { mode: 'sealed' });
        };
        const s = sheet(StandbySheet, []);
        const m = await rig.mount(s.el);
        expect(tid(m.container, 'standby-price')?.textContent).toBe(
            '€3.00 a month plus tax, charged by Hetzner to the account you already use.',
        );
        expect(m.container.textContent).toContain(en('pub.addons.standby.stops'));
        expect(m.container.textContent).toContain(en('pub.addons.standby.ties'));
        expect(btn(m.container, 'standby-open')?.getAttribute('aria-checked')).toBe('false');
        await rig.click(btn(m.container, 'standby-rent'));
        expect(inputOf(callsTo('wizard_addon_standby_add')[0])).toEqual({ operator_id: 1, mode: 'sealed' });
        expect(tid(m.container, 'standby-ready')?.textContent).toBe(en('pub.addons.standby.ready'));
        const steps = tid(m.container, 'addon-steps')!;
        // Only this relay's steps, only words with a sentence.
        expect(steps.textContent).toBe(
            ['renting', 'attaching', 'checking', 'signing'].map((w) => en(`pub.addons.step.${w}`)).join(''),
        );
        expect(s.onChanged).toHaveBeenCalled();
    });

    it('in Persian, the price reads ماهی ۳٫۰۰ یورو', async () => {
        handlers.wizard_addon_standby_price = () => ({ monthly_cents: 300, currency: 'EUR', vat_included: false });
        const m = await rig.mount(sheet(StandbySheet, [], fa).el);
        expect(tid(m.container, 'standby-price')?.textContent).toContain('ماهی ۳٫۰۰ یورو');
    });

    it('open is a choice the shell may refuse, and Hetzner\'s limit is said plainly', async () => {
        handlers.wizard_addon_standby_price = () => Promise.reject('E_NOT_BUILT: no');
        handlers.wizard_addon_standby_add = (a) =>
            Promise.reject(
                (a!.input as { mode: string }).mode === 'open'
                    ? 'E_STANDBY_OPEN_REFUSED: this relay has an Everyone file'
                    : 'E_STANDBY_LIMIT: resource_limit_exceeded',
            );
        const m = await rig.mount(sheet(StandbySheet, []).el);
        expect(m.container.textContent).toContain(en('pub.addons.standby.price_unknown'));
        await rig.click(btn(m.container, 'standby-open'));
        await rig.click(btn(m.container, 'standby-rent'));
        expect(inputOf(callsTo('wizard_addon_standby_add')[0]).mode).toBe('open');
        expect(tid(m.container, 'addon-error')?.getAttribute('data-code')).toBe('E_STANDBY_OPEN_REFUSED');
        expect(m.container.textContent).toContain(en('pub.addons.err.E_STANDBY_OPEN_REFUSED'));
        await rig.click(btn(m.container, 'standby-open'));
        await rig.click(btn(m.container, 'standby-rent'));
        expect(m.container.textContent).toContain(en('pub.addons.err.E_STANDBY_LIMIT'));
    });

    it('on: switch asks first, then shows the code to send, with Copy', async () => {
        handlers.wizard_addon_standby_promote = () => ({
            addon: row('standby', 'promoted'),
            key: '000G40 R40M3 0E209 185WP 03H2G',
            refresh_note_published: true,
            warnings: [],
        });
        const s = sheet(StandbySheet, [row('standby', 'ready', { mode: 'sealed' })]);
        const m = await rig.mount(s.el);
        expect(callsTo('wizard_addon_standby_price')).toHaveLength(0);
        expect(tid(m.container, 'standby-mode')?.textContent).toBe(en('pub.addons.standby.mode.sealed'));
        await rig.click(btn(m.container, 'standby-switch'));
        expect(m.container.textContent).toContain(en('pub.addons.standby.switch.body'));
        expect(callsTo('wizard_addon_standby_promote')).toHaveLength(0);
        await rig.click(btn(m.container, 'standby-switch-go'));
        expect(tid(m.container, 'standby-key')?.textContent).toBe('000G40 R40M3 0E209 185WP 03H2G');
        expect(m.container.textContent).toContain(en('pub.addons.standby.key.body'));
        expect(m.container.textContent).toContain(en('pub.addons.standby.key.published'));
        await rig.click(btn(m.container, 'standby-key-copy'));
        expect(clipboard).toBe('000G40 R40M3 0E209 185WP 03H2G');
        expect(btn(m.container, 'standby-key-copy')?.textContent).toBe(en('pub.addons.copied'));
    });

    it('promoted: the relay uses it; renting a new one names the price', async () => {
        handlers.wizard_addon_standby_price = () => ({ monthly_cents: 300, currency: 'EUR', vat_included: false });
        const m = await rig.mount(sheet(StandbySheet, [row('standby', 'promoted')]).el);
        expect(m.container.textContent).toContain(en('pub.addons.standby.promoted_line'));
        expect(btn(m.container, 'standby-rent')?.textContent).toBe('Rent a new standby (€3.00 a month)');
    });

    it('remove: what is still billing is said', async () => {
        handlers.wizard_addon_remove = () => ({
            addon_id: 7,
            removed: false,
            still_billing: ['fip-sb'],
            by_hand: [],
            warnings: ['E_STANDBY_STILL_BILLING: could not release'],
        });
        const m = await rig.mount(sheet(StandbySheet, [row('standby', 'ready')]).el);
        await rig.click(btn(m.container, 'standby-remove'));
        expect(m.container.textContent).toContain(en('pub.addons.standby.remove.body'));
        await rig.click(btn(m.container, 'standby-remove-go'));
        expect(calls.find((c) => c.cmd === 'wizard_addon_remove')?.args).toEqual({ addonId: 7 });
        const r = tid(m.container, 'addon-remove-report')!;
        expect(r.textContent).toContain(en('pub.addons.remove.not_done'));
        expect(r.textContent).toContain('Still billing: fip-sb');
    });
});

// ------------------------------------------------------------------ cdn

describe('the Cloudflare sheet', () => {
    it('off: the three things to make first, with exactly five permissions and the pre-filled key page', async () => {
        const m = await rig.mount(sheet(CdnSheet, []).el);
        const need = tid(m.container, 'cdn-need')!;
        for (const k of ['pub.addons.cdn.need.1', 'pub.addons.cdn.need.2', 'pub.addons.cdn.need.3', 'pub.addons.cdn.need.3.pick'])
            expect(need.textContent).toContain(en(k));
        expect(tid(m.container, 'cdn-permissions')?.textContent).toBe(CDN_PERMISSIONS.join(''));
        expect(CDN_PERMISSIONS).toHaveLength(5);
        for (const b of ['cdn-open-signup', 'cdn-open-registrar', 'cdn-open-token']) expect(btn(m.container, b), b).toBeTruthy();
        const u = decodeURIComponent(cloudflareTokenUrl());
        expect(u).toContain('"key":"origin_rules","type":"edit"');
        expect(u).not.toContain('workers');
        // The offer says what Cloudflare learns, and that Daal buys nothing.
        expect(m.container.textContent).toContain(en('pub.addons.cdn.offer'));
        expect(EN['pub.addons.cdn.need.2']).toContain('Daal never buys anything for you');
        expect(calls).toHaveLength(0);
    });

    it('a key that can do more is refused, said in one line, and leaves the field', async () => {
        handlers.wizard_addon_cdn_set_token = () => ({
            zones: ['example.com', 'other.org'],
            verdict: 'too_broad',
            stored: false,
            extra: ['Account — Workers Scripts — Edit'],
        });
        const m = await rig.mount(sheet(CdnSheet, []).el);
        await rig.type(btn(m.container, 'cdn-token'), 'cf-secret-1');
        await rig.click(btn(m.container, 'cdn-token-check'));
        expect(inputOf(callsTo('wizard_addon_cdn_set_token')[0])).toEqual({ operator_id: 1, token: 'cf-secret-1' });
        expect(tid(m.container, 'cdn-verdict')?.getAttribute('data-verdict')).toBe('too_broad');
        expect(m.container.textContent).toContain(en('pub.addons.cdn.verdict.too_broad'));
        expect(m.container.textContent).toContain(en('pub.addons.cdn.not_stored'));
        expect((btn(m.container, 'cdn-token') as unknown as { value: string }).value).toBe('');
        expect(btn(m.container, 'cdn-build')).toBeNull();
    });

    it('a right key: pick the domain, build with live steps', async () => {
        handlers.wizard_addon_cdn_set_token = () => ({ zones: ['example.com'], verdict: 'ok', stored: true });
        handlers.wizard_addon_cdn_build = async () => {
            for (const step of ['cloudflare', 'firewall', 'door', 'testing', 'signing'])
                emit?.({ operator_id: 1, kind: 'cdn', step, state: 'ok', detail: '' });
            return row('cdn', 'ready', { hostname: 'k3j9.example.com' });
        };
        const s = sheet(CdnSheet, []);
        const m = await rig.mount(s.el);
        await rig.type(btn(m.container, 'cdn-token'), 'cf-secret-1');
        await rig.click(btn(m.container, 'cdn-token-check'));
        expect(m.container.textContent).toContain('The key is right. It sees: example.com');
        expect(m.container.textContent).toContain(en('pub.addons.cdn.build.note'));
        await rig.click(btn(m.container, 'cdn-build'));
        expect(inputOf(callsTo('wizard_addon_cdn_build')[0])).toEqual({ operator_id: 1, zone: 'example.com' });
        expect(tid(m.container, 'addon-steps')?.textContent).toContain(en('pub.addons.step.door'));
        expect(s.onChanged).toHaveBeenCalled();
    });

    it('a failed build says why and keeps the provider text in Details', async () => {
        handlers.wizard_addon_cdn_set_token = () => ({ zones: ['example.com'], verdict: 'ok', stored: true });
        handlers.wizard_addon_cdn_build = () => Promise.reject('E_CDN_NEEDS_REBUILD: this relay was built before');
        const m = await rig.mount(sheet(CdnSheet, []).el);
        await rig.type(btn(m.container, 'cdn-token'), 'cf-secret-1');
        await rig.click(btn(m.container, 'cdn-token-check'));
        await rig.click(btn(m.container, 'cdn-build'));
        expect(tid(m.container, 'addon-error')?.getAttribute('data-code')).toBe('E_CDN_NEEDS_REBUILD');
        expect(m.container.textContent).toContain(en('pub.addons.err.E_CDN_NEEDS_REBUILD'));
    });

    it('on: the posture on open is a read; Check again tests; the fallback is a signed switch', async () => {
        handlers.wizard_addon_cdn_posture = (a) => ({
            name_hidden: (a!.input as { test: boolean }).test ? false : true,
            door_closed_to_others: true,
            last_test_at_unix: 1_800_000_000,
            last_test_ok: true,
            renews_at_unix: 0,
            needs_rebuild: false,
            hostname: 'k3j9.example.com',
            zone: 'example.com',
            plain_fallback: false,
            notes: '',
        });
        handlers.wizard_addon_cdn_set_plain_fallback = () => row('cdn', 'ready', { plain_fallback: true });
        const m = await rig.mount(sheet(CdnSheet, [row('cdn', 'ready', { hostname: 'k3j9.example.com' })]).el);
        expect(inputOf(callsTo('wizard_addon_cdn_posture')[0])).toEqual({ operator_id: 1, test: false });
        expect(tid(m.container, 'cdn-name-hidden')?.textContent).toBe(`${en('pub.addons.cdn.posture.name_hidden')}${en('pub.addons.yes')}`);
        expect(tid(m.container, 'cdn-door')?.textContent).toContain(en('pub.addons.yes'));
        expect(tid(m.container, 'cdn-last-test')?.textContent).toContain(en('pub.addons.cdn.posture.test_ok'));
        expect(tid(m.container, 'cdn-posture')?.textContent).toContain('k3j9.example.com');
        await rig.click(btn(m.container, 'cdn-check'));
        expect(inputOf(callsTo('wizard_addon_cdn_posture')[1])).toEqual({ operator_id: 1, test: true });
        expect(tid(m.container, 'cdn-name-hidden')?.textContent).toContain(en('pub.addons.no'));
        const sw = btn(m.container, 'cdn-fallback')!;
        expect(sw.getAttribute('aria-checked')).toBe('false');
        await rig.click(sw);
        expect(inputOf(callsTo('wizard_addon_cdn_set_plain_fallback')[0])).toEqual({ operator_id: 1, allow: true });
        expect(btn(m.container, 'cdn-fallback')?.getAttribute('aria-checked')).toBe('true');
    });

    it('remove: the key and the domain are the publisher\'s to end, and the sheet says so', async () => {
        handlers.wizard_addon_cdn_posture = () => Promise.reject('E_CDN_NO_TOKEN: none');
        handlers.wizard_addon_remove = () => ({
            addon_id: 7,
            removed: true,
            still_billing: [],
            by_hand: ['delete_cloudflare_token', 'cancel_domain'],
            warnings: ['relay_door_left_on'],
        });
        const m = await rig.mount(sheet(CdnSheet, [row('cdn', 'ready')]).el);
        await rig.click(btn(m.container, 'cdn-remove'));
        await rig.click(btn(m.container, 'cdn-remove-go'));
        const r = tid(m.container, 'addon-remove-report')!.textContent;
        expect(r).toContain(en('pub.addons.remove.done'));
        expect(r).toContain(en('pub.addons.by_hand.delete_cloudflare_token'));
        expect(r).toContain(en('pub.addons.by_hand.cancel_domain'));
        expect(r).toContain(en('pub.addons.warn.relay_door_left_on'));
    });
});

// ------------------------------------------------------------------ google

describe('the Google sheet', () => {
    it('off: the suspension warning, both paths, the builders\' note; sign-in not configured points to the by-hand way', async () => {
        handlers.wizard_freshness_status = () => ({ google_only: false });
        handlers.wizard_addon_google_sign_in = () => Promise.reject('E_GOOGLE_NOT_CONFIGURED: no client');
        const m = await rig.mount(sheet(GoogleSheet, []).el);
        expect(tid(m.container, 'google-warn')?.textContent).toBe(en('pub.addons.google.warn'));
        expect(EN['pub.addons.google.warn']).toMatch(/never your own/);
        expect(EN['pub.addons.google.warn']).toMatch(/without warning/);
        expect(tid(m.container, 'google-path-a')?.textContent).toContain(en('pub.addons.google.path_a.step.3'));
        expect(tid(m.container, 'google-path-a')?.textContent).toContain(en('pub.addons.google.builders'));
        expect(tid(m.container, 'google-path-b')?.textContent).toContain(en('pub.addons.google.path_b.title'));
        expect(tid(m.container, 'google-only')).toBeNull();
        await rig.click(btn(m.container, 'google-sign-in'));
        expect(m.container.textContent).toContain(en('pub.addons.err.E_GOOGLE_NOT_CONFIGURED'));
    });

    it('by hand: show and copy the script, paste the address back, and a failed check says why', async () => {
        handlers.wizard_freshness_status = () => ({ google_only: true });
        handlers.wizard_addon_google_script = () => ({ code_gs: 'var WRITE_KEY = "abc";', manifest_json: '{}' });
        handlers.wizard_addon_google_attach = () =>
            Promise.reject('E_GOOGLE_CHECK_FAILED: not_deployed: the script did not answer as it should');
        const m = await rig.mount(sheet(GoogleSheet, []).el);
        expect(tid(m.container, 'google-only')?.textContent).toBe(en('pub.addons.google.only'));
        await rig.click(btn(m.container, 'google-show-script'));
        expect((tid(m.container, 'google-script') as unknown as { value: string }).value).toBe('var WRITE_KEY = "abc";');
        expect(m.container.textContent).toContain(en('pub.addons.google.path_b.secret'));
        await rig.click(btn(m.container, 'google-copy-script'));
        expect(clipboard).toBe('var WRITE_KEY = "abc";');
        await rig.type(btn(m.container, 'google-url'), ' https://script.google.com/macros/s/AKfy/exec ');
        await rig.click(btn(m.container, 'google-attach'));
        expect(inputOf(callsTo('wizard_addon_google_attach')[0])).toEqual({
            operator_id: 1,
            url: 'https://script.google.com/macros/s/AKfy/exec',
        });
        const e = tid(m.container, 'addon-error')!;
        expect(e.getAttribute('data-code')).toBe('E_GOOGLE_CHECK_FAILED');
        expect(e.textContent).toContain(en('pub.addons.google.reason.not_deployed'));
    });

    it('on: the last check and Check now', async () => {
        handlers.wizard_freshness_status = () => ({ google_only: false });
        handlers.wizard_addon_google_check = () => ({ ok: true, via_front: true, checked_at_unix: 1_800_000_000, reason: '' });
        const m = await rig.mount(
            sheet(GoogleSheet, [row('google', 'ready', { url: 'https://script.google.com/macros/s/AKfy/exec?k=x' })]).el,
        );
        expect(tid(m.container, 'google-last-check')?.textContent).toContain(en('pub.addons.never'));
        expect(tid(m.container, 'google-path-a')).toBeNull();
        await rig.click(btn(m.container, 'google-check'));
        expect(tid(m.container, 'google-last-check')?.textContent).toContain(en('pub.addons.google.check.front'));
    });
});

// ------------------------------------------------------------------ elsewhere

describe('the add-ons outside their sheets', () => {
    it('the relay delete report says what became of each add-on', async () => {
        const outcomes = [
            { addon_id: 1, kind: 'standby' as const, removed: false, keeps_relay: false, code: 'with_relay' as const, error: '' },
            { addon_id: 2, kind: 'cdn' as const, removed: false, keeps_relay: true, code: 'failed' as const, error: 'origin_certificate: 500' },
            { addon_id: 3, kind: 'google' as const, removed: false, keeps_relay: false, code: 'left' as const, error: '' },
        ];
        const m = await rig.mount(<AddonOutcomeLines t={en} outcomes={outcomes} />);
        const s = tid(m.container, 'destroy-addons')!.textContent;
        expect(s).toContain('Standby address: goes with the relay.');
        expect(s).toContain(`${en('pub.addons.cdn.title')}: could not be removed yet`);
        expect(s).toContain(`${en('pub.addons.google.title')}: left running.`);
        expect(s).toContain('origin_certificate: 500');
        expect(addonOutcomeLine(fa, outcomes[0])).toBe(`${FA['pub.addons.standby.title']}: همراه رله حذف می‌شود.`);
        const n = await rig.mount(<AddonOutcomeLines t={en} outcomes={undefined} />);
        expect(tid(n.container, 'destroy-addons')).toBeNull();
    });

    it('the account check names a standby address and what it bills', () => {
        const base = {
            kind: 'floating-ip' as const,
            id: '9',
            name: 'daal-standby',
            address: '203.0.113.20',
            billing: true,
            verdict: 'in-use' as const,
            finding: 'yours_in_use' as const,
            belongs_to_relay_id: 1,
            can_delete: false,
        };
        expect(addonItemLine(en, { ...base, addon: 'standby', monthly_cost_cents: 300, cost_currency: 'EUR' })).toBe(
            "A relay's standby address · €3.00 a month",
        );
        expect(addonItemLine(fa, { ...base, addon: 'standby', monthly_cost_cents: 300, cost_currency: 'EUR' })).toContain('ماهی ۳٫۰۰ یورو');
        expect(addonItemLine(en, { ...base, addon: 'standby' })).toBe(en('pub.addons.account.standby_nocost'));
        expect(addonItemLine(en, base)).toBeNull();
    });

    it('an import line for a route that needs a newer app', () => {
        const lines = unavailableLines(en, { Unavailable: [{ Reason: 'needs_newer_app', Family: 'websocket-tls' }] } as never);
        expect(lines).toHaveLength(1);
        expect(lines[0]).toContain('needs a newer version of the app');
        const faLines = unavailableLines(fa, { Unavailable: [{ Reason: 'needs_newer_app', Family: 'websocket-tls' }] } as never);
        expect(faLines[0]).toContain('نسخهٔ تازه‌تر برنامه');
    });

    it('the recipient types a code: each answer has its own line, and an accepted one clears the field', async () => {
        const typed: string[] = [];
        let answer: 'accepted' | 'no_match' | 'malformed' | 'no_standby' | 'unavailable' = 'no_match';
        const onAccepted = vi.fn();
        const m = await rig.mount(
            <StandbyCodeEntry
                t={en}
                onAccepted={onAccepted}
                enter={async (k) => {
                    typed.push(k);
                    return answer;
                }}
            />,
        );
        const go = () => btn(m.container, 'standby-code-go');
        expect(go()?.getAttribute('disabled')).not.toBeNull();
        await rig.type(btn(m.container, 'standby-code-input'), '000g40-r40m3  0e209 185wp 03h2g');
        await rig.click(go());
        expect(typed).toEqual(['000G40 R40M3 0E209 185WP 03H2G']);
        expect(m.container.textContent).toContain(en('add.code.no_match'));
        for (const o of ['malformed', 'no_standby', 'unavailable'] as const) {
            answer = o;
            await rig.click(go());
            expect(m.container.textContent).toContain(en(`add.code.${o}`));
        }
        answer = 'accepted';
        await rig.click(go());
        expect(m.container.textContent).toContain(en('add.code.accepted'));
        expect(onAccepted).toHaveBeenCalledTimes(1);
        expect((btn(m.container, 'standby-code-input') as unknown as { value: string }).value).toBe('');
        expect(normaliseCode(' ab-cd ')).toBe('AB CD');
    });
});

// ------------------------------------------------------------------ strings

/** Every literal `t('…')` key in the add-on sources and the files this
 *  lane touched, plus every dynamic key family. */
function usedKeys(): string[] {
    const sources = [srcSection, srcText, srcUi, srcErrors, srcStandby, srcCdn, srcGoogle, srcOutcome, srcCode, srcAccount];
    const keys = new Set<string>();
    for (const src of sources) {
        for (const m of src.matchAll(/'((?:pub\.addons|add\.code|add\.choose)\.[a-zA-Z0-9_.]+)'/g)) {
            if (!m[1].endsWith('.')) keys.add(m[1]);
        }
    }
    for (const w of errs.STEP_WORDS) keys.add(`pub.addons.step.${w}`);
    for (const c of errs.ADDON_ERROR_CODES) keys.add(`pub.addons.err.${c}`);
    for (const c of errs.SHARED_CODES_WITH_COPY) keys.add(`pub.addons.err.${c}`);
    for (const w of errs.WARNING_WORDS) keys.add(`pub.addons.warn.${w}`);
    for (const w of errs.BY_HAND_WORDS) keys.add(`pub.addons.by_hand.${w}`);
    for (const v of ['ok', 'invalid', 'no_zone', 'zone_not_visible', 'too_broad', 'missing_permission', 'refused'])
        keys.add(`pub.addons.cdn.verdict.${v}`);
    for (const r of ['not_deployed', 'refused', 'stale', 'wrong_content', 'unreachable', 'no_address'])
        keys.add(`pub.addons.google.reason.${r}`);
    for (const c of ['removed', 'with_relay', 'failed', 'left', 'not_built']) keys.add(`pub.addons.outcome.${c}`);
    for (const m of ['sealed', 'open']) keys.add(`pub.addons.standby.mode.${m}`);
    for (const o of ['accepted', 'no_match', 'malformed', 'no_standby', 'unavailable']) keys.add(`add.code.${o}`);
    for (const c of ['EUR', 'USD']) keys.add(`pub.addons.money.${c}`);
    keys.add('add.unavailable.needs_newer_app');
    return [...keys].sort();
}

describe('the strings', () => {
    it('every key exists in English and Persian with the same placeholders', () => {
        const keys = usedKeys();
        expect(keys.length).toBeGreaterThan(180);
        for (const k of keys) {
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toBeTruthy();
            const ph = (s: string) => (s.match(/\{[a-z]+\}/g) ?? []).sort().join(',');
            expect(ph(FA[k]), k).toBe(ph(EN[k]));
        }
    });

    it('the Persian reads like an app: no narrated taps, no bookish verbs, Persian letters and digits', () => {
        for (const k of usedKeys()) {
            const s = FA[k];
            if (k === 'add.code.placeholder' || k.startsWith('pub.addons.money.')) continue;
            expect(s, k).toMatch(/[؀-ۿ]/);
            expect(s, k).not.toMatch(/بزنید/);
            expect(s, k).not.toMatch(/می‌باشد|نمایید|جهت |توسط|گردید|اقدام به/);
            expect(s, k).not.toMatch(/[يك]/);
            expect(s, k).not.toMatch(/[0-9]/);
        }
        // The fixed vocabulary.
        expect(FA['pub.addons.step.signing']).toContain('رله');
        expect(FA['pub.addons.cdn.remove']).toContain('راه');
        expect(FA['pub.addons.standby.rent']).toContain('آدرس');
        expect(FA['pub.addons.try_again']).toBe('تلاش دوباره');
        expect(FA['pub.addons.close']).toBe('بستن');
    });

    it('no cost, warning or tie is dropped in Persian', () => {
        expect(FA['pub.addons.standby.price']).toContain('مالیات');
        expect(FA['pub.addons.cdn.offer']).toContain('۱۰ دلار');
        expect(FA['pub.addons.cdn.offer']).toContain('ایمیل');
        expect(FA['pub.addons.google.warn']).toContain('بی‌خبر');
        expect(FA['pub.addons.google.only']).toContain('Google');
        expect(FA['pub.addons.by_hand.cancel_domain']).toContain('هزینه');
        expect(FA['pub.addons.cdn.fallback.help']).toContain('مسدود');
    });
});
