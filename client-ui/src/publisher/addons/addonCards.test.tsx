// The pieces around «More protection»: what a failure says, money, the
// Google account sheet, the relay delete report's add-on lines, the
// account check's standby line, the recipient's "I was sent a code"
// field, and every string they use, driven through the real command
// wrappers (wizardCommands.ts) against a fake shell.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import srcEn from '../../../../client-shared/i18n/d2-extra.en.json';
import srcFa from '../../../../client-shared/i18n/d2-extra.fa.json';
import srcSection from './AddonsSection.tsx?raw';
import srcText from './addonText.ts?raw';
import srcUi from './addonUi.tsx?raw';
import srcErrors from './addonErrors.ts?raw';
import srcSheets from './AccountSheets.tsx?raw';
import srcAccounts from './accounts.ts?raw';
import srcPage from '../AccountsPage.tsx?raw';
import srcOutcome from './AddonOutcomeLines.tsx?raw';
import srcCode from '../../components/StandbyCodeEntry.tsx?raw';
import srcAccount from '../AccountCheckSheet.tsx?raw';

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
    listen: async () => () => {},
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
const { GoogleSheet, cloudflareTokenUrl } = await import('./AccountSheets');
const { AddonOutcomeLines, addonOutcomeLine } = await import('./AddonOutcomeLines');
const { addonKeys } = await import('./addonText');
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
        // A known code without an add-on sentence keeps its own plain one.
        expect(errs.addonErrorText(en, 'E_RELAY_KEYS_CHANGED: x').line).toBe(en('pub.relay_keys_changed'));
        expect(errs.addonErrorText(en, 'subprocess: dial tcp: i/o timeout').line).toBe(en('pub.fail.unreachable'));
        // ECH off: the zone in the sentence.
        const ech = errs.addonErrorText(en, 'E_CDN_NO_ECH: example.org: Cloudflare publishes no ECH config');
        expect(ech.code).toBe('E_CDN_NO_ECH');
        expect(ech.line).toBe(en('pub.addons.err.E_CDN_NO_ECH').replace('{zone}', 'example.org'));
        expect(ech.detail).toContain('publishes no ECH config');
        // A relay that would bind the standby where its own traffic can
        // leave from it: one plain line, the helper's text in Details only.
        const old = 'E_STANDBY_NEEDS_REBUILD: E_STANDBY_NEEDS_REBUILD: this relay\'s software binds a second address where the relay\'s own traffic could leave from it; Nothing was rented (the relay advertises: bind-address)';
        const r = errs.addonErrorText(en, old);
        expect(r.code).toBe('E_STANDBY_NEEDS_REBUILD');
        expect(r.line).toBe('This relay is too old for a standby address. Set up a new relay to use it.');
        expect(r.line).not.toContain('bind-address');
        expect(r.detail).toContain('Nothing was rented');
        const rf = errs.addonErrorText(fa, old);
        expect(rf.line).toBe(FA['pub.addons.err.E_STANDBY_NEEDS_REBUILD']);
        expect(rf.line).toContain('آدرس یدکی');
        expect(rf.line).not.toContain('بزنید');
        expect(rf.line).not.toMatch(/[A-Za-z]/);
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

// ------------------------------------------------------------------ by hand

describe('the Google account sheet', () => {
    const NO_G = { connected: false, scriptMade: false, signIn: false };

    it('copy the script, paste the address back, and a failed check says why in one line', async () => {
        handlers.wizard_google_account_script = () => ({ code_gs: 'var WRITE_KEY_B64 = "abc";', manifest_json: '{}' });
        handlers.wizard_google_account_attach = () =>
            Promise.reject('E_GOOGLE_CHECK_FAILED: not_deployed: the script did not answer as it should');
        const onConnected = vi.fn();
        const m = await rig.mount(<GoogleSheet t={en} google={NO_G} onClose={() => {}} onConnected={onConnected} />);
        expect(tid(m.container, 'google-script')).toBeNull();
        await rig.click(btn(m.container, 'google-copy-script'));
        expect(clipboard).toBe('var WRITE_KEY_B64 = "abc";');
        expect(callsTo('wizard_google_account_script')[0].args).toBeUndefined();
        expect(m.container.textContent).toContain(en('pub.accounts.google.hand.secret'));
        await rig.type(btn(m.container, 'google-url'), ' https://script.google.com/macros/s/AKfy/exec ');
        await rig.click(btn(m.container, 'google-connect'));
        expect(inputOf(callsTo('wizard_google_account_attach')[0])).toEqual({
            url: 'https://script.google.com/macros/s/AKfy/exec',
        });
        const e = tid(m.container, 'addon-error')!;
        expect(e.getAttribute('data-code')).toBe('E_GOOGLE_CHECK_FAILED');
        expect(e.textContent).toContain(en('pub.addons.google.reason.not_deployed'));
        expect(onConnected).not.toHaveBeenCalled();
    });

    it('a sign-in that needs the Apps Script API on offers the setting', async () => {
        handlers.wizard_google_account_sign_in = () =>
            Promise.reject('E_GOOGLE_API_NOT_ENABLED: turn on the Apps Script API at script.google.com/home/usersettings, then try again');
        const m = await rig.mount(<GoogleSheet t={en} google={{ ...NO_G, signIn: true }} onClose={() => {}} onConnected={() => {}} />);
        await rig.click(btn(m.container, 'google-sign-in'));
        expect(tid(m.container, 'addon-error')?.getAttribute('data-code')).toBe('E_GOOGLE_API_NOT_ENABLED');
        expect(btn(m.container, 'google-api-open')?.textContent).toContain(en('pub.accounts.google.api.open'));
    });

    it('a build without the OAuth clients shows no sign-in anywhere', async () => {
        const m = await rig.mount(<GoogleSheet t={en} google={NO_G} onClose={() => {}} onConnected={() => {}} />);
        expect(btn(m.container, 'google-sign-in')).toBeNull();
        expect(tid(m.container, 'google-sign-in-block')).toBeNull();
        expect(m.container.textContent).not.toContain(en('pub.accounts.google.unverified'));
        expect(srcSheets).toMatch(/google\.signIn && \(/);
    });

    it('the Cloudflare key page is the pre-filled one with exactly the five permissions', () => {
        const u = new URL(cloudflareTokenUrl());
        expect(u.origin).toBe('https://dash.cloudflare.com');
        const groups = JSON.parse(u.searchParams.get('permissionGroupKeys') ?? '[]') as { key: string }[];
        expect(groups.map((g) => g.key)).toEqual(['zone', 'dns', 'ssl_and_certificates', 'zone_settings', 'origin']);
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

/** Every literal `t('…')` key in the add-on and Accounts sources and
 *  the files this lane touched, plus every dynamic key family. */
function usedKeys(): string[] {
    const sources = [srcSection, srcText, srcUi, srcErrors, srcSheets, srcAccounts, srcPage, srcOutcome, srcCode, srcAccount];
    const keys = new Set<string>(addonKeys());
    for (const src of sources) {
        for (const m of src.matchAll(/'((?:pub\.addons|pub\.accounts|add\.code|add\.choose)\.[a-zA-Z0-9_.]+)'/g)) {
            if (!m[1].endsWith('.')) keys.add(m[1]);
        }
    }
    for (const c of errs.ADDON_ERROR_CODES) keys.add(`pub.addons.err.${c}`);
    for (const c of errs.SHARED_CODES_WITH_COPY) keys.add(`pub.addons.err.${c}`);
    keys.add('pub.addons.err.other');
    for (const r of ['not_deployed', 'refused', 'stale', 'wrong_content', 'unreachable', 'full', 'no_address'])
        keys.add(`pub.addons.google.reason.${r}`);
    for (const c of ['removed', 'with_relay', 'failed', 'left', 'not_built']) keys.add(`pub.addons.outcome.${c}`);
    for (const o of ['accepted', 'no_match', 'malformed', 'no_standby', 'unavailable']) keys.add(`add.code.${o}`);
    for (const c of ['EUR', 'USD']) keys.add(`pub.addons.money.${c}`);
    keys.add('add.unavailable.needs_newer_app');
    return [...keys].sort();
}

describe('the strings', () => {
    it('every key exists in English and Persian with the same placeholders', () => {
        const keys = usedKeys();
        expect(keys.length).toBeGreaterThan(100);
        for (const k of keys) {
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toBeTruthy();
            const ph = (s: string) => (s.match(/\{[a-z]+\}/g) ?? []).sort().join(',');
            expect(ph(FA[k]), k).toBe(ph(EN[k]));
        }
    });

    it('no pub.addons or pub.accounts key is left over in the catalogue', () => {
        const used = new Set(usedKeys());
        // Used outside the add-on folder: the Google-only warning on the
        // refresh panel, and the "other" money format.
        for (const k of ['pub.addons.google.only', 'pub.addons.money.other']) used.add(k);
        const stale = Object.keys(EN).filter((k) => /^pub\.(addons|accounts)\./.test(k) && !used.has(k));
        expect(stale).toEqual([]);
        expect(Object.keys(FA).filter((k) => /^pub\.(addons|accounts)\./.test(k)).sort()).toEqual(
            Object.keys(EN).filter((k) => /^pub\.(addons|accounts)\./.test(k)).sort(),
        );
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
        expect(FA['pub.addons.standby.title']).toContain('آدرس');
        expect(FA['pub.addons.try_again']).toBe('تلاش دوباره');
        expect(FA['pub.addons.close']).toBe('بستن');
        expect(FA['pub.accounts.cf.key']).toBe('کلید دسترسی');
        expect(FA['pub.addons.title']).toBe('محافظت بیشتر');
        expect(FA['pub.accounts.title']).toBe('حساب‌ها');
        expect(FA['pub.accounts.connected']).toBe('✓ وصل است');
    });

    it('the warnings that matter are kept, each once and short', () => {
        // The cost.
        expect(EN['pub.addons.standby.cost']).toBe('€3 a month + VAT');
        expect(FA['pub.addons.standby.cost']).toContain('مالیات');
        expect(FA['pub.addons.cdn.cost']).toContain('۱۰ دلار');
        expect(FA['pub.addons.google.cost']).toBe('رایگان');
        // Google can close the account.
        expect(EN['pub.accounts.google.warn']).toMatch(/without warning/);
        expect(FA['pub.accounts.google.warn']).toContain('بی‌خبر');
        // Cloudflare sees the traffic.
        expect(EN['pub.accounts.cf.sees']).toMatch(/who connects/);
        expect(FA['pub.accounts.cf.sees']).toContain('Cloudflare می‌بیند');
        // A domain keeps billing.
        expect(EN['pub.addons.off.cdn']).toMatch(/keeps billing/);
        expect(FA['pub.addons.off.cdn']).toContain('هزینهٔ دامنه');
        // Every line of a row is short.
        for (const k of ['standby', 'cdn', 'google']) {
            for (const f of ['title', 'line', 'cost']) {
                expect(EN[`pub.addons.${k}.${f}`].length, `${k}.${f}`).toBeLessThanOrEqual(90);
            }
        }
    });

    it('nothing technical reaches the publisher: no ECH, posture, outer name, sealed/open, plain fallback, Everyone key', () => {
        for (const k of usedKeys()) {
            if (k.startsWith('pub.addons.err.') || k.startsWith('add.')) continue;
            expect(EN[k], k).not.toMatch(/\bECH\b|posture|outer name|sealed|plain fallback/i);
            // "the Everyone key" is jargon; "the file for everyone" is the app's own name for it.
            expect(EN[k], k).not.toMatch(/Everyone/);
        }
    });
});
