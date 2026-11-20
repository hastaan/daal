// The Add-ons shell (docs/optional-addons-plan.md, X3): three quiet
// blocks on the relay page and at the end of the build wizard, each with
// what it rescues, what it costs and what it ties to the publisher, all
// off and "in development" until their lanes land. Driven through the
// real command wrapper (wizardCommands.ts `Addons.list`).
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig } from '../../test/rig';
import type { Rig } from '../../test/rig';
import srcEn from '../../../../client-shared/i18n/d2-extra.en.json';
import srcFa from '../../../../client-shared/i18n/d2-extra.fa.json';
import type { AddonRow } from './addonTypes';

let listReply: () => Promise<unknown> = () => Promise.resolve([]);
const calls: { cmd: string; args: unknown }[] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        if (cmd === 'wizard_addons_list') return listReply();
        return Promise.reject(`E_NOT_BUILT: ${cmd} is not built yet`);
    },
}));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
    calls.length = 0;
    listReply = () => Promise.resolve([]);
});

const { translate } = await import('../../lib/i18n');
const { AddonsSection } = await import('./AddonsSection');
const { ADDON_BUILT, ADDON_COPY, addonKeys, summaryOf } = await import('./addonText');
const { Addons, classifyPublisherError } = await import('../wizardCommands');
const en = (k: string) => translate('en', k);
const fa = (k: string) => translate('fa', k);
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);
const EN = srcEn as Record<string, string>;
const FA = srcFa as Record<string, string>;

function row(kind: AddonRow['kind'], state: AddonRow['state']): AddonRow {
    return {
        id: 7,
        operator_id: 1,
        kind,
        state,
        provider_ids: {},
        monthly_cost_cents: kind === 'standby' ? 300 : 0,
        cost_currency: kind === 'standby' ? 'EUR' : '',
        has_secret: false,
        detail: {},
        created_at_unix: 1,
        updated_at_unix: 1,
    };
}

describe('the strings', () => {
    it('every one exists in English and in Persian, in the shared catalogue', () => {
        const keys = addonKeys();
        expect(keys.length).toBeGreaterThanOrEqual(31);
        for (const k of keys) {
            expect(EN[k], k).toBeTruthy();
            expect(FA[k], k).toMatch(/[؀-ۿ]/);
            const ph = (s: string) => (s.match(/\{[a-z]+\}/g) ?? []).sort().join(',');
            expect(ph(FA[k]), k).toBe(ph(EN[k]));
        }
    });

    it('the Persian follows docs/style/farsi.md: no narrated taps, no bookish verbs, Persian letters and digits', () => {
        for (const k of addonKeys()) {
            const s = FA[k];
            expect(s, k).not.toMatch(/بزنید/);
            expect(s, k).not.toMatch(/می‌باشد|نمایید|جهت |توسط/);
            expect(s, k).not.toMatch(/[يك]/);
            expect(s, k).not.toMatch(/[0-9]/);
        }
        // The fixed vocabulary: route is «راه», address «آدرس», relay «رله».
        expect(FA['pub.addons.cdn.title']).toContain('راه');
        expect(FA['pub.addons.standby.title']).toContain('آدرس');
        expect(FA['pub.addons.intro']).toContain('رله');
    });

    it('each card states its cost exactly, in both languages', () => {
        expect(EN['pub.addons.standby.cost']).toContain('€3.00 a month per relay, plus VAT');
        expect(FA['pub.addons.standby.cost']).toContain('۳٫۰۰ یورو');
        expect(FA['pub.addons.standby.cost']).toContain('مالیات');
        expect(EN['pub.addons.cdn.cost']).toContain('about $10 a year');
        expect(FA['pub.addons.cdn.cost']).toContain('۱۰ دلار در سال');
        expect(EN['pub.addons.google.cost']).toBe('Free.');
        expect(FA['pub.addons.google.cost']).toBe('رایگان.');
    });

    it('and never drops what it ties to the publisher', () => {
        expect(EN['pub.addons.cdn.ties']).toMatch(/email/);
        expect(EN['pub.addons.cdn.ties']).toMatch(/who connects and where they go/);
        expect(FA['pub.addons.cdn.ties']).toMatch(/ایمیل/);
        expect(EN['pub.addons.google.ties']).toMatch(/phone number/);
        expect(EN['pub.addons.google.ties']).toMatch(/never your own/);
        expect(FA['pub.addons.google.ties']).toMatch(/شماره تلفن/);
        expect(EN['pub.addons.standby.ties']).toMatch(/Nothing new/);
    });
});

describe('the Add-ons section', () => {
    it('is folded away by default and reads the ledger once', async () => {
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} />);
        expect(tid(m.container, 'addons-summary')?.textContent).toBe(en('pub.addons.summary.soon'));
        expect(tid(m.container, 'addon-standby')).toBeNull();
        expect(calls.filter((c) => c.cmd === 'wizard_addons_list')).toEqual([
            { cmd: 'wizard_addons_list', args: { operatorId: 1 } },
        ]);
    });

    it('opened: three blocks, each off, in development, with what it rescues, costs and ties to you', async () => {
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} defaultOpen />);
        const s = m.container.textContent;
        expect(s).toContain(en('pub.addons.intro'));
        for (const c of ADDON_COPY) {
            const b = tid(m.container, `addon-${c.kind}`)!;
            expect(b, c.kind).toBeTruthy();
            expect(b.getAttribute('data-state')).toBe('soon');
            const text = b.textContent;
            for (const k of [c.titleKey, c.lineKey, c.rescuesKey, c.costKey, c.tiesKey]) expect(text).toContain(en(k));
            expect(text).toContain(en('pub.addons.soon'));
            expect(text).toContain(en('pub.addons.soon.line'));
            const sw = byAttr(b, 'data-button', `addon-${c.kind}-toggle`)!;
            expect(sw.getAttribute('aria-checked')).toBe('false');
            expect(sw.getAttribute('disabled') !== null || (sw as unknown as { disabled?: boolean }).disabled).toBeTruthy();
        }
        expect(tid(m.container, 'addon-standby-cost')?.textContent).toContain('€3.00 a month per relay, plus VAT');
        expect(tid(m.container, 'addon-cdn-cost')?.textContent).toContain('$10');
        expect(tid(m.container, 'addon-google-cost')?.textContent).toContain('Free');
        // The shell starts nothing: a click on a switch sends no command.
        await rig.click(byAttr(m.container, 'data-button', 'addon-standby-toggle'));
        expect(calls.map((c) => c.cmd)).toEqual(['wizard_addons_list']);
    });

    it('the wizard says the relay works without them', async () => {
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} variant="wizard" defaultOpen />);
        expect(tid(m.container, 'addons-wizard')).toBeTruthy();
        expect(m.container.textContent).toContain(en('pub.addons.wizard.intro'));
        expect(m.container.textContent).not.toContain(en('pub.addons.intro'));
    });

    it('in Persian', async () => {
        const m = await rig.mount(<AddonsSection t={fa} operatorId={1} defaultOpen />);
        const s = m.container.textContent;
        expect(s).toContain(FA['pub.addons.title']);
        expect(s).toContain('۳٫۰۰ یورو');
        expect(s).toContain(FA['pub.addons.soon']);
    });

    it('a relay with a standby that is on says so; a promoted one does not count', async () => {
        listReply = () => Promise.resolve([row('standby', 'ready')]);
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} defaultOpen />);
        const b = tid(m.container, 'addon-standby')!;
        expect(b.getAttribute('data-state')).toBe('ready');
        expect(b.textContent).toContain(en('pub.addons.state.ready'));
        expect(b.textContent).not.toContain(en('pub.addons.soon.line'));
        expect(byAttr(b, 'data-button', 'addon-standby-toggle')?.getAttribute('aria-checked')).toBe('true');
        expect(tid(m.container, 'addons-summary')?.textContent).toBe('1 on');
        expect(summaryOf([row('standby', 'promoted')])).toEqual({ key: 'pub.addons.summary.soon', n: 0 });
        expect(summaryOf([], { standby: true, cdn: false, google: false })).toEqual({ key: 'pub.addons.summary.off', n: 0 });
    });

    it('a shell without the ledger, or no relay yet, is simply all off', async () => {
        listReply = () => Promise.reject('unknown command wizard_addons_list');
        const m = await rig.mount(<AddonsSection t={en} operatorId={1} defaultOpen />);
        expect(tid(m.container, 'addon-cdn')?.getAttribute('data-state')).toBe('soon');
        const n = await rig.mount(<AddonsSection t={en} operatorId={null} defaultOpen />);
        expect(all(n.container, (x) => x.getAttribute?.('data-state') === 'soon')).toHaveLength(3);
        expect(calls.filter((c) => c.cmd === 'wizard_addons_list')).toHaveLength(1);
    });

    it('nothing is built in this version, so nothing can be turned on', () => {
        expect(ADDON_BUILT).toEqual({ standby: false, cdn: false, google: false });
    });
});

describe('the command surface', () => {
    it('every add-on command reaches its Tauri name with one input object, and refuses as not built', async () => {
        const op = { operator_id: 1 };
        const cases: [Promise<unknown>, string][] = [
            [Addons.remove(7), 'wizard_addon_remove'],
            [Addons.standbyPrice(op), 'wizard_addon_standby_price'],
            [Addons.standbyAdd({ ...op, mode: 'sealed' }), 'wizard_addon_standby_add'],
            [Addons.standbyPromote(op), 'wizard_addon_standby_promote'],
            [Addons.standbyKey(op), 'wizard_addon_standby_key'],
            [Addons.cdnSetToken({ ...op, token: 'x' }), 'wizard_addon_cdn_set_token'],
            [Addons.cdnBuild({ ...op, zone: 'example.com' }), 'wizard_addon_cdn_build'],
            [Addons.cdnPosture(op), 'wizard_addon_cdn_posture'],
            [Addons.cdnSetPlainFallback({ ...op, allow: false }), 'wizard_addon_cdn_set_plain_fallback'],
            [Addons.googleScript(op), 'wizard_addon_google_script'],
            [Addons.googleSignIn(op), 'wizard_addon_google_sign_in'],
            [Addons.googleAttach({ ...op, url: 'https://script.google.com/macros/s/x/exec' }), 'wizard_addon_google_attach'],
            [Addons.googleCheck(op), 'wizard_addon_google_check'],
        ];
        for (const [p, name] of cases) {
            const e = await p.then(() => 'resolved', (err: unknown) => err);
            expect(classifyPublisherError(e), name).toBe('E_NOT_BUILT');
        }
        expect(calls.map((c) => c.cmd)).toEqual(cases.map(([, n]) => n));
        expect(calls[0].args).toEqual({ addonId: 7 });
        for (const c of calls.slice(1)) expect(Object.keys(c.args as object)).toEqual(['input']);
    });
});
