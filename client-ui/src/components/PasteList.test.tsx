// The paste box with several items, driven in the miniDom rig: one row
// per item; links and files added one at a time with a result each; the
// bulk check and removal only when two or more links were added, and the
// removal takes ONLY routes the check tried and that failed.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';

const calls: string[] = [];
const opened: string[] = [];
let routes: { routeId: string; checkedWhenUsed?: boolean }[] = [];
let nextId = 0;
/** link text → what uriImport does with it. */
let linkAnswer: (text: string) => { raw?: string; throws?: string };
/** route id → survey result. */
let surveyResults: Record<string, string> = {};
let surveyStart: Record<string, unknown> = { started: true };

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        if (cmd === 'survey_routes') {
            calls.push(`survey:${String(args?.start)}`);
            const results = Object.entries(surveyResults).map(([route_id, result]) => ({ route_id, result }));
            if (args?.start) return JSON.stringify({ state: 'waiting', trigger: 'user', total: results.length, done: 0, results: [], ...surveyStart });
            return JSON.stringify({ state: 'done', trigger: 'user', total: results.length, done: results.length, results });
        }
        if (cmd === 'open_external_url') {
            opened.push(String(args?.url));
            return null;
        }
        throw new Error(`not mocked: ${cmd}`);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: async () => null }));

const fake = {
    uriImport: async (text: string) => {
        calls.push(`uriImport:${text}`);
        const a = linkAnswer(text);
        if (a.throws) throw a.throws;
        // A tuic link stands for a route checked only when used.
        routes.push({ routeId: `pasted-${nextId++}`, checkedWhenUsed: text.startsWith('tuic://') });
        return { raw: a.raw ?? JSON.stringify({ Kind: 0, Fingerprint: 'self', RouteCount: 1 }) };
    },
    routesStrict: async () => routes.map((r) => ({ ...r })),
    routeDelete: async (id: string) => {
        calls.push(`routeDelete:${id}`);
        routes = routes.filter((r) => r.routeId !== id);
    },
    importSbpBytes: async () => {
        calls.push('importSbpBytes');
        routes.push({ routeId: `file-${nextId++}` });
        return JSON.stringify({ Kind: 0, Fingerprint: 'ab12', RouteCount: 1 });
    },
    subscriptionAdd: async () => {
        calls.push('subscriptionAdd');
        return 'sub';
    },
    resolveTrustPrompt: async (fp: string, d: number) => {
        calls.push(`resolve:${fp}:${d}`);
        return JSON.stringify({ Kind: 0, Fingerprint: fp });
    },
    listPublishers: async () => [],
    previewBundle: async () => ({}),
    importSbp: async () => '',
};
vi.mock('../contract/ContractProvider', () => ({ useContract: () => fake }));

const React = await import('react');
const { default: AddSheet } = await import('./AddSheet');
const { pasteTiming } = await import('./PasteList');
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const d2En = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...d2En };
const t = (k: string) => EN[k] ?? k;

const L1 = 'vless://u@a.example.org:443?security=reality&pbk=k#A';
const L2 = 'trojan://p@b.example.org:443?alpn=h2,http/1.1#B';
const L3 = 'hy2://p@c.example.org:443,8443-8450/?sni=c#C';
const WG = 'wg://k@d.example.org:51820#D';
const TU = 'tuic://u:p@d.example.org:443#D';
const TG = 'tg://proxy?server=p.example.org&port=443&secret=ee00ff';

let rig: Rig;
beforeAll(() => {
    rig = createRig();
    pasteTiming.pollMs = 5;
});
beforeEach(() => {
    calls.length = 0;
    opened.length = 0;
    routes = [{ routeId: 'old-1' }];
    nextId = 0;
    linkAnswer = () => ({});
    surveyResults = {};
    surveyStart = { started: true };
});
afterEach(async () => {
    await rig.unmountAll();
});

const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const rowsOf = (root: FakeNode) => all(root, (n) => n.nodeName === 'LI' && n.getAttribute('data-item') !== null);
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function paste(text: string) {
    const onImported = vi.fn();
    const onClose = vi.fn();
    const m = await rig.mount(<AddSheet t={t} onClose={onClose} onImported={onImported} initialStep="paste" />);
    await rig.type(btn(m.container, 'paste-box'), text);
    return { ...m, onImported, onClose };
}

async function drain(rounds = 30) {
    for (let i = 0; i < rounds; i++) {
        await React.act(async () => {
            await wait(6);
        });
    }
}

describe('one link: no bulk machinery', () => {
    it('keeps the single flow: Add, no list, no switch, no check', async () => {
        const m = await paste(L1);
        expect(btn(m.container, 'add-pasted')).toBeTruthy();
        expect(byAttr(m.container, 'data-testid', 'paste-list')).toBeNull();
        expect(btn(m.container, 'paste-keep-working')).toBeNull();
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(calls.filter((c) => c.startsWith('uriImport'))).toHaveLength(1);
        expect(btn(m.container, 'paste-check')).toBeNull();
        expect(calls.some((c) => c.startsWith('survey'))).toBe(false);
    });

    it('a single refused link gives its plain reason on the paste step', async () => {
        linkAnswer = () => ({ throws: 'engine call returned -1: vless: uri: plaintext_refused' });
        const m = await paste('vless://u@a.example.org:443?security=none');
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(m.container.textContent).toContain(t('add.multi.refused.plaintext_refused'));
        expect(m.container.textContent).not.toContain('plaintext_refused');
    });

    it('the first pasted link ever answers this phone\'s own trust prompt, then says the link was added', async () => {
        linkAnswer = () => ({ raw: JSON.stringify({ Kind: 1, Fingerprint: 'self' }) });
        const m = await paste(L1);
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(calls).toContain('resolve:self:0');
        expect(m.container.textContent).toContain(t('add.multi.link_added'));
        expect(m.container.textContent).not.toContain(t('add.done'));
    });

    it('a rejected verdict is a refusal on the paste step, never "added"', async () => {
        linkAnswer = () => ({ raw: JSON.stringify({ Kind: 3, Fingerprint: 'self', Reason: 'ErrRevokedPublisher' }) });
        const m = await paste(L1);
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(m.container.textContent).not.toContain(t('add.multi.link_added'));
        expect(btn(m.container, 'paste-box')).toBeTruthy();
        expect(m.onImported).not.toHaveBeenCalled();
    });

    it('a single WireGuard link: no tick, no Add, the plain line at once', async () => {
        const m = await paste(WG);
        expect(btn(m.container, 'add-pasted')).toBeNull();
        expect(byAttr(m.container, 'data-testid', 'paste-cannot-add')?.textContent).toBe(t('add.multi.refused.no_match'));
        expect(m.container.textContent).not.toContain(t('add.detect.uri'));
    });

    it('a quoted link is still one link', async () => {
        const m = await paste(`«${L1}»`);
        await rig.click(btn(m.container, 'add-pasted'));
        await rig.settle(8);
        expect(calls).toContain(`uriImport:${L1}`);
    });

    it('a single Telegram proxy is handed to Telegram, never added', async () => {
        const m = await paste(TG);
        expect(btn(m.container, 'add-pasted')).toBeNull();
        expect(m.container.textContent).toContain(t('add.multi.telegram.note'));
        await rig.click(btn(m.container, 'paste-open-telegram'));
        expect(opened).toEqual(['https://t.me/proxy?server=p.example.org&port=443&secret=ee00ff']);
        expect(calls.some((c) => c.startsWith('uriImport'))).toBe(false);
    });
});

describe('several items', () => {
    it('one row per item with a plain label; not understood is one muted line', async () => {
        const m = await paste(`Fresh servers:\n${L1}\n${L2}\n${TG}\nhttps://signal.tube/#s.example.org\nhttps://sub.example.org/x`);
        const rows = rowsOf(m.container);
        expect(rows.map((r) => r.getAttribute('data-item'))).toEqual(['unknown', 'route', 'route', 'messenger', 'messenger', 'web']);
        const text = m.container.textContent ?? '';
        expect(text).toContain('Connection link · VLESS');
        expect(text).toContain('Connection link · Trojan');
        expect(text).toContain(t('add.multi.kind.unknown'));
        expect(text).toContain(t('add.multi.signal.open'));
        // The credential of a link is never shown.
        expect(text).not.toContain('u@a.example.org');
        // Only links and files are in "Add all"; the web address waits.
        expect(btn(m.container, 'paste-add-all')?.textContent).toContain('Add all (2)');
    });

    it('adds each link once, a result per item, a refused one with its reason, the rest still added', async () => {
        linkAnswer = (s) => (s === L2 ? { throws: 'trojan: type=grpc: uri: transport_unsupported' } : {});
        const m = await paste(`${L1}\n${L2}\n${L3}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(calls.filter((c) => c.startsWith('uriImport'))).toEqual([`uriImport:${L1}`, `uriImport:${L2}`, `uriImport:${L3}`]);
        const text = m.container.textContent ?? '';
        expect(text).toContain(t('add.multi.refused.transport_unsupported'));
        expect(text.split(t('add.multi.state.added')).length - 1).toBe(2);
        expect(m.onImported).toHaveBeenCalled();
        expect(calls).not.toContain('subscriptionAdd');
    });

    it('an unknown refusal code gets the generic line', async () => {
        linkAnswer = (s) => (s === L1 ? { throws: 'uri: brand_new_code' } : {});
        const m = await paste(`${L1}\n${L2}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(m.container.textContent).toContain(t('add.multi.refused.other'));
    });

    it('the first pasted link ever answers this phone\'s own trust question', async () => {
        linkAnswer = () => ({ raw: JSON.stringify({ Kind: 1, Fingerprint: 'self' }) });
        const m = await paste(`${L1}\n${L2}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(calls.filter((c) => c === 'resolve:self:0')).toHaveLength(2);
        expect(m.container.textContent).toContain(t('add.multi.state.added'));
    });

    it('a web address is added only by its own Add', async () => {
        const m = await paste(`${L1}\n${L2}\nhttps://sub.example.org/x`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(calls).not.toContain('subscriptionAdd');
        await rig.click(btn(m.container, 'paste-add-web'));
        await drain(4);
        expect(calls.filter((c) => c === 'subscriptionAdd')).toHaveLength(1);
    });

    it('a Daal file among links goes through the file check', async () => {
        const bundle = 'UEsDBBQAAAAIAA' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);
        const m = await paste(`${bundle}\n${L1}`);
        // Not on its own: it does not go on by itself.
        await React.act(async () => {
            await wait(500);
        });
        expect(calls).not.toContain('importSbpBytes');
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(calls).toContain('importSbpBytes');
        // One link and a file: no bulk check.
        expect(btn(m.container, 'paste-check')).toBeNull();
    });
});

describe('bulk: check, then remove only what failed', () => {
    it('"Check them now" runs the survey; only the routes that were checked and failed are removed', async () => {
        const m = await paste(`${L1}\n${L2}\n${L3}\n${TU}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        // pasted-0 works, pasted-1 failed, pasted-2 was never checked,
        // pasted-3 (tuic here) is checked only when used. An old route
        // that failed is not this paste's.
        surveyResults = { 'pasted-0': 'carried', 'pasted-1': 'not_carrying', 'pasted-3': 'when_used', 'old-1': 'not_carrying' };
        expect(btn(m.container, 'paste-remove-failed')).toBeNull();
        await rig.click(btn(m.container, 'paste-check'));
        await drain();
        expect(calls).toContain('survey:true');
        const text = m.container.textContent ?? '';
        expect(text).toContain(t('add.multi.state.works'));
        expect(text).toContain(t('add.multi.state.failed'));
        expect(text).toContain(t('add.multi.state.when_used'));
        const remove = btn(m.container, 'paste-remove-failed');
        expect(remove?.textContent).toContain('Remove the one that did not answer');
        await rig.click(remove);
        await drain(6);
        expect(calls.filter((c) => c.startsWith('routeDelete'))).toEqual(['routeDelete:pasted-1']);
        expect(routes.map((r) => r.routeId)).toEqual(['old-1', 'pasted-0', 'pasted-2', 'pasted-3']);
    });

    it('a failed result for a route checked only when used is never removed', async () => {
        const m = await paste(`${L1}\n${TU}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        surveyResults = { 'pasted-0': 'carried', 'pasted-1': 'not_carrying' };
        await rig.click(btn(m.container, 'paste-check'));
        await drain();
        expect(btn(m.container, 'paste-remove-failed')).toBeNull();
        expect(m.container.textContent).toContain(t('add.multi.none_failed'));
    });

    it('"Keep only the ones that work" adds, checks and removes in one go', async () => {
        surveyResults = { 'pasted-0': 'not_carrying', 'pasted-1': 'carried', 'pasted-2': 'skipped' };
        const m = await paste(`${L1}\n${L2}\n${L3}`);
        await rig.click(btn(m.container, 'paste-keep-working'));
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain(40);
        expect(calls).toContain('survey:true');
        expect(calls.filter((c) => c.startsWith('routeDelete'))).toEqual(['routeDelete:pasted-0']);
        expect(m.container.textContent).toContain('Removed the one that did not answer.');
    });

    it('removes nothing when no route carried: the network itself may be down', async () => {
        surveyResults = { 'pasted-0': 'not_carrying', 'pasted-1': 'not_carrying', 'pasted-2': 'not_carrying' };
        const m = await paste(`${L1}\n${L2}\n${L3}`);
        await rig.click(btn(m.container, 'paste-keep-working'));
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain(40);
        expect(calls).toContain('survey:true');
        expect(calls.some((c) => c.startsWith('routeDelete'))).toBe(false);
        expect(byAttr(m.container, 'data-testid', 'paste-none-answered')?.textContent).toBe(t('add.multi.none_answered'));
        // No removal offer either; checking again is.
        expect(btn(m.container, 'paste-remove-failed')).toBeNull();
        expect(btn(m.container, 'paste-check')).toBeTruthy();
        expect(routes.map((r) => r.routeId)).toEqual(['old-1', 'pasted-0', 'pasted-1', 'pasted-2']);
    });

    it('says how many could not be checked, and never "every one answered" when none was', async () => {
        surveyResults = { 'pasted-0': 'carried', 'pasted-1': 'skipped' };
        const m = await paste(`${L1}\n${L2}\n${L3}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        await rig.click(btn(m.container, 'paste-check'));
        await drain();
        expect(byAttr(m.container, 'data-testid', 'paste-check-result')?.textContent).toBe(t('add.multi.none_failed'));
        expect(byAttr(m.container, 'data-testid', 'paste-unchecked')?.textContent).toBe('2 could not be checked now and stay. Check again later.');
        await rig.unmountAll();

        surveyResults = { 'old-1': 'carried' };
        const n = await paste(`${L1}\n${L2}`);
        await rig.click(btn(n.container, 'paste-add-all'));
        await drain();
        await rig.click(btn(n.container, 'paste-check'));
        await drain();
        expect(byAttr(n.container, 'data-testid', 'paste-check-result')?.textContent).toBe(t('home.survey.failed'));
        expect(n.container.textContent).not.toContain(t('add.multi.none_failed'));
    });

    it('a WireGuard link is named but not added: the engine cannot import it yet', async () => {
        const m = await paste(`${L1}\n${L2}\n${WG}`);
        expect(btn(m.container, 'paste-add-all')?.textContent).toContain('Add all (2)');
        expect(byAttr(m.container, 'data-testid', 'paste-cannot-add')?.textContent).toBe(t('add.multi.refused.no_match'));
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        expect(calls.filter((c) => c.startsWith('uriImport'))).toEqual([`uriImport:${L1}`, `uriImport:${L2}`]);
    });

    it('the paste box is read-only while the list adds and after', async () => {
        const m = await paste(`${L1}\n${L2}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        const box = btn(m.container, 'paste-box');
        expect(box?.getAttribute('readonly') ?? box?.getAttribute('readOnly')).not.toBeNull();
        expect(btn(m.container, 'paste-again')?.getAttribute('disabled')).not.toBeNull();
    });

    it('a check the engine will not start says why and removes nothing', async () => {
        surveyStart = { started: false, refused: 'busy' };
        const m = await paste(`${L1}\n${L2}`);
        await rig.click(btn(m.container, 'paste-add-all'));
        await drain();
        await rig.click(btn(m.container, 'paste-check'));
        await drain();
        expect(m.container.textContent).toContain(t('home.survey.busy'));
        expect(calls.some((c) => c.startsWith('routeDelete'))).toBe(false);
    });
});
