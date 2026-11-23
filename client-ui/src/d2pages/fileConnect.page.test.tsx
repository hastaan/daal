// "Connect with this file" on the Files tab, the whole page against a
// fake engine (round 3a review):
//
//   * Android shape: the call resolves at once (the VPN service started)
//     and the engine's answer comes in the polled `auto` block. The sheet
//     says "Connecting…" with Cancel meanwhile, and a pass that found
//     nothing says why; it never ends in silence.
//   * the person's pin (a way chosen by hand) is let go only once the
//     file has connected: a failed or refused connect leaves it.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr, type FakeNode } from '../test/miniDom';
import { createRig, type Rig } from '../test/rig';
import type { AutoStatus, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import type { Scenario } from '../harness/scenarios';

vi.mock('@tauri-apps/api/core', () => ({ invoke: () => Promise.reject('not mocked') }));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

let fake: unknown = null;
vi.mock('../contract/ContractProvider', () => ({ useContract: () => fake }));

const en = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const legacyEn = (await import('../i18n/en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...en };
const t = (k: string) => EN[k] ?? k;
const { default: NetworkPage } = await import('./NetworkPage');
const { HarnessContract } = await import('../backends/harness');
const { getPinnedRoute, setPinnedRoute } = await import('../lib/autoConnect');

let rig: Rig;
beforeAll(() => {
    rig = createRig();
    const store = new Map<string, string>();
    const ls = {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, String(v)),
        removeItem: (k: string) => void store.delete(k),
        clear: () => store.clear(),
    };
    (globalThis as unknown as { localStorage: unknown }).localStorage = ls;
    (rig.win as unknown as { localStorage: unknown }).localStorage = ls;
});
beforeEach(() => {
    setPinnedRoute(null);
});
afterEach(async () => {
    await rig.unmountAll();
});

function route(id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow {
    return {
        routeId: id,
        publisherId: 'b7e1',
        publisherName: 'Test',
        routeNickname: id,
        trustClass: 'trusted',
        family: 'vless-reality',
        familyMaturity: 'stable',
        inCooldown: false,
        ...over,
    };
}

const IDLE: AutoStatus = { state: 'idle', mode: false, trying: '', index: 0, total: 0, tried: [], verdict: '', routeId: '' };

const scenario = {
    id: 't',
    title: 't',
    screen: 'network',
    connection: { state: 'disconnected', mode: 'normal', auto: IDLE },
    availableRoutes: [route('r1'), route('r2', { family: 'hysteria2' }), route('o1', { publisherId: 'q', publisherName: 'Other' })],
} as unknown as Scenario;

/** A harness whose connect behaves like Android's, and whose summary
 *  says what the test sets. */
function androidLike(connect: () => Promise<null>) {
    const h = new HarnessContract({ stepMs: 1, scenario });
    let summary: ConnectionSummary = { ...(scenario.connection as ConnectionSummary) };
    const c = h as unknown as Record<string, unknown>;
    c.connectAutoWithin = vi.fn(connect);
    c.connectionSummary = async () => summary;
    c.disconnect = vi.fn(async () => {
        summary = { ...summary, auto: IDLE };
    });
    fake = h;
    return {
        h,
        set(auto: Partial<AutoStatus>) {
            summary = { ...summary, auto: { ...IDLE, ...auto } };
        },
    };
}

async function openFile(name: string): Promise<FakeNode> {
    const m = await rig.mount(<NetworkPage t={t} onNavigate={() => {}} />);
    const row = all(m.container, (n) => n.getAttribute?.('data-button') === 'file-row').find((n) => (n.textContent ?? '').includes(name));
    await rig.click(row);
    return rig.win.document.body;
}

const button = (body: FakeNode) => byAttr(body, 'data-button', 'file-connect');

/** Wait past the page's 2 s poll. */
async function nextPoll() {
    await new Promise((r) => setTimeout(r, 2100));
    await rig.settle();
}

describe('Connect with this file, Android shape', () => {
    it('says Connecting with Cancel while the engine tries, then why nothing connected', async () => {
        const e = androidLike(async () => null);
        const body = await openFile('Test');
        e.set({ state: 'trying', mode: true, trying: 'r1', index: 1, total: 2 });
        await rig.click(button(body));
        expect((e.h as unknown as { connectAutoWithin: ReturnType<typeof vi.fn> }).connectAutoWithin).toHaveBeenCalledWith(['r1', 'r2']);
        // The call is over; the engine is not.
        expect(button(body)?.textContent).toBe(t('conn.cancel_action'));
        expect(body.textContent).toContain(t('conn.headline_connecting'));

        e.set({ state: 'failed', mode: true, verdict: 'all_failed' });
        await nextPoll();
        expect(body.textContent).toContain(t('auto.verdict.all_failed'));
        expect(button(body)?.textContent).toBe(t('network.connect_file'));
    }, 10_000);

    it('Cancel stops the connect, and says nothing more', async () => {
        const e = androidLike(async () => null);
        const body = await openFile('Test');
        e.set({ state: 'trying', mode: true, trying: 'r1', index: 1, total: 2 });
        await rig.click(button(body));
        await rig.click(button(body));
        expect((e.h as unknown as { disconnect: ReturnType<typeof vi.fn> }).disconnect).toHaveBeenCalled();
        expect(button(body)?.textContent).toBe(t('network.connect_file'));
        expect(body.textContent).not.toContain(t('auto.verdict.all_failed'));
    });
});

describe("the person's pin", () => {
    it('stays when the file connect fails', async () => {
        setPinnedRoute('o1');
        androidLike(async () => {
            throw 'VPN permission refused';
        });
        const body = await openFile('Test');
        await rig.click(button(body));
        expect(getPinnedRoute()).toBe('o1');
        expect(body.textContent).toContain(t('network.action_failed'));
    });

    it('stays when the engine found nothing', async () => {
        setPinnedRoute('o1');
        const e = androidLike(async () => null);
        const body = await openFile('Test');
        e.set({ state: 'trying', mode: true, trying: 'r1', index: 1, total: 2 });
        await rig.click(button(body));
        e.set({ state: 'failed', mode: true, verdict: 'all_failed' });
        await nextPoll();
        expect(getPinnedRoute()).toBe('o1');
    }, 10_000);

    it('is let go once the file has connected', async () => {
        setPinnedRoute('o1');
        fake = new HarnessContract({ stepMs: 1, scenario });
        const body = await openFile('Test');
        await rig.click(button(body));
        await rig.settle(10);
        expect(getPinnedRoute()).toBeNull();
    });
});
