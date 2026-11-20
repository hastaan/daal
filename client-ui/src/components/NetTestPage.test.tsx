// The network test page (components/NetTestPage.tsx), driven in the
// miniDom fake against a pretend engine: consent → start → running →
// result → send → delete, and the refusals.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import type { NetTestApi } from '../lib/netTestCommands';
import type { NetStatus, NetworkLabel } from '../lib/netTest';

vi.mock('@tauri-apps/api/core', () => ({ invoke: () => Promise.reject('not mocked') }));
const routes = [{ publisherId: 'pars-relays', publisherName: 'Pars Relays' }];
vi.mock('../contract/ContractProvider', () => ({ useContract: () => ({ availableRoutes: async () => routes }) }));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

const React = await import('react');
const { translate } = await import('../lib/i18n');
const { default: NetTestPage } = await import('./NetTestPage');
const t = (k: string) => translate('en', k);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);

const PLAN = { steps: 23, minutes: 4, consentVersion: 1, names: ['www.google.com', 'github.com'], publicResolver: '1.1.1.1' };

/** A pretend engine with a script: what start answers, how many polls
 *  a run takes, what the result is. */
function engine(opts: { refuse?: string; retry?: number; offered?: boolean; sealRefuse?: string; stuck?: boolean } = {}) {
    let s: NetStatus = { kind: 'idle', plan: PLAN, offered: opts.offered ?? true, publisherId: 'pars-relays' };
    const hold = { stuck: opts.stuck === true };
    const calls: string[] = [];
    const started: { label: NetworkLabel; consent: number }[] = [];
    const api: NetTestApi = {
        status: async () => {
            calls.push('status');
            if (s.kind === 'running') {
                // `stuck`: a run that stays running until cancelled, so a
                // slow machine cannot finish it before the test acts.
                if (hold.stuck) return s;
                const next = s.step + 10;
                const now = s;
                s =
                    next > s.of
                        ? {
                              kind: 'result',
                              complete: true,
                              abortReason: '',
                              summary: ['netTest.summary.relayConnects', 'netTest.summary.privacy'],
                              netKind: 'wifi',
                              offered: true,
                              publisherId: 'pars-relays',
                              plan: PLAN,
                              reportJson: '{\n  "schema_version": 2\n}',
                          }
                        : { kind: 'running', step: next, of: s.of };
                return now;
            }
            return s;
        },
        start: async (label, consent) => {
            calls.push('start');
            started.push({ label, consent });
            if (opts.refuse) return { started: false, refused: opts.refuse, retryAfterMin: opts.retry };
            s = { kind: 'running', step: 1, of: 23 };
            return { started: true };
        },
        cancel: async (reason = '') => {
            calls.push(`cancel:${reason}`);
            s = {
                kind: 'result',
                complete: false,
                abortReason: reason === 'backgrounded' ? 'backgrounded' : 'cancelled',
                summary: ['netTest.summary.incomplete', 'netTest.summary.privacy'],
                netKind: 'wifi',
                offered: true,
                publisherId: 'pars-relays',
                plan: PLAN,
                reportJson: '{\n  "schema_version": 2\n}',
            };
            return true;
        },
        share: async (title) => {
            calls.push(`share:${title}`);
            return opts.sealRefuse ? { sealed: false, refused: opts.sealRefuse } : { sealed: true, fileName: 'net-ab12cd34.dat' };
        },
        discard: async () => {
            calls.push('discard');
            s = { kind: 'idle', plan: PLAN, offered: opts.offered ?? true, publisherId: 'pars-relays' };
            return 1;
        },
    };
    /** Let a `stuck` run go on to its end. */
    const release = () => {
        hold.stuck = false;
    };
    return { api, calls, started, release };
}

async function mount(api: NetTestApi, connState: 'connected' | 'disconnected' = 'disconnected') {
    const m = await rig.mount(
        <NetTestPage t={t} connState={connState} backLabel="Advanced" onBack={() => {}} api={api} pollMs={5} />,
    );
    await rig.settle(6);
    return m;
}

const view = (root: FakeNode) => byAttr(root, 'data-testid', 'nettest-page')?.getAttribute('data-view');

describe('network test page', () => {
    it('consent names what is tested and whose relay, then a run ends in a result that can be sent and deleted', async () => {
        const e = engine({ stuck: true });
        const m = await mount(e.api);
        expect(view(m.container)).toBe('consent');
        const s = m.container.textContent;
        expect(s).toContain('www.google.com');
        expect(s).toContain('1.1.1.1');
        expect(s).toContain('Pars Relays');
        expect(s).toContain(t('netTest.consent.vpnOff'));

        // Which internet: the person's choice goes to start, with the consent version shown.
        const select = btn(m.container, 'nettest-label')!;
        await React.act(async () => {
            select.value = 'mci';
            select.dispatchEvent(new (await import('../test/miniDom')).FakeEvent('change'));
        });
        await rig.click(btn(m.container, 'nettest-start'));
        expect(e.started).toEqual([{ label: 'mci', consent: 1 }]);
        expect(view(m.container)).toBe('running');
        expect(m.container.textContent).toMatch(/Step \d+ of 23/);

        // It polls to the end.
        e.release();
        for (let i = 0; i < 10 && view(m.container) === 'running'; i++) await rig.settle(4);
        expect(view(m.container)).toBe('result');
        expect(m.container.textContent).toContain(t('netTest.summary.relayConnects'));
        // Never an address or a name of a target on the result.
        expect(m.container.textContent).not.toContain('www.google.com');
        expect(m.container.textContent).toContain(t('netTest.send.whenConnected').replace('{name}', 'Pars Relays'));
        // "Show everything": the report as the engine keeps it, folded.
        expect(byAttr(m.container, 'data-testid', 'nettest-report-json')).toBeNull();
        await rig.click(btn(m.container, 'nettest-show-all'));
        expect(byAttr(m.container, 'data-testid', 'nettest-report-json')?.textContent).toContain('"schema_version": 2');

        await rig.click(btn(m.container, 'nettest-send'));
        expect(e.calls).toContain(`share:${t('netTest.send.chooser')}`);
        expect(byAttr(m.container, 'data-testid', 'nettest-ask-delete')).toBeTruthy();
        await rig.click(btn(m.container, 'nettest-delete-after'));
        expect(e.calls).toContain('discard');
        expect(byAttr(m.container, 'data-testid', 'nettest-deleted')).toBeTruthy();
        expect(view(m.container)).toBe('consent');
    });

    it('a refusal is one plain line, with the minutes filled in', async () => {
        const e = engine({ refuse: 'rate_limited', retry: 214 });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        const line = byAttr(m.container, 'data-testid', 'nettest-refused');
        expect(line?.textContent).toBe(t('netTest.refused.rate_limited').replace('{n}', '214'));
        expect(view(m.container)).toBe('consent');
    });

    it('an unknown refusal code is never shown as the code', async () => {
        const e = engine({ refuse: 'something_new' });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        const line = byAttr(m.container, 'data-testid', 'nettest-refused');
        expect(line?.textContent).toBe(t('netTest.refused.other'));
        expect(m.container.textContent).not.toContain('something_new');
    });

    it('while Daal is connected, Start waits and says to disconnect first', async () => {
        const e = engine();
        const m = await mount(e.api, 'connected');
        expect(byAttr(m.container, 'data-testid', 'nettest-connected')?.textContent).toBe(t('netTest.refused.connected'));
        expect(btn(m.container, 'nettest-start')?.getAttribute('disabled')).not.toBeNull();
    });

    it('Cancel stops the run and keeps a result that says so', async () => {
        const e = engine({ stuck: true });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        expect(view(m.container)).toBe('running');
        await rig.click(btn(m.container, 'nettest-cancel'));
        expect(e.calls).toContain('cancel:');
        expect(view(m.container)).toBe('result');
        expect(byAttr(m.container, 'data-testid', 'nettest-abort')?.textContent).toBe(t('netTest.aborted.cancelled'));
        // "Did not finish" is not said twice.
        expect(m.container.textContent).not.toContain(t('netTest.summary.incomplete'));
    });

    it('a seal refusal is one plain line and nothing is asked', async () => {
        const e = engine({ sealRefuse: 'no_result' });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        for (let i = 0; i < 10 && view(m.container) === 'running'; i++) await rig.settle(4);
        await rig.click(btn(m.container, 'nettest-send'));
        expect(byAttr(m.container, 'data-testid', 'nettest-send-problem')?.textContent).toBe(t('netTest.sealRefused.no_result'));
        expect(byAttr(m.container, 'data-testid', 'nettest-ask-delete')).toBeNull();
    });

    it('a run that stopped early offers Run again first; it shows the consent over the kept result', async () => {
        const e = engine({ stuck: true });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        await rig.click(btn(m.container, 'nettest-cancel'));
        expect(view(m.container)).toBe('result');
        const again = btn(m.container, 'nettest-again')!;
        expect(again.getAttribute('data-variant')).toBe('primary');
        expect(btn(m.container, 'nettest-send')?.getAttribute('data-variant')).toBe('secondary');

        await rig.click(again);
        expect(view(m.container)).toBe('consent');
        expect(byAttr(m.container, 'data-testid', 'nettest-replaces')?.textContent).toBe(t('netTest.again.replaces'));
        // Later goes back to the kept result, not away from the page.
        await rig.click(btn(m.container, 'nettest-later'));
        expect(view(m.container)).toBe('result');

        await rig.click(btn(m.container, 'nettest-again'));
        await rig.click(btn(m.container, 'nettest-start'));
        expect(e.started.length).toBe(2);
        expect(view(m.container)).toBe('running');
    });

    it('a finished run offers Run again after Send', async () => {
        const e = engine();
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        for (let i = 0; i < 10 && view(m.container) === 'running'; i++) await rig.settle(4);
        expect(btn(m.container, 'nettest-send')?.getAttribute('data-variant')).toBe('primary');
        expect(btn(m.container, 'nettest-again')?.getAttribute('data-variant')).toBe('secondary');
    });

    it('leaving the app while a test runs stops it', async () => {
        const e = engine({ stuck: true });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        expect(view(m.container)).toBe('running');
        const doc = rig.win.document as unknown as { visibilityState: string; dispatchEvent: (e: unknown) => void };
        const { FakeEvent } = await import('../test/miniDom');
        await React.act(async () => {
            doc.visibilityState = 'hidden';
            doc.dispatchEvent(new FakeEvent('visibilitychange'));
        });
        await rig.settle(4);
        doc.visibilityState = 'visible';
        expect(e.calls).toContain('cancel:backgrounded');
        expect(byAttr(m.container, 'data-testid', 'nettest-abort')?.textContent).toBe(t('netTest.aborted.backgrounded'));
    });

    it('leaving the page while a test runs stops it', async () => {
        const e = engine({ stuck: true });
        const m = await mount(e.api);
        await rig.click(btn(m.container, 'nettest-start'));
        expect(view(m.container)).toBe('running');
        await m.unmount();
        expect(e.calls.filter((c) => c.startsWith('cancel:'))).toEqual(['cancel:']);
    });

    it('leaving the page with no test running cancels nothing', async () => {
        const e = engine();
        const m = await mount(e.api);
        await m.unmount();
        expect(e.calls.some((c) => c.startsWith('cancel:'))).toBe(false);
    });

    it('with no test relay held, the page offers nothing to run', async () => {
        const e = engine({ offered: false });
        const m = await mount(e.api);
        expect(view(m.container)).toBe('unavailable');
        expect(btn(m.container, 'nettest-start')).toBeNull();
    });
});
