// The publisher's half of the network test, through the real command
// wrappers (wizardCommands.ts) against the harness fake
// (harness/netTestFake.ts): "Use as test relay" and opening a report.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import { netTestCommands } from '../harness/netTestFake';
import type { NetTestFake } from '../harness/netTestFake';

let table: Record<string, (a: Record<string, unknown> | undefined) => unknown> = {};
const calls: { cmd: string; args: unknown }[] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        const h = table[cmd];
        return h ? Promise.resolve().then(() => h(args)) : Promise.reject(`not mocked: ${cmd}`);
    },
}));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: async () => null }));

function shell(f: NetTestFake) {
    table = netTestCommands(f, 'pars-relays');
    calls.length = 0;
}

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
});

const { translate } = await import('../lib/i18n');
const { TestRelaySheet } = await import('./TestRelaySheet');
const { ReportViewer } = await import('./ReportViewer');
const t = (k: string) => translate('en', k);
const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const tid = (root: FakeNode, id: string) => byAttr(root, 'data-testid', id);

describe('Use as test relay', () => {
    it('a relay people connect with: the count is shown, a second question, and nobody is cut off', async () => {
        shell({ state: 'none' });
        const m = await rig.mount(<TestRelaySheet t={t} operatorId={1} onClose={() => {}} onOpenReport={() => {}} />);
        const s = m.container.textContent;
        expect(s).toContain(t('pub.testRelay.line'));
        expect(s).toContain(t('pub.testRelay.cost'));
        expect(tid(m.container, 'test-relay-in-use')?.textContent).toBe(
            `${t('pub.testRelay.inUse.people').replace('{n}', '2')} ${t('pub.testRelay.inUse.andEveryone')}`,
        );
        expect(tid(m.container, 'test-relay-sheet')?.getAttribute('data-on')).toBe('0');

        // The first press only asks.
        await rig.click(btn(m.container, 'test-relay-on'));
        expect(calls.some((c) => c.cmd === 'wizard_test_relay_set')).toBe(false);
        expect(tid(m.container, 'test-relay-confirm')?.textContent).toContain(t('pub.testRelay.confirm'));
        await rig.click(btn(m.container, 'test-relay-confirm-cancel'));
        expect(tid(m.container, 'test-relay-confirm')).toBeNull();

        await rig.click(btn(m.container, 'test-relay-on'));
        await rig.click(btn(m.container, 'test-relay-on-anyway'));
        expect(calls.find((c) => c.cmd === 'wizard_test_relay_set')?.args).toEqual({ operatorId: 1, on: true, confirmInUse: true });
        expect(tid(m.container, 'test-relay-sheet')?.getAttribute('data-on')).toBe('1');
        expect(tid(m.container, 'test-relay-done')?.textContent).toContain(
            t('pub.testRelay.done.people').replace('{n}', '2'),
        );
        expect(tid(m.container, 'test-relay-done')?.textContent).toContain(t('pub.testRelay.done.everyoneKept'));
        // Now: open a report, or stop.
        expect(btn(m.container, 'test-relay-open-report')).toBeTruthy();
        await rig.click(btn(m.container, 'test-relay-off'));
        expect(calls.filter((c) => c.cmd === 'wizard_test_relay_set').pop()?.args).toEqual({
            operatorId: 1,
            on: false,
            confirmInUse: false,
        });
        expect(tid(m.container, 'test-relay-done')?.textContent).toContain(t('pub.testRelay.done.off'));
    });

    it('a separate relay nobody uses is switched on with one press', async () => {
        shell({ state: 'none', relayPeople: 0, relayEveryone: false });
        const m = await rig.mount(<TestRelaySheet t={t} operatorId={1} onClose={() => {}} onOpenReport={() => {}} />);
        expect(tid(m.container, 'test-relay-in-use')).toBeNull();
        await rig.click(btn(m.container, 'test-relay-on'));
        expect(calls.find((c) => c.cmd === 'wizard_test_relay_set')?.args).toEqual({ operatorId: 1, on: true, confirmInUse: false });
        expect(tid(m.container, 'test-relay-done')?.textContent).toContain(t('pub.testRelay.done.nobody'));
        expect(tid(m.container, 'test-relay-done')?.textContent).not.toContain(t('pub.testRelay.done.everyoneKept'));
    });

    it('people who came onto the relay meanwhile: the wizard refuses and the sheet asks', async () => {
        shell({ state: 'none', relayPeople: 0, relayEveryone: false });
        const m = await rig.mount(<TestRelaySheet t={t} operatorId={1} onClose={() => {}} onOpenReport={() => {}} />);
        table.wizard_test_relay_set = () => Promise.reject('E_TEST_RELAY_IN_USE: 1 people connect with this relay');
        await rig.click(btn(m.container, 'test-relay-on'));
        expect(tid(m.container, 'test-relay-confirm')).toBeTruthy();
        expect(tid(m.container, 'test-relay-sheet')?.getAttribute('data-on')).toBe('0');
    });

    it('a failure is a plain line with the relay\'s words under Details, and nothing changes', async () => {
        shell({ state: 'none', relayPeople: 0, relayEveryone: false });
        table.wizard_test_relay_set = () => Promise.reject('E_DEPLOY_TOO_OLD: the setup helper bundled with this app cannot make a report key');
        const m = await rig.mount(<TestRelaySheet t={t} operatorId={1} onClose={() => {}} onOpenReport={() => {}} />);
        await rig.click(btn(m.container, 'test-relay-on'));
        expect(m.container.textContent).toContain(t('pub.fail.deploy_too_old'));
        expect(tid(m.container, 'test-relay-sheet')?.getAttribute('data-on')).toBe('0');
    });
});

describe('Open a network test report', () => {
    const pickApi = (copied: string[]) => ({
        pick: async () => '/staging/picked/net-ab12cd34.dat',
        open: (path: string) => import('./wizardCommands').then(({ Wizard }) => Wizard.reportOpen(path)),
        copy: async (s: string) => {
            copied.push(s);
        },
    });

    it('shows each stage in words and copies the report as text', async () => {
        shell({ state: 'none', testRelayOn: true });
        const copied: string[] = [];
        const m = await rig.mount(<ReportViewer t={t} onClose={() => {}} api={pickApi(copied)} />);
        await rig.click(btn(m.container, 'report-pick'));
        expect(calls.find((c) => c.cmd === 'wizard_report_open')?.args).toEqual({ path: '/staging/picked/net-ab12cd34.dat' });
        for (const st of ['A', 'B', 'C']) expect(tid(m.container, `report-stage-${st}`), st).toBeTruthy();
        const s = m.container.textContent;
        expect(s).toContain(t('netTest.label.mci'));
        expect(s).toContain(t('netTest.probe.relay_plain_cover_sni'));
        expect(s).toContain(t('netTest.res.reset_injected_likely'));
        expect(s).toContain(t('netTest.q.reset_looks_injected'));
        await rig.click(btn(m.container, 'report-copy'));
        expect(copied[0]).toContain('[relay_plain_cover_sni=reset_injected_likely/handshake]');
    });

    it('a report this phone has no key for is one plain line', async () => {
        shell({ state: 'none', testRelayOn: true, reportOpen: 'not_ours' });
        const m = await rig.mount(<ReportViewer t={t} onClose={() => {}} api={pickApi([])} />);
        await rig.click(btn(m.container, 'report-pick'));
        expect(tid(m.container, 'report-failure')?.textContent).toBe(t('netTest.open.notOurs'));
        expect(tid(m.container, 'report-head')).toBeNull();
    });
});

describe('the harness fake answers like the engine', () => {
    it('idle → start → running → done → share → discard', async () => {
        shell({ state: 'idle' });
        const status = () => JSON.parse(String(table.field_probe_status(undefined)));
        expect(status()).toMatchObject({ state: 'idle', has_test_relay: true, publisher_id: 'pars-relays' });
        expect(JSON.parse(String(table.field_probe_start(undefined)))).toEqual({ started: true });
        let s = status();
        expect(s.state).toBe('running');
        for (let i = 0; i < 40 && s.state === 'running'; i++) s = status();
        expect(s).toMatchObject({ state: 'done', complete: true });
        expect(JSON.parse(String(table.field_probe_share(undefined)))).toMatchObject({ sealed: true, file_name: 'net-ab12cd34.dat' });
        expect(table.field_probe_discard(undefined)).toBe(1);
        expect(status().state).toBe('idle');
    });

    it('a refusal carries its minutes', () => {
        shell({ state: 'idle', refuse: 'rate_limited' });
        expect(JSON.parse(String(table.field_probe_start(undefined)))).toEqual({
            started: false,
            refused: 'rate_limited',
            retry_after_min: 214,
        });
    });
});
