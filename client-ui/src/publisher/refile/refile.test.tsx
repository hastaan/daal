// "New files for everyone" (wave 2, owner-approved leftover 3): when it
// is offered, the question, the one relay call, and the list the
// publisher works through one person at a time: with one person and
// with ten.
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../../test/miniDom';
import type { FakeNode } from '../../test/miniDom';
import { createRig, type Rig } from '../../test/rig';
import type { ArtifactInfo, RecipientSummary, RefileItem, RefileReport } from '../wizardCommands';

const calls: Array<{ cmd: string; args: Record<string, unknown> | undefined }> = [];
let refileAnswer: RefileReport | Error = { operator_id: 1, items: [], removal_failed: [], all_done: true, code_wrapped: true };
let repackPath = '/stage/1.r3.sbpx';
let removalsAnswer: RefileReport = { operator_id: 1, items: [], removal_failed: [], all_done: true, code_wrapped: false };

vi.mock('@tauri-apps/api/core', () => ({
    invoke: async (cmd: string, args?: Record<string, unknown>) => {
        calls.push({ cmd, args });
        if (cmd === 'wizard_refile_people') {
            if (refileAnswer instanceof Error) throw refileAnswer;
            return refileAnswer;
        }
        if (cmd === 'wizard_refile_removals') return removalsAnswer;
        if (cmd === 'share_invite_sbpx') return null;
        if (cmd === 'wizard_recipient_repack_sbpx') return { id: args?.recipientId, sbpx_path: repackPath };
        throw new Error(`not mocked: ${cmd}`);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

const en = (await import('../../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const fa = (await import('../../i18n/d2/d2-extra.fa.json')).default as Record<string, string>;
const legacyEn = (await import('../../i18n/en.json')).default as Record<string, string>;
const EN = { ...legacyEn, ...en };
const t = (k: string) => EN[k] ?? k;
const { DensityProvider } = await import('../../design/DensityProvider');
const { RefileSheet } = await import('./RefileSheet');
const { RefileOffer } = await import('./RefileOffer');
const { PeopleSection, joinPeople } = await import('../PeopleSection');
const { allHandled, hasStandby, refileAvailable, refileNudge, refileRows, itemLabel } = await import('./refile');

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
beforeEach(() => {
    calls.length = 0;
});
afterEach(async () => {
    await rig.unmountAll();
});

const btn = (root: FakeNode, id: string) => byAttr(root, 'data-button', id);
const btns = (root: FakeNode, id: string) => all(root, (n) => n.getAttribute('data-button') === id);
const stageOf = (root: FakeNode) => byAttr(root, 'data-testid', 'refile')?.getAttribute('data-refile-stage');

function item(id: number, over: Partial<RefileItem> = {}): RefileItem {
    return {
        recipient_id: id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        status: 'done',
        reason: '',
        sbpx_path: `/stage/1.r${id}.sbpx`,
        detail: '',
        ...over,
    };
}
function report(items: RefileItem[], over: Partial<RefileReport> = {}): RefileReport {
    return {
        operator_id: 1,
        items,
        removal_failed: [],
        all_done: items.every((i) => i.status === 'done'),
        code_wrapped: items.every((i) => i.status === 'done'),
        ...over,
    };
}

async function drain() {
    for (let i = 0; i < 8; i++) await rig.settle(2);
}

describe('when it is offered', () => {
    const standby = [{ kind: 'standby', state: 'ready' }] as never;
    it('needs a standby code to protect, no file for everyone, and someone left', () => {
        expect(hasStandby(standby)).toBe(true);
        expect(hasStandby([{ kind: 'standby', state: 'failed' }] as never)).toBe(false);
        expect(hasStandby(null)).toBe(false);
        expect(refileAvailable({ standby: true, everyone: false, current: 1 })).toBe(true);
        expect(refileAvailable({ standby: true, everyone: false, current: 10 })).toBe(true);
        expect(refileAvailable({ standby: false, everyone: false, current: 3 })).toBe(false);
        expect(refileAvailable({ standby: true, everyone: true, current: 3 })).toBe(false);
        expect(refileAvailable({ standby: true, everyone: false, current: 0 })).toBe(false);
    });

    it('the card after a removal shows only while the code is plain', () => {
        const f = { standby: true, everyone: false, current: 2 };
        expect(refileNudge(f, 'plain')).toBe(true);
        expect(refileNudge(f, undefined)).toBe(true);
        expect(refileNudge(f, 'wrapped')).toBe(false);
        expect(refileNudge({ ...f, everyone: true }, 'plain')).toBe(false);
    });

    it('the card is calm: one line of why and a way out', async () => {
        const onOpen = vi.fn();
        const onDismiss = vi.fn();
        const m = await rig.mount(<RefileOffer t={t} onOpen={onOpen} onDismiss={onDismiss} />);
        expect(m.container.textContent).toContain('So the standby code stays useless to anyone else.');
        await rig.click(btn(m.container, 'refile-later'));
        expect(onDismiss).toHaveBeenCalledOnce();
        await rig.click(btn(m.container, 'refile-open'));
        expect(onOpen).toHaveBeenCalledOnce();
    });
});

describe('the rows', () => {
    it('ready, failed with a reason, waiting for an answer', () => {
        const rows = refileRows(
            report([
                item(2),
                item(3, { status: 'failed', reason: 'relay_full', sbpx_path: '' }),
                item(4, { status: 'needs_answer', reason: 'restore_unanswered', sbpx_path: '' }),
                item(5, { status: 'failed', reason: 'something_new', sbpx_path: '' }),
            ]),
        );
        expect(rows.map((r) => r.state)).toEqual(['ready', 'failed', 'waiting', 'failed']);
        expect(rows[1].reasonKey).toBe('pub.renew.reason.relay_full');
        expect(rows[2].reasonKey).toBe('pub.renew.reason.needs_answer');
        expect(rows[3].reasonKey).toBe('pub.renew.reason.other');
        expect(itemLabel({ display_name: '', name: 'r9', recipient_id: 9 })).toBe('r9');
    });

    it('everyone handled means every ready row was sent', () => {
        const rows = refileRows(report([item(2), item(3)]));
        expect(allHandled(rows, new Set([2]))).toBe(false);
        expect(allHandled(rows, new Set([2, 3]))).toBe(true);
        expect(allHandled([], new Set())).toBe(false);
    });
});

async function mountSheet(people: string[]) {
    const onChanged = vi.fn();
    const m = await rig.mount(
        <DensityProvider>
            <RefileSheet t={t} operatorId={1} relayName="Pars" people={people} onClose={vi.fn()} onChanged={onChanged} />
        </DensityProvider>,
    );
    return { m, onChanged };
}

describe('the sheet', () => {
    it('closed half way and opened again: the list and its ticks, and Done says who is left', async () => {
        refileAnswer = report([item(2), item(3)]);
        let kept: import('./RefileSheet').RefileKept | null = null;
        const mountKept = () =>
            rig.mount(
                <DensityProvider>
                    <RefileSheet
                        t={t}
                        operatorId={1}
                        relayName="Pars"
                        people={['Person 2', 'Person 3']}
                        kept={kept}
                        onKeep={(k) => (kept = k)}
                        onClose={vi.fn()}
                    />
                </DensityProvider>,
            );
        const m = await mountKept();
        await rig.click(btn(m.container, 'refile-go'));
        await drain();
        await rig.click(btns(m.container, 'refile-share')[0]);
        await drain();
        await m.unmount();
        const made = calls.filter((c) => c.cmd === 'wizard_refile_people').length;

        const again = await mountKept();
        expect(stageOf(again.container)).toBe('list');
        expect(all(again.container, (n) => n.getAttribute('data-testid') === 'refile-tick')).toHaveLength(1);
        expect(calls.filter((c) => c.cmd === 'wizard_refile_people')).toHaveLength(made);
        // Done with one unsent: one line, the sheet stays.
        await rig.click(btn(again.container, 'refile-done'));
        expect(byAttr(again.container, 'data-testid', 'refile-unsent')?.textContent).toBe(
            en['pub.refile.unsent'].replace('{n}', '1'),
        );
        expect(stageOf(again.container)).toBe('list');
        // Making them again sits behind the same question.
        await rig.click(btn(again.container, 'refile-again'));
        expect(stageOf(again.container)).toBe('ask');
    });

    it('from an update switch, the reason is the new way to get updates', async () => {
        const m = await rig.mount(
            <DensityProvider>
                <RefileSheet t={t} operatorId={1} relayName="Pars" people={['Person 2']} reason="updates" onClose={vi.fn()} />
            </DensityProvider>,
        );
        expect(m.container.textContent).toContain(en['pub.refile.why.updates']);
        expect(m.container.textContent).not.toContain(en['pub.refile.why']);
        expect(m.container.textContent).toContain(en['pub.refile.old_stop']);
    });

    it('asks first, with why and the cost, and touches the relay only on "Make new files"', async () => {
        const { m } = await mountSheet(['Person 2']);
        expect(stageOf(m.container)).toBe('ask');
        const text = m.container.textContent ?? '';
        expect(text).toContain(en['pub.refile.why']);
        expect(text).toContain(en['pub.refile.old_stop']);
        expect(byAttr(m.container, 'data-testid', 'refile-count')?.textContent).toBe('For one person');
        expect(calls.filter((c) => c.cmd === 'wizard_refile_people')).toHaveLength(0);
        // No jargon in what the publisher reads.
        expect(text).not.toMatch(/generation|wrap|secret|re-key/i);
    });

    it('one person: made, shared, ticked, and the closing line says it is done', async () => {
        refileAnswer = report([item(2)]);
        const { m, onChanged } = await mountSheet(['Person 2']);
        await rig.click(btn(m.container, 'refile-go'));
        await drain();
        expect(calls.find((c) => c.cmd === 'wizard_refile_people')?.args).toEqual({ operatorId: 1 });
        expect(onChanged).toHaveBeenCalled();
        expect(stageOf(m.container)).toBe('list');
        expect(m.container.textContent).toContain(en['pub.refile.send_line']);
        expect(btns(m.container, 'refile-qr')).toHaveLength(1);
        expect(byAttr(m.container, 'data-testid', 'refile-tick')).toBeNull();
        await rig.click(btn(m.container, 'refile-share'));
        await drain();
        expect(calls.find((c) => c.cmd === 'share_invite_sbpx')?.args).toMatchObject({ sbpxPath: '/stage/1.r2.sbpx' });
        expect(byAttr(m.container, 'data-testid', 'refile-tick')).not.toBeNull();
        expect(m.container.textContent).toContain(en['pub.refile.all_sent']);
    });

    it('ten people: ten rows, each sent on its own; the line waits for the last', async () => {
        const ids = Array.from({ length: 10 }, (_, i) => i + 2);
        refileAnswer = report(ids.map((id) => item(id)));
        const { m } = await mountSheet(ids.map((id) => `Person ${id}`));
        expect(byAttr(m.container, 'data-testid', 'refile-count')?.textContent).toBe('For 10 people');
        await rig.click(btn(m.container, 'refile-go'));
        await drain();
        expect(all(m.container, (n) => n.getAttribute('data-refile-person') !== null)).toHaveLength(10);
        for (let i = 0; i < 10; i++) {
            expect(m.container.textContent).not.toContain(en['pub.refile.all_sent']);
            await rig.click(btns(m.container, 'refile-share')[i]);
            await drain();
        }
        expect(all(m.container, (n) => n.getAttribute('data-testid') === 'refile-tick')).toHaveLength(10);
        expect(m.container.textContent).toContain(en['pub.refile.all_sent']);
    });

    it('a person whose file could not be made gets the reason and "Try again" for just theirs', async () => {
        refileAnswer = report([item(2), item(3, { status: 'failed', reason: 'relay_full', sbpx_path: '' })]);
        const { m } = await mountSheet(['Person 2', 'Person 3']);
        await rig.click(btn(m.container, 'refile-go'));
        await drain();
        const failed = byAttr(m.container, 'data-refile-person', 'Person 3');
        expect(failed?.getAttribute('data-refile-state')).toBe('failed');
        expect(failed?.textContent).toContain(en['pub.refile.not_made']);
        expect(failed?.textContent).toContain(en['pub.renew.reason.relay_full']);
        expect(btns(m.container, 'refile-share')).toHaveLength(1);
        repackPath = '/stage/1.r3.sbpx';
        await rig.click(btn(m.container, 'refile-retry'));
        await drain();
        expect(calls.find((c) => c.cmd === 'wizard_recipient_repack_sbpx')?.args).toEqual({ operatorId: 1, recipientId: 3 });
        expect(byAttr(m.container, 'data-refile-person', 'Person 3')?.getAttribute('data-refile-state')).toBe('ready');
        expect(btns(m.container, 'refile-share')).toHaveLength(2);
    });

    it('a removal the relay could not make is said, and the relay failing keeps the question', async () => {
        refileAnswer = report([item(2)], {
            removal_failed: [item(1, { status: 'failed', reason: 'relay_unreachable', sbpx_path: '' })],
            all_done: false,
        });
        const { m } = await mountSheet(['Person 2']);
        await rig.click(btn(m.container, 'refile-go'));
        await drain();
        expect(byAttr(m.container, 'data-testid', 'refile-removal-failed')?.textContent).toBe(
            'Person 1 may still be able to connect: the relay did not confirm the removal.',
        );
        // «Try again» sends only the removals: no question, nobody re-keyed.
        const before = calls.filter((c) => c.cmd === 'wizard_refile_people').length;
        await rig.click(btn(m.container, 'refile-removal-retry'));
        await drain();
        expect(calls.find((c) => c.cmd === 'wizard_refile_removals')?.args).toEqual({ operatorId: 1 });
        expect(calls.filter((c) => c.cmd === 'wizard_refile_people')).toHaveLength(before);
        expect(stageOf(m.container)).toBe('list');
        expect(byAttr(m.container, 'data-testid', 'refile-removal-failed')).toBeNull();
        await m.unmount();

        refileAnswer = new Error('E_RELAY_UNREACHABLE: the relay did not answer, so nothing was changed');
        const again = await mountSheet(['Person 2']);
        await rig.click(btn(again.m.container, 'refile-go'));
        await drain();
        expect(stageOf(again.m.container)).toBe('ask');
        expect(all(again.m.container, (n) => n.getAttribute('role') === 'alert').length).toBeGreaterThan(0);
    });
});

function person(id: number, over: Partial<RecipientSummary> = {}): RecipientSummary {
    return {
        id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        address_str: `daal1qqqqqqqqqqqqqqqqqqqq${id}`,
        provisioned_at_unix: 1_763_500_000,
        revoked_at_unix: 0,
        ...over,
    } as RecipientSummary;
}
function file(id: number): ArtifactInfo {
    return {
        kind: 'sbpx',
        path: `/stage/${id}.sbpx`,
        exists: true,
        size_bytes: 900,
        modified_at_unix: 1_763_500_000,
        recipient_id: id,
        recipient_label: `Person ${id}`,
    };
}

describe("the people section's ⋯", () => {
    const noop = () => {};
    async function mount(onRefile?: () => void, notice?: React.ReactNode) {
        const rs = [person(2), person(1, { revoked_at_unix: 9 })];
        return rig.mount(
            <DensityProvider>
                <PeopleSection
                    t={t}
                    action={{ busy: null, outcome: null }}
                    loading={false}
                    people={joinPeople(rs, [file(2)])}
                    onAdd={noop}
                    onSend={noop}
                    onRemake={noop}
                    onReplace={noop}
                    onRemoveAccess={noop}
                    onRemoveFromList={noop}
                    onRefile={onRefile}
                    notice={notice}
                />
            </DensityProvider>,
        );
    }

    it('holds "New files for everyone" when the page offers it', async () => {
        const onRefile = vi.fn();
        const m = await mount(onRefile);
        await rig.click(btn(m.container, 'people-more'));
        const it = btn(m.container, 'refile');
        expect(it?.textContent).toContain(en['pub.refile.menu']);
        await rig.click(it);
        expect(onRefile).toHaveBeenCalledOnce();
    });

    it('is not there when the page does not offer it, and the card sits under the header', async () => {
        const m = await mount(undefined, <div data-testid="refile-offer">card</div>);
        expect(btn(m.container, 'people-more')).toBeNull();
        expect(byAttr(m.container, 'data-testid', 'refile-offer')).not.toBeNull();
    });
});

describe('the words', () => {
    it('every key is in both languages, with its placeholders', () => {
        const keys = Object.keys(en).filter((k) => k.startsWith('pub.refile.'));
        expect(keys.length).toBeGreaterThan(10);
        for (const k of keys) {
            expect(fa[k], k).toBeTruthy();
            for (const ph of en[k].match(/\{[a-z]+\}/g) ?? []) expect(fa[k], k).toContain(ph);
            expect(fa[k], k).not.toMatch(/بزنید|[يك]/);
        }
        expect(en['pub.refile.why']).toContain('so the standby code stays useless to anyone else');
    });
});
