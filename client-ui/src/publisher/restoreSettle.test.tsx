// After a restore (PB-1, PB-2) and the screens that show the recovery
// words (PB-20): the pure rules, the visible sentences in English and
// Persian, and the relay page mounted for real against a mocked shell.
import { renderToStaticMarkup as markup } from 'react-dom/server';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { all, byAttr } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import pageSource from './PublisherRecipientsPage.tsx?raw';
import backupSource from './BackupPage.tsx?raw';
import restoreSource from './RestorePage.tsx?raw';
import mainSource from '../main.tsx?raw';

const answer: { fn: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } = {
    fn: () => new Promise(() => {}),
};
const invoked: [string, Record<string, unknown> | undefined][] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => {
        invoked.push([cmd, args]);
        return answer.fn(cmd, args);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

import {
    RelayOnlyRemoveSheet,
    RestoreQuestionCard,
    healthWithoutWaiting,
    relayOnlyRows,
    settleCard,
    withoutRelayOnly,
    settleReport,
    waitingIds,
    waitingLabel,
} from './restoreSettle';
import type { RecipientSummary, RenewReport, RestoreUnsettled } from './wizardCommands';
import { renewFixture, renewResultKey, renewTargets, renewWaiting } from './renew';
import { storedFileName } from './wizardCommands';
import { RenewSheet } from './RenewSheet';
import { healthFixture } from './relayHealth';
import { PeopleSection, personState } from './PeopleSection';
import { failureKey } from './failureText';
import { secureScreenAcquire, secureScreenClearAtStart, secureScreenHolders, setSecureScreenSetterForTests, useSecureScreen } from './useSecureScreen';
import { DensityProvider } from '../design/DensityProvider';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const tEn = (k: string) => EN[k] ?? `MISSING:${k}`;
const tFa = (k: string) => FA[k] ?? `MISSING:${k}`;
const decode = (s: string) => s.replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');
const render = (el: React.ReactElement) => decode(markup(<DensityProvider>{el}</DensityProvider>));
const idle = { busy: null, outcome: null };
const noop = () => {};

function person(id: number, over: Partial<RecipientSummary> = {}): RecipientSummary {
    return {
        id,
        name: `r${id}`,
        display_name: `Person ${id}`,
        address_str: `daal1qq${id}`,
        fingerprint_hex: '',
        provisioned_at_unix: 1_763_500_000,
        revoked_at_unix: 0,
        sbpx_path: '',
        ...over,
    };
}
const SARA: RestoreUnsettled = { people: [{ recipient_id: 2, name: 'Sara' }], checked: true, check_error: null };

const NEW_KEYS = Object.keys(EN).filter(
    (k) =>
        k.startsWith('pub.restore_settle.') ||
        k.startsWith('pub.people.relay_only.') ||
        [
            'pub.people.state.needs_answer',
            'pub.renew.status.needs_answer',
            'pub.renew.reason.needs_answer',
            'pub.renew.waiting_line',
            'pub.renew.result.waiting',
            'pub.health.people_unknown',
            'pub.fail.restore_unanswered',
            'pub.fail.restore_answered',
            'pub.fail.relay_user_in_list',
            'pub.fail.relay_user_invalid',
        ].includes(k),
);

describe('strings', () => {
    it('every new sentence is in English and Persian, translated, with the same placeholders', () => {
        expect(NEW_KEYS.length).toBe(29);
        for (const k of NEW_KEYS) {
            expect(FA[k], k).toBeTruthy();
            expect(FA[k], k).not.toBe(EN[k]);
            const ph = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(',');
            expect(ph(FA[k]), k).toBe(ph(EN[k]));
        }
    });

    it('no new sentence names a protocol, a code or a command line', () => {
        for (const k of NEW_KEYS) {
            for (const s of [EN[k], FA[k]]) {
                expect(s, k).not.toMatch(/E_[A-Z_]{3,}|\bAPI\b|\bSSH\b|\bJSON\b|daal-deploy|users-revoke|--[a-z]|\bmgmt\b/i);
            }
        }
    });

    it('the health line no longer says this phone cannot remove them', () => {
        expect(EN['pub.health.people_unknown']).not.toMatch(/cannot remove/);
        expect(EN['pub.health.people_unknown']).toContain(EN['pub.people.title']);
        expect(FA['pub.health.people_unknown']).toContain(FA['pub.people.title']);
    });

    it('the sentences the owner asked for, word for word', () => {
        expect(EN['pub.restore_settle.why']).toBe(
            'This phone was restored from a backup. Since that backup was made, these people are no longer on the relay. Were they removed, or should they still have access?',
        );
        expect(EN['pub.people.relay_only.row']).toBe(
            'Someone added from your other phone; this phone does not have their name',
        );
        // The result after "keep" names the renew button by its label.
        expect(EN['pub.restore_settle.done.keep']).toContain(EN['pub.renew.action']);
        expect(FA['pub.restore_settle.done.keep']).toContain(FA['pub.renew.action']);
        // ...and says first what is true now: her file does not work
        // until the renew runs and she gets the new one. It never says
        // she "keeps" access she does not have yet.
        expect(EN['pub.restore_settle.done.keep'].startsWith("{name}'s file does not work yet.")).toBe(true);
        expect(FA['pub.restore_settle.done.keep'].startsWith('فایل {name} هنوز کار نمی‌کند.')).toBe(true);
        expect(EN['pub.restore_settle.done.keep']).not.toMatch(/keeps access/);
        expect(FA['pub.restore_settle.done.keep']).not.toContain('نگه می‌دارد');
    });
});

describe('PB-1, the rules', () => {
    it('the card: ask while anyone waits, "could not check" only on a failed check, else nothing', () => {
        expect(settleCard(null)).toBe('hidden');
        expect(settleCard({ people: [], checked: true, check_error: null })).toBe('hidden');
        // Not restored, or settled: nothing to ask.
        expect(settleCard({ people: [], checked: false, check_error: null })).toBe('hidden');
        expect(settleCard({ people: [], checked: false, check_error: 'timeout' })).toBe('could_not_check');
        expect(settleCard(SARA)).toBe('ask');
        // A failed re-check does not drop people already known to wait.
        expect(settleCard({ ...SARA, checked: false, check_error: 'timeout' })).toBe('ask');
    });

    it('asks by the name this phone shows for them', () => {
        expect(waitingLabel(SARA.people[0], [person(2, { display_name: 'Sara joon' })])).toBe('Sara joon');
        expect(waitingLabel(SARA.people[0], [])).toBe('Sara');
        expect(waitingLabel({ recipient_id: 9, name: '' }, [])).toBe('#9');
        expect([...waitingIds(SARA)]).toEqual([2]);
    });

    it('waiting people are a question, not "missing on the relay": the health count and the banner leave them out', () => {
        const h = healthFixture({ people_missing: 3 });
        expect(healthWithoutWaiting(h, 1)!.people_missing).toBe(2);
        expect(healthWithoutWaiting(h, 5)!.people_missing).toBe(0);
        expect(healthWithoutWaiting(h, 0)).toBe(h);
        expect(healthWithoutWaiting(null, 2)).toBeNull();
        expect(healthWithoutWaiting(healthFixture({ people_missing: null }), 2)!.people_missing).toBeNull();
    });

    it('the shell already leaves the people it counts as waiting out of people_missing: never subtracted twice', () => {
        // What relay_health sends: Sara waits, Omid (renewable) is missing.
        const h = healthFixture({ people_missing: 1, people_needing_answer: 1 });
        expect(healthWithoutWaiting(h, 1)).toBe(h);
        expect(healthWithoutWaiting(h, 1)!.people_missing).toBe(1);
        // One more waiting than the shell counted (an older cached check).
        expect(healthWithoutWaiting(h, 2)!.people_missing).toBe(0);
    });

    it('renew names waiting people apart and never plans them', () => {
        const rs = [person(1), person(2), person(3, { revoked_at_unix: 5 })];
        expect(renewTargets(rs, new Set([2])).map((r) => r.id)).toEqual([1]);
        expect(renewWaiting(rs, new Set([2, 3])).map((r) => r.id)).toEqual([2]);
        expect(renewTargets(rs).map((r) => r.id)).toEqual([1, 2]);
    });

    it('a renew result is never "all done" while anyone waits, and a waiting person left out gets a row', () => {
        const report: RenewReport = renewFixture({
            items: [renewFixture().items[0]],
            everyone_file: null,
            all_done: true,
        });
        const shown = settleReport(report, SARA.people, [person(1), person(2, { display_name: 'Sara' })]);
        expect(shown.all_done).toBe(false);
        expect(shown.items.map((i) => [i.recipient_id, i.status])).toEqual([
            [1, 'done'],
            [2, 'needs_answer'],
        ]);
        expect(renewResultKey(shown)).toBe('pub.renew.result.waiting');
        // The shell's own row for them is shown as waiting too, with no file.
        const fromShell = settleReport(
            renewFixture({
                items: [{ ...renewFixture().items[0], recipient_id: 2, status: 'not_attempted', sbpx_path: '/x' }],
                everyone_file: null,
                all_done: true,
            }),
            SARA.people,
            [],
        );
        expect(fromShell.items[0]).toMatchObject({ status: 'needs_answer', sbpx_path: '' });
        expect(fromShell.all_done).toBe(false);
        // Nobody waiting: the report is untouched.
        expect(settleReport(report, [], [])).toBe(report);
        expect(renewResultKey(report)).toBe('pub.renew.result.all_done');
        // A failure is still called a failure.
        expect(renewResultKey(settleReport(renewFixture(), SARA.people, []))).toBe('pub.renew.result.some_failed');
    });

    it("a waiting person's row says so", () => {
        const row = { key: 'p2', label: 'Sara', recipient: person(2), file: null, revoked: false };
        expect(personState(tEn, row, true)).toBe(EN['pub.people.state.needs_answer']);
        expect(personState(tEn, { ...row, revoked: true }, true)).toBe(EN['pub.people.state.removed']);
    });
});

describe('the People list while someone waits', () => {
    it("a waiting person's row offers nothing (the question is above), the others keep their buttons", () => {
        const people = [
            { key: 'p1', label: 'Maman', recipient: person(1), file: null, revoked: false },
            { key: 'p2', label: 'Sara', recipient: person(2), file: null, revoked: false },
        ];
        const html = render(
            <PeopleSection
                t={tEn}
                action={idle}
                loading={false}
                people={people}
                onAdd={noop}
                onSend={noop}
                onSave={noop}
                onRemake={noop}
                onReplace={noop}
                onRemoveAccess={noop}
                onRemoveFromList={noop}
                waiting={new Set([2])}
            />,
        );
        const sara = html.slice(html.indexOf('>Sara<'));
        const maman = html.slice(html.indexOf('>Maman<'), html.indexOf('>Sara<'));
        expect(maman).toContain(`>${EN['pub.people.remove_access']}<`);
        expect(sara).toContain(EN['pub.people.state.needs_answer']);
        expect(sara).not.toContain(`>${EN['pub.people.remove_access']}<`);
        expect(sara).not.toContain(`>${EN['pub.people.remake']}<`);
    });
});

describe('the refusals the shell can send, in plain words', () => {
    it('each new code has its own sentence, never the generic one', () => {
        expect(failureKey('E_RESTORE_UNANSWERED: say first')).toBe('pub.fail.restore_unanswered');
        expect(failureKey('E_RESTORE_NOT_ASKED: x')).toBe('pub.fail.restore_answered');
        expect(failureKey('E_RESTORE_ALREADY_ANSWERED: x')).toBe('pub.fail.restore_answered');
        expect(failureKey('E_RELAY_USER_IN_LIST: x')).toBe('pub.fail.relay_user_in_list');
        expect(failureKey('E_RELAY_USER_INVALID: x')).toBe('pub.fail.relay_user_invalid');
    });

    it("the shell's own waiting row (reason restore_unanswered) is shown as waiting", () => {
        const shell = renewFixture({
            items: [
                {
                    recipient_id: 2,
                    name: 'r2',
                    display_name: 'Sara',
                    status: 'needs_answer',
                    reason: 'restore_unanswered',
                    sbpx_path: '',
                    detail: '',
                },
            ],
            everyone_file: null,
            all_done: false,
        });
        const shown = settleReport(shell, SARA.people, []);
        expect(shown.items).toHaveLength(1);
        expect(shown.items[0].status).toBe('needs_answer');
        expect(renewResultKey(shown)).toBe('pub.renew.result.waiting');
        // Even when the page has not yet heard who waits.
        expect(renewResultKey(shell)).toBe('pub.renew.result.waiting');
    });
});

describe('PB-3, the stored name', () => {
    it('names the file Downloads stored; an older shell that says nothing gets the asked name', () => {
        expect(storedFileName('Maman (1).sbpx', 'Maman.sbpx')).toBe('Maman (1).sbpx');
        expect(storedFileName(null, 'Maman.sbpx')).toBe('Maman.sbpx');
        expect(storedFileName(undefined, 'Maman.sbpx')).toBe('Maman.sbpx');
        expect(storedFileName('  ', 'Maman.sbpx')).toBe('Maman.sbpx');
    });
});

describe('PB-2, the rules', () => {
    it('never offers a relay user who is in this phone\'s list', () => {
        const h = healthFixture({ people_unknown: 2, relay_only: ['r9', 'r1', 'r9', ''] });
        expect(relayOnlyRows(h, [person(1)])).toEqual(['r9']);
        expect(relayOnlyRows(null, [])).toEqual([]);
        // A result that did not read the relay's people lists nobody.
        expect(relayOnlyRows(healthFixture({ relay_only: null }), [])).toEqual([]);
    });

    it('a removed relay user leaves the list and the count at once, nobody else does', () => {
        const h = healthFixture({ people_unknown: 2, relay_only: ['r9', 'r12'] });
        const after = withoutRelayOnly(h, 'r9')!;
        expect(after.relay_only).toEqual(['r12']);
        expect(after.people_unknown).toBe(1);
        expect(withoutRelayOnly(h, 'r4')).toBe(h);
        expect(withoutRelayOnly(null, 'r9')).toBeNull();
    });
});

describe('the sentences on the screen, in both languages', () => {
    it.each([
        ['en', tEn, EN],
        ['fa', tFa, FA],
    ] as const)('%s: the question card names each person with two answers, nothing chosen', (_l, t, cat) => {
        const html = render(
            <RestoreQuestionCard
                t={t}
                unsettled={{ people: [...SARA.people, { recipient_id: 3, name: 'Dayi' }], checked: true, check_error: null }}
                recipients={[person(2, { display_name: 'Sara' }), person(3, { display_name: 'Dayi' })]}
                action={idle}
                onAnswer={noop}
                onCheckAgain={noop}
            />,
        );
        expect(html).not.toContain('MISSING:');
        expect(html).toContain(cat['pub.restore_settle.why']);
        expect(html).toContain('>Sara<');
        expect(html).toContain('>Dayi<');
        expect(html.split(`>${cat['pub.restore_settle.keep']}<`).length - 1).toBe(2);
        expect(html.split(`>${cat['pub.restore_settle.removed']}<`).length - 1).toBe(2);
        // Nothing pre-selected: no pressed, checked or selected state.
        expect(html).not.toMatch(/aria-pressed|aria-checked|checked=|selected=/);
    });

    it.each([
        ['en', tEn, EN],
        ['fa', tFa, FA],
    ] as const)('%s: when the relay could not be asked, it says so and assumes nothing', (_l, t, cat) => {
        const html = render(
            <RestoreQuestionCard
                t={t}
                unsettled={{ people: [], checked: false, check_error: 'mgmt: timeout' }}
                recipients={[]}
                action={idle}
                onAnswer={noop}
                onCheckAgain={noop}
            />,
        );
        expect(html).toContain(cat['pub.restore_settle.could_not_check']);
        expect(html).toContain(`>${cat['pub.restore_settle.check_again']}<`);
        expect(html).not.toContain(cat['pub.restore_settle.keep']);
        // The raw text only under Details.
        expect(html.indexOf('mgmt: timeout')).toBeGreaterThan(html.indexOf('<details>'));
        expect(html.indexOf('<details>')).toBeGreaterThan(0);
    });

    it.each([
        ['en', tEn, EN],
        ['fa', tFa, FA],
    ] as const)('%s: the remove sheet names the relay user and says it cannot be undone here', (_l, t, cat) => {
        const html = render(
            <RelayOnlyRemoveSheet t={t} user="r9" busy={false} error={null} onCancel={noop} onConfirm={noop} />,
        );
        expect(html).toContain(cat['pub.people.relay_only.confirm.title'].replace('{user}', 'r9'));
        expect(html).toContain(cat['pub.people.relay_only.confirm.body'].replace('{user}', 'r9'));
        expect(html).toContain(cat['pub.people.relay_only.confirm.undo']);
    });

    it.each([
        ['en', tEn, EN],
        ['fa', tFa, FA],
    ] as const)('%s: renew names the waiting person as waiting and is not "all done"', (_l, t, cat) => {
        const recipients = [person(1, { display_name: 'Maman' }), person(2, { display_name: 'Sara' })];
        const confirm = render(
            <RenewSheet
                t={t}
                operatorId={1}
                recipients={recipients}
                hasEveryoneFile={false}
                renew={() => new Promise(() => {})}
                send={{ onSend: noop, onSave: noop, onQr: noop, onCopy: noop }}
                onClose={noop}
                waiting={SARA.people}
            />,
        );
        expect(confirm).toContain(cat['pub.renew.confirm.body'].replace('{n}', '1'));
        expect(confirm).toContain(cat['pub.renew.status.needs_answer']);
        expect(confirm).toContain(cat['pub.renew.waiting_line']);
        const result = render(
            <RenewSheet
                t={t}
                operatorId={1}
                recipients={recipients}
                hasEveryoneFile={false}
                renew={() => new Promise(() => {})}
                send={{ onSend: noop, onSave: noop, onQr: noop, onCopy: noop }}
                onClose={noop}
                waiting={SARA.people}
                initialReport={renewFixture({ items: [renewFixture().items[0]], everyone_file: null, all_done: true })}
            />,
        );
        expect(result).toContain(cat['pub.renew.result.waiting']);
        expect(result).not.toContain(cat['pub.renew.result.all_done']);
        expect(result).toContain(cat['pub.renew.reason.needs_answer']);
        // Sara has no file to send: only Maman's row has the send buttons.
        expect(result.split(`>${cat['pub.people.send']}<`).length - 1).toBe(1);
    });
});

// ---- rendered ------------------------------------------------------------

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
const secureCalls: boolean[] = [];
beforeEach(() => {
    secureCalls.length = 0;
    setSecureScreenSetterForTests(async (on) => {
        secureCalls.push(on);
    });
});
afterEach(async () => {
    await rig.unmountAll();
    invoked.length = 0;
    answer.fn = () => new Promise(() => {});
    setSecureScreenSetterForTests(null);
});
const button = (c: FakeNode, name: string) => byAttr(c, 'data-button', name);
const text = (n: FakeNode | null) => n?.textContent ?? '';
const calls = (cmd: string) => invoked.filter((c) => c[0] === cmd).map((c) => c[1]);

const OP = {
    id: 7,
    status: 'provisioned',
    provider: 'hetzner',
    region: 'fsn1',
    server_type: 'cx22',
    publisher_pub_hex: 'aa',
    created_at_unix: 1,
    nickname: 'Bahar',
    public_ip: '203.0.113.7',
    public_ipv6: '',
    server_id: '9',
    helper_ip: '198.51.100.2',
    last_provisioned_at_unix: 1,
    decommissioned_at_unix: 0,
    has_signed_sbp: true,
    signed_sbp_at_unix: 1,
    live_recipient_count: 2,
    total_recipient_count: 2,
    floating_ip_id: '',
    can_reserve_address: true,
    toolbox_profile: 'default',
    served_families: [],
    people_needing_renewal: 0,
};

/** The shell for a relay restored from an older backup: Sara was removed
 *  on the old phone after the backup (the relay lacks her), and r9 was
 *  added there after it (the list lacks them). */
function restoredRelay() {
    const st = {
        unsettled: SARA as RestoreUnsettled,
        relayOnly: ['r9', 'r1'],
        recipients: [person(1, { display_name: 'Maman' }), person(2, { display_name: 'Sara' })],
    };
    answer.fn = (cmd, args) => {
        switch (cmd) {
            case 'wizard_list_operators':
                return Promise.resolve([OP]);
            case 'wizard_recipient_list':
                return Promise.resolve(st.recipients);
            case 'wizard_list_artifacts':
                return Promise.resolve(
                    [1, 2].map((id) => ({
                        kind: 'sbpx',
                        path: `/stage/${id}.sbpx`,
                        exists: true,
                        size_bytes: 900,
                        modified_at_unix: 1,
                        recipient_id: id,
                        recipient_label: '',
                    })),
                );
            case 'publisher_custody_status':
                return Promise.resolve({ level: 'hardware', unlocked: true, ok: true, error: '', legacy_pending: false, legacy_aliases: [], has_existing_blob: true });
            case 'wizard_get_helper_ip':
                return Promise.resolve('198.51.100.2');
            case 'wizard_relay_health':
                // As relay_health answers: Sara, while she waits, is
                // counted as needing an answer and NOT as missing; once
                // kept she is missing (renew brings her back); r9 is
                // unknown.
                return Promise.resolve(
                    healthFixture({
                        operator_id: 7,
                        people_needing_answer: st.unsettled.people.length,
                        people_missing: st.unsettled.people.length > 0 ? 0 : st.recipients.some((r) => r.id === 2 && r.revoked_at_unix === 0) ? 1 : 0,
                        people_unknown: st.relayOnly.filter((u) => u !== 'r1').length,
                        relay_only: st.relayOnly.filter((u) => u !== 'r1'),
                    }),
                );
            case 'wizard_restore_unsettled':
                return Promise.resolve(st.unsettled);
            case 'wizard_restore_answer': {
                st.unsettled = { people: [], checked: true, check_error: null };
                if (args?.keep === false) {
                    st.recipients = st.recipients.map((r) => (r.id === args.recipientId ? { ...r, revoked_at_unix: 9 } : r));
                }
                return Promise.resolve(null);
            }
            case 'wizard_relay_only_revoke':
                st.relayOnly = st.relayOnly.filter((u) => u !== args?.relayUser);
                return Promise.resolve(null);
            default:
                return new Promise(() => {});
        }
    };
    return st;
}

async function mountPage() {
    const { default: Page } = await import('./PublisherRecipientsPage');
    const m = await rig.mount(<Page t={tEn} operatorId={7} onBack={noop} />);
    await rig.settle(8);
    return m;
}

describe('the relay page after a restore, mounted', () => {
    it('PB-1: the first check asks about Sara by name; renew is not invited; "still should have access" is sent and stored', async () => {
        restoredRelay();
        const m = await mountPage();
        const card = byAttr(m.container, 'data-testid', 'restore-question');
        expect(card?.getAttribute('data-state')).toBe('ask');
        expect(text(card)).toContain(EN['pub.restore_settle.why']);
        expect(byAttr(card!, 'data-person', '2') != null).toBe(true);
        expect(text(card)).toContain('Sara');
        expect(text(card)).not.toContain('Maman');
        // Read after the health check, for this relay.
        expect(calls('wizard_restore_unsettled')).toEqual([{ operatorId: 7 }]);
        // The relay-only names came with the health result: opening the
        // page reaches the relay once (the health check, which answers
        // from its cache when it is fresh), never a second time.
        expect(calls('wizard_relay_only_users')).toEqual([]);
        expect(calls('wizard_relay_health').length).toBe(1);
        // Sara is the only one missing and she is a question: no banner
        // inviting the renew that would bring her back.
        expect(byAttr(m.container, 'data-testid', 'renew-banner') == null).toBe(true);
        expect(text(m.container)).toContain(EN['pub.people.state.needs_answer']);

        await rig.click(button(m.container, 'settle-keep-2'));
        await rig.settle(6);
        expect(calls('wizard_restore_answer')).toEqual([{ operatorId: 7, recipientId: 2, keep: true }]);
        expect(byAttr(m.container, 'data-testid', 'restore-question') == null).toBe(true);
        expect(text(m.container)).toContain("Sara's file does not work yet.");
        // Now she is simply missing, and renewing her is what was asked.
        expect(byAttr(m.container, 'data-testid', 'renew-banner') != null).toBe(true);
        expect(calls('wizard_restore_answer').length).toBe(1);
    });

    it('PB-1: "was removed" marks her removed and the relay is checked again', async () => {
        restoredRelay();
        const m = await mountPage();
        const before = calls('wizard_relay_health').length;
        await rig.click(button(m.container, 'settle-removed-2'));
        await rig.settle(8);
        expect(calls('wizard_restore_answer')).toEqual([{ operatorId: 7, recipientId: 2, keep: false }]);
        expect(calls('wizard_relay_health').length).toBeGreaterThan(before);
        expect(text(m.container)).toContain(EN['pub.people.state.removed']);
        expect(byAttr(m.container, 'data-testid', 'renew-banner') == null).toBe(true);
        expect(calls('wizard_renew_everyone')).toEqual([]);
    });

    it('PB-1: a relay that cannot be asked: the card says so, and nobody is offered or created', async () => {
        const st = restoredRelay();
        st.unsettled = { people: [], checked: false, check_error: 'relay did not answer' };
        const m = await mountPage();
        const card = byAttr(m.container, 'data-testid', 'restore-question');
        expect(card?.getAttribute('data-state')).toBe('could_not_check');
        expect(button(m.container, 'settle-keep-2') == null).toBe(true);
        expect(calls('wizard_restore_answer')).toEqual([]);
    });

    it('PB-2: the relay-only person is listed with Remove access; Back cancels; confirming revokes by relay name and checks again', async () => {
        restoredRelay();
        const m = await mountPage();
        const list = byAttr(m.container, 'data-testid', 'relay-only');
        expect(text(list)).toContain(EN['pub.people.relay_only.row']);
        expect(byAttr(list!, 'data-relay-user', 'r9') != null).toBe(true);
        // r1 is Maman, in this phone's list: never offered here.
        expect(byAttr(list!, 'data-relay-user', 'r1') == null).toBe(true);

        await rig.click(button(m.container, 'relay-only-remove-r9'));
        const sheet = byAttr(m.container, 'data-testid', 'relay-only-sheet');
        expect(text(sheet)).toContain(EN['pub.people.relay_only.confirm.body'].replace('{user}', 'r9'));
        expect(text(sheet)).toContain(EN['pub.people.relay_only.confirm.undo']);
        await rig.back();
        expect(byAttr(m.container, 'data-testid', 'relay-only-sheet') == null).toBe(true);
        expect(calls('wizard_relay_only_revoke')).toEqual([]);

        await rig.click(button(m.container, 'relay-only-remove-r9'));
        const before = calls('wizard_relay_health').length;
        await rig.click(button(m.container, 'relay-only-confirm'));
        await rig.settle(8);
        expect(calls('wizard_relay_only_revoke')).toEqual([{ operatorId: 7, relayUser: 'r9' }]);
        expect(byAttr(m.container, 'data-testid', 'relay-only-sheet') == null).toBe(true);
        expect(byAttr(m.container, 'data-testid', 'relay-only') == null).toBe(true);
        expect(text(m.container)).toContain('Access removed for r9.');
        expect(calls('wizard_relay_health').length).toBeGreaterThan(before);
        // The normal per-person remove was not used for it.
        expect(calls('wizard_recipient_revoke')).toEqual([]);
    });

    it('PB-2: once removed, the person leaves People even while the re-check has not answered', async () => {
        restoredRelay();
        const base = answer.fn;
        let revoked = false;
        answer.fn = (cmd, args) => {
            if (cmd === 'wizard_relay_only_revoke') revoked = true;
            // The relay check after the removal never answers.
            if (cmd === 'wizard_relay_health' && revoked) return new Promise(() => {});
            return base(cmd, args);
        };
        const m = await mountPage();
        expect(byAttr(m.container, 'data-relay-user', 'r9') != null).toBe(true);
        await rig.click(button(m.container, 'relay-only-remove-r9'));
        await rig.click(button(m.container, 'relay-only-confirm'));
        await rig.settle(6);
        expect(calls('wizard_relay_only_revoke')).toEqual([{ operatorId: 7, relayUser: 'r9' }]);
        expect(byAttr(m.container, 'data-relay-user', 'r9') == null).toBe(true);
    });

    it('PB-2: a failed removal stays on the sheet and says why', async () => {
        restoredRelay();
        const base = answer.fn;
        answer.fn = (cmd, args) => (cmd === 'wizard_relay_only_revoke' ? Promise.reject('E_RELAY_UNREACHABLE: timeout') : base(cmd, args));
        const m = await mountPage();
        await rig.click(button(m.container, 'relay-only-remove-r9'));
        await rig.click(button(m.container, 'relay-only-confirm'));
        await rig.settle(6);
        const sheet = byAttr(m.container, 'data-testid', 'relay-only-sheet');
        expect(sheet != null).toBe(true);
        expect(all(sheet!, (n) => n.getAttribute?.('role') === 'alert').length).toBe(1);
        expect(byAttr(m.container, 'data-relay-user', 'r9') != null).toBe(true);
    });

    it('PB-3: a saved file is named as Downloads stored it, not as it was asked for', async () => {
        restoredRelay();
        const base = answer.fn;
        answer.fn = (cmd, args) =>
            cmd === 'save_sbpx_to_downloads' ? Promise.resolve('Maman (1).sbpx') : base(cmd, args);
        const m = await mountPage();
        const save = all(m.container, (n) => n.nodeName === 'BUTTON' && n.textContent === EN['pub.people.save'])[0];
        expect(save != null).toBe(true);
        await rig.click(save);
        await rig.settle(4);
        expect(calls('save_sbpx_to_downloads')).toEqual([{ sbpxPath: '/stage/1.sbpx', fileName: 'Maman.sbpx' }]);
        expect(text(m.container)).toContain(EN['pub.fb.save.ok'].replace('{name}', 'Maman (1).sbpx'));
    });

    it('the page source wires both lists through the hook and the renew sheet gets the waiting people', () => {
        expect(pageSource).toContain('useRestoreSettle(operatorId, provisioned, settleTick)');
        expect(pageSource).toContain('waiting={waiting}');
        expect(pageSource).toContain('health={healthShown}');
    });
});

describe('PB-20, the secure screen', () => {
    it('on at mount, off at unmount', async () => {
        function Words() {
            useSecureScreen(true);
            return <div>words</div>;
        }
        const m = await rig.mount(<Words />);
        expect(secureCalls).toEqual([true]);
        await m.unmount();
        expect(secureCalls).toEqual([true, false]);
        expect(secureScreenHolders()).toBe(0);
    });

    it('the page asks for it off when it starts, unless a screen already holds it', async () => {
        const flush = () => new Promise((r) => setTimeout(r, 0));
        secureScreenClearAtStart();
        expect(secureCalls).toEqual([false]);
        const off = secureScreenAcquire();
        secureScreenClearAtStart();
        await flush();
        expect(secureCalls).toEqual([false, true]);
        off();
        await flush();
        expect(secureCalls).toEqual([false, true, false]);
        expect(mainSource).toContain('secureScreenClearAtStart();');
    });

    it('two such screens at once: on once, off only when the last one goes', async () => {
        const off1 = secureScreenAcquire();
        const off2 = secureScreenAcquire();
        off1();
        off1(); // a second release of the same hold counts once
        await Promise.resolve();
        expect(secureCalls).toEqual([true]);
        off2();
        await Promise.resolve();
        expect(secureCalls).toEqual([true, false]);
    });

    it('one call at a time: "off" is not sent before "on" has answered, so the window gets them in order', async () => {
        const flush = () => new Promise((r) => setTimeout(r, 0));
        const pending: (() => void)[] = [];
        setSecureScreenSetterForTests((on) => {
            secureCalls.push(on);
            return new Promise<void>((r) => pending.push(r));
        });
        const off = secureScreenAcquire();
        off();
        await flush();
        // The shell has not answered "on" yet: "off" waits for it.
        expect(secureCalls).toEqual([true]);
        pending.shift()!();
        await flush();
        expect(secureCalls).toEqual([true, false]);
        // A quick on-off while "off" is on its way sends nothing more
        // once it is wanted off again.
        const off2 = secureScreenAcquire();
        off2();
        pending.shift()!();
        await flush();
        expect(secureCalls).toEqual([true, false]);
        expect(pending.length).toBe(0);
    });

    it('an "on" the platform refused is sent again by the next screen, never in a loop', async () => {
        const flush = () => new Promise((r) => setTimeout(r, 0));
        let fail = true;
        setSecureScreenSetterForTests(async (on) => {
            secureCalls.push(on);
            if (fail) throw new Error('not yet');
        });
        const off1 = secureScreenAcquire();
        await flush();
        expect(secureCalls).toEqual([true]);
        fail = false;
        const off2 = secureScreenAcquire();
        await flush();
        expect(secureCalls).toEqual([true, true]);
        off1();
        off2();
        await flush();
        expect(secureCalls).toEqual([true, true, false]);
    });

    it('active turning false clears it', async () => {
        const React = await import('react');
        let flip: (v: boolean) => void = noop;
        function Step() {
            const [on, setOn] = React.useState(true);
            flip = setOn;
            useSecureScreen(on);
            return <div />;
        }
        await rig.mount(<Step />);
        expect(secureCalls).toEqual([true]);
        await React.act(async () => flip(false));
        await rig.settle();
        expect(secureCalls).toEqual([true, false]);
    });

    it('a screen torn down by an error clears it, and a platform call that fails does not break the screen', async () => {
        const React = await import('react');
        setSecureScreenSetterForTests(async (on) => {
            secureCalls.push(on);
            throw new Error('no window');
        });
        class Boundary extends React.Component<{ children: React.ReactNode }, { failed: boolean }> {
            state = { failed: false };
            static getDerivedStateFromError() {
                return { failed: true };
            }
            componentDidCatch() {}
            render() {
                return this.state.failed ? <div data-failed="1" /> : this.props.children;
            }
        }
        let boom: () => void = noop;
        function Words() {
            const [bad, setBad] = React.useState(false);
            boom = () => setBad(true);
            useSecureScreen(true);
            if (bad) throw new Error('render failed');
            return <div data-words="1" />;
        }
        const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
        const m = await rig.mount(
            <Boundary>
                <Words />
            </Boundary>,
        );
        expect(byAttr(m.container, 'data-words', '1') != null).toBe(true);
        expect(secureCalls).toEqual([true]);
        await React.act(async () => boom());
        await rig.settle();
        quiet.mockRestore();
        expect(byAttr(m.container, 'data-failed', '1') != null).toBe(true);
        expect(secureCalls).toEqual([true, false]);
        expect(secureScreenHolders()).toBe(0);
    });

    it('the backup page: on through the words and typing them back (no blink between), off when they are done', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'never' });
        const m = await rig.mount(<BackupPage t={tEn} api={api} onBack={noop} rand={() => 0} />);
        expect(secureCalls).toEqual([]);
        await rig.click(button(m.container, 'create-words'));
        expect(byAttr(m.container, 'data-state', 'words') != null).toBe(true);
        expect(secureCalls).toEqual([true]);
        await rig.click(button(m.container, 'wrote'));
        expect(byAttr(m.container, 'data-state', 'confirm') != null).toBe(true);
        expect(secureCalls).toEqual([true]);
        const field = (i: number) => byAttr(m.container, 'data-word-index', String(i));
        for (const i of [0, 1, 2]) await rig.type(field(i), HARNESS_WORDS[i]);
        await rig.click(button(m.container, 'confirm'));
        expect(byAttr(m.container, 'data-state', 'ready') != null).toBe(true);
        expect(secureCalls).toEqual([true, false]);
    });

    it('the restore page: on while the words are typed, off at the preview', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'empty', file: 'ok' });
        const m = await rig.mount(<RestorePage t={tEn} api={api} pick={async () => '/p'} onBack={noop} onDone={noop} />);
        expect(secureCalls).toEqual([]);
        await rig.click(button(m.container, 'choose'));
        expect(byAttr(m.container, 'data-state', 'words') != null).toBe(true);
        expect(secureCalls).toEqual([true]);
        await rig.type(all(m.container, (n) => n.nodeName === 'TEXTAREA')[0], HARNESS_WORDS.join(' '));
        await rig.click(button(m.container, 'open'));
        expect(byAttr(m.container, 'data-state', 'preview') != null).toBe(true);
        expect(secureCalls).toEqual([true, false]);
    });

    it('the three screens and the check sheet use the hook', () => {
        expect(backupSource.match(/useSecureScreen\(true\)/g)).toHaveLength(3);
        expect(restoreSource).toContain("useSecureScreen(flow.step === 'words')");
    });
});
