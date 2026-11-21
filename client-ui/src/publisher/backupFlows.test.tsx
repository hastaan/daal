// Rendered flows: the backup page, the restore page, and the relay
// list's PA-1 / PA-7 buttons and the QR sheet's PA-4 error, mounted for
// real (react-dom in the miniDom fake) against the harness backup fake
// or a mocked invoke.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { all, byAttr, byText } from '../test/miniDom';
import type { FakeNode } from '../test/miniDom';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';

const answer: { fn: (cmd: string, args?: Record<string, unknown>) => Promise<unknown> } = {
    fn: () => new Promise(() => {}),
};
const invoked: [string, unknown][] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: Record<string, unknown>) => {
        invoked.push([cmd, args]);
        return answer.fn(cmd, args);
    },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));

let rig: Rig;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
    invoked.length = 0;
    answer.fn = () => new Promise(() => {});
});

const en = (await import('../i18n/d2/d2-extra.en.json')).default as Record<string, string>;
const t = (k: string) => en[k] ?? k;
const text = (n: FakeNode) => n.textContent;
const state = (c: FakeNode) => byAttr(c, 'data-state')?.getAttribute('data-state');
const button = (c: FakeNode, name: string) => byAttr(c, 'data-button', name);

describe('the backup page, start to end', () => {
    it('words once, a wrong word caught by position, the same words shown again, then saved', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'never' });
        const wordsNew = vi.spyOn(api, 'wordsNew');
        const make = vi.spyOn(api, 'make');
        let left = 0;
        const m = await rig.mount(<BackupPage t={t} api={api} onBack={() => (left += 1)} rand={() => 0} />);
        expect(state(m.container)).toBe('ready');
        expect(text(m.container)).toContain(t('pub.backup.warning'));
        await rig.click(button(m.container, 'create-words'));
        expect(state(m.container)).toBe('words');
        const shown = all(byAttr(m.container, 'data-testid', 'backup-words')!, (n) => n.nodeName === 'LI').map(text);
        expect(shown.length).toBe(12);
        await rig.click(button(m.container, 'wrote'));
        expect(state(m.container)).toBe('confirm');
        // rand() = 0 asks for words 1, 2 and 3.
        const field = (i: number) => byAttr(m.container, 'data-word-index', String(i));
        await rig.type(field(0), HARNESS_WORDS[0]);
        await rig.type(field(1), 'wrong');
        await rig.type(field(2), HARNESS_WORDS[2]);
        await rig.click(button(m.container, 'confirm'));
        expect(text(m.container)).toContain('That is not word number 2. Look at your paper again.');
        await rig.click(button(m.container, 'show-again'));
        expect(state(m.container)).toBe('words');
        expect(all(byAttr(m.container, 'data-testid', 'backup-words')!, (n) => n.nodeName === 'LI').map(text)).toEqual(shown);
        expect(wordsNew).toHaveBeenCalledTimes(1);
        await rig.click(button(m.container, 'wrote'));
        await rig.type(field(0), HARNESS_WORDS[0]);
        await rig.type(field(1), HARNESS_WORDS[1].toUpperCase());
        await rig.type(field(2), HARNESS_WORDS[2]);
        await rig.click(button(m.container, 'confirm'));
        expect(state(m.container)).toBe('ready');
        expect(text(m.container)).toContain(t('pub.backup.words.saved'));
        // The words are gone from the screen.
        expect(byAttr(m.container, 'data-testid', 'backup-words')).toBeNull();
        await rig.click(button(m.container, 'save-downloads'));
        expect(make).toHaveBeenCalledWith('downloads', undefined, t('pub.backup.share.title'));
        expect(state(m.container)).toBe('done');
        expect(text(m.container)).toContain('Saved as daal-backup-2026-11-19-1030.daalbackup');
        expect(left).toBe(0);
        await rig.back();
        expect(left).toBe(1);
    });

    it('a save that fails says so and changes nothing', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'last' });
        api.make = () => Promise.reject('E_BACKUP_SAVE_FAILED: io error');
        const m = await rig.mount(<BackupPage t={t} api={api} onBack={() => {}} />);
        await rig.click(button(m.container, 'save-share'));
        expect(state(m.container)).toBe('ready');
        const f = byAttr(m.container, 'data-testid', 'backup-failure')!;
        expect(text(f)).toContain('The backup could not be saved. Nothing was changed.');
        // Raw text only inside the Details fold.
        const details = all(f, (n) => n.nodeName === 'DETAILS')[0];
        expect(text(details)).toContain('io error');
    });

    it('Back is refused while the backup is being made', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'last' });
        api.make = () => new Promise(() => {});
        let left = 0;
        const m = await rig.mount(<BackupPage t={t} api={api} onBack={() => (left += 1)} />);
        await rig.click(button(m.container, 'save-downloads'));
        expect(state(m.container)).toBe('making');
        await rig.back();
        expect(left).toBe(0);
        expect(state(m.container)).toBe('making');
    });
});

describe('the restore page, start to end', () => {
    it('an empty phone: choose, wrong words refused, right words, restore, the old-phone notice', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'empty', file: 'ok' });
        const restore = vi.spyOn(api, 'restore');
        let done = 0;
        const m = await rig.mount(
            <RestorePage t={t} api={api} pick={async () => '/staging/picked/x.bin'} onBack={() => {}} onDone={() => (done += 1)} />,
        );
        expect(state(m.container)).toBe('pick');
        await rig.click(button(m.container, 'choose'));
        expect(state(m.container)).toBe('words');
        const area = all(m.container, (n) => n.nodeName === 'TEXTAREA')[0];
        await rig.type(area, 'abandon wrong ' + HARNESS_WORDS.slice(2).join(' '));
        expect(text(m.container)).toContain('12 of 12 words');
        await rig.click(button(m.container, 'open'));
        expect(state(m.container)).toBe('words');
        expect(text(m.container)).toContain(t('pub.backup.err.wrong_words'));
        await rig.type(area, HARNESS_WORDS.map((w, i) => `${i + 1}. ${w}`).join(' '));
        await rig.click(button(m.container, 'open'));
        expect(state(m.container)).toBe('preview');
        expect(byAttr(m.container, 'data-testid', 'restore-replace')).toBeNull();
        await rig.click(button(m.container, 'restore'));
        expect(restore.mock.calls[0][2]).toBeNull();
        expect(state(m.container)).toBe('done');
        expect(text(m.container)).toContain(t('pub.restore.done'));
        expect(byAttr(m.container, 'data-testid', 'restore-notice')).not.toBeNull();
        await rig.click(button(m.container, 'to-relays'));
        expect(done).toBe(1);
    });

    it('a file that is not a backup, a damaged one, a newer one: each its own sentence, back at choosing', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi } = await import('./backupHarness');
        for (const [file, key] of [
            ['not', 'pub.backup.err.not_a_backup'],
            ['damaged', 'pub.backup.err.damaged'],
            ['newer', 'pub.backup.err.newer'],
        ] as const) {
            const api = harnessBackupApi({ file });
            const m = await rig.mount(<RestorePage t={t} api={api} pick={async () => '/p'} onBack={() => {}} onDone={() => {}} />);
            await rig.click(button(m.container, 'choose'));
            expect(state(m.container)).toBe('pick');
            expect(text(m.container)).toContain(t(key));
            await m.unmount();
        }
    });

    it('over existing relays: the button names them and sends the digest', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ file: 'replace' });
        const restore = vi.spyOn(api, 'restore');
        const m = await rig.mount(<RestorePage t={t} api={api} pick={async () => '/p'} onBack={() => {}} onDone={() => {}} />);
        await rig.click(button(m.container, 'choose'));
        await rig.type(all(m.container, (n) => n.nodeName === 'TEXTAREA')[0], HARNESS_WORDS.join(' '));
        await rig.click(button(m.container, 'open'));
        expect(text(byAttr(m.container, 'data-testid', 'restore-replace')!)).toContain(
            'This phone already has relays: Sahand. Restoring replaces them.',
        );
        expect(button(m.container, 'restore')).toBeNull();
        expect(text(button(m.container, 'replace')!)).toBe('Replace Sahand with the backup');
        await rig.click(button(m.container, 'replace'));
        expect(restore.mock.calls[0][2]).toBe('harness-digest');
        expect(state(m.container)).toBe('done');
    });

    it('an unfinished restore offers Try again, which finishes it', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'notice' });
        api.restore = () => Promise.reject('E_RESTORE_UNFINISHED: custody put failed');
        const finish = vi.spyOn(api, 'finishRestore');
        const m = await rig.mount(<RestorePage t={t} api={api} pick={async () => '/p'} onBack={() => {}} onDone={() => {}} />);
        await rig.click(button(m.container, 'choose'));
        await rig.type(all(m.container, (n) => n.nodeName === 'TEXTAREA')[0], HARNESS_WORDS.join(' '));
        await rig.click(button(m.container, 'open'));
        await rig.click(button(m.container, 'restore'));
        expect(text(m.container)).toContain('The restore did not finish.');
        // Only Try again: no live Restore/Replace button next to it.
        expect(state(m.container)).toBe('unfinished');
        expect(button(m.container, 'restore')).toBeNull();
        expect(button(m.container, 'replace')).toBeNull();
        await rig.click(button(m.container, 'finish'));
        expect(finish).toHaveBeenCalledTimes(1);
        expect(state(m.container)).toBe('done');
    });
});

// ---- the relay list -------------------------------------------------

const baseOp = {
    id: 6,
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
    live_recipient_count: 0,
    total_recipient_count: 0,
    floating_ip_id: '',
    can_reserve_address: true,
    toolbox_profile: 'default',
    served_families: [],
    has_cloud_token: true,
};

describe('PA-1 rendered: Try again on a live relay gives back the address only', () => {
    it('calls wizard_release_address for each listed address and never a delete', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const op = { ...baseOp, unreleased_addresses: ['198.51.100.1', '198.51.100.2'] };
        answer.fn = (cmd, args) => {
            if (cmd === 'wizard_list_operators') return Promise.resolve([op]);
            if (cmd === 'wizard_release_address') {
                const a = (args as { address: string }).address;
                return Promise.resolve({ address: a, code: a.endsWith('.1') ? 'released' : 'still_attached', still_billing: [] });
            }
            return new Promise(() => {});
        };
        const m = await rig.mount(
            <RelayListPage t={t} onOpen={() => {}} onNew={() => {}} onResume={() => {}} backup={harnessBackupApi()} />,
        );
        await rig.click(byText(m.container, t('pub.relays.destroy.addr.retry')));
        const cmds = invoked.map((c) => c[0]);
        expect(invoked.filter((c) => c[0] === 'wizard_release_address').map((c) => c[1])).toEqual([
            { operatorId: 6, address: '198.51.100.1' },
            { operatorId: 6, address: '198.51.100.2' },
        ]);
        expect(cmds).not.toContain('wizard_relay_destroy');
        expect(cmds).not.toContain('wizard_setup_remove_server');
        const lines = byAttr(m.container, 'data-testid', 'release-results')!;
        expect(text(lines)).toContain(t('pub.relays.release.released'));
        expect(text(lines)).toContain(t('pub.relays.release.still_attached'));
    });
});

describe('PA-7 rendered: the list delete of a setup on the person\'s own server', () => {
    it('asks keep or delete; Keep never passes "delete my own server" and says the server was left', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const { recoveryFixture } = await import('./setupRecovery');
        const op = { ...baseOp, status: 'pre-provision', has_signed_sbp: false, setup_interrupted: true };
        answer.fn = (cmd) => {
            if (cmd === 'wizard_list_operators') return Promise.resolve([op]);
            if (cmd === 'wizard_setup_recovery')
                return Promise.resolve(recoveryFixture('server_running', { server_origin: 'yours' }));
            if (cmd === 'wizard_relay_destroy')
                return Promise.resolve({ server_deleted: false, ssh_key_deleted: false, firewall_deleted: false, local_removed: true, warnings: [] });
            return new Promise(() => {});
        };
        const m = await rig.mount(
            <RelayListPage t={t} onOpen={() => {}} onNew={() => {}} onResume={() => {}} backup={harnessBackupApi()} />,
        );
        // Behind the unfinished row's ⋯ (no Remove button on the row).
        await rig.click(button(m.container, 'relay-row-more'));
        await rig.click(button(m.container, 'remove'));
        expect(button(m.container, 'keep')).not.toBeNull();
        expect(button(m.container, 'delete')).not.toBeNull();
        await rig.click(button(m.container, 'keep'));
        expect(invoked.filter((c) => c[0] === 'wizard_relay_destroy').map((c) => c[1])).toEqual([
            { operatorId: 6, deleteServer: false, deleteOwnServer: false },
        ]);
        expect(text(m.container)).toContain('Removed from this phone. Your server was left as it is.');
    });

    it('Delete my server passes it, and only then', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const { recoveryFixture } = await import('./setupRecovery');
        const op = { ...baseOp, status: 'pre-provision', has_signed_sbp: false };
        answer.fn = (cmd) => {
            if (cmd === 'wizard_list_operators') return Promise.resolve([op]);
            if (cmd === 'wizard_setup_recovery')
                return Promise.resolve(recoveryFixture('server_running', { server_origin: 'yours' }));
            if (cmd === 'wizard_relay_destroy')
                return Promise.resolve({ server_deleted: true, ssh_key_deleted: true, firewall_deleted: true, local_removed: true, warnings: [] });
            return new Promise(() => {});
        };
        const m = await rig.mount(
            <RelayListPage t={t} onOpen={() => {}} onNew={() => {}} onResume={() => {}} backup={harnessBackupApi()} />,
        );
        // Behind the unfinished row's ⋯ (no Remove button on the row).
        await rig.click(button(m.container, 'relay-row-more'));
        await rig.click(button(m.container, 'remove'));
        await rig.click(button(m.container, 'delete'));
        expect(invoked.filter((c) => c[0] === 'wizard_relay_destroy').map((c) => c[1])).toEqual([
            { operatorId: 6, deleteServer: true, deleteOwnServer: true },
        ]);
        expect(button(m.container, 'done')).not.toBeNull();
    });

    it('a setup still running: the sheet deletes nothing', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const { recoveryFixture } = await import('./setupRecovery');
        const op = { ...baseOp, status: 'pre-provision', has_signed_sbp: false };
        answer.fn = (cmd) => {
            if (cmd === 'wizard_list_operators') return Promise.resolve([op]);
            if (cmd === 'wizard_setup_recovery') return Promise.resolve(recoveryFixture('running'));
            return new Promise(() => {});
        };
        const m = await rig.mount(
            <RelayListPage t={t} onOpen={() => {}} onNew={() => {}} onResume={() => {}} backup={harnessBackupApi()} />,
        );
        // Behind the unfinished row's ⋯ (no Remove button on the row).
        await rig.click(button(m.container, 'relay-row-more'));
        await rig.click(button(m.container, 'remove'));
        expect(byAttr(m.container, 'data-plan', 'wait')).not.toBeNull();
        expect(button(m.container, 'delete')).toBeNull();
        expect(button(m.container, 'keep')).toBeNull();
        expect(invoked.map((c) => c[0])).not.toContain('wizard_relay_destroy');
    });
});

describe('PA-4 rendered: a failing per-person QR', () => {
    it('shows the plain sentence, and the raw text only inside Details', async () => {
        const { QrSendSheet } = await import('./QrSendSheet');
        answer.fn = (cmd) =>
            cmd === 'wizard_qr_render' ? Promise.reject('E_FILE_MISSING: /data/user/0/staging/6.r4.sbpx') : new Promise(() => {});
        const m = await rig.mount(
            <QrSendSheet t={t} operatorId={6} relayName="Bahar" artifact="recipient:4" onClose={() => {}} />,
        );
        const box = byAttr(m.container, 'data-testid', 'qr-error')!;
        expect(box).not.toBeNull();
        expect(text(box)).toContain(t('pub.fail.file_missing'));
        const details = all(box, (n) => n.nodeName === 'DETAILS')[0];
        expect(text(details)).toContain('/data/user/0/staging/6.r4.sbpx');
        // Outside the fold the raw text does not appear.
        const outside = box.childNodes.filter((n) => n.nodeName !== 'DETAILS').map(text).join('');
        expect(outside).not.toContain('/data/user/0');
    });
});

describe('D1 rendered: the relay list card', () => {
    it('a list with relays and no backup says so and opens the backup page', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        answer.fn = (cmd) => (cmd === 'wizard_list_operators' ? Promise.resolve([baseOp]) : new Promise(() => {}));
        let opened = 0;
        let restore = 0;
        const m = await rig.mount(
            <RelayListPage
                t={t}
                onOpen={() => {}}
                onNew={() => {}}
                onResume={() => {}}
                onBackup={() => (opened += 1)}
                onRestore={() => (restore += 1)}
                backup={harnessBackupApi({ status: 'never' })}
            />,
        );
        expect(byAttr(m.container, 'data-card', 'never')).not.toBeNull();
        await rig.click(button(m.container, 'backup'));
        expect(opened).toBe(1);
        // Restore is in the header's ⋯ once relays exist.
        await rig.click(button(m.container, 'relays-more'));
        await rig.click(button(m.container, 'restore-link'));
        expect(restore).toBe(1);
    });

    it('after a restore the list shows the old-phone notice until it is dismissed', async () => {
        const { default: RelayListPage } = await import('./RelayListPage');
        const { harnessBackupApi } = await import('./backupHarness');
        answer.fn = (cmd) => (cmd === 'wizard_list_operators' ? Promise.resolve([baseOp]) : new Promise(() => {}));
        const api = harnessBackupApi({ status: 'notice' });
        const m = await rig.mount(<RelayListPage t={t} onOpen={() => {}} onNew={() => {}} onResume={() => {}} backup={api} />);
        expect(byAttr(m.container, 'data-testid', 'restore-notice')).not.toBeNull();
        await rig.click(button(m.container, 'understand'));
        expect(byAttr(m.container, 'data-testid', 'restore-notice')).toBeNull();
    });
});

describe('repair wave: the backup page and the restore page answer what really happened', () => {
    it('a backup sent to another app is not the last backup until the person says it arrived', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const { backupCard } = await import('./backup');
        const api = harnessBackupApi({ status: 'never' });
        await api.wordsConfirm([0, 1, 2].map((i) => ({ index: i, word: ['legal', 'winner', 'thank'][i] })));
        const confirm = vi.spyOn(api, 'confirmShared');
        const m = await rig.mount(<BackupPage t={t} api={api} onBack={() => {}} />);
        await rig.click(button(m.container, 'save-share'));
        expect(byAttr(m.container, 'data-testid', 'shared-ask')).not.toBeNull();
        expect(text(m.container)).toContain(t('pub.backup.share.ask'));
        // Still "never backed up" while it waits.
        expect(backupCard(await api.status())).toBe('never');
        await rig.click(button(m.container, 'share-no'));
        expect(confirm).toHaveBeenLastCalledWith(false);
        expect(state(m.container)).toBe('ready');
        expect(text(m.container)).toContain(t('pub.backup.share.not'));
        expect(backupCard(await api.status())).toBe('never');
        await rig.click(button(m.container, 'save-share'));
        await rig.click(button(m.container, 'share-yes'));
        expect(confirm).toHaveBeenLastCalledWith(true);
        expect(state(m.container)).toBe('done');
        expect(text(m.container)).toContain(t('pub.backup.done.share.ok'));
        expect(backupCard(await api.status())).toBe('last');
    });

    it('Back steps inside the page: type-back to the words, the words ask before leaving', async () => {
        const { default: BackupPage } = await import('./BackupPage');
        const { harnessBackupApi } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'last' });
        await api.wordsConfirm([0, 1, 2].map((i) => ({ index: i, word: ['legal', 'winner', 'thank'][i] })));
        let left = 0;
        const m = await rig.mount(<BackupPage t={t} api={api} onBack={() => (left += 1)} rand={() => 0} />);
        await rig.click(button(m.container, 'backup-more'));
        await rig.click(button(m.container, 'new-words'));
        await rig.click(byText(m.container, t('pub.backup.words.renew.go')));
        expect(state(m.container)).toBe('words');
        await rig.click(button(m.container, 'wrote'));
        expect(state(m.container)).toBe('confirm');
        await rig.back();
        expect(state(m.container)).toBe('words');
        expect(left).toBe(0);
        await rig.back();
        expect(text(byAttr(m.container, 'data-testid', 'leave-body')!)).toBe(t('pub.backup.leave.body'));
        expect(left).toBe(0);
        // Back on the question = stay.
        await rig.back();
        expect(byAttr(m.container, 'data-testid', 'leave-body')).toBeNull();
        expect(state(m.container)).toBe('words');
        await rig.click(button(m.container, 'page-back'));
        await rig.click(button(m.container, 'leave-go'));
        expect(left).toBe(1);
    });

    it('unconfirmed new words and confirmed new words are each said on the page and the card', async () => {
        const { BackupReady } = await import('./BackupPage');
        const { backupStatusFixture, backupCard, backupCardKey } = await import('./backup');
        const { renderToStaticMarkup } = await import('react-dom/server');
        const base = { words_set: true, last_backup_at_unix: 1_763_460_000 };
        const { DensityProvider } = await import('../design/DensityProvider');
        const pending = renderToStaticMarkup(
            <DensityProvider>
                <BackupReady t={t} status={backupStatusFixture({ ...base, words_pending: true })} busy={false} savedWords={false}
                    onCreateWords={() => {}} onMake={() => {}} />
            </DensityProvider>,
        );
        expect(pending).toContain(t('pub.backup.words.pending'));
        const changed = backupStatusFixture({ ...base, words_changed: true, stale: true });
        const html = renderToStaticMarkup(
            <DensityProvider>
                <BackupReady t={t} status={changed} busy={false} savedWords={false} onCreateWords={() => {}} onMake={() => {}} />
            </DensityProvider>,
        );
        expect(html).toContain(t('pub.backup.words.changed'));
        expect(backupCard(changed)).toBe('words');
        expect(t(backupCardKey('words'))).toContain('opens only with the old words');
    });

    it('Back after a restore from the first-run wizard goes to the relays, never to the empty wizard', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'empty', file: 'ok' });
        let done = 0;
        let back = 0;
        const m = await rig.mount(
            <RestorePage t={t} api={api} pick={async () => '/p'} onBack={() => (back += 1)} onDone={() => (done += 1)} />,
        );
        await rig.click(button(m.container, 'choose'));
        await rig.type(all(m.container, (n) => n.nodeName === 'TEXTAREA')[0], HARNESS_WORDS.join(' '));
        await rig.click(button(m.container, 'open'));
        await rig.click(button(m.container, 'restore'));
        expect(state(m.container)).toBe('done');
        await rig.back();
        expect([done, back]).toEqual([1, 0]);
        await rig.click(button(m.container, 'page-back'));
        expect([done, back]).toEqual([2, 0]);
    });

    it('a restore refused because a setup runs says restore, not backup; a file that cannot be read says so', async () => {
        const { default: RestorePage } = await import('./RestorePage');
        const { harnessBackupApi, HARNESS_WORDS } = await import('./backupHarness');
        const api = harnessBackupApi({ status: 'empty', file: 'ok' });
        api.restore = () => Promise.reject('E_SETUP_RUNNING: a setup is still running');
        const m = await rig.mount(<RestorePage t={t} api={api} pick={async () => '/p'} onBack={() => {}} onDone={() => {}} />);
        await rig.click(button(m.container, 'choose'));
        await rig.type(all(m.container, (n) => n.nodeName === 'TEXTAREA')[0], HARNESS_WORDS.join(' '));
        await rig.click(button(m.container, 'open'));
        await rig.click(button(m.container, 'restore'));
        expect(text(m.container)).toContain(t('pub.restore.blocked.setup_running'));
        expect(text(m.container)).not.toContain(t('pub.backup.blocked.setup_running'));
        await m.unmount();

        const api2 = harnessBackupApi({ status: 'empty', file: 'ok' });
        api2.inspect = () => Promise.reject('E_BACKUP_READ_FAILED: cannot open the file: NotFound');
        const m2 = await rig.mount(<RestorePage t={t} api={api2} pick={async () => '/p'} onBack={() => {}} onDone={() => {}} />);
        await rig.click(button(m2.container, 'choose'));
        expect(state(m2.container)).toBe('pick');
        expect(text(m2.container)).toContain(t('pub.backup.err.read_failed'));
        expect(text(m2.container)).not.toContain(t('pub.backup.err.not_a_backup'));
    });
});

describe('repair wave: words that read right', () => {
    it('one relay, one person, setups counted right; the words say nobody can open the file without them', async () => {
        const { backupHasText, unfinishedText, previewText, backupStatusFixture } = await import('./backup');
        const one = backupStatusFixture().contents;
        const c = { ...one, people_total: 1 };
        expect(backupHasText(t, c)).toBe(
            'The backup will have: 1 relay (Bahar), 1 person and their files, and the key to your hosting account.',
        );
        const two = { ...c, relays: [c.relays[0], { ...c.relays[0], id: 2, nickname: 'Sahand' }], people_total: 3 };
        expect(backupHasText(t, two)).toContain('2 relays (Bahar, Sahand), 3 people and their files');
        expect(unfinishedText(t, 1)).toBe('1 setup has not finished. It goes into the backup as it is now.');
        expect(unfinishedText(t, 2)).toBe('2 setups have not finished. They go into the backup as they are now.');
        expect(previewText(t, 0, c)).toContain('It has 1 relay (Bahar) and 1 person.');
        expect(t('pub.backup.words.body')).toContain('Without these words nobody, not even Daal, can open your backup.');
        const fa = (await import('../i18n/d2/d2-extra.fa.json')).default as Record<string, string>;
        expect(fa['pub.backup.words.body']).toContain('حتی دال');
        expect(fa['pub.backup.share.title']).toBeTruthy();
    });

    it('people the relay lets in that this phone does not know get their own line', async () => {
        const { healthLines, renderLine } = await import('./relayHealth');
        const h = {
            operator_id: 1, checked_at_unix: 1, from_cache: false, overall: 'working', server: 'running',
            management: 'answers', management_reason: '', keys_match: true, people_missing: 0,
            everyone_missing: false, people_unknown: 2, ways: [], details: [],
        } as const;
        const lines = healthLines(t, h as never);
        const l = lines.find((x) => x.key === 'pub.health.people_unknown');
        expect(l).toBeTruthy();
        expect(renderLine(t, l!)).toContain('does not know can still connect through this relay: 2');
    });
});
