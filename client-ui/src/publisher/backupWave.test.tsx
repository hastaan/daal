// Backup and restore (D1/D2), PA-1, PA-3, PA-4, PA-7 — the pure half and
// the visible sentences, in English and Persian. The rendered flows are
// in backupFlows.test.tsx.
import { renderToStaticMarkup as markup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import backupPageSource from './BackupPage.tsx?raw';
import restorePageSource from './RestorePage.tsx?raw';
import listSource from './RelayListPage.tsx?raw';

const calls: [string, unknown][] = [];
vi.mock('@tauri-apps/api/core', () => ({
    invoke: (cmd: string, args?: unknown) => {
        calls.push([cmd, args]);
        return Promise.resolve(null);
    },
}));

import {
    backupCard,
    backupCardKey,
    backupFailure,
    backupHasText,
    backupStatusFixture,
    blockedKey,
    confirmPositions,
    firstMismatch,
    previewText,
    providersOf,
    restoreNoticeFixture,
    typedWords,
    wordCount,
} from './backup';
import { Backup, Wizard, classifyPublisherError } from './wizardCommands';
import type { DestroyReport, ReleaseAddressResult, SetupRecovery } from './wizardCommands';
import { BackupConfirm, BackupDone, BackupReady, BackupWords, FailureLine, backupBackRefused } from './BackupPage';
import { RestorePreview, restoreBackRefused, stepAfterFailure } from './RestorePage';
import { RestoreNoticeCard, keyLineText, saveNewKeys } from './RestoreNotice';
import { BackupCard } from './BackupCard';
import { harnessBackupApi, HARNESS_WORDS } from './backupHarness';
import {
    releaseLiveAddresses,
    releaseResultKey,
    releaseRetryFor,
    releaseStillBills,
    retryRelease,
    stillBills,
} from './destroyReport';
import { addressLineKey, UnreleasedAddresses } from './DestroyAddresses';
import { ReleaseResults } from './RelayListPage';
import { deleteMine, keepMine, listDeleteFor } from './listDelete';
import { recoveryFixture } from './setupRecovery';
import { QrErrorBlock } from './QrSendSheet';
import { OtherServerNote, otherServerId } from './OtherServerNote';
import { DeleteOutcome } from './SetupRecoveryCard';
import { DensityProvider } from '../design/DensityProvider';
import { wizardBack } from './PublisherWizard';
import { pageBackTarget, restoreBackView } from '../d2pages/PublisherPage';

/** Static markup with entities decoded, so sentences compare as written. */
const renderToStaticMarkup = (el: React.ReactElement) =>
    markup(el).replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const tEn = (k: string) => EN[k] ?? `MISSING:${k}`;
const tFa = (k: string) => FA[k] ?? `MISSING:${k}`;

const NEW_KEYS = Object.keys(EN).filter(
    (k) =>
        k.startsWith('pub.backup.') ||
        k.startsWith('pub.restore.') ||
        k.startsWith('pub.relays.release.') ||
        k === 'pub.back.setup_running' ||
        k === 'pub.relays.keep_mine.done' ||
        k === 'pub.relays.destroy.addr.in_use' ||
        k === 'pub.relays.destroy.other_server',
);

function report(over: Partial<DestroyReport> = {}): DestroyReport {
    return {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        local_removed: true,
        warnings: [],
        addresses: [],
        retry_needed: false,
        ...over,
    };
}

describe('strings', () => {
    it('every new sentence exists in English and Persian, translated, with the same placeholders', () => {
        expect(NEW_KEYS.length).toBeGreaterThan(90);
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
                expect(s, k).not.toMatch(/E_[A-Z_]{3,}|hcloud|\bAEAD\b|Argon|\bJSON\b|daal-deploy|--[a-z]/);
            }
        }
    });
});

describe('D1 the relay list card', () => {
    it('never / stale / last / hidden', () => {
        expect(backupCard(null)).toBe('hidden');
        expect(backupCard(backupStatusFixture({ has_publisher_data: false }))).toBe('hidden');
        expect(backupCard(backupStatusFixture())).toBe('never');
        expect(backupCard(backupStatusFixture({ last_backup_at_unix: 5, stale: true }))).toBe('stale');
        expect(backupCard(backupStatusFixture({ last_backup_at_unix: 5 }))).toBe('last');
        expect(EN[backupCardKey('never')]).toBe(
            'Only this phone can manage your relays. If you lose it, nobody can add or remove people. Make a backup.',
        );
        expect(EN[backupCardKey('stale')]).toBe('Your backup is out of date. It does not have your latest changes.');
    });

    it('renders the sentence and the right button, in both languages', () => {
        for (const t of [tEn, tFa]) {
            const never = renderToStaticMarkup(<BackupCard t={t} status={backupStatusFixture()} onBackup={() => {}} />);
            expect(never).toContain(t('pub.backup.card.never'));
            expect(never).toContain(t('pub.backup.card.make'));
            const stale = renderToStaticMarkup(
                <BackupCard t={t} status={backupStatusFixture({ last_backup_at_unix: 5, stale: true })} onBackup={() => {}} />,
            );
            expect(stale).toContain(t('pub.backup.card.stale'));
            expect(stale).toContain(t('pub.backup.card.make_new'));
        }
        // The relay page shows it only when the backup is out of date.
        expect(
            renderToStaticMarkup(
                <BackupCard t={tEn} status={backupStatusFixture({ last_backup_at_unix: 5 })} onlyWhenStale />,
            ),
        ).toBe('');
        expect(listSource).toContain('<BackupCard t={t} status={backupStatus} onBackup={onBackup} />');
        expect(listSource).toContain("t('pub.restore.link')");
    });
});

describe('D1 the backup page', () => {
    it('says what the backup holds, what it does not, the warning, and the last date', () => {
        const s = backupStatusFixture({ words_set: true, last_backup_at_unix: 1_763_460_000 });
        for (const t of [tEn, tFa]) {
            const html = renderToStaticMarkup(
                <BackupReady t={t} status={s} busy={false} savedWords={false} onCreateWords={() => {}} onMake={() => {}} onCheckWords={() => {}} onNewWords={() => {}} />,
            );
            expect(html).toContain(backupHasText(t, s.contents));
            expect(html).toContain(t('pub.backup.hasnot'));
            expect(html).toContain(t('pub.backup.warning'));
            expect(html).toContain('data-button="save-downloads"');
            expect(html).toContain('data-button="save-share"');
            expect(html).toContain('data-button="check-words"');
            expect(html).toContain('data-button="new-words"');
        }
        expect(backupHasText(tEn, s.contents)).toBe(
            'The backup will have: 1 relay (Bahar), 3 people and their files, and the key to your hosting account.',
        );
    });

    it('without words, the only button makes the words', () => {
        const html = renderToStaticMarkup(
            <BackupReady t={tEn} status={backupStatusFixture()} busy={false} savedWords={false} onCreateWords={() => {}} onMake={() => {}} onCheckWords={() => {}} onNewWords={() => {}} />,
        );
        expect(html).toContain('data-button="create-words"');
        expect(html).not.toContain('data-button="save-downloads"');
        expect(html).toContain(EN['pub.backup.last.never']);
    });

    it('each blocked reason is its own sentence, the detail under Details', () => {
        for (const b of ['setup_running', 'secret_unreadable', 'custody_locked', 'custody_backend', 'legacy_pending'] as const) {
            const html = renderToStaticMarkup(
                <BackupReady t={tEn} status={backupStatusFixture({ blocked: b, blocked_detail: 'relay 1' })} busy={false} savedWords={false} onCreateWords={() => {}} onMake={() => {}} onCheckWords={() => {}} onNewWords={() => {}} />,
            );
            expect(html).toContain(EN[blockedKey(b)!]);
            expect(html).not.toContain('data-button');
            expect(html.indexOf('relay 1')).toBeGreaterThan(html.indexOf('<details'));
        }
        expect(EN['pub.backup.blocked.setup_running']).toBe('A setup is still running. Make the backup when it has finished.');
    });

    it('the words: twelve, numbered, left to right; one confirm field per asked position with no keyboard help', () => {
        const words = renderToStaticMarkup(<BackupWords t={tFa} words={HARNESS_WORDS} onWrote={() => {}} />);
        expect(words).toContain('dir="ltr"');
        expect((words.match(/<li>/g) ?? []).length).toBe(12);
        expect(words).toContain(FA['pub.backup.words.body']);
        const confirm = renderToStaticMarkup(
            <BackupConfirm t={tEn} positions={[1, 4, 9]} typed={{}} wrong={4} busy={false} onType={() => {}} onCheck={() => {}} onShowAgain={() => {}} />,
        );
        expect((confirm.match(/<input/g) ?? []).length).toBe(3);
        for (const a of ['autoCapitalize="off"', 'autoCorrect="off"', 'spellcheck="false"', 'dir="ltr"', 'autoComplete="off"']) {
            expect(confirm).toContain(a);
        }
        expect(confirm).toContain('Type word number 2');
        expect(confirm).toContain('That is not word number 5. Look at your paper again.');
        expect(confirm).toContain('data-button="show-again"');
    });

    it('done says where the file went', () => {
        const made = { file_name: 'daal-backup-2026-11-19.daalbackup', made_at_unix: 1, contents: backupStatusFixture().contents };
        expect(renderToStaticMarkup(<BackupDone t={tEn} made={{ ...made, destination: 'downloads' }} onDone={() => {}} />)).toContain(
            'Saved to Downloads as daal-backup-2026-11-19.daalbackup.',
        );
        expect(renderToStaticMarkup(<BackupDone t={tEn} made={{ ...made, destination: 'share' }} onDone={() => {}} />)).toContain(
            // Only reached once the person said the file arrived.
            EN['pub.backup.done.share.ok'],
        );
    });

    it('Back is refused while the backup is made', () => {
        expect(backupBackRefused({ k: 'making', status: backupStatusFixture(), destination: 'share' }, false)).toBe(true);
        expect(backupBackRefused({ k: 'ready', status: backupStatusFixture() }, true)).toBe(true);
        expect(backupBackRefused({ k: 'ready', status: backupStatusFixture() }, false)).toBe(false);
    });

    it('the words are never logged or stored by the screens', () => {
        for (const src of [backupPageSource, restorePageSource]) {
            expect(src).not.toMatch(/localStorage|sessionStorage|console\./);
        }
    });
});

describe('D1 the words', () => {
    it('three distinct positions in 0..11, even from a broken random source', () => {
        for (let i = 0; i < 50; i++) {
            const p = confirmPositions();
            expect(new Set(p).size).toBe(3);
            for (const x of p) expect(x >= 0 && x < 12).toBe(true);
        }
        expect(confirmPositions(() => 0)).toEqual([0, 1, 2]);
    });

    it('typing is read the way the shell reads it: Persian keyboard, numbering, commas, capitals', () => {
        expect(typedWords('شذشدیخد')).toEqual(['abandon']);
        expect(typedWords('1. Legal, 2. WINNER، ３thank')).toEqual(['legal', 'winner', 'thank']);
        expect(typedWords('ｌｅｇａｌ')).toEqual(['legal']);
        expect(wordCount('legal‌winner thank')).toBe(3);
        expect(wordCount('')).toBe(0);
    });

    it('a mismatch is caught from the words still on screen, by position', () => {
        const w = HARNESS_WORDS;
        expect(firstMismatch(w, [0, 5, 11], { 0: 'legal', 5: 'sausage', 11: 'yell' })).toBe(-1);
        expect(firstMismatch(w, [0, 5, 11], { 0: 'legal', 5: 'sauce', 11: 'yellow' })).toBe(5);
        expect(firstMismatch(w, [0, 5, 11], { 0: 'legal', 5: 'sausage' })).toBe(11);
    });
});

describe('D1/D2 refusals: one plain sentence each, nothing raw outside Details', () => {
    const codes: [string, string][] = [
        ['E_BACKUP_NOT_A_BACKUP', 'This file is not a Daal backup.'],
        ['E_BACKUP_DAMAGED', 'This backup file is damaged or incomplete. Try another copy of it.'],
        ['E_BACKUP_NEWER', 'This backup was made by a newer version of Daal. Update the app, then try again.'],
        ['E_BACKUP_WORDS_INVALID', 'One of the words is not right. Check each word against your paper.'],
        ['E_BACKUP_WRONG_WORDS', 'These words do not open this backup. It may have been made with other words.'],
        ['E_RESTORE_WOULD_REPLACE', 'Something changed on this phone. Look again before replacing.'],
        ['E_RESTORE_STATE_CHANGED', 'Something changed on this phone. Look again before replacing.'],
        ['E_RESTORE_UNFINISHED', 'The restore did not finish.'],
        ['E_BACKUP_SAVE_FAILED', 'The backup could not be saved. Nothing was changed.'],
    ];
    it.each(codes)('%s', (code, sentence) => {
        const e = `${code}: tail`;
        expect(classifyPublisherError(e)).toBe(code);
        const f = backupFailure(e);
        expect(EN[f.key]).toBe(sentence);
        expect(FA[f.key]).toBeTruthy();
        const html = renderToStaticMarkup(<FailureLine t={tEn} failure={f} />);
        expect(html).toContain(sentence);
        expect(html.indexOf(code)).toBeGreaterThan(html.indexOf('<details'));
    });

    it('the file and word refusals are four different sentences', () => {
        const keys = ['E_BACKUP_NOT_A_BACKUP', 'E_BACKUP_DAMAGED', 'E_BACKUP_NEWER', 'E_BACKUP_WRONG_WORDS', 'E_BACKUP_WORDS_INVALID'].map(
            (c) => backupFailure(`${c}: x`).key,
        );
        expect(new Set(keys).size).toBe(5);
    });

    it('a failure sends the restore back to the step that can fix it', () => {
        expect(stepAfterFailure(backupFailure('E_BACKUP_DAMAGED: x'), 'words')).toBe('pick');
        expect(stepAfterFailure(backupFailure('E_BACKUP_NEWER: x'), 'pick')).toBe('pick');
        expect(stepAfterFailure(backupFailure('E_BACKUP_WRONG_WORDS: x'), 'working')).toBe('words');
        expect(stepAfterFailure(backupFailure('E_RESTORE_STATE_CHANGED: x'), 'working')).toBe('preview');
        // Committed and not finished: its own step, only "Try again".
        expect(stepAfterFailure(backupFailure('E_RESTORE_UNFINISHED: x'), 'working')).toBe('unfinished');
        expect(backupFailure('E_RESTORE_UNFINISHED: x').after).toBe('finish');
        expect(restoreBackRefused('working', false)).toBe(true);
        expect(restoreBackRefused('words', true)).toBe(true);
        expect(restoreBackRefused('pick', false)).toBe(false);
    });
});

describe('D2 restore preview and replace', () => {
    const contents = backupStatusFixture().contents;
    it('an empty phone: Restore, no replace box', () => {
        const html = renderToStaticMarkup(
            <RestorePreview t={tEn} preview={{ made_at_unix: 1_763_460_000, app_version: 'x', contents, replace: null }} busy={false} onRestore={() => {}} onCancel={() => {}} />,
        );
        expect(html).toContain(previewText(tEn, 1_763_460_000, contents));
        expect(html).toContain('It has 1 relay (Bahar) and 3 people.');
        expect(html).toContain('data-button="restore"');
        expect(html).not.toContain('restore-replace');
    });

    it('a phone with relays: the button names what is replaced, and the ones only here are named too', () => {
        const sahand = { ...contents.relays[0], id: 7, nickname: 'Sahand' };
        for (const t of [tEn, tFa]) {
            const html = renderToStaticMarkup(
                <RestorePreview
                    t={t}
                    preview={{ made_at_unix: 1, app_version: 'x', contents, replace: { this_phone: [sahand], only_on_this_phone: [sahand], digest: 'd' } }}
                    busy={false}
                    onRestore={() => {}}
                    onCancel={() => {}}
                />,
            );
            expect(html).toContain(t('pub.restore.replace').replace('{names}', 'Sahand'));
            expect(html).toContain(t('pub.restore.replace.orphans').replace('{names}', 'Sahand'));
            expect(html).toContain(t('pub.restore.replace.go').replace('{names}', 'Sahand'));
            expect(html).not.toContain('data-button="restore"');
        }
    });

    it('the old-phone notice says what is true, and the refresh line only when there are refresh keys', () => {
        const html = renderToStaticMarkup(<RestoreNoticeCard t={tEn} notice={restoreNoticeFixture()} onEnterKey={() => {}} onDismiss={() => {}} />);
        for (const k of ['title', 'body1', 'body2', 'body3', 'newkey', 'ok']) expect(html).toContain(EN[`pub.restore.oldphone.${k}`]);
        expect(html).not.toContain(EN['pub.restore.oldphone.body4']);
        expect(EN['pub.restore.oldphone.body3']).toContain('Daal cannot change that key yet.');
        const refresh = renderToStaticMarkup(
            <RestoreNoticeCard t={tFa} notice={restoreNoticeFixture({ has_refresh_keys: true })} onEnterKey={() => {}} onDismiss={() => {}} />,
        );
        expect(refresh).toContain(FA['pub.restore.oldphone.body4']);
    });

    it('a new hosting key is tested before it replaces the old one; a refused key says so and changes nothing', async () => {
        const notice = restoreNoticeFixture({
            relays: [
                { ...restoreNoticeFixture().relays[0], id: 1, nickname: 'A' },
                { ...restoreNoticeFixture().relays[0], id: 2, nickname: 'B' },
                { ...restoreNoticeFixture().relays[0], id: 3, nickname: 'Gone', status: 'decommissioned' },
                { ...restoreNoticeFixture().relays[0], id: 4, nickname: 'V', provider: 'vultr' },
            ],
        });
        expect(providersOf(notice)[0]).toEqual({ provider: 'hetzner', relays: notice.relays.slice(0, 2) });
        const replaceKey = vi.fn(async (p: string, _t: string, ids: number[]) => {
            if (p === 'vultr') throw 'E_HOSTING_KEY_REJECTED: the hosting company did not accept this key: 401';
            return ids;
        });
        const check = vi.fn(async (id: number) =>
            ({ overall: id === 1 ? 'working' : 'partly', operator_id: id }) as never,
        );
        const r = await saveNewKeys(tEn, notice, { hetzner: '  newtoken ', vultr: 'typo' }, { replaceKey, check });
        expect(replaceKey.mock.calls).toEqual([
            ['hetzner', 'newtoken', [1, 2]],
            ['vultr', 'typo', [4]],
        ]);
        // Only relays whose key was taken are checked.
        expect(check.mock.calls).toEqual([[1], [2]]);
        expect(keyLineText(tEn, r.lines[0])).toBe('A: the new key works, and the relay is working.');
        // No "See below" with nothing below it.
        expect(keyLineText(tEn, r.lines[1])).toBe('B: the new key works. The relay is only partly working; open it to see why.');
        expect(r.refused.vultr.message).toBe(EN['pub.restore.newkey.rejected']);
        expect(r.refused.vultr.message).not.toContain('E_HOSTING');
        expect(r.refused.vultr.detail).toContain('401');
    });

    it('a key for another hosting account is refused by name', async () => {
        const notice = restoreNoticeFixture();
        const replaceKey = vi.fn(async () => {
            throw 'E_HOSTING_KEY_WRONG_ACCOUNT: relay 1: its server is not in the account this key opens';
        });
        const r = await saveNewKeys(tEn, notice, { hetzner: 'k' }, { replaceKey, check: vi.fn() });
        expect(r.lines).toEqual([]);
        expect(r.refused.hetzner.message).toBe(
            'This key opens a hosting account that does not have Bahar. The key this phone had is still in use. Make the new key in the account that has your relays.',
        );
    });

    it('the notice says changes after the backup day are not in it', () => {
        const html = renderToStaticMarkup(
            <RestoreNoticeCard t={tEn} notice={restoreNoticeFixture()} onEnterKey={() => {}} onDismiss={() => {}} />,
        );
        expect(html).toContain('Changes made on the old phone after that day are not in it.');
    });
});

describe('D1/D2 wrappers: the command names and argument keys of the contract', () => {
    it('Backup.*', async () => {
        calls.length = 0;
        await Backup.status();
        await Backup.wordsNew();
        await Backup.wordsConfirm([{ index: 1, word: 'x' }]);
        await Backup.wordsCheck('w');
        await Backup.make('downloads');
        await Backup.make('share', 'f.daalbackup');
        await Backup.inspect('/p');
        await Backup.open('/p', 'w');
        await Backup.restore('/p', 'w', null);
        await Backup.restore('/p', 'w', 'dg');
        await Backup.finishRestore();
        await Backup.dismissNotice();
        await Backup.confirmShared(true);
        await Backup.replaceHostingKey('hetzner', 'k', [1, 2]);
        await Wizard.releaseAddress(4, '198.51.100.9');
        expect(calls).toEqual([
            ['publisher_backup_status', undefined],
            ['publisher_backup_words_new', undefined],
            ['publisher_backup_words_confirm', { answers: [{ index: 1, word: 'x' }] }],
            ['publisher_backup_words_check', { words: 'w' }],
            ['publisher_backup_make', { destination: 'downloads', fileName: null, chooserTitle: null }],
            ['publisher_backup_make', { destination: 'share', fileName: 'f.daalbackup', chooserTitle: null }],
            ['publisher_backup_inspect', { path: '/p' }],
            ['publisher_backup_open', { path: '/p', words: 'w' }],
            ['publisher_backup_restore', { path: '/p', words: 'w', replaceDigest: null }],
            ['publisher_backup_restore', { path: '/p', words: 'w', replaceDigest: 'dg' }],
            ['publisher_backup_finish_restore', undefined],
            ['publisher_backup_dismiss_notice', undefined],
            ['publisher_backup_confirm_shared', { arrived: true }],
            ['publisher_replace_hosting_key', { provider: 'hetzner', token: 'k', operatorIds: [1, 2] }],
            ['wizard_release_address', { operatorId: 4, address: '198.51.100.9' }],
        ]);
    });

    it('the harness fake walks the same refusals', async () => {
        const replace = harnessBackupApi({ file: 'replace' });
        await expect(replace.restore('p', HARNESS_WORDS.join(' '), null)).rejects.toMatch(/^E_RESTORE_WOULD_REPLACE/);
        await expect(replace.restore('p', HARNESS_WORDS.join(' '), 'stale')).rejects.toMatch(/^E_RESTORE_STATE_CHANGED/);
        await expect(replace.restore('p', HARNESS_WORDS.join(' '), 'harness-digest')).resolves.toBeTruthy();
        await expect(harnessBackupApi({ file: 'damaged' }).inspect('p')).rejects.toMatch(/^E_BACKUP_DAMAGED/);
        await expect(harnessBackupApi().open('p', 'one two')).rejects.toMatch(/^E_BACKUP_WORDS_INVALID/);
    });
});

describe('D3 Back decisions', () => {
    it('the wizard: refuse while building, else a step back, else the list it came from', () => {
        expect(wizardBack({ building: true, stepIdx: 2, hasRootBack: true })).toBe('refuse');
        expect(wizardBack({ building: false, stepIdx: 2, hasRootBack: false })).toBe('step');
        expect(wizardBack({ building: false, stepIdx: 0, hasRootBack: true })).toBe('root');
        expect(wizardBack({ building: false, stepIdx: 0, hasRootBack: false })).toBe('none');
        // A recovery delete or a cancel still running: Back waits, so
        // its outcome (an address that still costs money) is seen.
        expect(wizardBack({ building: false, stepIdx: 2, hasRootBack: true, busyElsewhere: true })).toBe('wait');
        // The relay row is gone and the screen leaves only through Done.
        expect(wizardBack({ building: false, stepIdx: 2, hasRootBack: false, leavesOnlyByDone: true })).toBe('done');
        expect(wizardBack({ building: true, stepIdx: 2, hasRootBack: false, busyElsewhere: true })).toBe('refuse');
        expect(EN['pub.back.setup_running']).toBe('The setup is still running. It is safe to wait here.');
    });

    it('the publisher pages', () => {
        expect(pageBackTarget({ k: 'relay', operatorId: 1 })).toEqual({ k: 'list' });
        expect(pageBackTarget({ k: 'list' })).toBeNull();
        expect(restoreBackView('wizard')).toEqual({ k: 'wizard' });
        expect(restoreBackView('list')).toEqual({ k: 'list' });
    });
});

// ---------------------------------------------------------------- PA-1

describe('PA-1 an address left on a live relay', () => {
    const res = (address: string, code: ReleaseAddressResult['code']): ReleaseAddressResult => ({ address, code, still_billing: [] });

    it('Try again on a live relay releases each listed address and never deletes anything', async () => {
        expect(releaseRetryFor('provisioned')).toBe('release_address');
        const releaseAddress = vi.fn(async (_op: number, a: string) => res(a, a.endsWith('.1') ? 'released' : 'release_failed'));
        const destroy = { relayDestroy: vi.fn(async () => report()), setupRemoveServer: vi.fn(async () => report()) };
        const out = await releaseLiveAddresses({ id: 3 }, ['198.51.100.1', '198.51.100.2'], releaseAddress);
        expect(releaseAddress.mock.calls).toEqual([
            [3, '198.51.100.1'],
            [3, '198.51.100.2'],
        ]);
        expect(out.map((r) => r.code)).toEqual(['released', 'release_failed']);
        expect(await retryRelease({ id: 3, status: 'provisioned' }, destroy)).toBeNull();
        expect(destroy.relayDestroy).not.toHaveBeenCalled();
        expect(destroy.setupRemoveServer).not.toHaveBeenCalled();
        expect(listSource).toContain("releaseRetryFor(op.status) === 'release_address'");
        expect(listSource).toContain('(id, a) => Wizard.releaseAddress(id, a)');
    });

    it('each outcome has its sentence; a failure offers Try again and keeps the raw text under Details', () => {
        expect(EN[releaseResultKey('released')]).toBe('Given back. It no longer costs money.');
        expect(EN[releaseResultKey('in_use')]).toBe('Your relay uses this address, so it was kept.');
        expect(EN[releaseResultKey('not_daal')]).toBe(
            "Daal did not reserve this address, so it did not remove it. If you do not use it, remove it at your hosting company's website.",
        );
        expect(EN[releaseResultKey('still_attached')]).toBe('This address is attached to a server, so it was kept. It still costs money.');
        expect(EN[releaseResultKey('release_failed')]).toBe('It could not be given back and still costs money.');
        expect(releaseStillBills([res('a', 'released'), res('b', 'in_use'), res('c', 'not_daal')])).toBe(false);
        expect(releaseStillBills([res('a', 'still_attached')])).toBe(true);
        const html = renderToStaticMarkup(
            <ReleaseResults
                t={tFa}
                results={[res('198.51.100.1', 'released'), { ...res('198.51.100.2', 'release_failed'), error: 'quota locked' }]}
                failure={{ message: FA['pub.fail.generic'] ?? 'x', detail: 'provider said 500' }}
                onRetry={() => {}}
            />,
        );
        expect(html).toContain(FA['pub.relays.release.released']);
        expect(html).toContain(FA['pub.relays.release.release_failed']);
        expect(html).toContain(FA['pub.relays.destroy.addr.retry']);
        expect(html.indexOf('provider said 500')).toBeGreaterThan(html.indexOf('<details'));
        expect(html.indexOf('quota locked')).toBeGreaterThan(html.indexOf('<details'));
        // The card of a live relay now offers the button, and says it
        // does not touch the relay.
        const card = renderToStaticMarkup(<UnreleasedAddresses t={tEn} ips={['198.51.100.9']} live onRetry={() => {}} />);
        expect(card).toContain(EN['pub.relays.release.intro']);
        expect(card).toContain(EN['pub.relays.destroy.addr.retry']);
    });

    it('a delete report that kept the relay\'s own address is not "still costs money"', () => {
        expect(EN[addressLineKey('in_use')]).toContain('{ip}');
        expect(stillBills(report({ addresses: [{ id: '1', ip: '203.0.113.7', released: false, code: 'in_use' }] }))).toBe(false);
    });
});

// ---------------------------------------------------------------- PA-3

describe('PA-3 another server with the relay\'s name', () => {
    it('says Daal did not delete it, offers the account check, keeps the id under Details', () => {
        const r = report({ server_deleted: false, local_removed: false, other_server_id: '4242', other_server_name: 'daal-fsn1-ab' });
        expect(otherServerId(r)).toBe('4242');
        expect(otherServerId(report())).toBe('');
        for (const t of [tEn, tFa]) {
            const html = renderToStaticMarkup(<OtherServerNote t={t} report={r} />);
            expect(html).toContain(t('pub.relays.destroy.other_server'));
            expect(html).toContain(t('pub.account.open'));
            expect(html.indexOf('4242')).toBeGreaterThan(html.indexOf('<details'));
        }
        expect(EN['pub.relays.destroy.other_server']).toBe(
            "Your hosting account still has a server with this relay's name. Daal did not delete it.",
        );
        // The wizard's cancel / recovery report shows it instead of
        // "the server was NOT deleted".
        const out = renderToStaticMarkup(<DensityProvider><DeleteOutcome t={tEn} report={r} /></DensityProvider>);
        expect(out).toContain('data-testid="other-server"');
        expect(out).not.toContain(EN['pub.setup.recover.deleted.server_kept']);
        expect(listSource).toContain("otherServerId(report) !== ''");
    });
});

// ---------------------------------------------------------------- PA-4

describe('PA-4 the QR sheet error', () => {
    it('the plain sentence is visible; the raw text only inside Details', () => {
        for (const t of [tEn, tFa]) {
            const html = renderToStaticMarkup(
                <QrErrorBlock t={t} artifact="recipient:4" error="E_FILE_MISSING: /data/staging/1.r4.sbpx gone" />,
            );
            expect(html).toContain(t('qr.send.error.title'));
            expect(html).toContain(t('pub.fail.file_missing'));
            const raw = html.indexOf('/data/staging/1.r4.sbpx');
            expect(raw).toBeGreaterThan(html.indexOf('<details'));
            expect(raw).toBeLessThan(html.indexOf('</details>'));
        }
    });
});

// ---------------------------------------------------------------- PA-7

describe('PA-7 the list delete of an unfinished setup asks first', () => {
    const op = (over = {}) => ({ id: 6, status: 'pre-provision', has_cloud_token: true, ...over });
    const ask = (rec: SetupRecovery) => vi.fn(async (_id: number) => rec);

    it('your own server: Delete my server / Keep my server', async () => {
        const plan = await listDeleteFor(op(), ask(recoveryFixture('server_running', { server_origin: 'yours' })));
        expect(plan.kind).toBe('choice');
        const rd = vi.fn(async (_op: number, _d: boolean, _o?: boolean) => report());
        await deleteMine(6, rd);
        expect(rd).toHaveBeenLastCalledWith(6, true, true);
        await keepMine(6, rd);
        expect(rd).toHaveBeenLastCalledWith(6, false);
        // "Keep my server" never passes delete_own_server.
        expect(rd.mock.calls[1].length).toBe(2);
        calls.length = 0;
        await keepMine(6, (id, d, o) => Wizard.relayDestroy(id, d, o));
        expect(calls[0]).toEqual(['wizard_relay_destroy', { operatorId: 6, deleteServer: false, deleteOwnServer: false }]);
        expect(EN['pub.relays.keep_mine.done']).toBe('Removed from this phone. Your server was left as it is.');
    });

    it('a setup still running: no delete at all', async () => {
        expect((await listDeleteFor(op(), ask(recoveryFixture('running')))).kind).toBe('wait');
    });

    it('a rented server, nothing rented, no token, or a finished relay: today\'s delete sheet', async () => {
        expect((await listDeleteFor(op(), ask(recoveryFixture('server_running')))).kind).toBe('destroy');
        expect((await listDeleteFor(op(), ask(recoveryFixture('none')))).kind).toBe('destroy');
        expect((await listDeleteFor(op(), ask(recoveryFixture('unknown', { check_error: 'no_token' })))).kind).toBe('destroy');
        const never = vi.fn();
        expect((await listDeleteFor(op({ status: 'provisioned' }), never)).kind).toBe('destroy');
        expect(never).not.toHaveBeenCalled();
    });

    it('a failed look with a token stored is "could not check" (the wizard\'s fallback), never local-only', async () => {
        const fail = vi.fn(async () => {
            throw 'database is locked';
        });
        // recoveryCheckFailed → state unknown → plan delete → the delete
        // sheet, which offers deleting the server.
        expect((await listDeleteFor(op(), fail)).kind).toBe('destroy');
        expect((await listDeleteFor(op({ has_cloud_token: false }), fail)).kind).toBe('destroy');
        expect(listSource).toContain('void startDelete(op);');
        expect(listSource).toContain('deleteMine(cur.op.id');
        expect(listSource).toContain('keepMine(cur.op.id');
    });
});

// A new relay can start with the hosting key another relay saved.
import { canReuseSaved, savedKeyLine } from './PublisherWizard';
import enMain from '../i18n/en.json';
import faMain from '../i18n/fa.json';

describe('reusing a saved hosting key for a new relay', () => {
    const saved = { operator_id: 1, nickname: 'Test' };
    it('is offered only when nothing was typed and this relay has no key', () => {
        expect(canReuseSaved(saved, '', false)).toBe(true);
        expect(canReuseSaved(saved, '  ', false)).toBe(true);
        expect(canReuseSaved(saved, 'abc', false)).toBe(false);
        expect(canReuseSaved(saved, '', true)).toBe(false);
        expect(canReuseSaved(null, '', false)).toBe(false);
    });
    it('names the relay the key came from, in both languages', () => {
        for (const cat of [enMain, faMain] as Record<string, string>[]) {
            const t = (k: string) => cat[k] ?? k;
            expect(savedKeyLine(t, 'Test')).toContain('Test');
            expect(savedKeyLine(t, 'Test')).not.toContain('{relay}');
            expect(savedKeyLine(t, '')).toBe(cat['wiz.provider.token.saved_other']);
            expect(cat['wiz.provider.token.saved_other']).toBeTruthy();
        }
        expect(faMain['wiz.provider.token.saved_other']).not.toBe(
            enMain['wiz.provider.token.saved_other'],
        );
    });
});
