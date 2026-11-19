// backupHarness — the backup and restore screens without the shell.
//
// In the browser preview (`?harness=…`) and in the tests there is no
// Rust side, so the screens take an `api` with the same shape as
// `Backup` and this file supplies one that walks every state:
//
//   ?backup=never|stale|last|blocked_setup|blocked_secret|notice|pending
//       which status the relay list and the backup page start from
//   ?backupFile=ok|not|damaged|newer|replace
//       what the chosen file turns out to be (`replace`: this phone
//       already has relays)
//   words containing "wrong" do not open the backup; fewer or more
//   than twelve words are "one of the words is not right".
//
// Nothing here is real and nothing is stored.

import { Backup } from './wizardCommands';
import type {
    BackupContents,
    BackupInspect,
    BackupPreview,
    BackupStatus,
    MadeBackup,
    RestoreResult,
} from './wizardCommands';
import { backupStatusFixture, restoreNoticeFixture, wordCount } from './backup';
import { isTauriRuntime } from '../backends';
import { isHarnessActive } from '../harness/scenarios';

export type BackupApi = typeof Backup;

/** Twelve real list words, for the preview only. */
export const HARNESS_WORDS = [
    'legal', 'winner', 'thank', 'year', 'wave', 'sausage',
    'worth', 'useful', 'legal', 'winner', 'thank', 'yellow',
];

function param(name: string): string | null {
    if (typeof window === 'undefined') return null;
    const q = new URLSearchParams(window.location.search || window.location.hash.split('?')[1] || '');
    return q.get(name);
}

export function harnessStatus(kind: string | null): BackupStatus {
    switch (kind) {
        case 'stale':
            return backupStatusFixture({ words_set: true, last_backup_at_unix: 1_763_460_000, stale: true });
        case 'last':
            return backupStatusFixture({ words_set: true, last_backup_at_unix: 1_763_460_000 });
        case 'blocked_setup':
            return backupStatusFixture({ blocked: 'setup_running' });
        case 'blocked_secret':
            return backupStatusFixture({ blocked: 'secret_unreadable', blocked_detail: 'relay 1' });
        case 'notice':
            return backupStatusFixture({
                words_set: true,
                last_backup_at_unix: 1_763_460_000,
                restore_notice: restoreNoticeFixture(),
            });
        case 'pending':
            return backupStatusFixture({ restore_pending: true });
        case 'empty':
            return backupStatusFixture({ has_publisher_data: false });
        default:
            return backupStatusFixture();
    }
}

const coded = (code: string) => Promise.reject(`${code}: harness`);

/** A fake with the shape of `Backup`. `file` and `status` override the
 *  URL parameters (tests). */
export function harnessBackupApi(opts: { status?: string | null; file?: string | null } = {}): BackupApi {
    let status = harnessStatus(opts.status ?? param('backup'));
    const file = () => opts.file ?? param('backupFile') ?? 'ok';
    const contents = (): BackupContents => backupStatusFixture().contents;
    const existing = () =>
        file() === 'replace'
            ? {
                  relays: [{ ...contents().relays[0], id: 7, nickname: 'Sahand', public_ip: '198.51.100.4' }],
                  people_total: 1,
                  digest: 'harness-digest',
              }
            : null;
    const checkFile = (): Promise<void> => {
        switch (file()) {
            case 'not':
                return coded('E_BACKUP_NOT_A_BACKUP');
            case 'damaged':
                return coded('E_BACKUP_DAMAGED');
            case 'newer':
                return coded('E_BACKUP_NEWER');
            default:
                return Promise.resolve();
        }
    };
    const checkWords = (words: string): Promise<void> => {
        if (wordCount(words) !== 12) return coded('E_BACKUP_WORDS_INVALID');
        if (/wrong/i.test(words)) return coded('E_BACKUP_WRONG_WORDS');
        return Promise.resolve();
    };
    return {
        status: async () => status,
        wordsNew: async () => {
            status = { ...status, words_pending: true };
            return { words: [...HARNESS_WORDS] };
        },
        wordsConfirm: async (answers) => {
            for (const a of answers) {
                if (a.word.trim().toLowerCase() !== HARNESS_WORDS[a.index]) {
                    return coded('E_BACKUP_WORDS_MISMATCH');
                }
            }
            status = {
                ...status,
                words_set: true,
                words_pending: false,
                words_changed: status.words_set && status.last_backup_at_unix > 0 ? true : status.words_changed,
                stale: status.words_set && status.last_backup_at_unix > 0 ? true : status.stale,
            };
            return undefined;
        },
        wordsCheck: async (words) => words.trim().toLowerCase().split(/\s+/).join(' ') === HARNESS_WORDS.join(' '),
        make: async (destination, fileName) => {
            const made: MadeBackup = {
                file_name: fileName ?? 'daal-backup-2026-11-19-1030.daalbackup',
                made_at_unix: Math.floor(Date.now() / 1000),
                contents: status.contents,
                destination,
                confirmed: destination === 'downloads',
            };
            // Like the shell: a share waits for "it arrived".
            if (destination === 'downloads') {
                status = { ...status, last_backup_at_unix: made.made_at_unix, stale: false, words_changed: false };
            } else {
                status = { ...status, share_unconfirmed_at_unix: made.made_at_unix };
            }
            return made;
        },
        confirmShared: async (arrived) => {
            const at = status.share_unconfirmed_at_unix ?? 0;
            if (at <= 0) return false;
            status = arrived
                ? { ...status, last_backup_at_unix: at, stale: false, words_changed: false, share_unconfirmed_at_unix: 0 }
                : { ...status, share_unconfirmed_at_unix: 0 };
            return arrived;
        },
        replaceHostingKey: async (_provider, token, ids) => {
            if (/wrong/i.test(token)) return coded('E_HOSTING_KEY_REJECTED');
            return ids;
        },
        inspect: async (): Promise<BackupInspect> => {
            await checkFile();
            return { existing: existing() };
        },
        open: async (_path, words): Promise<BackupPreview> => {
            await checkFile();
            await checkWords(words);
            const ex = existing();
            return {
                made_at_unix: 1_763_460_000,
                app_version: '0.0.0-harness',
                contents: contents(),
                replace: ex ? { this_phone: ex.relays, only_on_this_phone: ex.relays, digest: ex.digest } : null,
            };
        },
        restore: async (_path, words, replaceDigest): Promise<RestoreResult> => {
            await checkFile();
            await checkWords(words);
            const ex = existing();
            if (ex && replaceDigest === null) return coded('E_RESTORE_WOULD_REPLACE');
            if (ex && replaceDigest !== ex.digest) return coded('E_RESTORE_STATE_CHANGED');
            const notice = restoreNoticeFixture();
            status = { ...status, restore_notice: notice };
            return { contents: contents(), notice };
        },
        finishRestore: async () => {
            status = { ...status, restore_pending: false };
            return undefined;
        },
        dismissNotice: async () => {
            status = { ...status, restore_notice: null };
            return undefined;
        },
    };
}

let harness: BackupApi | null = null;

/** The real commands inside the app; the fake in the browser preview. */
export function backupApi(): BackupApi {
    if (isTauriRuntime() && !isHarnessActive()) return Backup;
    harness ??= harnessBackupApi();
    return harness;
}
