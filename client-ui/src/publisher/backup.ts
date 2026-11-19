// backup — the pure half of the backup and restore screens (D1/D2).
//
// One backup file holds everything needed to carry on from another
// phone: the relays, their keys, the key to the hosting account, the
// people and their files. It is locked with twelve recovery words the
// app makes and shows once. The format, the words' checks and the
// restore itself live in Rust (daal-wizard/src/publisher_backup.rs);
// this file decides only what the screens say and which call a button
// makes. Nothing here logs or stores the words.

import type {
    BackupBlocked,
    BackupContents,
    BackupStatus,
    RelayLine,
    RestoreNotice,
} from './wizardCommands';
import { classifyPublisherError } from './wizardCommands';
import { failureKey, rawErrorText } from './failureText';

export const WORD_COUNT = 12;

// ---- the card on the relay list --------------------------------------

export type BackupCard = 'hidden' | 'never' | 'stale' | 'words' | 'last';

/** Which card the relay list shows. Hidden when there is nothing to back
 *  up, or the status could not be read (a shell that predates backup). */
export function backupCard(s: BackupStatus | null): BackupCard {
    if (!s || !s.has_publisher_data) return 'hidden';
    if (s.last_backup_at_unix <= 0) return 'never';
    // New words were confirmed after the last backup: the file on hand
    // opens only with the old words.
    if (s.words_changed) return 'words';
    if (s.stale) return 'stale';
    return 'last';
}

export function backupCardKey(c: BackupCard): string {
    switch (c) {
        case 'never':
            return 'pub.backup.card.never';
        case 'stale':
            return 'pub.backup.card.stale';
        case 'words':
            return 'pub.backup.card.words';
        default:
            return 'pub.backup.card.last';
    }
}

export function backupCardButtonKey(c: BackupCard): string | null {
    if (c === 'never') return 'pub.backup.card.make';
    if (c === 'stale' || c === 'words') return 'pub.backup.card.make_new';
    return null;
}

/** A date in the phone's own time zone and language. */
export function dayLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toLocaleDateString(undefined, { dateStyle: 'medium' });
    } catch {
        return '';
    }
}

// ---- what a backup holds ---------------------------------------------

/** What a person calls a relay: its name, else its address, else its
 *  number. Never empty. */
export function relayLineName(r: RelayLine): string {
    return r.nickname || r.public_ip || `#${r.id}`;
}

export function relayNames(lines: RelayLine[]): string {
    return lines.map(relayLineName).join(', ');
}

/** Only relays that still run count in "{n} relays". */
function liveRelays(c: BackupContents): RelayLine[] {
    return c.relays.filter((r) => r.status !== 'decommissioned');
}

export function fill(s: string, vars: Record<string, string | number>): string {
    return s.replace(/\{(\w+)\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
}

/** `key.one` for exactly one when the catalogue has it, else `key`
 *  ("1 relay", never "1 relays"). Farsi does not need the split and
 *  keeps the same text under both. */
export function countKey(t: (k: string) => string, key: string, n: number): string {
    if (n === 1) {
        const one = `${key}.one`;
        const s = t(one);
        if (s && s !== one) return s;
    }
    return t(key);
}

/** "{n} relays" / "1 relay". */
export function relaysCount(t: (k: string) => string, n: number): string {
    return fill(countKey(t, 'pub.count.relays', n), { n });
}

/** "{n} people" / "1 person". */
export function peopleCount(t: (k: string) => string, n: number): string {
    return fill(countKey(t, 'pub.count.people', n), { n });
}

/** "The backup will have: 2 relays (Bahar, Sahand), 3 people and their
 *  files, and the key to your hosting account." */
export function backupHasText(t: (k: string) => string, c: BackupContents): string {
    const live = liveRelays(c);
    const key = c.includes_hosting_key ? 'pub.backup.has' : 'pub.backup.has.no_key';
    return fill(t(key), {
        n: live.length,
        names: relayNames(live),
        m: c.people_total,
        relays: relaysCount(t, live.length),
        people: peopleCount(t, c.people_total),
    });
}

/** "{n} setups have not finished" / "1 setup has not finished". */
export function unfinishedText(t: (k: string) => string, n: number): string {
    return fill(countKey(t, 'pub.backup.has.unfinished', n), { n });
}

export function blockedKey(b: BackupBlocked): string | null {
    switch (b) {
        case 'setup_running':
            return 'pub.backup.blocked.setup_running';
        case 'secret_unreadable':
            return 'pub.backup.blocked.secret_unreadable';
        case 'custody_locked':
            return 'pub.backup.blocked.custody_locked';
        case 'custody_backend':
            return 'pub.backup.blocked.custody_backend';
        case 'legacy_pending':
            return 'pub.backup.blocked.legacy_pending';
        default:
            return null;
    }
}

// ---- the words ---------------------------------------------------------

/** Three distinct positions (0-based) to ask for, in order. */
export function confirmPositions(rand: () => number = Math.random): number[] {
    const picked = new Set<number>();
    let guard = 0;
    while (picked.size < 3 && guard < 1000) {
        picked.add(Math.floor(rand() * WORD_COUNT) % WORD_COUNT);
        guard += 1;
    }
    // A broken random source must still give three distinct positions.
    for (let i = 0; picked.size < 3; i++) picked.add(i);
    return [...picked].sort((a, b) => a - b);
}

/** The Persian keyboard letter on each Latin key (standard layout, the
 *  one Gboard Persian uses), so words typed with the keyboard left on
 *  Persian still count. The same table the shell parses with; here it
 *  only drives the live word count. */
const FA_KEYS: Record<string, string> = {
    'ض': 'q', 'ص': 'w', 'ث': 'e', 'ق': 'r', 'ف': 't', 'غ': 'y', 'ع': 'u', 'ه': 'i', 'خ': 'o', 'ح': 'p',
    'ش': 'a', 'س': 's', 'ی': 'd', 'ي': 'd', 'ى': 'd', 'ب': 'f', 'ل': 'g', 'ا': 'h', 'آ': 'h', 'ت': 'j',
    'ن': 'k', 'م': 'l', 'ظ': 'z', 'ط': 'x', 'ز': 'c', 'ر': 'v', 'ذ': 'b', 'د': 'n', 'پ': 'm',
};

/** The words as the shell will read them: lower-case Latin runs, every
 *  other character a separator (so "1." numbering disappears). */
export function typedWords(text: string): string[] {
    let out = '';
    for (const ch of text) {
        const code = ch.codePointAt(0) ?? 0;
        let c = ch;
        if (FA_KEYS[ch]) c = FA_KEYS[ch];
        else if (code >= 0xff21 && code <= 0xff3a) c = String.fromCharCode(code - 0xff21 + 97);
        else if (code >= 0xff41 && code <= 0xff5a) c = String.fromCharCode(code - 0xff41 + 97);
        else c = ch.toLowerCase();
        out += c >= 'a' && c <= 'z' && c.length === 1 ? c : ' ';
    }
    return out.split(' ').filter((w) => w.length > 0);
}

export function wordCount(text: string): number {
    return typedWords(text).length;
}

/** The "Check" step: what was typed for each asked position. */
export function confirmAnswers(
    positions: number[],
    typed: Record<number, string>,
): { index: number; word: string }[] {
    return positions.map((i) => ({ index: i, word: (typed[i] ?? '').trim() }));
}

/** The position the person got wrong, when it can be told without the
 *  shell (the shown words are still in state). -1 when all match. */
export function firstMismatch(
    words: string[],
    positions: number[],
    typed: Record<number, string>,
): number {
    for (const i of positions) {
        const got = typedWords(typed[i] ?? '');
        const want = words[i] ?? '';
        const ok =
            got.length === 1 &&
            (got[0] === want || (got[0].length >= 4 && want.startsWith(got[0])));
        if (!ok) return i;
    }
    return -1;
}

// ---- errors, one sentence each ----------------------------------------

/** What the screen does after a failure, besides saying it. */
export type AfterFailure = 'none' | 'finish' | 'look_again' | 'pick_again' | 'words_again';

export interface BackupFailure {
    key: string;
    detail: string;
    after: AfterFailure;
}

/** `context: 'restore'` words the shared refusals for the restore
 *  screen (a running setup blocks a restore, not a backup). */
export function backupFailure(e: unknown, context: 'backup' | 'restore' = 'backup'): BackupFailure {
    const detail = rawErrorText(e);
    switch (classifyPublisherError(e)) {
        case 'E_BACKUP_NOT_A_BACKUP':
            return { key: 'pub.backup.err.not_a_backup', detail, after: 'pick_again' };
        case 'E_BACKUP_READ_FAILED':
            return { key: 'pub.backup.err.read_failed', detail, after: 'pick_again' };
        case 'E_RESTORE_FAILED':
            // One transaction, rolled back: the preview and its button stay.
            return { key: 'pub.backup.err.restore_failed', detail, after: 'none' };
        case 'E_BACKUP_DAMAGED':
            return { key: 'pub.backup.err.damaged', detail, after: 'pick_again' };
        case 'E_BACKUP_NEWER':
            return { key: 'pub.backup.err.newer', detail, after: 'pick_again' };
        case 'E_BACKUP_WORDS_INVALID':
            return { key: 'pub.backup.err.words_invalid', detail, after: 'words_again' };
        case 'E_BACKUP_WRONG_WORDS':
            return { key: 'pub.backup.err.wrong_words', detail, after: 'words_again' };
        case 'E_RESTORE_WOULD_REPLACE':
        case 'E_RESTORE_STATE_CHANGED':
            return { key: 'pub.backup.err.changed', detail, after: 'look_again' };
        case 'E_RESTORE_UNFINISHED':
            return { key: 'pub.backup.err.unfinished', detail, after: 'finish' };
        case 'E_BACKUP_SAVE_FAILED':
            return { key: 'pub.backup.err.save_failed', detail, after: 'none' };
        case 'E_BACKUP_NO_WORDS':
            return { key: 'pub.backup.err.no_words', detail, after: 'none' };
        case 'E_BACKUP_NOTHING':
            return { key: 'pub.backup.err.nothing', detail, after: 'none' };
        case 'E_BACKUP_SECRET_UNREADABLE':
            return { key: 'pub.backup.blocked.secret_unreadable', detail, after: 'none' };
        case 'E_SETUP_RUNNING':
            return {
                key: context === 'restore' ? 'pub.restore.blocked.setup_running' : 'pub.backup.blocked.setup_running',
                detail,
                after: 'none',
            };
        case 'E_BACKUP_WORDS_MISMATCH':
            return { key: 'pub.backup.words.mismatch.any', detail, after: 'none' };
        default:
            return { key: failureKey(e), detail, after: 'none' };
    }
}

// ---- restore ------------------------------------------------------------

/** "Made on {date}. It has {n} relays ({names}) and {m} people." */
export function previewText(t: (k: string) => string, madeAt: number, c: BackupContents): string {
    const live = liveRelays(c);
    return fill(t('pub.restore.preview'), {
        date: dayLabel(madeAt),
        n: live.length,
        names: relayNames(live),
        m: c.people_total,
        relays: relaysCount(t, live.length),
        people: peopleCount(t, c.people_total),
    });
}

/** Which providers a "new hosting key" sheet asks for, each with the
 *  relays that use it. */
export function providersOf(notice: RestoreNotice): { provider: string; relays: RelayLine[] }[] {
    const by = new Map<string, RelayLine[]>();
    for (const r of notice.relays) {
        if (r.status === 'decommissioned' || !r.provider) continue;
        const list = by.get(r.provider) ?? [];
        list.push(r);
        by.set(r.provider, list);
    }
    return [...by.entries()].map(([provider, relays]) => ({ provider, relays }));
}

/** The harness and the tests: one status per card. */
export function backupStatusFixture(over: Partial<BackupStatus> = {}): BackupStatus {
    const relays: RelayLine[] = [
        {
            id: 1,
            nickname: 'Bahar',
            public_ip: '203.0.113.7',
            status: 'provisioned',
            provider: 'hetzner',
            people: 3,
            removed_people: 1,
            has_hosting_key: true,
        },
    ];
    return {
        has_publisher_data: true,
        words_set: false,
        last_backup_at_unix: 0,
        stale: false,
        contents: {
            relays,
            people_total: 3,
            files: 6,
            includes_hosting_key: true,
            unfinished_setups: 0,
        },
        blocked: '',
        blocked_detail: '',
        restore_pending: false,
        restore_notice: null,
        ...over,
    };
}

export function restoreNoticeFixture(over: Partial<RestoreNotice> = {}): RestoreNotice {
    return {
        restored_at_unix: 1_763_546_400,
        backup_made_at_unix: 1_763_460_000,
        relays: backupStatusFixture().contents.relays,
        has_refresh_keys: false,
        ...over,
    };
}
