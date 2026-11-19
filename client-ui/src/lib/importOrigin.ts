// How a publisher's routes reached this phone — remembered at the
// moment of the import, because nothing afterwards can tell.
//
// The Connections page badges each publisher row with where it came
// from. The engine's flat route projection does not carry that, so the
// page inferred it from the trust class, and its fallback was the word
// "pasted": on the second phone pass a file chosen with the file picker
// was labelled "pasted" (backlog PH-27). The add sheet KNOWS which lane
// an import came through, so it writes that down here, keyed by the
// publisher's fingerprint, and the badge uses it. Where nothing was
// written down (an import made before this existed, or on another
// install) the badge says only what is certain: it was added on this
// phone.
//
// Platform-side preference, like lib/prefs.ts: a fingerprint and one of
// four words. No secret, no route detail — but a fingerprint says whose
// file this phone held, so the record does not outlive what it is
// about: removing a publisher forgets its entry (forgetImportOrigin) and
// a panic wipe clears the lot (lib/localTraces.ts).
import type { SourceKind } from '../contract/D2Contract';

export type ImportOrigin = 'file' | 'sealed_file' | 'paste' | 'scan';

const KEY = 'daal.d2.import_origin';

function readAll(): Record<string, string> {
    try {
        const raw = localStorage.getItem(KEY);
        const v: unknown = raw ? JSON.parse(raw) : null;
        return v && typeof v === 'object' ? (v as Record<string, string>) : {};
    } catch {
        return {};
    }
}

function norm(fingerprintHex: string): string {
    return fingerprintHex.trim().toLowerCase();
}

/** Remember how this publisher's routes arrived. An empty fingerprint
 *  (the host did not say whose import it was) is not recorded. */
export function recordImportOrigin(fingerprintHex: string | undefined, origin: ImportOrigin): void {
    const k = norm(fingerprintHex ?? '');
    if (!k) return;
    try {
        const all = readAll();
        all[k] = origin;
        localStorage.setItem(KEY, JSON.stringify(all));
    } catch {
        /* no storage: the badge falls back to what is certain */
    }
}

/** The publisher was removed from this phone: what was written down
 *  about it goes too. */
export function forgetImportOrigin(publisherId: string): void {
    const k = norm(publisherId);
    if (!k) return;
    try {
        const all = readAll();
        if (!(k in all)) return;
        delete all[k];
        if (Object.keys(all).length === 0) localStorage.removeItem(KEY);
        else localStorage.setItem(KEY, JSON.stringify(all));
    } catch {
        /* no storage: nothing was kept */
    }
}

/** Panic wipe: every record of whose files this phone ever held. */
export function clearImportOrigins(): void {
    try {
        localStorage.removeItem(KEY);
    } catch {
        /* no storage: nothing was kept */
    }
}

export function importOriginOf(publisherId: string): ImportOrigin | undefined {
    const v = readAll()[norm(publisherId)];
    return v === 'file' || v === 'sealed_file' || v === 'paste' || v === 'scan' ? v : undefined;
}

/** i18n key of a publisher row's badge.
 *
 *  A subscription (or a mix with one) is known from the subscription
 *  list and keeps its badge. Otherwise the recorded lane decides. With
 *  nothing recorded, the trust-class guesses 'sbpx' / 'sbp' keep their
 *  badges (they describe the publisher's signature, not the lane), and
 *  the old fallback — which claimed "pasted" — says "added on this
 *  phone" instead. */
export function sourceBadgeKey(kind: SourceKind, origin: ImportOrigin | undefined): string {
    if (kind === 'subscription') return 'network.badge.subscription';
    if (kind === 'mixed') return 'network.badge.mixed';
    if (origin === 'sealed_file') return 'network.badge.sealed';
    if (origin === 'file') return 'network.badge.file';
    if (origin === 'paste') return 'network.badge.pasted';
    if (origin === 'scan') return 'network.badge.scanned';
    if (kind === 'sbpx') return 'network.badge.sealed';
    if (kind === 'sbp') return 'network.badge.signed';
    return 'network.badge.added';
}
