// rotateTlsVerdict — what the app says after a disguise change.
//
// The backend decides who needs a new file (`needs_file`). That answer
// is computed from what the relay's signed file COMMITS to. When the
// re-sign that follows a disguise change fails, the backend can be left
// with nothing to read (or with the old commitment), fall through to
// its first branch, and answer `nobody` — and the screen then said
// "Nothing in the files people hold has changed. Nobody needs a new
// file." directly above a warning that signing had failed. The comforting
// sentence won, because it was first and in the default colour.
//
// `nobody` is only a fact when the file was signed again, or when there
// was nothing to sign. So when the re-sign was attempted and failed,
// this never repeats `nobody`: it says what happened and what to do.

import type { RotateTlsSummary } from './wizardCommands';

type Summary = Pick<
    RotateTlsSummary,
    | 'needs_file'
    | 'pack_resigned'
    | 'refresh_note_published'
    | 'live_recipients'
    | 'shared_pack_stale'
    | 'warnings'
>;

export interface RotateTlsVerdict {
    /** i18n key of the headline sentence. */
    verdictKey: string;
    /** Whether the headline is bad news (drawn in red). */
    alarming: boolean;
    /** i18n key of "why it is not reaching people by itself", or null. */
    whyKey: string | null;
    /** i18n key of what the operator should do next, or null. */
    nextKey: string | null;
    /** Show "one step is yours: put the signed file at the download
     *  address". Only when a note actually went out. */
    showUpload: boolean;
    /** Show "files saved on this device were made before the change". */
    showLocalFiles: boolean;
}

/** The backend's own words when the re-sign leg failed
 *  (relay_rotation.rs). Matched only as a second signal, for the case
 *  where nobody holds a file yet but a signed file existed. */
const SIGN_FAILED_WARNING = /signing the relay's file again failed/i;

/** Was the relay's file left un-signed although there was one to sign?
 *
 *  `pack_resigned === false` alone is not enough: a relay with nothing
 *  signed yet has nothing to re-sign, and for it `nobody` is true. The
 *  re-sign was needed when someone holds a file made from it (a person,
 *  or an everyone-file on disk), or when the backend says in so many
 *  words that it tried. */
export function resignFailed(s: Summary): boolean {
    if (s.pack_resigned) return false;
    if (s.live_recipients > 0 || s.shared_pack_stale) return true;
    return (s.warnings ?? []).some((w) => SIGN_FAILED_WARNING.test(w));
}

export function rotateTlsVerdict(s: Summary, mirrorsInPack: number): RotateTlsVerdict {
    const failed = resignFailed(s);
    const base = 'pub.danger.rotate_tls.done';

    // The one case this file exists for.
    if (failed && s.needs_file === 'nobody') {
        return {
            verdictKey: `${base}.verdict.sign_failed`,
            alarming: true,
            whyKey: null,
            nextKey: `${base}.sign_failed.next`,
            showUpload: false,
            showLocalFiles: true,
        };
    }

    const notReaching =
        s.needs_file === 'one_route_until_new_file' || s.needs_file === 'everyone';
    const whyKey = !notReaching
        ? null
        : !s.pack_resigned
          ? `${base}.why.not_signed`
          : mirrorsInPack > 0 && !s.refresh_note_published
            ? `${base}.why.note_not_published`
            : `${base}.why.no_refresh_address`;

    return {
        verdictKey: `${base}.verdict.${s.needs_file}`,
        alarming: s.needs_file === 'everyone',
        whyKey,
        nextKey: failed ? `${base}.sign_failed.next` : null,
        showUpload: s.refresh_note_published && s.needs_file !== 'nobody',
        showLocalFiles:
            (s.live_recipients > 0 || s.shared_pack_stale) && s.needs_file !== 'nobody',
    };
}
