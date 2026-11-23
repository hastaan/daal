// refile — "New files for everyone" (wave 2, owner-approved leftover 3).
//
// After a person is removed, the relay's standby code goes back to its
// plain form until every remaining person has a new file
// (daal-wizard/src/addon_standby.rs: the update generation moves on a
// removal). One calm action makes each remaining person's file again
// (daal-wizard/src/refile.rs, one relay window) and then lets the
// publisher send them one by one.
//
// Pure: when to offer it, and what each row of the list says.
import type { AddonRow } from '../addons/addonTypes';
import type { RefileItem, RefileReport } from '../wizardCommands';

/** The relay has a standby address whose code a person would be sent,
 *  or an update-note switch on (GitHub, DNS): after a removal, notes are
 *  written only for the newest files, and a file made before a switch
 *  went on does not know where to look. */
export function hasStandby(addons: readonly AddonRow[] | null | undefined): boolean {
    return (addons ?? []).some(
        (a) =>
            (a.kind === 'standby' && (a.state === 'ready' || a.state === 'promoted')) ||
            ((a.kind === 'gittag' || a.kind === 'dnsnote') && a.state === 'ready'),
    );
}

/** Why new files are wanted: the standby code (a standby address is
 *  held), or only the update switches (a note switch on, no standby). */
export function refileReason(addons: readonly AddonRow[] | null | undefined): 'code' | 'updates' {
    const rows = addons ?? [];
    const standby = rows.some((a) => a.kind === 'standby' && (a.state === 'ready' || a.state === 'promoted'));
    const notes = rows.some((a) => (a.kind === 'gittag' || a.kind === 'dnsnote') && a.state === 'ready');
    return !standby && notes ? 'updates' : 'code';
}

export interface OfferFacts {
    /** A standby address exists (hasStandby). */
    standby: boolean;
    /** The relay has a file for everyone: its code is always plain. */
    everyone: boolean;
    /** People not removed. */
    current: number;
}

/** "New files for everyone" is offered (the people ⋯ menu) when it can
 *  change something: a standby code to protect, no file for everyone,
 *  and at least one person left. */
export function refileAvailable(f: OfferFacts): boolean {
    return f.standby && !f.everyone && f.current > 0;
}

/** Right after a removal, the calm card offers it when the code went
 *  plain (`form` from Addons.standbyKey; unknown counts as plain). */
export function refileNudge(f: OfferFacts, form: 'wrapped' | 'plain' | undefined): boolean {
    return refileAvailable(f) && form !== 'wrapped';
}

/** One person in the list after the files were made. */
export interface RefileRow {
    id: number;
    label: string;
    /** `ready`: a new file to send; `failed`: no new file (retry);
     *  `waiting`: restored from a backup and not answered for. */
    state: 'ready' | 'failed' | 'waiting';
    path: string;
    /** The plain reason, an i18n key, for `failed` and `waiting`. */
    reasonKey?: string;
}

/** The renew sheet's reasons are the same words (pub.renew.reason.*). */
function reasonKey(i: RefileItem): string {
    if (i.status === 'needs_answer') return 'pub.renew.reason.needs_answer';
    switch (i.reason) {
        case 'relay_unreachable':
        case 'relay_full':
        case 'relay_too_old':
        case 'file_write_failed':
        case 'signing_failed':
            return `pub.renew.reason.${i.reason}`;
        default:
            return 'pub.renew.reason.other';
    }
}

/** What the person is called: the name the publisher gave, else the
 *  relay's, as the people list does (PeopleSection personLabel). */
export function itemLabel(i: Pick<RefileItem, 'display_name' | 'name' | 'recipient_id'>): string {
    return i.display_name || i.name || `#${i.recipient_id}`;
}

export function refileRows(report: RefileReport): RefileRow[] {
    return report.items.map((i) => {
        const label = itemLabel(i);
        if (i.status === 'done' && i.sbpx_path) return { id: i.recipient_id, label, state: 'ready', path: i.sbpx_path };
        if (i.status === 'needs_answer') return { id: i.recipient_id, label, state: 'waiting', path: '', reasonKey: reasonKey(i) };
        return { id: i.recipient_id, label, state: 'failed', path: '', reasonKey: reasonKey(i) };
    });
}

/** Everyone who could get a new file has been sent theirs. */
export function allHandled(rows: readonly RefileRow[], handled: ReadonlySet<number>): boolean {
    const ready = rows.filter((r) => r.state === 'ready');
    return ready.length > 0 && ready.every((r) => handled.has(r.id));
}
