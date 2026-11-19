// setupRecovery — what to say, and what to offer, when a setup was
// interrupted (D1).
//
// The app can be killed after the hosting company has started billing
// for a server and before anything was written to the relay row. The
// shell keeps a setup journal and can ask the account what is there;
// this module turns its answer (`SetupRecovery`) into one card: a plain
// sentence that says truthfully what exists and whether it costs
// money, and the buttons that are safe for exactly that state.
//
// Pure on purpose: the wizard renders it, the tests drive it, and the
// one function with side effects (`performRecovery`) takes the commands
// it calls as an argument so a test can see which one it chose.

import type { DestroyReport, SetupRecovery } from './wizardCommands';
import { retryNeeded } from './destroyReport';

export type RecoveryButton =
    /** Rent a server and set it up (nothing exists yet). */
    | 'start'
    /** Ask the account again. */
    | 'check_again'
    /** The server finished while the app was closed: save it. */
    | 'continue'
    /** Re-use the server that already exists (no second one rented). */
    | 'finish_here'
    /** Delete the server and what was made with it; keep the relay. */
    | 'delete_server'
    /** Delete it, then rent a new one (hosting cannot finish in place). */
    | 'delete_and_rebuild'
    /** Delete it and stop: the relay goes too. */
    | 'delete_and_stop'
    /** The person's own server: carry on setting it up. */
    | 'finish_yours'
    /** Nothing bills: start again (rents a server). */
    | 'start_again'
    /** Could not look: try to delete whatever was made. */
    | 'delete_whatever';

/** Buttons that delete something. Each goes through a confirm that
 *  names what will be deleted. */
export const DESTRUCTIVE: ReadonlySet<RecoveryButton> = new Set<RecoveryButton>([
    'delete_server',
    'delete_and_rebuild',
    'delete_and_stop',
    'delete_whatever',
]);

export interface RecoveryView {
    /** Headline sentence key. */
    titleKey: string;
    /** Further sentences, in order. */
    bodyKeys: string[];
    /** Primary first. */
    buttons: RecoveryButton[];
    /** True when something is (or may be) costing money right now. */
    billing: boolean;
}

/** Why the account could not be checked, in plain words. */
export function checkErrorKey(code: SetupRecovery['check_error']): string {
    switch (code) {
        case 'no_token':
            return 'pub.setup.recover.why.no_token';
        case 'offline':
            return 'pub.setup.recover.why.offline';
        case 'account_unreadable':
            return 'pub.setup.recover.why.account_unreadable';
        case 'custody_locked':
            return 'pub.setup.recover.why.custody_locked';
        default:
            return 'pub.setup.recover.why.failed';
    }
}

/** `null` means the question is still out. */
export function recoveryView(rec: SetupRecovery | null): RecoveryView {
    if (rec === null) {
        return { titleKey: 'pub.setup.recover.loading', bodyKeys: [], buttons: [], billing: false };
    }
    switch (rec.state) {
        case 'none':
            return { titleKey: 'pub.setup.recover.none', bodyKeys: [], buttons: ['start'], billing: false };
        case 'running':
            return {
                titleKey: 'pub.setup.recover.running',
                bodyKeys: [],
                buttons: ['check_again'],
                billing: true,
            };
        case 'finished_unsaved':
            return {
                titleKey: 'pub.setup.recover.finished_unsaved',
                bodyKeys: ['pub.setup.recover.finished_unsaved.body'],
                buttons: ['continue'],
                billing: true,
            };
        case 'server_running':
            if (rec.server_origin === 'yours') {
                return {
                    titleKey: 'pub.setup.recover.yours',
                    bodyKeys: ['pub.setup.recover.yours.body'],
                    buttons: ['finish_yours'],
                    billing: true,
                };
            }
            // "started {date}" only when the journal gave a date.
            const runningTitle = rec.started_at_unix
                ? 'pub.setup.recover.server_running'
                : 'pub.setup.recover.server_running.nodate';
            if (rec.can_finish_here) {
                return {
                    titleKey: runningTitle,
                    bodyKeys: ['pub.setup.recover.server_running.body'],
                    buttons: ['finish_here', 'delete_server'],
                    billing: true,
                };
            }
            return {
                titleKey: runningTitle,
                bodyKeys: ['pub.setup.recover.cannot_finish_here'],
                buttons: ['delete_and_rebuild', 'delete_and_stop'],
                billing: true,
            };
        case 'nothing_billing':
            // The server is gone, but the account still holds something
            // Daal reserved that bills (an address whose release failed).
            // "Nothing is costing money" would be false: say what is
            // left, and offer to delete it before renting again.
            if (rec.billing !== 'no' || rec.leftovers.some((l) => l.billing)) {
                return {
                    titleKey: 'pub.setup.recover.address_kept',
                    bodyKeys: ['pub.setup.recover.address_kept.body'],
                    buttons: ['delete_server', 'start_again'],
                    billing: true,
                };
            }
            return {
                titleKey: 'pub.setup.recover.nothing_billing',
                bodyKeys: ['pub.setup.recover.start_again.body'],
                buttons: ['start_again'],
                billing: false,
            };
        case 'unknown':
        default:
            return {
                titleKey: 'pub.setup.recover.unknown',
                bodyKeys: [checkErrorKey(rec.check_error)],
                buttons: ['check_again', 'delete_whatever'],
                billing: true,
            };
    }
}

export function buttonKey(b: RecoveryButton): string {
    return `pub.setup.recover.btn.${b}`;
}

/** The handle a person can match against their hosting account. */
export function serverWhere(rec: SetupRecovery): string {
    return rec.public_ip || rec.server_id || '';
}

/** The confirm sentence for a destructive button: what goes, and —
 *  for the one that rents again — that a new server is rented. */
export function confirmKey(b: RecoveryButton): string {
    switch (b) {
        case 'delete_and_rebuild':
            return 'pub.setup.recover.confirm.delete_and_rebuild';
        case 'delete_and_stop':
            return 'pub.setup.recover.confirm.delete_and_stop';
        case 'delete_whatever':
            return 'pub.setup.recover.confirm.delete_whatever';
        default:
            return 'pub.setup.recover.confirm.delete_server';
    }
}

/** What a recovery button led to, so the wizard knows what to show. */
export type RecoveryResult =
    | { kind: 'build' }
    | { kind: 'requery' }
    /** A delete ran; `report` says what is gone. `relayGone` means the
     *  relay row itself was removed and the wizard should leave. */
    | { kind: 'deleted'; report: DestroyReport; relayGone: boolean; thenBuild: boolean };

export interface RecoveryDeps {
    runBuild: (existingServerId?: string) => Promise<void> | void;
    setupRemoveServer: (op: number) => Promise<DestroyReport>;
    relayDestroy: (op: number, deleteServer: boolean, deleteOwnServer?: boolean) => Promise<DestroyReport>;
    /** Remember (or forget, with null) the server the next build is to
     *  finish on. Every button sets it: an id chosen by an earlier press
     *  must never ride along into a build it was not chosen for — after
     *  its server was deleted it would make every build fail. */
    setExisting: (serverId: string | null) => void;
}

/** Carry out one (already confirmed) recovery button. */
export async function performRecovery(
    b: RecoveryButton,
    op: number,
    rec: SetupRecovery,
    deps: RecoveryDeps,
): Promise<RecoveryResult> {
    switch (b) {
        case 'start':
        case 'continue':
        case 'start_again':
            deps.setExisting(null);
            await deps.runBuild();
            return { kind: 'build' };
        case 'finish_here':
        case 'finish_yours':
            // The id the shell found: Hetzner re-images that same
            // server (same address, same bill) once its labels prove
            // it is this relay's; a person's own server is set up in
            // place as on the first run.
            deps.setExisting(rec.server_id || null);
            await deps.runBuild(rec.server_id || undefined);
            return { kind: 'build' };
        case 'check_again':
            return { kind: 'requery' };
        case 'delete_server': {
            deps.setExisting(null);
            const report = await deps.setupRemoveServer(op);
            return { kind: 'deleted', report, relayGone: false, thenBuild: false };
        }
        case 'delete_and_rebuild': {
            deps.setExisting(null);
            const report = await deps.setupRemoveServer(op);
            // Rent the new one only when the old one is proven gone AND
            // nothing Daal reserved still bills — otherwise the person
            // pays for two, or the "still costs money" line would vanish
            // the moment the build starts. The card stays up with its
            // Try again.
            const thenBuild = report.server_deleted && !retryNeeded(report);
            if (thenBuild) await deps.runBuild();
            return { kind: 'deleted', report, relayGone: false, thenBuild };
        }
        case 'delete_and_stop':
        case 'delete_whatever': {
            deps.setExisting(null);
            const report = await deps.relayDestroy(op, true);
            return { kind: 'deleted', report, relayGone: report.local_removed, thenBuild: false };
        }
    }
}

/** What the wizard does once a recovery button has run.
 *   requery — ask the shell again (the relay is still being set up);
 *   leave   — the press deleted the relay itself (or left it only to
 *             release an address): the card shows the report and a
 *             Done that leaves the wizard. Asking again here would read
 *             "nothing rented yet — Start" for a relay being deleted. */
export function afterRecovery(
    b: RecoveryButton,
    res: RecoveryResult,
): { requery: boolean; leave: boolean } {
    if (res.kind === 'requery') return { requery: true, leave: false };
    if (res.kind !== 'deleted') return { requery: false, leave: false };
    if (b === 'delete_and_stop' || b === 'delete_whatever') return { requery: false, leave: true };
    return { requery: !res.thenBuild, leave: false };
}

/** After a build that was told to finish on an existing server failed:
 *  which server id the next build may still use.
 *   - Daal's own server (finish_here): a failed adopt is rolled back,
 *     which deletes that server — the id now names nothing, and every
 *     later build would fail on it. Forget it; a retry without it is
 *     refused by the shell if the server does exist (E_SERVER_EXISTS)
 *     and lands back on the card, so nothing is rented twice.
 *   - the person's own server (finish_yours): never rolled back, still
 *     theirs. Keep it, or a retry would rent a new one. */
export function existingAfterFailure(
    existing: string | null,
    origin: 'created' | 'yours' | '' | null,
): string | null {
    if (!existing) return null;
    return origin === 'yours' ? existing : null;
}

/** Is the shell missing the recovery command altogether (an app whose
 *  shell predates it)? Only then may the wizard fall back to the old
 *  consent card; any other failure is "could not check". */
export function isMissingCommand(e: unknown): boolean {
    const s = String(e ?? '');
    return /command\s+\S+\s+not\s+found/i.test(s) || /unknown command/i.test(s);
}

/** What the card shows when the question itself failed. */
export function recoveryCheckFailed(e: unknown): SetupRecovery {
    return recoveryFixture('unknown', {
        provider: '',
        check_error: 'failed',
        started_at_unix: 0,
        details: [String(e)],
    });
}

// ---- Cancel ----------------------------------------------------------

/** What "Cancel" does for this relay.
 *   local       — nothing was rented (or Daal cannot reach the account):
 *                 forget the unfinished relay, as before.
 *   delete      — delete everything this setup made, then the relay.
 *   yours_choice— the person's own server: delete it, or keep it.
 *   wait        — a setup is still running; deleting now would race it. */
export type CancelPlan = 'local' | 'delete' | 'yours_choice' | 'wait';

export function cancelPlan(rec: SetupRecovery | null): CancelPlan {
    if (!rec || rec.state === 'none') return 'local';
    if (rec.check_error === 'no_token') return 'local';
    if (rec.state === 'running') return 'wait';
    if (rec.server_origin === 'yours') return 'yours_choice';
    return 'delete';
}

export function cancelBodyKey(rec: SetupRecovery): string {
    switch (rec.state) {
        case 'running':
            return 'pub.setup.cancel.body.running';
        case 'nothing_billing':
            return rec.billing !== 'no' || rec.leftovers.some((l) => l.billing)
                ? 'pub.setup.cancel.body.address_kept'
                : 'pub.setup.cancel.body.nothing_billing';
        case 'unknown':
            return 'pub.setup.cancel.body.unknown';
        default:
            return rec.server_origin === 'yours'
                ? 'pub.setup.cancel.body.yours'
                : 'pub.setup.cancel.body.server_running';
    }
}

/** Cancel and delete. The person's own server goes only when they chose
 *  "Delete my server" (`yours_choice`). The report is for the sheet to
 *  show; `relayGone` says the wizard must leave once it is read. */
export async function cancelDelete(
    op: number,
    plan: CancelPlan,
    relayDestroy: RecoveryDeps['relayDestroy'],
): Promise<{ report: DestroyReport; relayGone: boolean }> {
    const report = await relayDestroy(op, true, plan === 'yours_choice');
    return { report, relayGone: report.local_removed };
}

export function kindKey(kind: string): string {
    switch (kind) {
        case 'server':
            return 'pub.account.kind.server';
        case 'floating-ip':
            return 'pub.account.kind.floating_ip';
        case 'ssh-key':
            return 'pub.account.kind.ssh_key';
        case 'firewall':
            return 'pub.account.kind.firewall';
        default:
            return 'pub.account.kind.other';
    }
}

/** The harness and the tests: one fixture per state. */
export function recoveryFixture(
    state: SetupRecovery['state'],
    over: Partial<SetupRecovery> = {},
): SetupRecovery {
    const running = state === 'server_running' || state === 'finished_unsaved';
    return {
        state,
        provider: 'hetzner',
        server_origin: running ? 'created' : '',
        can_finish_here: state === 'finished_unsaved' || state === 'server_running',
        server_id: running ? '123' : '',
        public_ip: running ? '203.0.113.7' : '',
        billing: running ? 'yes' : state === 'nothing_billing' ? 'no' : 'unknown',
        leftovers: running
            ? [{ kind: 'server', id: '123', name: 'daal-fsn1-0011223344556677', billing: true }]
            : [],
        check_error: state === 'unknown' ? 'offline' : '',
        started_at_unix: state === 'none' ? 0 : 1_763_546_400,
        details: [],
        ...over,
    };
}
