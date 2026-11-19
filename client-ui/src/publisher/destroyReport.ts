// destroyReport — reading a DestroyReport (D4): does anything Daal
// reserved still cost money? Pure, shared by the relay list, the
// recovery card and the wizard.

import type { DestroyReport } from './wizardCommands';

/** True when an address is known to still cost money because Daal's own
 *  release did not go through — the case "Try again" exists for. */
export function retryNeeded(report: DestroyReport): boolean {
    return (
        report.retry_needed === true ||
        (report.addresses ?? []).some((a) => a.code === 'release_failed')
    );
}

/** True when anything reported still costs money: a failed release, an
 *  address still attached to another server, or one the person reserved
 *  themselves. "The billing has stopped" is said only when this is false. */
export function stillBills(report: DestroyReport): boolean {
    return retryNeeded(report) || (report.addresses ?? []).some((a) => a.code !== 'released');
}

/** Which call gives back the addresses a relay card says still bill —
 *  and whether there is one at all.
 *   decommissioned — the relay was deleted except for the address:
 *                    the same delete again (idempotent once the
 *                    server is gone).
 *   pre-provision  — "Delete this server" of an unfinished setup: the
 *                    same removal again, which KEEPS the relay.
 *   anything else  — a working relay. Its delete would take the live
 *                    server and everyone on it, so no button: the card
 *                    only says the address still costs money. */
export type ReleaseRetry = 'relay_destroy' | 'setup_remove_server' | null;

export function releaseRetryFor(status: string): ReleaseRetry {
    if (status === 'decommissioned') return 'relay_destroy';
    if (status === 'pre-provision') return 'setup_remove_server';
    return null;
}

export interface ReleaseDeps {
    relayDestroy: (op: number, deleteServer: boolean) => Promise<DestroyReport>;
    setupRemoveServer: (op: number) => Promise<DestroyReport>;
}

/** Run the retry `releaseRetryFor` picked; null when there is none. */
export async function retryRelease(
    op: { id: number; status: string },
    deps: ReleaseDeps,
): Promise<DestroyReport | null> {
    switch (releaseRetryFor(op.status)) {
        case 'relay_destroy':
            return deps.relayDestroy(op.id, true);
        case 'setup_remove_server':
            return deps.setupRemoveServer(op.id);
        default:
            return null;
    }
}
