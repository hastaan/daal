// destroyReport — reading a DestroyReport (D4): does anything Daal
// reserved still cost money? Pure, shared by the relay list, the
// recovery card and the wizard.

import type { DestroyReport, ReleaseAddressResult } from './wizardCommands';

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
    // `in_use` is the relay's own address: kept on purpose, not a leftover.
    return (
        retryNeeded(report) ||
        (report.addresses ?? []).some((a) => a.code !== 'released' && a.code !== 'in_use')
    );
}

/** Which call gives back the addresses a relay card says still bill —
 *  and whether there is one at all.
 *   decommissioned — the relay was deleted except for the address:
 *                    the same delete again (idempotent once the
 *                    server is gone).
 *   pre-provision  — "Delete this server" of an unfinished setup: the
 *                    same removal again, which KEEPS the relay.
 *   provisioned    — a working relay (PA-1). Its delete would take the
 *                    live server and everyone on it, so the retry is
 *                    `releaseAddress` for each listed address, which
 *                    never touches the server.
 *   anything else  — no button: the card only says it still costs money. */
export type ReleaseRetry = 'relay_destroy' | 'setup_remove_server' | 'release_address' | null;

export function releaseRetryFor(status: string): ReleaseRetry {
    if (status === 'decommissioned') return 'relay_destroy';
    if (status === 'pre-provision') return 'setup_remove_server';
    if (status === 'provisioned') return 'release_address';
    return null;
}

export interface ReleaseDeps {
    relayDestroy: (op: number, deleteServer: boolean) => Promise<DestroyReport>;
    setupRemoveServer: (op: number) => Promise<DestroyReport>;
}

/** PA-1: give back each listed address of a live relay, one by one.
 *  One that fails does not stop the others; a thrown error (an old
 *  helper: E_DEPLOY_TOO_OLD) is the caller's to explain. */
export async function releaseLiveAddresses(
    op: { id: number },
    addresses: string[],
    releaseAddress: (op: number, address: string) => Promise<ReleaseAddressResult>,
): Promise<ReleaseAddressResult[]> {
    const out: ReleaseAddressResult[] = [];
    for (const a of addresses) out.push(await releaseAddress(op.id, a));
    return out;
}

/** True when any address of a live-relay release still costs money. */
export function releaseStillBills(results: ReleaseAddressResult[]): boolean {
    return results.some((r) => r.code === 'still_attached' || r.code === 'release_failed');
}

/** The sentence for one live-relay release outcome. */
export function releaseResultKey(code: ReleaseAddressResult['code']): string {
    switch (code) {
        case 'released':
            return 'pub.relays.release.released';
        case 'in_use':
            return 'pub.relays.release.in_use';
        case 'not_daal':
            return 'pub.relays.release.not_daal';
        case 'still_attached':
            return 'pub.relays.release.still_attached';
        default:
            return 'pub.relays.release.release_failed';
    }
}

/** Run a delete-shaped retry `releaseRetryFor` picked; null when there is
 *  none, and null for a live relay — that one is `releaseLiveAddresses`,
 *  never a delete. */
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
