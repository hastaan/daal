// listDelete — PA-7: the relay list's delete for an unfinished setup.
//
// The list's delete sheet offers "forget it" or "delete the server" and
// never passes "delete my own server", so for a setup on the person's
// own server the shell (correctly) left their server alone — and the
// report then said the server was gone. Now, for an unfinished relay,
// the list first asks the same question the wizard's Cancel asks
// (`setupRecovery` → `cancelPlan`):
//
//   yours_choice — "Delete my server" / "Keep my server"
//   wait         — a setup is still running: nothing is deleted
//   delete       — today's delete sheet (rented server, deleted)
//   local        — today's delete sheet (nothing rented, or no token)
//
// A failed look with a token stored is "could not check" (the wizard's
// `recoveryCheckFailed`), never a local-only forget.

import type { DestroyReport, OperatorSummary, SetupRecovery } from './wizardCommands';
import { cancelPlan, recoveryCheckFailed } from './setupRecovery';

export type ListDelete =
    | { kind: 'destroy' }
    | { kind: 'choice'; rec: SetupRecovery }
    | { kind: 'wait'; rec: SetupRecovery };

export async function listDeleteFor(
    op: Pick<OperatorSummary, 'id' | 'status' | 'has_cloud_token'>,
    setupRecovery: (id: number) => Promise<SetupRecovery>,
): Promise<ListDelete> {
    if (op.status !== 'pre-provision') return { kind: 'destroy' };
    let rec: SetupRecovery | null;
    try {
        rec = await setupRecovery(op.id);
    } catch (e) {
        rec = op.has_cloud_token === true ? recoveryCheckFailed(e) : null;
    }
    switch (cancelPlan(rec)) {
        case 'yours_choice':
            return { kind: 'choice', rec: rec! };
        case 'wait':
            return { kind: 'wait', rec: rec! };
        default:
            return { kind: 'destroy' };
    }
}

type Destroy = (op: number, deleteServer: boolean, deleteOwnServer?: boolean) => Promise<DestroyReport>;

/** "Delete my server": the only path that may take the person's own server. */
export function deleteMine(op: number, relayDestroy: Destroy): Promise<DestroyReport> {
    return relayDestroy(op, true, true);
}

/** "Keep my server": forget the relay on this phone; the server is not
 *  touched and "delete my own server" is never passed. */
export function keepMine(op: number, relayDestroy: Destroy): Promise<DestroyReport> {
    return relayDestroy(op, false);
}
