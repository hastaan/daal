// renew — "Renew everyone's files" after the relay got a new server (D2).
//
// A rebuild puts the relay on a new machine that has never heard of the
// people on it, so every file handed out stops working. One action
// re-creates every person who still has access on the new server and
// rewrites their files; people whose access was removed stay removed
// (the shell only ever sends them a removal). It is safe to press
// twice: whoever already has a file from the first press is left alone.

import type { OperatorSummary, RecipientSummary, RelayHealth, RenewEvent, RenewItem, RenewReport } from './wizardCommands';

/** Whether the "the server is new" banner shows. */
export function renewBannerVisible(
    op: Pick<OperatorSummary, 'status' | 'people_needing_renewal'> | null,
    health: Pick<RelayHealth, 'people_missing' | 'everyone_missing'> | null,
    justRebuilt: boolean,
): boolean {
    if (!op || op.status !== 'provisioned') return false;
    if (justRebuilt) return true;
    if ((op.people_needing_renewal ?? 0) > 0) return true;
    if ((health?.people_missing ?? 0) > 0) return true;
    return health?.everyone_missing === true;
}

/** What the banner may claim. Only a rebuild (seen here, or a marker
 *  the shell counts) is "the server is new"; a health check that found
 *  people missing says how many, nothing more. */
export interface RenewBannerText {
    key: string;
    n: number;
}

export function renewBannerText(
    op: Pick<OperatorSummary, 'people_needing_renewal'> | null,
    health: Pick<RelayHealth, 'people_missing' | 'everyone_missing'> | null,
    justRebuilt: boolean,
): RenewBannerText {
    if (justRebuilt || (op?.people_needing_renewal ?? 0) > 0) {
        return { key: 'pub.renew.banner', n: 0 };
    }
    const n = health?.people_missing ?? 0;
    if (n > 0) return { key: n === 1 ? 'pub.renew.banner.missing_one' : 'pub.renew.banner.missing', n };
    return { key: 'pub.renew.banner.everyone_missing', n: 0 };
}

export function statusKey(s: RenewItem['status'] | 'working'): string {
    return `pub.renew.status.${s}`;
}

export function reasonKey(r: RenewItem['reason']): string {
    return r ? `pub.renew.reason.${r}` : '';
}

/** The people the confirm names: everyone whose access was not removed. */
export function renewTargets(recipients: RecipientSummary[]): RecipientSummary[] {
    return recipients.filter((r) => r.revoked_at_unix === 0);
}

/** Live progress, keyed by recipient id ("everyone" for the shared file). */
export type RenewProgress = Record<string, RenewEvent['status']>;

export function progressKey(recipient_id: number | null): string {
    return recipient_id == null ? 'everyone' : String(recipient_id);
}

export function applyRenewEvent(p: RenewProgress, ev: RenewEvent, operatorId: number): RenewProgress {
    if (ev.operator_id !== operatorId) return p;
    return { ...p, [progressKey(ev.recipient_id)]: ev.status };
}

/** Results to list: people first, then the everyone file. Revoked
 *  people the server no longer knew are left out by the shell. */
export function reportRows(r: RenewReport): RenewItem[] {
    return r.everyone_file ? [...r.items, r.everyone_file] : [...r.items];
}

export function rowOk(i: RenewItem): boolean {
    return i.status === 'done' || i.status === 'already_done';
}

export function renewFixture(over: Partial<RenewReport> = {}): RenewReport {
    return {
        operator_id: 1,
        items: [
            {
                recipient_id: 1,
                name: 'r1',
                display_name: 'Maman',
                status: 'done',
                reason: '',
                sbpx_path: '/stage/1.r1.sbpx',
                detail: '',
            },
            {
                recipient_id: 2,
                name: 'r2',
                display_name: 'Baba',
                status: 'already_done',
                reason: '',
                sbpx_path: '/stage/1.r2.sbpx',
                detail: '',
            },
            {
                recipient_id: 3,
                name: 'r3',
                display_name: 'Sara',
                status: 'failed',
                reason: 'relay_full',
                sbpx_path: '',
                detail: 'mgmt: 507 user cap reached',
            },
            {
                recipient_id: 4,
                name: 'r4',
                display_name: 'Old phone',
                status: 'removed_from_server',
                reason: '',
                sbpx_path: '',
                detail: '',
            },
        ],
        everyone_file: {
            recipient_id: null,
            name: 'r0',
            display_name: '',
            status: 'done',
            reason: '',
            sbpx_path: '',
            detail: '',
        },
        all_done: false,
        ...over,
    };
}
