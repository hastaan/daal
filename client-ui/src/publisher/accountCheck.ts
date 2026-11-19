// accountCheck — "is anything of Daal's still running in my hosting
// account?" (D1).
//
// The rule the screen states once: Daal only offers to delete what it
// labelled as its own when it made it. Identification is by Daal's own
// labels and names, decided on the Rust/Go side; this module only sorts
// what came back into groups a person can read, and never makes an item
// deletable that the shell did not mark `can_delete` — nor any item at
// all when the account could not be read completely.

import type { AccountCheckAccount, AccountItem, ResourceRef } from './wizardCommands';

export type AccountGroup = 'billing_unused' | 'unfinished' | 'free_leftovers' | 'cannot_tell' | 'in_use';

export const GROUP_ORDER: AccountGroup[] = ['billing_unused', 'unfinished', 'free_leftovers', 'cannot_tell', 'in_use'];

export function groupOf(i: AccountItem): AccountGroup {
    switch (i.finding) {
        case 'not_on_this_phone':
        case 'second_server_for_relay':
            return 'billing_unused';
        case 'leftover':
            return i.billing ? 'billing_unused' : 'free_leftovers';
        case 'unfinished_setup':
            return 'unfinished';
        case 'yours_in_use':
            return 'in_use';
        case 'cannot_tell':
        default:
            return 'cannot_tell';
    }
}

export function groupItems(acc: AccountCheckAccount): Record<AccountGroup, AccountItem[]> {
    const out: Record<AccountGroup, AccountItem[]> = {
        billing_unused: [],
        unfinished: [],
        free_leftovers: [],
        cannot_tell: [],
        in_use: [],
    };
    for (const i of acc.items ?? []) out[groupOf(i)].push(i);
    return out;
}

/** Whether this item may get a checkbox at all. */
export function deletable(acc: AccountCheckAccount, i: AccountItem): boolean {
    if (!acc.complete) return false;
    if (!i.can_delete) return false;
    const g = groupOf(i);
    // Unfinished setups are handled on their own card (it can finish
    // them); in-use and cannot-tell are never offered here.
    return g === 'billing_unused' || g === 'free_leftovers';
}

export function refKey(r: ResourceRef): string {
    return `${r.kind}:${r.id}`;
}

/** Ticked by default: everything deletable. */
export function defaultSelection(acc: AccountCheckAccount): Set<string> {
    return new Set((acc.items ?? []).filter((i) => deletable(acc, i)).map(refKey));
}

export function selectedRefs(acc: AccountCheckAccount, sel: Set<string>): ResourceRef[] {
    return (acc.items ?? [])
        .filter((i) => deletable(acc, i) && sel.has(refKey(i)))
        .map((i) => ({ kind: i.kind, id: i.id }));
}

export function errorKey(code: AccountCheckAccount['error_code']): string {
    return code ? `pub.account.error.${code}` : '';
}

export function outcomeKey(code: string): string {
    return `pub.account.out.${code}`;
}

export function accountFixture(over: Partial<AccountCheckAccount> = {}): AccountCheckAccount {
    return {
        account_key: 'hetzner:1',
        provider: 'hetzner',
        relay_ids: [1, 2],
        complete: true,
        error_code: '',
        details: [],
        items: [
            { kind: 'server', id: '10', name: 'daal-fsn1-aa', address: '203.0.113.7', billing: true, verdict: 'in-use', finding: 'yours_in_use', belongs_to_relay_id: 1, can_delete: false },
            { kind: 'server', id: '11', name: 'daal-fsn1-bb', address: '203.0.113.8', billing: true, verdict: 'unclaimed', finding: 'not_on_this_phone', belongs_to_relay_id: null, can_delete: true },
            { kind: 'server', id: '12', name: 'daal-fsn1-aa', address: '203.0.113.9', billing: true, verdict: 'unclaimed', finding: 'second_server_for_relay', belongs_to_relay_id: 1, can_delete: true },
            { kind: 'floating-ip', id: '42', name: 'daal-fsn1-aa-fip', address: '198.51.100.9', billing: true, verdict: 'orphan', finding: 'leftover', belongs_to_relay_id: 1, can_delete: true },
            { kind: 'ssh-key', id: '901', name: 'daal-fsn1-aa-ephemeral', address: '', billing: false, verdict: 'orphan', finding: 'leftover', belongs_to_relay_id: 1, can_delete: true },
            { kind: 'server', id: '13', name: 'daal-fsn1-cc', address: '203.0.113.10', billing: true, verdict: 'unclaimed', finding: 'unfinished_setup', belongs_to_relay_id: 2, can_delete: false },
            { kind: 'server', id: '14', name: 'daal-fsn1-dd', address: '203.0.113.11', billing: true, verdict: 'unproven', finding: 'cannot_tell', belongs_to_relay_id: null, can_delete: true },
        ],
        ...over,
    };
}
