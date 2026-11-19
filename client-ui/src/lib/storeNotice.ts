// "Daal had to reset your saved connections" — said once.
//
// The engine reports `store_recovered` for as long as it runs after
// finding its route store damaged at start. The pages poll that every
// two seconds; the notice must not come back on every poll, or on every
// page, once the person has read it. "Read" is remembered for this run
// of the app only (sessionStorage, with a module variable behind it for
// a webview that has no storage): a LATER start that has to reset again
// is a new event and is said again.

const KEY = 'daal.d2.store_reset_notice.seen';

type Store = Pick<Storage, 'getItem' | 'setItem'>;

let seenInMemory = false;

function defaultStore(): Store | undefined {
    try {
        return typeof sessionStorage === 'undefined' ? undefined : sessionStorage;
    } catch {
        return undefined;
    }
}

/** Whether the notice should be on screen. */
export function storeResetNoticeDue(
    storeRecovered: boolean,
    store: Store | undefined = defaultStore(),
): boolean {
    if (!storeRecovered) return false;
    if (seenInMemory) return false;
    try {
        if (store?.getItem(KEY) === '1') return false;
    } catch { /* storage unavailable: the module variable decides */ }
    return true;
}

export function markStoreResetNoticeSeen(store: Store | undefined = defaultStore()): void {
    seenInMemory = true;
    try {
        store?.setItem(KEY, '1');
    } catch { /* storage unavailable */ }
}

/** Test seam: forget the in-memory half. */
export function resetStoreNoticeMemoryForTest(): void {
    seenInMemory = false;
}
