// Which route summaries not to ask for again.
//
// The engine names its active route from memory; the route's display
// details live in the store. When the store no longer holds that route
// (it was reset, the file was removed) the engine keeps naming it, and
// the pages — which poll every 2 s — kept asking the store for it:
// `sql: no rows in result set`, logged on every poll (backlog PH-26).
//
// A failed read alone does not say the route is gone: on the first
// phone pass the store stopped answering for a while with every route
// still in it. So the caller reads the route LIST once after a failed
// summary, and this keeps the two outcomes apart:
//
//   gone       the list answered and does not hold the route. Not asked
//              again until the route set may have changed (`clear`) or
//              a later list shows it (`listed`).
//   unreadable the list did not answer either, or still holds the
//              route. Asked again after RETRY_MS, not on every poll.
export const RETRY_MS = 30_000;

export class MissingRoutes {
    private gone = new Set<string>();
    private retryAt = new Map<string, number>();

    shouldAsk(routeId: string, nowMs: number): boolean {
        if (this.gone.has(routeId)) return false;
        const at = this.retryAt.get(routeId);
        return at === undefined || nowMs >= at;
    }

    /** The summary was read. */
    found(routeId: string): void {
        this.gone.delete(routeId);
        this.retryAt.delete(routeId);
    }

    /** The summary could not be read. `listedIds` is the route list read
     *  right after, or `undefined` when that could not be read either. */
    failed(routeId: string, nowMs: number, listedIds: readonly string[] | undefined): void {
        if (listedIds !== undefined && !listedIds.includes(routeId)) {
            this.gone.add(routeId);
            this.retryAt.delete(routeId);
            return;
        }
        this.retryAt.set(routeId, nowMs + RETRY_MS);
    }

    /** A route list was read: anything in it exists. */
    listed(ids: readonly string[]): void {
        for (const id of ids) this.found(id);
    }

    /** The route set may have changed: ask afresh. */
    clear(): void {
        this.gone.clear();
        this.retryAt.clear();
    }
}
