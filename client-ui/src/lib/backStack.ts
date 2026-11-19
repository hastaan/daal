// backStack — the ONE place the app answers the system Back.
//
// The UI navigates by React state and kept no browser history, so on
// Android the generated WryActivity's back callback found nothing to go
// back to and finished the activity: with a sheet open, Back closed the
// whole app (PA-25). WryActivity already calls `webView.goBack()` while
// `canGoBack()` is true, and a same-document `history.pushState` entry
// makes it true; `goBack()` then fires `popstate` here. The same entry
// answers browser Back and Alt+Left on desktop.
//
// Whatever wants Back (an open sheet, an inner page) registers a
// handler. While anything is registered there is exactly one sentinel
// history entry; Back pops it, and the topmost handler runs. With
// nothing registered there is no sentinel, `canGoBack()` is false, and
// Back leaves the app exactly as before.
//
// Order: every `sheet` is above every `page`; within a layer, the most
// recently registered is on top. A handler that refuses (a busy sheet,
// a setup that must not be interrupted) simply does nothing: its entry
// stays, so the sentinel comes back and the next Back asks it again.
//
// Only this module may call pushState / history.back or listen to
// popstate (a grep test holds that).

export type BackLayer = 'page' | 'sheet';

export interface HistoryLike {
    pushState(state: unknown, title: string, url?: string | null): void;
    back(): void;
}

export interface WinLike {
    addEventListener(type: string, fn: (e: never) => void): void;
    removeEventListener(type: string, fn: (e: never) => void): void;
    location?: { href: string };
}

interface Entry {
    layer: BackLayer;
    seq: number;
    onBack: () => void;
}

export interface BackStack {
    register(layer: BackLayer, onBack: () => void): () => void;
    /** Test/inspection: how many handlers are registered. */
    size(): number;
    /** Test/inspection: whether our history entry is in place. */
    hasSentinel(): boolean;
    /** Run reconcile now (tests; the real one is scheduled). */
    flush(): void;
    /** Remove the listeners (tests). */
    dispose(): void;
}

const RANK: Record<BackLayer, number> = { page: 0, sheet: 1 };

interface KeyLike {
    key?: string;
    altKey?: boolean;
    preventDefault?: () => void;
    target?: { nodeName?: string; isContentEditable?: boolean } | null;
}

/** Alt+Left inside a text field moves the caret by a word (macOS
 *  Option+Left): it is not Back there. */
function inTextField(ev: KeyLike): boolean {
    const n = ev.target;
    if (!n) return false;
    const name = (n.nodeName ?? '').toUpperCase();
    return name === 'INPUT' || name === 'TEXTAREA' || n.isContentEditable === true;
}

/**
 * The pure core. `schedule` defaults to `setTimeout(fn, 0)` so that a
 * reconcile runs after React has committed the state change a handler
 * made; tests pass their own.
 */
export function createBackStack(
    history: HistoryLike,
    win: WinLike,
    schedule: (fn: () => void) => void = (fn) => {
        setTimeout(fn, 0);
    },
): BackStack {
    const entries: Entry[] = [];
    let seq = 0;
    let sentinel = false;
    let ignorePops = 0;
    let pending = false;

    const top = (): Entry | null => {
        let best: Entry | null = null;
        for (const e of entries) {
            if (
                !best ||
                RANK[e.layer] > RANK[best.layer] ||
                (RANK[e.layer] === RANK[best.layer] && e.seq > best.seq)
            ) {
                best = e;
            }
        }
        return best;
    };

    const reconcileNow = () => {
        pending = false;
        if (entries.length > 0 && !sentinel) {
            sentinel = true;
            history.pushState({ daalBack: true }, '', win.location?.href ?? null);
        } else if (entries.length === 0 && sentinel) {
            sentinel = false;
            ignorePops += 1;
            history.back();
        }
    };

    const reconcile = () => {
        if (pending) return;
        pending = true;
        schedule(reconcileNow);
    };

    const runTop = () => {
        const e = top();
        if (!e) return;
        try {
            e.onBack();
        } finally {
            reconcile();
        }
    };

    const onPop = () => {
        if (ignorePops > 0) {
            ignorePops -= 1;
            return;
        }
        // The browser has just removed our entry, whatever happens next.
        sentinel = false;
        runTop();
    };

    const onKey = (ev: KeyLike) => {
        const isBack =
            ev.key === 'BrowserBack' || (ev.altKey === true && ev.key === 'ArrowLeft' && !inTextField(ev));
        if (!isBack) return;
        // Never let the webview itself navigate away from the app.
        ev.preventDefault?.();
        if (entries.length === 0) return;
        if (sentinel) history.back();
        // A reconcile is still pending: there is no entry to pop yet, so
        // answer directly — the result is the same as a popped Back.
        else runTop();
    };

    win.addEventListener('popstate', onPop as (e: never) => void);
    win.addEventListener('keydown', onKey as (e: never) => void);

    return {
        register(layer, onBack) {
            const e: Entry = { layer, seq: ++seq, onBack };
            entries.push(e);
            reconcile();
            let done = false;
            return () => {
                if (done) return;
                done = true;
                const i = entries.indexOf(e);
                if (i >= 0) entries.splice(i, 1);
                reconcile();
            };
        },
        size: () => entries.length,
        hasSentinel: () => sentinel,
        flush: () => reconcileNow(),
        dispose() {
            win.removeEventListener('popstate', onPop as (e: never) => void);
            win.removeEventListener('keydown', onKey as (e: never) => void);
        },
    };
}

let shared: BackStack | null = null;

/** The app's one stack, or null outside a browser (tests, SSR). */
export function appBackStack(): BackStack | null {
    if (typeof window === 'undefined' || typeof window.history === 'undefined') return null;
    if (!shared) shared = createBackStack(window.history, window as unknown as WinLike);
    return shared;
}
