// "Daal could not start" — said in words, once the shell knows it.
//
// Since the first phone pass a failed engine start no longer crashes
// the app: the shell stays up and every engine command rejects with
// `engine_unavailable: <reason>`. The pages did nothing with that: the
// Connection page drew an ordinary "not connected" with a working-
// looking Connect button, the Connections page offered "Try again" for
// something trying again cannot fix, and the Publisher tab printed the
// framework's own "state not managed…" text in red.
//
// `engine_status` (src-tauri/src/lib.rs) is the one command that always
// answers. This file turns its answer — or a rejection that carries the
// `engine_unavailable:` prefix — into "there is a start problem, and
// here is the raw reason for the Details fold". The sentence the person
// reads is ours (`engine.start_failed.*`), never the reason.
import { useCallback, useEffect, useState } from 'react';
import { engineStatus } from './bridge';
import { errorText } from './errorText';

export interface EngineStart {
    engineReady: boolean;
    engineError?: string;
    publisherStoreReady: boolean;
    publisherStoreError?: string;
}

function text(v: unknown): string | undefined {
    return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

/** `undefined` for anything that is not an engine_status answer (an
 *  older shell, the browser harness): "unknown", which accuses nobody. */
export function parseEngineStatus(raw: unknown): EngineStart | undefined {
    if (!raw || typeof raw !== 'object') return undefined;
    const o = raw as Record<string, unknown>;
    if (typeof o.engine_ready !== 'boolean') return undefined;
    return {
        engineReady: o.engine_ready,
        engineError: text(o.engine_error),
        // Absent = an older shell that did not report it: not a problem.
        publisherStoreReady: o.publisher_store_ready !== false,
        publisherStoreError: text(o.publisher_store_error),
    };
}

/** The contract prefix every engine command rejects with while the
 *  engine is not usable (daal-desktop-core/src/errors.rs). */
export const ENGINE_UNAVAILABLE_PREFIX = 'engine_unavailable:';

export function isEngineUnavailable(e: unknown): boolean {
    return errorText(e).startsWith(ENGINE_UNAVAILABLE_PREFIX);
}

/** A start problem to show, with the raw reason for Details. */
export interface StartProblem {
    detail: string;
}

/** The recipient side: is the connection engine unusable? */
export function engineStartProblem(
    status: EngineStart | undefined,
    rejection?: unknown,
): StartProblem | null {
    if (status && !status.engineReady) {
        return { detail: status.engineError ?? 'engine not started' };
    }
    // A status that says "ready" outranks an old rejection.
    if (status?.engineReady) return null;
    if (rejection !== undefined && isEngineUnavailable(rejection)) {
        return { detail: errorText(rejection).slice(ENGINE_UNAVAILABLE_PREFIX.length).trim() || 'engine not started' };
    }
    return null;
}

/** May a tap on the Connection page's main button go ahead? With a
 *  start problem a connect (or the recovery sheet, which only offers
 *  other connects) can do nothing but fail under a notice that already
 *  says why. Stopping is always allowed. */
export function tapAllowedWithStartProblem(
    problem: StartProblem | null,
    action: 'connect' | 'disconnect' | 'recovery',
): boolean {
    return problem === null || action === 'disconnect';
}

/** The publisher side: i18n key of the sentence for a publisher page
 *  that could not load its list at start. The raw text is for Details.
 *
 *  `pub.boot.unavailable` when the cause is the start of the app (what
 *  it has saved about the person's servers could not be opened, or the
 *  engine did not start): trying the same thing again cannot work, and
 *  the sentence says to restart instead. Anything else keeps the
 *  ordinary "try again" sentence. */
export function publisherBootFailureKey(raw: string, status: EngineStart | undefined): string {
    if (status && (!status.publisherStoreReady || !status.engineReady)) return 'pub.boot.unavailable';
    if (raw.startsWith(ENGINE_UNAVAILABLE_PREFIX)) return 'pub.boot.unavailable';
    // Tauri's own words for a command whose state was never registered
    // — what a failed open of the operator database leaves behind.
    if (/state not managed/i.test(raw)) return 'pub.boot.unavailable';
    return 'pub.fail.generic';
}

/** Asks the shell once at mount whether the engine started, and lets a
 *  page report a rejected call (`report(e)`), which matters only when
 *  it carries the engine_unavailable prefix — the status is then asked
 *  again, since it has the full reason. */
export function useEngineStartProblem(): [StartProblem | null, (e: unknown) => void] {
    const [status, setStatus] = useState<EngineStart | undefined>(undefined);
    const [rejection, setRejection] = useState<unknown>(undefined);
    useEffect(() => {
        let alive = true;
        void engineStatus().then((s) => {
            if (alive) setStatus(parseEngineStatus(s));
        });
        return () => {
            alive = false;
        };
    }, []);
    const report = useCallback((e: unknown) => {
        if (!isEngineUnavailable(e)) return;
        setRejection(e);
        void engineStatus().then((s) => {
            const parsed = parseEngineStatus(s);
            if (parsed) setStatus(parsed);
        });
    }, []);
    return [engineStartProblem(status, rejection), report];
}
