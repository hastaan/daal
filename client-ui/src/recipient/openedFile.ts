// openedFile.ts — a file handed to Daal by Android ("Open with Daal",
// "Share to Daal").
//
// The shell stages the file the way stage_picked_file does and keeps its
// path for the UI:
//   take_opened_file() -> string | null   the path, once; then null
//   event "daal://opened-file" { path }    one arriving while Daal runs
//
// One listener for the whole app, and the path goes to ONE page: the
// most recently mounted subscriber (Home, or Files when it is open).
// A path that arrives with nobody listening waits for the next one.
// An older shell has neither the command nor the event: every call is
// guarded, and the app behaves as before (nothing is opened).

import { useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';

type Handler = (path: string) => void;
/** How a path came: with the launch (`take_opened_file`), or while
 *  Daal was already running (the event). */
export type OpenedSource = 'launch' | 'event';
type Watcher = (source: OpenedSource) => void;

const subscribers: Handler[] = [];
const waiting: string[] = [];
const watchers: Watcher[] = [];
let started = false;

function deliver(path: string, source: OpenedSource = 'event') {
    const top = subscribers[subscribers.length - 1];
    if (top) {
        top(path);
        return;
    }
    waiting.push(path);
    // Nobody on screen can open it: the shell decides what to do (go to
    // Home on launch; offer "Open" while the person is busy elsewhere).
    for (const w of watchers) w(source);
}

/** Exported for tests: hand a path to the subscribers as the event would. */
export function _deliverOpenedFile(path: string, source: OpenedSource = 'event'): void {
    deliver(path, source);
}

/** Exported for tests: forget every subscriber and waiting path. */
export function _resetOpenedFile(): void {
    subscribers.length = 0;
    waiting.length = 0;
    watchers.length = 0;
    started = true;
}

/** Start listening now (the event, then the launch file). The shell
 *  calls this at mount, so a file opened with Daal is announced to the
 *  native side even when the first place shown is not Home or Files. */
export function startOpenedFile(): void {
    void start();
}

/** Whether a handed-over file is waiting for Home or Files to mount. */
export function openedFileWaiting(): boolean {
    return waiting.length > 0;
}

/** The shell's hook: told when a file arrives that no mounted page can
 *  take. Returns the unsubscribe. */
export function watchUnclaimedOpenedFiles(w: Watcher): () => void {
    watchers.push(w);
    if (waiting.length) w('launch');
    return () => {
        const i = watchers.indexOf(w);
        if (i >= 0) watchers.splice(i, 1);
    };
}

function pathOf(payload: unknown): string | null {
    if (typeof payload === 'string') return payload || null;
    const p = (payload as { path?: unknown } | null)?.path;
    return typeof p === 'string' && p ? p : null;
}

async function start() {
    if (started) return;
    started = true;
    // While Daal runs.
    try {
        const { listen } = await import('@tauri-apps/api/event');
        await listen<{ path: string }>('daal://opened-file', (e) => {
            const p = pathOf(e.payload);
            if (p) deliver(p, 'event');
        });
    } catch {
        /* an older shell, or a plain browser: nothing arrives this way */
    }
    // The file Daal was opened with, if any.
    try {
        const p = pathOf(await invoke<unknown>('take_opened_file'));
        if (p) deliver(p, 'launch');
    } catch {
        /* an older shell has no such command */
    }
}

/** Receive files handed to Daal while this component is mounted. The
 *  newest mounted caller gets each one; a file that arrived before any
 *  caller mounted is handed to the first one. */
export function useOpenedFile(onFile: Handler): void {
    const ref = useRef(onFile);
    ref.current = onFile;
    useEffect(() => {
        const h: Handler = (p) => ref.current(p);
        subscribers.push(h);
        while (waiting.length) {
            const p = waiting.shift()!;
            h(p);
        }
        void start();
        return () => {
            const i = subscribers.lastIndexOf(h);
            if (i >= 0) subscribers.splice(i, 1);
        };
    }, []);
}

/** Opened files for a page that shows them in a sheet (Home, Files).
 *  A file that arrives while the sheet is in the middle of something (a
 *  scan with blocks held, a trust question, a passphrase being typed)
 *  does not replace it: it waits, and opens once that sheet closes. */
export function useOpenedFileSheet(sheetOpen: boolean, open: (path: string) => void) {
    const inProgress = useRef(false);
    const queue = useRef<string[]>([]);
    const openRef = useRef(open);
    openRef.current = open;
    const sheetOpenRef = useRef(sheetOpen);
    sheetOpenRef.current = sheetOpen;
    useOpenedFile((path) => {
        if (sheetOpenRef.current && inProgress.current) {
            queue.current.push(path);
            return;
        }
        openRef.current(path);
    });
    return useMemo(
        () => ({
            /** The sheet reports whether it is in the middle of something. */
            setInProgress: (b: boolean) => {
                inProgress.current = b;
            },
            /** The sheet closed: the next waiting file, if any, opens. */
            closed: () => {
                inProgress.current = false;
                const next = queue.current.shift();
                if (next) openRef.current(next);
            },
        }),
        [],
    );
}
