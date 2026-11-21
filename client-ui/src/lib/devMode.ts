// devMode — the per-device "developer tools" switch (spec B.12).
//
// Off by default. Anything for experts only (engine words, raw JSON,
// switches with no read-back) renders only while it is on. Settings turns
// it on (seven taps on the version line) and off (its own button). It is
// also on in the browser harness when the URL carries ?dev=1, so the
// developer surfaces can be captured without touching storage.

import { useEffect, useState } from 'react';

export const DEV_MODE_KEY = 'daal.d2.dev.enabled';
export const DEV_MODE_EVENT = 'daal-devmode';

function fromUrl(): boolean {
    try {
        const params = new URLSearchParams(window.location.search);
        return params.has('harness') && params.get('dev') === '1';
    } catch {
        return false;
    }
}

// When storage throws (a private window), the switch still holds for
// this session.
let memory = false;
const listeners = new Set<() => void>();

// The browser harness only: a scenario (or a step of its walk) turns
// developer mode on or off for this page alone, without touching storage,
// so the next scenario opened in the same browser starts clean.
let override: boolean | null = null;

export function isDeveloperMode(): boolean {
    if (override !== null) return override;
    if (fromUrl()) return true;
    try {
        return window.localStorage.getItem(DEV_MODE_KEY) === '1';
    } catch {
        return memory;
    }
}

export function setDeveloperMode(on: boolean): void {
    try {
        if (on) window.localStorage.setItem(DEV_MODE_KEY, '1');
        else window.localStorage.removeItem(DEV_MODE_KEY);
    } catch {
        /* storage refused: `memory` below keeps it for this session */
    }
    memory = on;
    // A switch from Settings wins over a harness hold.
    override = null;
    announce(on);
}

function announce(on: boolean): void {
    try {
        const Ev = (window as unknown as { CustomEvent?: typeof CustomEvent }).CustomEvent;
        const ev = Ev ? new Ev(DEV_MODE_EVENT, { detail: on }) : ({ type: DEV_MODE_EVENT } as Event);
        window.dispatchEvent(ev);
    } catch {
        /* no window events (tests without a DOM) */
    }
    for (const fn of Array.from(listeners)) fn();
}

/** Harness only (harness/driver.ts): hold developer mode on or off for
 *  this page, or `null` to follow storage again. Never persisted. */
export function setDeveloperModeOverride(on: boolean | null): void {
    override = on;
    announce(on ?? isDeveloperMode());
}

/** React hook: re-renders when developer mode is switched anywhere. */
export function useDeveloperMode(): boolean {
    const [on, setOn] = useState<boolean>(() => isDeveloperMode());
    useEffect(() => {
        const sync = () => setOn(isDeveloperMode());
        listeners.add(sync);
        let win: Window | null = null;
        try {
            win = window;
            win.addEventListener(DEV_MODE_EVENT, sync);
            // Another window of the app (desktop) switched it.
            win.addEventListener('storage', sync);
        } catch {
            win = null;
        }
        sync();
        return () => {
            listeners.delete(sync);
            win?.removeEventListener(DEV_MODE_EVENT, sync);
            win?.removeEventListener('storage', sync);
        };
    }, []);
    return on;
}
