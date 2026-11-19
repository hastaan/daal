// useSecureScreen — keep screenshots, screen recording and the
// recent-apps thumbnail away from a screen that shows secrets (PB-20):
// the twelve recovery words, typing three of them back, typing them all
// to check them, and typing them on the restore page.
//
// One counter for the whole app: the flag goes on when the first such
// screen mounts and off when the last one unmounts, so two of them open
// at once (the words page and the check sheet) never switch it off
// under each other. Cleanup runs on unmount, on `active` turning false,
// and when an error tears the screen down, since React runs effect
// cleanups for a subtree an error boundary removes.
//
// The calls go one at a time (`pump`): the next is sent only when the
// last has answered, so the window gets "on" and "off" in the order the
// page wanted them even though the shell runs each call on its own task.
//
// A failed call is swallowed: on a computer the command is a no-op, and
// a phone that cannot set the flag must still show the words. A new
// app window starts without the flag, and the Android plugin clears it
// when it loads, so an app killed while it was on starts clear. A page
// that reloads inside the same window does not reload the plugin, so
// the page also asks for "off" once when it starts
// (`secureScreenClearAtStart`, called from main.tsx).

import { useEffect } from 'react';
import { Platform } from './wizardCommands';

type Setter = (on: boolean) => Promise<unknown>;

let holders = 0;
/** What the page wants now: on while any such screen is mounted. */
let desired = false;
/** What the platform last accepted; null when unknown (nothing asked
 *  yet since the page started, or the last call failed). */
let confirmed: boolean | null = null;
/** The one call on its way, if any. */
let inFlight = false;
/** Bumped by the test reset, so a call from before it is ignored. */
let generation = 0;
let setter: Setter = (on) => Platform.secureScreen(on);

/** Bring the platform to `desired`, one call at a time. A second call is
 *  never issued before the first has answered, so "on" then "off" (or
 *  the reverse) reach the window in the order they were wanted, however
 *  the shell schedules its tasks; and only the latest wish is sent, so a
 *  quick on-off-on sends what is wanted at each answer. A call that fails
 *  leaves the state unknown: the next change of wish, or the next screen
 *  that mounts, sends it again (never a retry loop on a platform that
 *  keeps refusing). */
function pump(): void {
    if (inFlight || confirmed === desired) return;
    const want = desired;
    const gen = generation;
    inFlight = true;
    let p: Promise<unknown>;
    try {
        p = Promise.resolve(setter(want));
    } catch (e) {
        p = Promise.reject(e);
    }
    p.then(
        () => {
            if (gen === generation) confirmed = want;
        },
        () => {
            /* see the header: never in the way of the screen */
            if (gen === generation) confirmed = null;
        },
    ).finally(() => {
        if (gen !== generation) return;
        inFlight = false;
        // After a success, catch up with any change made meanwhile.
        // After a failure, only a changed wish is sent now.
        if (confirmed !== null || desired !== want) pump();
    });
}

export function secureScreenAcquire(): () => void {
    holders += 1;
    desired = true;
    pump();
    let released = false;
    return () => {
        if (released) return;
        released = true;
        holders = Math.max(0, holders - 1);
        if (holders > 0) return;
        // Off a moment later: when one secret screen replaces another
        // (the words, then typing them back) React unmounts the first
        // and mounts the second in the same commit, and the flag must
        // not blink off between them.
        queueMicrotask(() => {
            if (holders === 0) {
                desired = false;
                pump();
            }
        });
    };
}

/** Once, when the page starts: nothing is holding the flag yet, so ask
 *  for it off (a reload must not inherit it from the page before). */
export function secureScreenClearAtStart(): void {
    if (holders > 0) return;
    desired = false;
    confirmed = null;
    pump();
}

export function useSecureScreen(active: boolean): void {
    useEffect(() => {
        if (!active) return;
        return secureScreenAcquire();
    }, [active]);
}

/** Tests: replace the platform call and reset the counter. */
export function setSecureScreenSetterForTests(s: Setter | null): void {
    setter = s ?? ((on) => Platform.secureScreen(on));
    holders = 0;
    desired = false;
    confirmed = false;
    inFlight = false;
    generation += 1;
}

/** Tests: how many screens hold the flag on. */
export function secureScreenHolders(): number {
    return holders;
}
