/// <reference types="vite/client" />
// The one Back mechanism (PA-25 / D3): pure core with a fake history
// that behaves like WryActivity — Back goes back in the webview while
// it can, otherwise it finishes the activity.
import { describe, expect, it } from 'vitest';
import { createBackStack } from './backStack';
import type { HistoryLike, WinLike } from './backStack';

function rig() {
    const listeners: Record<string, ((e: unknown) => void)[]> = {};
    const win: WinLike = {
        addEventListener: (t, fn) => {
            (listeners[t] ??= []).push(fn as (e: unknown) => void);
        },
        removeEventListener: (t, fn) => {
            listeners[t] = (listeners[t] ?? []).filter((f) => f !== fn);
        },
        location: { href: 'app://index' },
    };
    const fire = (t: string, e: unknown = {}) => (listeners[t] ?? []).forEach((f) => f(e));
    // Entries above the app's first page.
    let depth = 0;
    let appLeft = false;
    const history: HistoryLike = {
        pushState: () => {
            depth += 1;
        },
        back: () => {
            if (depth === 0) {
                appLeft = true;
                return;
            }
            depth -= 1;
            fire('popstate');
        },
    };
    const queue: (() => void)[] = [];
    const stack = createBackStack(history, win, (fn) => queue.push(fn));
    const flush = () => {
        while (queue.length) queue.shift()!();
    };
    /** The system Back: WryActivity's callback. */
    const systemBack = () => {
        if (depth > 0) history.back();
        else appLeft = true;
        flush();
    };
    return {
        stack,
        flush,
        systemBack,
        fire,
        depth: () => depth,
        appLeft: () => appLeft,
    };
}

describe('backStack', () => {
    it('Back closes sheets one at a time, last opened first', () => {
        const r = rig();
        const closed: string[] = [];
        const un: Record<string, () => void> = {};
        const open = (name: string) => {
            un[name] = r.stack.register('sheet', () => {
                closed.push(name);
                un[name]();
            });
        };
        open('a');
        open('b');
        r.flush();
        expect(r.depth()).toBe(1); // one sentinel, not one per sheet
        r.systemBack();
        expect(closed).toEqual(['b']);
        expect(r.depth()).toBe(1);
        r.systemBack();
        expect(closed).toEqual(['b', 'a']);
        expect(r.depth()).toBe(0);
        expect(r.appLeft()).toBe(false);
        // Nothing registered: Back leaves the app as it always did.
        r.systemBack();
        expect(r.appLeft()).toBe(true);
    });

    it('a sheet is above a page even when it registered first', () => {
        const r = rig();
        const got: string[] = [];
        r.stack.register('sheet', () => got.push('sheet'));
        r.stack.register('page', () => got.push('page'));
        r.flush();
        r.systemBack();
        expect(got).toEqual(['sheet']);
    });

    it('a refused Back puts the sentinel back, so the app stays', () => {
        const r = rig();
        let asked = 0;
        r.stack.register('sheet', () => {
            asked += 1; // busy: does nothing
        });
        r.flush();
        r.systemBack();
        expect(asked).toBe(1);
        expect(r.stack.hasSentinel()).toBe(true);
        expect(r.depth()).toBe(1);
        r.systemBack();
        expect(asked).toBe(2);
        expect(r.appLeft()).toBe(false);
    });

    it('closing a sheet with its own button removes the sentinel and the pop is ignored', () => {
        const r = rig();
        let pageBacks = 0;
        let sheetBacks = 0;
        const unSheet = r.stack.register('sheet', () => (sheetBacks += 1));
        r.flush();
        unSheet();
        r.flush();
        expect(r.depth()).toBe(0);
        expect(r.stack.hasSentinel()).toBe(false);
        expect(sheetBacks).toBe(0);
        // A page registered later still gets its own Back.
        r.stack.register('page', () => (pageBacks += 1));
        r.flush();
        r.systemBack();
        expect(pageBacks).toBe(1);
    });

    it('the pop of our own history.back is never taken for a Back, even when it arrives late', () => {
        // A browser delivers popstate asynchronously. Close a sheet with
        // its button and open another before that pop arrives: the late
        // pop must not close the new one.
        const listeners: ((e: unknown) => void)[] = [];
        const pops: (() => void)[] = [];
        let depth = 0;
        const history: HistoryLike = {
            pushState: () => {
                depth += 1;
            },
            back: () => {
                depth -= 1;
                pops.push(() => listeners.forEach((f) => f({})));
            },
        };
        const win: WinLike = {
            addEventListener: (t, fn) => {
                if (t === 'popstate') listeners.push(fn as (e: unknown) => void);
            },
            removeEventListener: () => {},
        };
        const stack = createBackStack(history, win, (fn) => fn());
        let bBacks = 0;
        const unA = stack.register('sheet', () => {});
        unA(); // closed by its own button: our history.back() is in flight
        stack.register('sheet', () => (bBacks += 1));
        expect(depth).toBe(1);
        pops.shift()!(); // the late pop of our own back()
        expect(bBacks).toBe(0);
        expect(stack.hasSentinel()).toBe(true);
    });

    it('with nothing registered there is no history entry and Back leaves the app', () => {
        const r = rig();
        r.flush();
        expect(r.depth()).toBe(0);
        r.systemBack();
        expect(r.appLeft()).toBe(true);
    });

    it('a Strict-Mode double register/unregister is safe', () => {
        const r = rig();
        let n = 0;
        const u1 = r.stack.register('sheet', () => (n += 1));
        u1();
        u1(); // twice: no-op
        const u2 = r.stack.register('sheet', () => (n += 1));
        r.flush();
        expect(r.stack.size()).toBe(1);
        expect(r.depth()).toBe(1);
        r.systemBack();
        expect(n).toBe(1);
        u2();
        r.flush();
        expect(r.depth()).toBe(0);
    });

    it('Alt+Left and BrowserBack go back only while something is registered', () => {
        const r = rig();
        let prevented = 0;
        const key = (k: string, alt = false) =>
            r.fire('keydown', { key: k, altKey: alt, preventDefault: () => (prevented += 1) });
        key('ArrowLeft', true);
        expect(r.appLeft()).toBe(false);
        expect(prevented).toBe(1);
        let backs = 0;
        r.stack.register('page', () => (backs += 1));
        r.flush();
        key('BrowserBack');
        r.flush();
        expect(backs).toBe(1);
        key('ArrowLeft'); // no Alt: not Back
        expect(backs).toBe(1);
        // Alt+Left in a text field moves the caret; it is not Back.
        r.fire('keydown', { key: 'ArrowLeft', altKey: true, target: { nodeName: 'TEXTAREA' }, preventDefault: () => {} });
        r.flush();
        expect(backs).toBe(1);
    });
});

describe('one mechanism', () => {
    const sources = import.meta.glob(['../**/*.ts', '../**/*.tsx', '!../**/*.test.ts', '!../**/*.test.tsx', '!../test/**'], {
        query: '?raw',
        import: 'default',
        eager: true,
    }) as Record<string, string>;

    it('the sources were found', () => {
        expect(Object.keys(sources).length).toBeGreaterThan(100);
        expect(Object.keys(sources)).toContain('./backStack.ts');
    });

    it('only backStack.ts touches browser history or listens to popstate', () => {
        for (const [path, src] of Object.entries(sources)) {
            if (path === './backStack.ts') continue;
            expect(src, path).not.toMatch(/pushState|replaceState|history\.back\(|history\.go\(|['"]popstate['"]/);
        }
    });

    it('every hand-made dialog answers Back (imports useBack) or is built on a primitive that does', () => {
        const dialogs = Object.entries(sources).filter(([, src]) => /role="dialog"/.test(src));
        // The 2026-11 redesign moved most hand-made dialogs onto Sheet /
        // MenuSheet; what is left by hand still has to answer Back.
        expect(dialogs.length).toBeGreaterThanOrEqual(3);
        for (const [path, src] of dialogs) {
            expect(src, path).toMatch(/import \{ useBack \} from '[./]+(lib\/)?useBack'/);
        }
        // The dialogs that moved are built on the primitives, so they answer
        // Back through BottomSheet/Modal (checked below).
        for (const p of [
            '../components/CustodyPanel.tsx',
            '../components/PanicWipeDialog.tsx',
            '../components/RecoverySheet.tsx',
            '../components/connection/ModePickerSheet.tsx',
        ]) {
            expect(sources[p], p).toMatch(/import \{[^}]*\b(Sheet|MenuSheet)\b[^}]*\} from '[./]+design\/primitives'/);
        }
        expect(sources['../design/primitives/MenuSheet.tsx']).toMatch(/\bSheet\b/);
        // The primitives every Sheet goes through.
        for (const p of ['../design/primitives/BottomSheet.tsx', '../design/primitives/Modal.tsx']) {
            expect(sources[p], p).toContain('useBack(true, onClose)');
        }
    });
});

// Android: the shell asks the stack directly. Seen on the phone
// 2026-11-19: with the history entry, a second Back in a row left the
// app, because Chromium skips an entry added without a touch.
describe('Back answered natively (Android)', () => {
    it('answers every Back in a row without touching history, then lets the app close', () => {
        let pushes = 0;
        const win: WinLike = { addEventListener: () => {}, removeEventListener: () => {} };
        const history: HistoryLike = {
            pushState: () => {
                pushes += 1;
            },
            back: () => {
                throw new Error('history must not be used');
            },
        };
        const stack = createBackStack(history, win, (fn) => fn(), true);
        const seen: string[] = [];
        let offSheet = () => {};
        const offPage = stack.register('page', () => {
            seen.push('page');
            offPage();
        });
        offSheet = stack.register('sheet', () => {
            seen.push('sheet');
            offSheet();
        });
        expect(stack.answerNative()).toBe(true);
        expect(stack.answerNative()).toBe(true);
        expect(seen).toEqual(['sheet', 'page']);
        // Nothing open: Back goes on to leave the app.
        expect(stack.answerNative()).toBe(false);
        expect(pushes).toBe(0);
        expect(stack.hasSentinel()).toBe(false);
    });

    it('a handler that refuses keeps the app open', () => {
        const win: WinLike = { addEventListener: () => {}, removeEventListener: () => {} };
        const history: HistoryLike = { pushState: () => {}, back: () => {} };
        const stack = createBackStack(history, win, (fn) => fn(), true);
        stack.register('sheet', () => {});
        expect(stack.answerNative()).toBe(true);
        expect(stack.answerNative()).toBe(true);
    });
});
