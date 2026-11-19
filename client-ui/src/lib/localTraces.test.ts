// What the webview remembers about the routes on this phone must not
// outlive them: a panic wipe clears it, a removed publisher or route
// takes its own entry along.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getPinnedRoute, setPinnedRoute } from './autoConnect';
import { importOriginOf, recordImportOrigin } from './importOrigin';
import { clearLocalTraces, forgetPublisher, forgetRoute } from './localTraces';

const store = new Map<string, string>();
beforeEach(() => {
    store.clear();
    vi.stubGlobal('localStorage', {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
    });
});
afterEach(() => vi.unstubAllGlobals());

const everything = () => [...store.entries()].map(([k, v]) => `${k}=${v}`).join('\n');

describe('local traces', () => {
    it('panic wipe leaves no publisher fingerprint and no route id behind — and keeps display preferences', () => {
        store.set('daal.d2.locale', 'fa'); // a display preference: not ours to clear
        recordImportOrigin('AABBCCDDEEFF0011', 'file');
        recordImportOrigin('99887766', 'scan');
        setPinnedRoute('route-4f2a');
        expect(everything()).toContain('aabbccddeeff0011');
        expect(everything()).toContain('route-4f2a');
        clearLocalTraces();
        expect(everything()).not.toContain('aabbccddeeff0011');
        expect(everything()).not.toContain('99887766');
        expect(everything()).not.toContain('route-4f2a');
        expect(getPinnedRoute()).toBeNull();
        expect(importOriginOf('aabbccddeeff0011')).toBeUndefined();
        expect(store.get('daal.d2.locale')).toBe('fa');
    });
    it('removing a publisher forgets that publisher only', () => {
        recordImportOrigin('aabbcc', 'file');
        recordImportOrigin('ddeeff', 'paste');
        forgetPublisher('AABBCC');
        expect(everything()).not.toContain('aabbcc');
        expect(importOriginOf('ddeeff')).toBe('paste');
        forgetPublisher('ddeeff');
        // The last entry gone: no empty record is left lying there.
        expect(store.size).toBe(0);
    });
    it('removing a route forgets a pin on it', () => {
        setPinnedRoute('r3');
        forgetRoute('r1');
        expect(getPinnedRoute()).toBe('r3');
        forgetRoute('r3');
        expect(getPinnedRoute()).toBeNull();
    });
    it('never throws without storage', () => {
        vi.stubGlobal('localStorage', {
            getItem: () => {
                throw new Error('denied');
            },
            setItem: () => {
                throw new Error('denied');
            },
            removeItem: () => {
                throw new Error('denied');
            },
        });
        expect(() => clearLocalTraces()).not.toThrow();
        expect(() => forgetPublisher('aabbcc')).not.toThrow();
        expect(() => forgetRoute('r1')).not.toThrow();
    });
});
