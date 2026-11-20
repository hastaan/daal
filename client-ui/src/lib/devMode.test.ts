import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createRig } from '../test/rig';
import type { Rig } from '../test/rig';
import { byAttr } from '../test/miniDom';
import { DEV_MODE_KEY, isDeveloperMode, setDeveloperMode, setDeveloperModeOverride, useDeveloperMode } from './devMode';

class FakeStorage {
    map = new Map<string, string>();
    broken = false;
    getItem(k: string) {
        if (this.broken) throw new Error('SecurityError');
        return this.map.has(k) ? this.map.get(k)! : null;
    }
    setItem(k: string, v: string) {
        if (this.broken) throw new Error('SecurityError');
        this.map.set(k, String(v));
    }
    removeItem(k: string) {
        if (this.broken) throw new Error('SecurityError');
        this.map.delete(k);
    }
}

let rig: Rig;
let storage: FakeStorage;
beforeAll(() => {
    rig = createRig();
});
afterEach(async () => {
    await rig.unmountAll();
    rig.win.location.search = '';
});
const fresh = () => {
    storage = new FakeStorage();
    (rig.win as unknown as { localStorage: FakeStorage }).localStorage = storage;
};

describe('developer mode', () => {
    it('is off by default', () => {
        fresh();
        expect(isDeveloperMode()).toBe(false);
    });

    it('is switched on and off through its storage key', () => {
        fresh();
        setDeveloperMode(true);
        expect(storage.getItem(DEV_MODE_KEY)).toBe('1');
        expect(isDeveloperMode()).toBe(true);
        setDeveloperMode(false);
        expect(storage.getItem(DEV_MODE_KEY)).toBeNull();
        expect(isDeveloperMode()).toBe(false);
    });

    it('a harness hold switches it for this page only, never in storage, and Settings wins over it', () => {
        fresh();
        setDeveloperModeOverride(true);
        expect(isDeveloperMode()).toBe(true);
        expect(storage.getItem(DEV_MODE_KEY)).toBeNull();
        setDeveloperModeOverride(false);
        rig.win.location.search = '?harness=x&dev=1';
        expect(isDeveloperMode()).toBe(false);
        setDeveloperModeOverride(null);
        expect(isDeveloperMode()).toBe(true);
        rig.win.location.search = '';
        setDeveloperModeOverride(true);
        setDeveloperMode(false);
        expect(isDeveloperMode()).toBe(false);
    });

    it('a stored value other than "1" is off', () => {
        fresh();
        storage.setItem(DEV_MODE_KEY, 'true');
        expect(isDeveloperMode()).toBe(false);
    });

    it('is on in the harness with ?dev=1, and only in the harness', () => {
        fresh();
        rig.win.location.search = '?harness=settings-default&dev=1';
        expect(isDeveloperMode()).toBe(true);
        rig.win.location.search = '?dev=1';
        expect(isDeveloperMode()).toBe(false);
        rig.win.location.search = '?harness=settings-default';
        expect(isDeveloperMode()).toBe(false);
    });

    it('storage that throws neither crashes nor loses the switch for this session', () => {
        fresh();
        storage.broken = true;
        expect(isDeveloperMode()).toBe(false);
        expect(() => setDeveloperMode(true)).not.toThrow();
        expect(isDeveloperMode()).toBe(true);
        setDeveloperMode(false);
        expect(isDeveloperMode()).toBe(false);
    });

    it('a screen that gates on it re-renders when it is switched', async () => {
        fresh();
        const React = await import('react');
        function Gate() {
            const dev = useDeveloperMode();
            return React.createElement('div', { 'data-gate': dev ? 'dev' : 'plain' });
        }
        const m = await rig.mount(React.createElement(Gate));
        expect(byAttr(m.container, 'data-gate', 'plain')).not.toBeNull();
        await (await import('react')).act(async () => setDeveloperMode(true));
        await rig.settle();
        expect(byAttr(m.container, 'data-gate', 'dev')).not.toBeNull();
        await (await import('react')).act(async () => setDeveloperMode(false));
        await rig.settle();
        expect(byAttr(m.container, 'data-gate', 'plain')).not.toBeNull();
    });
});
