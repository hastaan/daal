// The browser harness's pretend Tauri shell must do nothing unless the
// page is a harness page whose scenario asks for it, and must never
// shadow a real shell. Runs in node with a hand-made `window`.
import { afterEach, describe, expect, it, vi } from 'vitest';

type W = {
    location: { search: string; href: string; origin: string; replace?: (u: string) => void };
    fetch: typeof fetch;
    setTimeout: typeof setTimeout;
    __TAURI_INTERNALS__?: Record<string, unknown>;
    __TAURI_EVENT_PLUGIN_INTERNALS__?: unknown;
};

function fakeWindow(search: string, extra: Partial<W> = {}): W {
    const href = `http://localhost:5181/${search}`;
    return {
        location: { search, href, origin: 'http://localhost:5181', replace: vi.fn() },
        fetch: vi.fn() as unknown as typeof fetch,
        setTimeout,
        ...extra,
    };
}

async function load(w: W) {
    vi.resetModules();
    vi.stubGlobal('window', w);
    return import('./publisherFake');
}

afterEach(() => {
    vi.unstubAllGlobals();
});

describe('publisherFake', () => {
    it('is inert without ?harness=', async () => {
        const w = fakeWindow('');
        const realFetch = w.fetch;
        const m = await load(w);
        expect(m.installPublisherFake()).toBe(false);
        expect(w.__TAURI_INTERNALS__).toBeUndefined();
        expect(w.__TAURI_EVENT_PLUGIN_INTERNALS__).toBeUndefined();
        expect(w.fetch).toBe(realFetch);
        expect(w.location.replace).not.toHaveBeenCalled();
    });

    it('is inert on an unknown ?harness= id', async () => {
        const w = fakeWindow('?harness=no-such-scenario');
        const m = await load(w);
        expect(m.installPublisherFake()).toBe(false);
        expect(w.__TAURI_INTERNALS__).toBeUndefined();
    });

    it('is inert on a harness scenario that asks for no fake shell', async () => {
        const w = fakeWindow('?harness=connection-connected');
        const m = await load(w);
        expect(m.installPublisherFake()).toBe(false);
        expect(w.__TAURI_INTERNALS__).toBeUndefined();
    });

    it('never shadows a real Tauri shell, whatever the URL says', async () => {
        const realInvoke = vi.fn();
        const internals = { invoke: realInvoke };
        const w = fakeWindow('?harness=pub-relay-list', { __TAURI_INTERNALS__: internals });
        const realFetch = w.fetch;
        const m = await load(w);
        expect(m.installPublisherFake()).toBe(false);
        expect(w.__TAURI_INTERNALS__).toBe(internals);
        expect(internals.invoke).toBe(realInvoke);
        expect(w.fetch).toBe(realFetch);
    });

    it('keeps the harness engine contract on a harness page', async () => {
        const w = fakeWindow('?harness=pub-relay-list');
        vi.resetModules();
        vi.stubGlobal('window', w);
        const backends = await import('../backends');
        const { HarnessContract } = await import('../backends/harness');
        expect(backends.activeContract).toBeInstanceOf(HarnessContract);
    });

    it('refuses commands it does not know', async () => {
        const m = await load(fakeWindow(''));
        const h = m.makeHandler({ relays: 'two' });
        expect(h('wizard_provision', {})).toBeUndefined();
        expect(h('wizard_destroy_server', {})).toBeUndefined();
        expect(Array.isArray(h('wizard_list_operators', {}))).toBe(true);
    });
});
