// The main screen, driven the way the page drives it: the harness
// contract for the engine, `mainScreenView` for what is shown and
// `runMainTap` for what a tap does. ConnectionPage itself is these two
// calls plus drawing (this codebase has no DOM to click in), so the
// properties the selection wave exists for are asserted HERE, at the
// level where they can break:
//
//   - a tap with routes on the device connects automatically, once, and
//     navigates nowhere;
//   - a tap with nothing imported opens the add sheet;
//   - a failed pass shows its sentence and a "Try again" that connects;
//   - while trying, the tap is Cancel and it disconnects;
//   - no state is a dead end.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HarnessContract } from '../backends/harness';
import type { AutoStatus, ConnState, ConnectionSummary, RouteDisplayRow } from '../contract/D2Contract';
import { startConnect } from './autoConnect';
import { mainScreenView, retryTarget, runMainTap, type MainScreenInput } from './mainScreen';
import type { Scenario } from '../harness/scenarios';
import legacyEn from '../i18n/en.json';
import en from '../i18n/d2/d2-extra.en.json';
import desktopEn from '../i18n/d2/desktop.en.json';
import mobileEn from '../i18n/d2/mobile.en.json';

const EN = { ...(legacyEn as object), ...(desktopEn as object), ...(mobileEn as object), ...(en as object) } as Record<string, string>;
const t = (k: string) => EN[k] ?? k;

const way = (id: string, over: Partial<RouteDisplayRow> = {}): RouteDisplayRow => ({
    routeId: id,
    publisherId: 'pub',
    publisherName: 'Pars',
    routeNickname: id,
    trustClass: 'trusted',
    family: 'vless-reality',
    ...over,
});
const dead = (id: string) => way(id, { healthPct: 10 }); // the harness: does not carry
const scenario = (routes: RouteDisplayRow[]): Scenario =>
    ({
        id: 't',
        title: 't',
        screen: 'connection',
        connection: { state: 'disconnected', mode: 'normal' },
        availableRoutes: routes,
    }) as Scenario;

const auto = (over: Partial<AutoStatus>): AutoStatus => ({
    state: 'idle',
    mode: false,
    trying: '',
    index: 0,
    total: 0,
    tried: [],
    verdict: '',
    routeId: '',
    ...over,
});

/** A miniature of the page: its state, its poll, its tap. */
class Page {
    conn: ConnectionSummary | null = null;
    routes: RouteDisplayRow[] | undefined;
    pinnedRaw: string | null = null;
    optimistic: ConnState | null = null;
    calls: string[] = [];
    constructor(readonly contract: HarnessContract) {
        for (const m of ['connect', 'connectAuto', 'disconnect'] as const) {
            const real = (contract[m] as (...a: unknown[]) => Promise<unknown>).bind(contract);
            (contract as unknown as Record<string, unknown>)[m] = (...a: unknown[]) => {
                this.calls.push(a.length ? `${m}:${String(a[0])}` : m);
                return real(...a);
            };
        }
    }
    async poll() {
        this.conn = await this.contract.connectionSummary();
        this.routes = await this.contract.routesStrict();
    }
    view(over: Partial<MainScreenInput> = {}) {
        return mainScreenView({
            t,
            locale: 'en',
            nowMs: 1_000_000,
            conn: this.conn,
            optimistic: this.optimistic,
            connectInFlight: false,
            intent: null,
            hostFailed: false,
            pinnedRaw: this.pinnedRaw,
            routes: this.routes,
            wasConnected: false,
            remembered: undefined,
            ...over,
        });
    }
    /** What ConnectionPage's onDaalClick does. */
    tap() {
        return runMainTap(this.view().plan, {
            disconnect: () => this.contract.disconnect(),
            addFile: () => void this.calls.push('openAddSheet'),
            recovery: () => void this.calls.push('openRecoverySheet'),
            connect: (what) => startConnect(this.contract, what),
        });
    }
}

beforeEach(() => vi.stubGlobal('window', { location: { search: '?harness=connection-disconnected' } }));
afterEach(() => vi.unstubAllGlobals());

describe('the main screen: a tap connects by itself', () => {
    it('with routes on the device: connectAuto, once — and no navigation, no sheet', async () => {
        const p = new Page(new HarnessContract({ stepMs: 0, scenario: scenario([dead('r1'), way('r2'), way('r3')]) }));
        await p.poll();
        const before = p.view();
        expect(before.headline).toBe('Press to connect.');
        expect(before.plan).toEqual({ kind: 'auto' });
        await p.tap();
        expect(p.calls).toEqual(['connectAuto']);
        await p.poll();
        const after = p.view();
        expect(after.state).toBe('connected');
        expect(after.headline).toBe("You're connected.");
        // It moved past a way that did not work, and says so.
        expect(after.connectedNoteKey).toBe('auto.note.moved_on');
        expect(after.engineAuto).toBe(true);
        // Connected: the tap disconnects.
        expect(after.plan).toEqual({ kind: 'disconnect' });
    });

    it('with the list not readable: still connectAuto (the engine knows what it holds)', async () => {
        const p = new Page(new HarnessContract({ stepMs: 0, scenario: scenario([way('r1')]) }));
        await p.poll();
        p.routes = undefined;
        await p.tap();
        expect(p.calls).toEqual(['connectAuto']);
    });

    it('with nothing imported (the list was READ and is empty): the add sheet, and no connect', async () => {
        const p = new Page(new HarnessContract({ stepMs: 0, scenario: scenario([]) }));
        await p.poll();
        const v = p.view();
        expect(v.needFile).toBe(true);
        expect(v.headline).toBe('Add your file to get started.');
        expect(v.tapLabel).toBe('Add your file');
        await p.tap();
        expect(p.calls).toEqual(['openAddSheet']);
    });

    it('a failed pass: its sentence is the headline, and "Try again" connects automatically again', async () => {
        const p = new Page(new HarnessContract({ stepMs: 0, scenario: scenario([dead('r1'), dead('r2')]) }));
        await p.poll();
        await p.tap();
        await p.poll();
        const v = p.view();
        expect(v.failure).toBeDefined();
        expect(v.failure!.tried.map((x) => x.routeId)).toEqual(['r1', 'r2']);
        expect(v.headline).toBe(t(`auto.verdict.${v.failure!.verdict}`));
        expect(v.headline).not.toBe('Press to connect.');
        expect(v.stateLabel).toBe('Not connected');
        expect(v.failure!.noRetry).toBe(false);
        expect(v.failure!.retryOff).toBe(false);
        expect(retryTarget(v.pinnedId)).toEqual({ kind: 'auto' });
        // The main control too: it tries again, it does not open a list.
        expect(v.plan).toEqual({ kind: 'auto' });
        await p.tap();
        expect(p.calls).toEqual(['connectAuto', 'connectAuto']);
        // The page's own optimistic "connecting" outranks the old failure.
        p.optimistic = 'connecting';
        const during = p.view({ intent: 'auto' });
        expect(during.failure).toBeUndefined();
        expect(during.showProgress).toBe(true);
    });

    it('while trying: the headline is progress, the tap is Cancel, and it disconnects', async () => {
        const p = new Page(new HarnessContract({ stepMs: 40, scenario: scenario([dead('r1'), way('r2')]) }));
        await p.poll();
        const pending = p.tap();
        await new Promise((r) => setTimeout(r, 5));
        await p.poll();
        const v = p.view();
        expect(v.state).toBe('connecting');
        expect(v.showProgress).toBe(true);
        expect(v.headline).toBe('Trying way 1 of 2…');
        expect(v.tapLabel).toBe('Cancel');
        expect(v.plan).toEqual({ kind: 'disconnect' });
        await p.tap();
        expect(p.calls).toEqual(['connectAuto', 'disconnect']);
        await pending;
        await p.poll();
        expect(p.view().headline).toBe('Press to connect.');
    });
});

describe('the main screen: no dead ends', () => {
    const routes = [way('r1'), way('r2')];
    const failed = (verdict: string, over: Partial<ConnectionSummary> = {}): ConnectionSummary => ({
        state: 'error',
        mode: 'normal',
        routeCheck: 'failed',
        routeRunning: false,
        auto: auto({ state: 'failed', verdict }),
        ...over,
    });
    const view = (over: Partial<MainScreenInput>) =>
        mainScreenView({
            t,
            locale: 'en',
            nowMs: 1_000_000,
            conn: null,
            optimistic: null,
            connectInFlight: false,
            intent: null,
            hostFailed: false,
            pinnedRaw: null,
            routes,
            wasConnected: false,
            remembered: undefined,
            ...over,
        });

    it('"Daal will not choose any of these": says so, offers choosing by hand, and no futile Try again', () => {
        const v = view({ conn: failed('none_usable') });
        expect(v.headline).toBe('Daal does not pick any of the ways on this phone by itself.');
        expect(v.failure).toMatchObject({ wantsChooser: true, noRetry: true, actionText: 'You can choose one yourself.' });
        // ...and once they have chosen, the tap connects THAT — the
        // automatic failure still on screen is not the pin's.
        const picked = view({ conn: failed('none_usable'), pinnedRaw: 'r2' });
        expect(picked.plan).toEqual({ kind: 'pinned', routeId: 'r2' });
        expect(picked.failure!.noRetry).toBe(false);
        expect(retryTarget(picked.pinnedId)).toEqual({ kind: 'pinned', routeId: 'r2' });
        const calls: string[] = [];
        runMainTap(picked.plan, {
            disconnect: () => calls.push('disconnect'),
            addFile: () => calls.push('add'),
            recovery: () => calls.push('recovery'),
            connect: (w) => calls.push(w.kind === 'pinned' ? `connect:${w.routeId}` : 'auto'),
        });
        expect(calls).toEqual(['connect:r2']);
    });

    it('the ways are resting: the sentence of the pass that tried stays, with the wait, and Try again is off', () => {
        const resting = routes.map((r, i) => ({ ...r, inCooldown: true, cooldownUntilUnixMs: 1_000_000 + (i + 3) * 60_000 }));
        const remembered = { verdict: 'all_failed', tried: [] };
        const v = view({ conn: failed('all_cooling_down'), routes: resting, remembered });
        expect(v.headline).toBe('None of the ways in your file worked on this network.');
        expect(v.failure).toMatchObject({ retryOff: true, restText: 'You can try again in about 3 min.' });
        // With nothing remembered the engine's own sentence stands, once.
        const bare = view({ conn: failed('all_cooling_down'), routes: resting });
        expect(bare.headline).toBe('Every way failed a little while ago, so Daal is giving them a rest.');
        expect(bare.failure!.actionText).toBe('Try again in about 3 min.');
        expect(bare.failure!.restText).toBeUndefined();
    });

    it('the way the person chose failed: says so and offers Daal choosing', () => {
        const own: ConnectionSummary = { state: 'error', mode: 'normal', routeCheck: 'failed', routeRunning: false, auto: auto({}) };
        const v = view({ conn: own, pinnedRaw: 'r2' });
        expect(v.pinnedFailed).toBe(true);
        expect(v.headline).toBe('The one you chose did not work.');
        // Not for the two failures that rest nothing (try the same again).
        expect(view({ conn: { ...own, routeCheckCategory: 'path_too_slow' }, pinnedRaw: 'r2' }).pinnedFailed).toBe(false);
        // Not without a pin.
        expect(view({ conn: own }).pinnedFailed).toBe(false);
    });

    it('Android, holding: says the phone has no internet meanwhile, and the tap lets go', () => {
        const held = failed('relay_unreachable', { holding: true, auto: auto({ state: 'failed', mode: true, verdict: 'relay_unreachable' }) });
        const v = view({ conn: held });
        expect(v.holding).toBe(true);
        expect(v.headline).toBe('Connection lost. Daal keeps trying.');
        expect(v.stateLabel).toBe('Connection lost');
        expect(v.plan).toEqual({ kind: 'disconnect' });
        expect(v.tapLabel).toBe('Disconnect');
        // The verdict is still there for the panel.
        expect(v.failure?.verdict).toBe('relay_unreachable');
        // The same blob without the flag (desktop, or after the service
        // let go): an ordinary failure, and the tap tries again.
        const free = view({ conn: { ...held, holding: false } });
        expect(free.holding).toBe(false);
        expect(free.plan).toEqual({ kind: 'auto' });
        // While the engine is mid-pass the pass is the news.
        const retrying = view({ conn: { ...held, state: 'connecting', auto: auto({ state: 'trying', mode: true, index: 1, total: 2 }) } });
        expect(retrying.holding).toBe(false);
        expect(retrying.tapLabel).toBe('Cancel');
    });

    it('the engine refused the store read (an unknown code): the generic sentence, never the code', () => {
        const v = view({ conn: failed('store_unreadable') });
        expect(v.headline).toBe('Daal could not connect.');
        expect(v.headline).not.toContain('store');
    });
});
