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
import { failureDetailsShown, homeBadges, mainScreenView, retryTarget, runMainTap, usingName, type MainScreenInput } from './mainScreen';
import type { Scenario } from '../harness/scenarios';
import legacyEn from '../i18n/en.json';
import en from '../i18n/d2/d2-extra.en.json';
import desktopEn from '../i18n/d2/desktop.en.json';
import mobileEn from '../i18n/d2/mobile.en.json';

const EN = { ...(legacyEn as object), ...(desktopEn as object), ...(mobileEn as object), ...(en as object) } as Record<string, string>;
const t = (k: string) => EN[k] ?? k;
/** The text as a person reads it: without the direction isolates. */
const plain = (s: string | undefined) => s?.replace(/[\u2066-\u2069]/g, '');

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
        expect(before.headline).toBe('Tap to connect');
        expect(before.tone).toBe('ready');
        expect(before.primary).toBeUndefined();
        expect(before.plan).toEqual({ kind: 'auto' });
        // Ready says what is ready, by kind: three ways, one kind.
        expect(before.line).toBe('3 ways ready');
        expect(before.readyKinds).toMatchObject({ names: ['VLESS Reality'], more: 0 });
        await p.tap();
        expect(p.calls).toEqual(['connectAuto']);
        await p.poll();
        const after = p.view();
        expect(after.state).toBe('connected');
        expect(after.headline).toBe('Connected');
        // Who made the file, and the kind of connection in use.
        expect(plain(after.line)).toBe('Using Pars · VLESS Reality');
        expect(after.tone).toBe('good');
        expect(after.readyKinds.names).toEqual([]);
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
        expect(v.headline).toBe('Add your file');
        expect(v.tone).toBe('none');
        // One gold button and one link: "Add my file", "No file yet? Send my address".
        expect(v.primary).toBe('add_file');
        expect(v.link).toBe('no_file_address');
        expect(v.line).toBeUndefined();
        expect(v.tapLabel).toBe('Add my file');
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
        // The headline is one short line; the verdict's sentence is the
        // developer detail, and what to do is the line under it.
        expect(v.headline).toBe("Couldn't connect");
        expect(v.detail).toBe(t(`auto.verdict.${v.failure!.verdict}`));
        expect(v.line).toBe(v.failure!.actionText);
        expect(v.primary).toBe('try_again');
        expect(v.tone).toBe('bad');
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
        // "Connecting…", and under it which kind and how far along.
        expect(v.headline).toBe('Connecting…');
        expect(v.line).toBe('Trying VLESS Reality · 1 of 2');
        expect(v.trying).toMatchObject({ index: 1, total: 2 });
        expect(v.detail).toBe('Trying way 1 of 2…');
        expect(v.tone).toBe('busy');
        expect(v.tapLabel).toBe('Cancel');
        expect(v.plan).toEqual({ kind: 'disconnect' });
        await p.tap();
        expect(p.calls).toEqual(['connectAuto', 'disconnect']);
        await pending;
        await p.poll();
        expect(p.view().headline).toBe('Tap to connect');
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
        expect(v.detail).toBe('Daal does not pick any of the ways on this phone by itself.');
        expect(v.headline).toBe("Couldn't connect");
        // No futile Try again; the link is choosing by hand.
        expect(v.primary).toBeUndefined();
        expect(v.link).toBe('choose');
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
        expect(v.detail).toBe('None of the ways in your file worked on this network.');
        expect(v.failure).toMatchObject({ retryOff: true, restText: 'You can try again in about 3 min.' });
        // The wait is the one line under the headline.
        expect(v.line).toBe('You can try again in about 3 min.');
        // With nothing remembered the engine's own sentence stands, once.
        const bare = view({ conn: failed('all_cooling_down'), routes: resting });
        expect(bare.detail).toBe('Every way failed a little while ago, so Daal is giving them a rest.');
        expect(bare.line).toBe('Try again in about 3 min.');
        expect(bare.failure!.actionText).toBe('Try again in about 3 min.');
        expect(bare.failure!.restText).toBeUndefined();
    });

    it('the way the person chose failed: says so and offers Daal choosing', () => {
        const own: ConnectionSummary = { state: 'error', mode: 'normal', routeCheck: 'failed', routeRunning: false, auto: auto({}) };
        const v = view({ conn: own, pinnedRaw: 'r2' });
        expect(v.pinnedFailed).toBe(true);
        expect(v.headline).toBe("That way didn't work");
        expect(v.primary).toBe('let_daal_choose');
        // Not for the two failures that rest nothing (try the same again).
        expect(view({ conn: { ...own, routeCheckCategory: 'path_too_slow' }, pinnedRaw: 'r2' }).pinnedFailed).toBe(false);
        // Not without a pin.
        expect(view({ conn: own }).pinnedFailed).toBe(false);
    });

    it('Android, holding: says the phone has no internet meanwhile, and the tap lets go', () => {
        const held = failed('relay_unreachable', { holding: true, auto: auto({ state: 'failed', mode: true, verdict: 'relay_unreachable' }) });
        const v = view({ conn: held });
        expect(v.holding).toBe(true);
        expect(v.headline).toBe('Reconnecting…');
        expect(v.line).toBe('Other apps have no internet until Daal reconnects or you stop.');
        expect(v.primary).toBe('try_now');
        expect(v.link).toBe('disconnect');
        expect(v.tone).toBe('holding');
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
        expect(v.detail).toBe('Daal could not connect.');
        expect(v.headline).toBe("Couldn't connect");
        expect(v.line).not.toContain('store');
        expect(v.detail).not.toContain('store');
    });
});

describe('Home: one headline, one line, at most one button and one link (spec C2)', () => {
    const base = (over: Partial<MainScreenInput>) =>
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
            routes: [way('r1'), way('r2')],
            wasConnected: false,
            remembered: undefined,
            ...over,
        });
    const failedWith = (verdict: string): ConnectionSummary => ({
        state: 'error',
        mode: 'normal',
        routeCheck: 'failed',
        routeRunning: false,
        auto: auto({ state: 'failed', verdict }),
    });

    it('connected shows a visible Disconnect link; connecting shows Cancel', () => {
        const up = base({ conn: { state: 'connected', mode: 'normal', routeCheck: 'ok', routeRunning: false } as ConnectionSummary });
        expect(up.headline).toBe(t('conn.headline_connected'));
        expect(up.primary).toBeUndefined();
        expect(up.link).toBe('disconnect');
        const going = base({ conn: { state: 'connecting', mode: 'normal', routeRunning: false } as ConnectionSummary });
        expect(going.link).toBe('cancel');
    });
    it('no internet: its own headline and line, Try again, and no link', () => {
        const v = base({ conn: failedWith('network_down') });
        expect(v.headline).toBe('No internet');
        expect(v.line).toBe('Check Wi-Fi or mobile data.');
        expect(v.lineNoInternet).toBe(true);
        expect(v.primary).toBe('try_again');
        expect(v.link).toBeUndefined();
    });
    it('a failure that wants a file links "Add a new file" — never also the chooser', () => {
        const v = base({ conn: failedWith('no_routes') });
        expect(v.link).toBe('add_new_file');
        expect(v.line).toBe('Add the file you were sent.');
        expect(base({ conn: failedWith('all_need_new_file') }).link).toBeUndefined();
    });
    it('every action line under a failure is one short line (≤ 60 characters)', () => {
        for (const verdict of ['no_routes', 'all_need_new_file', 'all_expired_or_revoked', 'network_down', 'udp_blocked_here',
            'relay_unreachable', 'name_blocked', 'address_blocked', 'all_failed', 'none_usable', 'store_unreadable']) {
            const line = base({ conn: failedWith(verdict) }).line ?? '';
            expect(line.length, verdict).toBeLessThanOrEqual(60);
        }
    });
    it('a connect the relay could not carry: "Couldn\'t connect" and the line that says whom to tell', () => {
        const own: ConnectionSummary = {
            state: 'error',
            mode: 'normal',
            routeCheck: 'failed',
            routeRunning: false,
            routeCheckCategory: 'relay_no_egress',
        };
        const v = base({ conn: own });
        expect(v.headline).toBe("Couldn't connect");
        expect(v.line).toBe("The server can't reach the internet. Tell the person who gave you the file.");
        expect(v.primary).toBe('try_again');
        expect(base({ conn: { ...own, routeCheckCategory: 'path_too_slow' } }).line).toBe('The network is too slow right now.');
    });
    it('connected and slow: "Connected", the way in use, and the Slow badge', () => {
        const c: ConnectionSummary = {
            state: 'connected',
            mode: 'lifeline',
            routeCheck: 'degraded',
            activeRoute: way('r1', { publisherName: 'Maman' }),
        };
        const v = base({ conn: c });
        expect(v.headline).toBe('Connected');
        expect(plain(v.line)).toBe('Using Maman · VLESS Reality');
        expect(v.slow).toBe(true);
        expect(v.tone).toBe('slow');
        expect(v.primary).toBeUndefined();
        // Slow first, then Lifeline; at most two.
        // The engine is not choosing here (no auto block): Manual.
        expect(homeBadges(v, c.mode)).toEqual(['slow', 'manual']);
        expect(homeBadges({ ...v, engineAuto: true }, c.mode)).toEqual(['slow', 'lifeline']);
        expect(homeBadges({ ...v, pinnedId: 'r1' }, c.mode)).toEqual(['slow', 'manual']);
        expect(homeBadges({ ...v, slow: false, pinnedId: 'r1' }, 'normal')).toEqual(['manual']);
        expect(homeBadges({ ...v, slow: false, engineAuto: true }, 'normal')).toEqual([]);
    });
    it('a lost connection being retried: "Reconnecting…", amber', () => {
        // The backend reads a connected route that stopped carrying as
        // "connecting" (lib/routeCheck.ts connStateWithCheck).
        const v = base({ conn: { state: 'connecting', mode: 'normal', routeCheck: 'failed', routeRunning: true } });
        expect(v.state).toBe('connecting');
        expect(v.headline).toBe('Reconnecting…');
        expect(v.tone).toBe('holding');
    });
    it('"Using {name}" falls back to our own words for a route whose details could not be read', () => {
        expect(usingName({ state: 'connected', mode: 'normal', activeRoute: way('r9', { publisherName: '', routeNickname: '' }) }, t)).toBeTruthy();
        expect(usingName({ state: 'disconnected', mode: 'normal' }, t)).toBeUndefined();
    });
});

describe('the failure Details fold', () => {
    it('is drawn when ways were tried, not when the phone has no internet (nothing tried)', () => {
        expect(failureDetailsShown([{}], false)).toBe(true);
        expect(failureDetailsShown([], false)).toBe(false);
        // Developer mode keeps it, for the verdict code.
        expect(failureDetailsShown([], true)).toBe(true);
    });
});

describe('Home says what Daal knows, and nothing it does not', () => {
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
            routes: [way('r1'), way('r2')],
            wasConnected: false,
            remembered: undefined,
            ...over,
        });
    const trying = (over: Partial<AutoStatus>): ConnectionSummary => ({
        state: 'connecting',
        mode: 'normal',
        routeRunning: true,
        routeCheck: 'verifying',
        auto: auto({ state: 'trying', mode: true, trying: 'r2', index: 2, total: 4, ...over }),
    });

    it('ready: the count, and the kind that carried here only when it was measured here', () => {
        const routes = [
            way('r1', { family: 'hysteria2', measured: { grade: 'failing', samples: 2, carried: 0, failed: 2 } }),
            way('r2', { family: 'websocket-tls', measured: { grade: 'good', setupMs: 300, samples: 4, carried: 4, failed: 0 } }),
            way('r3', { family: 'wireguard', familyMaturity: 'unsupported' }),
        ];
        const v = view({ conn: { state: 'disconnected', mode: 'normal' }, routes });
        // The kind this build cannot dial is not "ready".
        expect(v.line).toBe('2 ways ready · WebSocket TLS worked here before');
        // In the engine's order: the kind that carried here first, the
        // one that failed here last.
        expect(v.readyKinds.names).toEqual(['WebSocket TLS', 'Hysteria 2']);
        expect(v.readyKinds.tags.map((k) => k.mark)).toEqual(['good', 'bad']);
        // Nothing measured: the count alone.
        expect(view({ conn: { state: 'disconnected', mode: 'normal' }, routes: [way('r1')] }).line).toBe('1 way ready');
        // The list could not be read: nothing at all, not "0 ways".
        expect(view({ conn: { state: 'disconnected', mode: 'normal' }, routes: undefined }).line).toBeUndefined();
        // The engine refused the last connect: its notice speaks, no "ready".
        const refused = view({ conn: { state: 'disconnected', mode: 'normal', connectRefused: 'needs_new_file' } });
        expect(refused.line).toBeUndefined();
        expect(refused.readyKinds.names).toEqual([]);
    });
    it('a kind this app cannot name is never printed (a family comes from a file)', () => {
        const v = view({ conn: { state: 'disconnected', mode: 'normal' }, routes: [way('r1', { family: 'evil<b>' })] });
        expect(v.line).toBe('1 way ready');
        expect(v.readyKinds.names).toEqual([]);
    });
    it('trying: by kind, "n of m", and two at once by both kinds', () => {
        const routes = [way('r1', { family: 'hysteria2' }), way('r2', { family: 'vless-reality' }), way('r3', { family: 'tuic' }), way('r4')];
        const one = view({ conn: trying({}), routes });
        expect(one.line).toBe('Trying VLESS Reality · 2 of 4');
        expect(one.trying).toEqual({ text: 'Trying VLESS Reality · 2 of 4', index: 2, total: 4 });
        const two = view({ conn: trying({ trying: 'r2', racing: ['r2', 'r3'], index: 2 }), routes });
        expect(two.line).toBe('Trying VLESS Reality and TUIC at once');
        expect(two.trying?.racing).toBe(true);
        // The engine said no position: the kind, without "of".
        expect(view({ conn: trying({ index: 0, total: 0 }), routes }).line).toBe('Trying VLESS Reality');
        // A way this app cannot name: plain "Connecting…", no line.
        const unknown = view({ conn: trying({ trying: 'r9' }), routes });
        expect(unknown.line).toBeUndefined();
        expect(unknown.trying).toBeUndefined();
        // After a connection dropped: no "Trying …" under "Connecting…".
        expect(view({ conn: trying({}), routes, wasConnected: true }).line).toBeUndefined();
    });
    it('connected on a way whose kind is unknown: the publisher alone', () => {
        const v = view({ conn: { state: 'connected', mode: 'normal', routeCheck: 'ok', activeRoute: way('r1', { publisherName: 'Maman', family: 'x' }) } });
        expect(plain(v.line)).toBe('Using Maman');
    });
});
