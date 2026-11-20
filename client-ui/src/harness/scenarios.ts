// scenarios.ts — typed catalog of every harness state.
//
// Each scenario is one fully-populated payload for a screen ×
// connection-state combination. The catalog is single-source-of-truth
// for:
//   - HarnessContract (consumes scenario data)
//   - DevPicker (renders the scenario list in dev)
//   - tools/screenshot-harness.mjs (iterates over the list)
//
// Adding a new scenario: append to SCENARIOS, and it picks up in all
// three consumers.

// `last` as the real engine sends it (Unix seconds of an hour) and the
// app shows it — not a hand-written string the engine never produces.
import { lastBucketText } from '../lib/measured';
import type {
    ConnectionSummary,
    PointerRotationSummary,
    RouteDisplayRow,
    RouteHealthDisplayRow,
    SkippedFamilyRow,
    ThroughputSnapshot,
    WhyThisRouteSummary,
} from '../contract/D2Contract';

// ---- canned routes ----

const ROUTE_PARS_RESCUE_03: RouteDisplayRow = {
    routeId: 'pars-rescue-03',
    publisherId: 'pars-relays',
    publisherName: 'Pars Relays',
    routeNickname: 'Rescue 03',
    trustClass: 'trusted',
    family: 'pars',
    inCooldown: false,
    budgetExhausted: false,
    healthPct: 96,
    sourceName: 'Pars Relays',
};

const ROUTE_PARS_RESCUE_01: RouteDisplayRow = {
    routeId: 'pars-rescue-01',
    publisherId: 'pars-relays',
    publisherName: 'Pars',
    routeNickname: 'Rescue 01',
    trustClass: 'trusted',
    family: 'pars',
    inCooldown: true,
    budgetExhausted: true,
    healthPct: 64,
    sourceName: 'Pars Relays',
};

const ROUTE_FRIEND_MAY6: RouteDisplayRow = {
    routeId: 'friend-may-6',
    publisherId: 'friend',
    publisherName: 'Friend',
    routeNickname: 'May 6',
    trustClass: 'pinned',
    family: 'friend',
    inCooldown: false,
    budgetExhausted: false,
    healthPct: 28,
    // No sourceName → renders as "pinned manually".
};

const ROUTE_EMERGENCY_K3F: RouteDisplayRow = {
    routeId: 'emergency-k3f',
    publisherId: 'emergency',
    publisherName: 'Emergency',
    routeNickname: 'K3F',
    trustClass: 'unknown',
    family: 'emergency',
    inCooldown: false,
    budgetExhausted: false,
    healthPct: 50,
    sourceName: 'Emergency Bulletin',
};

// What a route ACTUALLY looks like on a fresh install after the Wave-1
// honesty pass: the engine has observed nothing, so every measured
// field is absent rather than zero. Keep this scenario — it is the one
// that catches a regression back to fabricated defaults.
const ROUTE_FRESH_UNMEASURED: RouteDisplayRow = {
    routeId: 'fresh-import-01',
    publisherId: 'pars-relays',
    publisherName: 'Pars Relays',
    routeNickname: 'Just imported',
    trustClass: 'pinned',
    family: 'vless-reality',
    familyMaturity: 'stable',
    // inCooldown / budgetExhausted / healthPct deliberately absent.
    proven: false,
    sourceName: 'Pars Relays',
};

// A family this build cannot dial. The chip must say so rather than
// showing the ⚡ "experimental" badge, which would invite the user to
// flip a gate that changes nothing.
const ROUTE_UNSUPPORTED_WG: RouteDisplayRow = {
    routeId: 'legacy-wg-01',
    publisherId: 'pars-relays',
    publisherName: 'Pars Relays',
    routeNickname: 'Old WG',
    trustClass: 'pinned',
    family: 'wireguard',
    familyMaturity: 'unsupported',
    proven: false,
};

// Four ways from one file, as an engine that MEASURES reports them on
// the network the phone is on now (`measured`, lib/measured.ts): one
// that works well here, one that works slowly, one that did not work
// here last time, one never tried here. The harness's own automatic
// connect reads these the way the engine reads its memory: the one
// that carried here goes first, alone.
const way = (
    n: number,
    nickname: string,
    family: string,
    measured: RouteDisplayRow['measured'],
): RouteDisplayRow => ({
    routeId: `tehran-way-${n}`,
    publisherId: 'pars-relays',
    publisherName: 'Pars Relays',
    routeNickname: nickname,
    trustClass: 'trusted',
    family,
    familyMaturity: 'stable',
    inCooldown: false,
    budgetExhausted: false,
    measured,
    sourceName: 'Pars Relays',
});

const WAY_GOOD = way(1, 'Way 1', 'vless-reality', {
    grade: 'good', setupMs: 320, samples: 9, carried: 9, failed: 0, last: lastBucketText(1795082400),
});
const WAY_SLOW = way(2, 'Way 2', 'websocket-tls', {
    grade: 'slow', setupMs: 5200, samples: 4, carried: 3, failed: 1, last: lastBucketText(1795035600),
});
const WAY_FAILING = way(3, 'Way 3', 'hysteria2', {
    grade: 'failing', samples: 3, carried: 0, failed: 3, last: lastBucketText(1795078800),
});
const WAY_UNTRIED = way(4, 'Way 4', 'trojan', {
    grade: 'unknown', samples: 0, carried: 0, failed: 0,
});
const MEASURED_ROUTES: RouteDisplayRow[] = [WAY_GOOD, WAY_SLOW, WAY_FAILING, WAY_UNTRIED];

// The same file on a network the phone has never been on: nothing is
// remembered, so automatic connect tries two at a time. The first two
// do not get through here (`healthPct` below 50 is the harness's "does
// not work here"); one of the second pair does.
const NEW_NETWORK_ROUTES: RouteDisplayRow[] = [
    { ...way(1, 'Way 1', 'hysteria2', { grade: 'unknown', samples: 0, carried: 0, failed: 0 }), healthPct: 10 },
    { ...way(2, 'Way 2', 'vless-reality', { grade: 'unknown', samples: 0, carried: 0, failed: 0 }), healthPct: 10 },
    way(3, 'Way 3', 'tuic', { grade: 'unknown', samples: 0, carried: 0, failed: 0 }),
    way(4, 'Way 4', 'websocket-tls', { grade: 'unknown', samples: 0, carried: 0, failed: 0 }),
];

// ---- scenario type ----

export type ScreenId =
    | 'connection'
    | 'network'
    | 'status'
    | 'settings'
    | 'publisher'
    | 'onboarding'
    | 'modal';

export interface Scenario {
    /** URL key — what shows up after ?harness=. */
    id: string;
    /** Short title displayed in DevPicker. */
    title: string;
    /** Top-level screen this scenario exercises. */
    screen: ScreenId;
    /** Optional grouping (e.g. "connected", "error", "empty"). */
    state?: string;
    /** Optional initial route the app should land on, e.g. '/routes'. */
    initialRoute?: string;

    connection: ConnectionSummary;
    why?: WhyThisRouteSummary;
    pointer?: PointerRotationSummary;
    routeHealth?: RouteHealthDisplayRow[];
    availableRoutes?: RouteDisplayRow[];
    throughput?: ThroughputSnapshot;
    rawDiagnosticsJson?: string;
    // v0.2.x — extras consumed by HarnessContract for the full
    // plumbing pass. All optional; defaults live in the contract.
    schedulerStatusJson?: string;
    statsRedactedJson?: string;
    bootstrapStatusJson?: string;
    wasmModules?: string[];
    wasmKillSwitchPubkey?: string;
    skippedFamilies?: SkippedFamilyRow[];
    /** The pretend Tauri shell (publisherFake.ts) and the taps that open
     *  the screen. Absent: the page behaves exactly as before. */
    fake?: FakeShell;
}

/** One tap or wait on the way to a screen (driver.ts names the
 *  targets: `btn:`, `key:`, `css:`, `text:`). */
export type DriveStep =
    | { click: string; nth?: number; optional?: boolean }
    | { type: string; text: string; nth?: number }
    | { waitFor: string; nth?: number }
    | { scroll: string; nth?: number }
    | { sleep: number }
    /** Stop the page's timers (after the target shows, or at once). */
    | { freeze: true | string }
    /** Stop only its long timers (3 s and up, or this many ms and up):
     *  a notice stays up after the next tap, a hand-off waits. */
    | { keep: true | number };

/** What the fake shell holds, and how to reach the screen. */
export interface FakeShell {
    /** `two`: one working relay with three people (one removed), and
     *  one setup that never finished. `none`: a first run. */
    relays: 'two' | 'none';
    health?: 'good' | 'way_failing' | 'unreachable';
    /** PB-1: Baba was restored from a backup and waits for an answer. */
    waiting?: boolean;
    /** PB-2: the relay lets in someone this phone has no row for. */
    relayOnly?: boolean;
    /** The recipient's own Daal address exists already. */
    identity?: 'none' | 'made';
    /** What importing pasted text or a finished QR scan answers
     *  (`partial`: imported, but one way in the file is not usable
     *  on this phone). */
    importVerdict?: 'imported' | 'partial' | 'trust' | 'refused';
    /** URL parameters other harness fakes read (`backup=stale`). */
    params?: Record<string, string>;
    /** Which tab to open first. */
    open?: 'publisher' | 'network' | 'connection';
    steps?: DriveStep[];
}

// ---- shared fragments ----

const DEFAULT_THROUGHPUT: ThroughputSnapshot = {
    upBytesPerSec: 12 * 1024,
    downBytesPerSec: 318 * 1024,
    windowMs: 1000,
};

const DEFAULT_ROUTE_HEALTH: RouteHealthDisplayRow[] = [
    { routeId: ROUTE_PARS_RESCUE_03.routeId, label: 'Pars · Rescue 03', pct: 96, severity: 'ok' },
    { routeId: ROUTE_PARS_RESCUE_01.routeId, label: 'Pars · Rescue 01', pct: 64, severity: 'warn' },
    { routeId: ROUTE_FRIEND_MAY6.routeId,   label: 'Friend · May 6',  pct: 28, severity: 'bad' },
];

const DEFAULT_AVAILABLE_ROUTES: RouteDisplayRow[] = [
    ROUTE_PARS_RESCUE_03,
    ROUTE_PARS_RESCUE_01,
    ROUTE_FRIEND_MAY6,
    ROUTE_EMERGENCY_K3F,
];

// A device that has taken a rotated pointer set.
const POINTER_OK: PointerRotationSummary = {
    havePersisted: true,
    primarySource: 'persisted',
    fallbackSource: 'persisted',
    primaryValidUntil: new Date(Date.now() + 14 * 86400 * 1000).toISOString(),
    validForDays: 14,
};

// A device still on the pointers compiled into the binary, with no
// expiry reported. This is the common real-world case and it is the one
// that used to render as "Pointers rotated successfully."
const POINTER_EMBEDDED: PointerRotationSummary = {
    havePersisted: false,
    primarySource: 'embedded',
    fallbackSource: 'embedded',
};

const WHY_CONNECTED: WhyThisRouteSummary = {
    active: ROUTE_PARS_RESCUE_03,
    reasonText:
        "Lowest latency among trusted routes; matches the current network's history.",
    skipped: [
        { route: ROUTE_PARS_RESCUE_01, reason: 'rate-limited',       reasonToken: 'rate_limited' },
        { route: ROUTE_FRIEND_MAY6,    reason: 'recent failure',     reasonToken: 'recent_failure' },
        { route: ROUTE_EMERGENCY_K3F,  reason: 'last-resort tier',   reasonToken: 'last_resort_tier' },
    ],
    decisionId: 'harness-decision-001',
};

// What the panel shows today on a real device: the selector was handed
// a one-route slice, so there is no comparison to report. `null`, not
// `[]` — the difference is the whole point of this scenario.
const WHY_NOT_EVALUATED: WhyThisRouteSummary = {
    active: ROUTE_FRESH_UNMEASURED,
    reasonText: 'Tunnel up on fresh-import-01.',
    skipped: null,
    skippedFamilies: [{ family: 'hysteria2', ladderStep: 2, reasonTag: 'udp_unavailable' }],
    decisionId: 'harness-decision-002',
};

const CONN_BASE: ConnectionSummary = {
    state: 'disconnected',
    mode: 'normal',
    // The host has told the engine which network this is (on a phone:
    // the VPN service's network callback) — what the rows say about
    // "here" is about this network.
    network: { fromHost: true, kind: 'wifi', validated: 1, metered: 0 },
    networkLabel: 'Wi-Fi',
    pointerValidDays: 14,
};

// ---- taps shared by the fake-shell scenarios (driver.ts) ----

/** From the relay list into the working relay's page. */
const OPEN_RELAY: DriveStep[] = [
    // The working relay's card opens on a tap; its title is the name.
    { click: 'text:Family relay' },
    { waitFor: 'css:[data-testid="health-panel"]' },
    { sleep: 300 },
];

/** Hosting key pasted, then on to "name and size". */
const WIZARD_TO_2: DriveStep[] = [
    { type: 'css:input', text: 'hcloud_Zx9VtQe1pL4mR7sK2wY8bN3cF6hJ0dA5' },
    { click: 'key:wiz.nav.next' },
];

/** Something that reads as a pasted connection file (`UEsDB…`). */
const PASTED_FILE =
    'UEsDBBQAAAAIAA' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);

const PASTE: DriveStep[] = [
    { click: 'key:auto.add_file' },
    { click: 'key:add.tab.paste' },
    { type: 'css:textarea', text: PASTED_FILE },
];

// ---- catalog ----

export const SCENARIOS: Scenario[] = [
    // --- Connection ---
    {
        id: 'connection-connected',
        title: 'Connection · connected',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            connectedSinceUnixMs: Date.now() - 8078 * 1000,
            activeRoute: ROUTE_PARS_RESCUE_03,
        },
        why: WHY_CONNECTED,
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        id: 'connection-disconnected',
        title: 'Connection · disconnected',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-connecting',
        title: 'Connection · connecting',
        screen: 'connection',
        state: 'connecting',
        connection: { ...CONN_BASE, state: 'connecting' },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-error',
        title: 'Connection · error',
        screen: 'connection',
        state: 'error',
        connection: { ...CONN_BASE, state: 'error' },
        pointer: POINTER_EMBEDDED,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-needs-route',
        title: 'Connection · needs-route',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: [],
    },

    // Automatic connect, as the engine's `auto` block describes it
    // (lib/autoConnect.ts). Canned moments; pressing the main control in
    // any disconnected scenario runs the harness's own small version.
    {
        id: 'connection-auto-trying',
        title: 'Connection · automatic, trying way 2 of 4',
        screen: 'connection',
        state: 'connecting',
        connection: {
            ...CONN_BASE,
            state: 'connecting',
            routeRunning: true,
            routeCheck: 'verifying',
            activeRoute: ROUTE_FRIEND_MAY6,
            auto: {
                state: 'trying',
                mode: true,
                trying: ROUTE_FRIEND_MAY6.routeId,
                index: 2,
                total: 4,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
                ],
                verdict: '',
                routeId: '',
            },
        },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-auto-moved',
        title: 'Connection · automatic, connected after moving on',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: ROUTE_PARS_RESCUE_03,
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 2,
                total: 4,
                tried: [
                    { routeId: ROUTE_FRIEND_MAY6.routeId, family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply' },
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: 'vless-reality', result: 'carried', category: '' },
                ],
                verdict: 'moved_on',
                routeId: ROUTE_PARS_RESCUE_03.routeId,
            },
        },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-auto-failed',
        title: 'Connection · automatic, nothing worked',
        screen: 'connection',
        state: 'error',
        connection: {
            ...CONN_BASE,
            state: 'error',
            routeRunning: false,
            auto: {
                state: 'failed',
                mode: false,
                trying: '',
                index: 0,
                total: 2,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout' },
                    { routeId: ROUTE_FRIEND_MAY6.routeId, family: 'websocket-tls', result: 'start_failed', category: 'tcp_connect_timeout' },
                ],
                verdict: 'relay_unreachable',
                routeId: '',
            },
        },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },

    // Measurement, trying two at once, moving for speed, and the phone
    // itself being offline (lib/measured.ts, lib/autoConnect.ts).
    {
        id: 'connection-auto-racing',
        title: 'Connection · automatic, trying two ways at once',
        screen: 'connection',
        state: 'connecting',
        connection: {
            ...CONN_BASE,
            state: 'connecting',
            routeRunning: true,
            routeCheck: 'verifying',
            activeRoute: NEW_NETWORK_ROUTES[2],
            auto: {
                state: 'trying',
                mode: true,
                trying: NEW_NETWORK_ROUTES[2].routeId,
                racing: [NEW_NETWORK_ROUTES[2].routeId, NEW_NETWORK_ROUTES[3].routeId],
                index: 3,
                total: 4,
                tried: [
                    { routeId: NEW_NETWORK_ROUTES[0].routeId, family: 'hysteria2', result: 'not_carrying', category: 'udp_no_reply', racedWith: NEW_NETWORK_ROUTES[1].routeId },
                    { routeId: NEW_NETWORK_ROUTES[1].routeId, family: 'vless-reality', result: 'start_failed', category: 'tcp_connect_timeout', racedWith: NEW_NETWORK_ROUTES[0].routeId },
                ],
                verdict: '',
                routeId: '',
            },
        },
        availableRoutes: NEW_NETWORK_ROUTES,
    },
    {
        // Press the main control: nothing is remembered on this
        // network, so the harness tries two at a time.
        id: 'connection-new-network',
        title: 'Connection · a network never seen before (press to connect)',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: NEW_NETWORK_ROUTES,
    },
    {
        // Press the main control: the way that worked here goes first,
        // alone, and carries.
        id: 'connection-measured',
        title: 'Connection · measured on this network (press to connect)',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: MEASURED_ROUTES,
    },
    {
        id: 'connection-connected-good',
        title: 'Connection · connected, works well here',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: WAY_GOOD,
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 1,
                total: 3,
                tried: [{ routeId: WAY_GOOD.routeId, family: WAY_GOOD.family, result: 'carried', category: '', setupMs: 310 }],
                verdict: '',
                routeId: WAY_GOOD.routeId,
            },
        },
        availableRoutes: MEASURED_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        id: 'connection-connected-slow',
        title: 'Connection · connected, slow here',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'degraded',
            routeCheckCategory: 'path_too_slow',
            activeRoute: WAY_SLOW,
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 1,
                total: 3,
                tried: [{ routeId: WAY_SLOW.routeId, family: WAY_SLOW.family, result: 'carried', category: '', setupMs: 5400 }],
                verdict: '',
                routeId: WAY_SLOW.routeId,
            },
        },
        availableRoutes: MEASURED_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        id: 'connection-moved-faster',
        title: 'Connection · automatic, moved to a faster way',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: WAY_GOOD,
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 0,
                total: 0,
                tried: [{ routeId: WAY_GOOD.routeId, family: WAY_GOOD.family, result: 'carried', category: '', setupMs: 330 }],
                verdict: 'moved_faster',
                routeId: WAY_GOOD.routeId,
            },
        },
        availableRoutes: MEASURED_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        // The phone itself says it has no internet: nothing was tried.
        id: 'connection-network-down',
        title: 'Connection · this phone has no internet',
        screen: 'connection',
        state: 'error',
        connection: {
            ...CONN_BASE,
            state: 'error',
            routeRunning: false,
            auto: {
                state: 'failed',
                mode: false,
                trying: '',
                index: 0,
                total: 4,
                tried: [],
                verdict: 'network_down',
                routeId: '',
            },
        },
        availableRoutes: MEASURED_ROUTES,
    },

    // --- Routes ---
    {
        // Every grade on one page, and a way saved by hand earlier while
        // Daal is connected automatically on another.
        id: 'routes-measured',
        title: 'Routes · measured on this network',
        screen: 'network',
        initialRoute: '/routes',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: WAY_GOOD,
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 1,
                total: 3,
                tried: [{ routeId: WAY_GOOD.routeId, family: WAY_GOOD.family, result: 'carried', category: '', setupMs: 310 }],
                verdict: '',
                routeId: WAY_GOOD.routeId,
            },
        },
        availableRoutes: MEASURED_ROUTES,
        routeHealth: MEASURED_ROUTES.map((r) => ({
            routeId: r.routeId,
            label: `Pars · ${r.routeNickname}`,
            measured: r.measured,
        })),
    },
    {
        id: 'routes-populated',
        title: 'Routes · populated',
        screen: 'network',
        initialRoute: '/routes',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        routeHealth: DEFAULT_ROUTE_HEALTH,
    },
    {
        id: 'routes-empty',
        title: 'Routes · empty',
        screen: 'network',
        initialRoute: '/routes',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: [],
    },
    {
        id: 'routes-with-cooldown',
        title: 'Routes · cooldown',
        screen: 'network',
        initialRoute: '/routes',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        availableRoutes: [ROUTE_PARS_RESCUE_03, ROUTE_PARS_RESCUE_01],
    },
    {
        // The fresh-install truth on an engine that sends no
        // measurement: nothing measured, nothing claimed. No row says
        // anything about how it does here, and the unsupported family
        // must read "unsupported", not "experimental".
        id: 'routes-unmeasured',
        title: 'Routes · nothing measured yet',
        screen: 'network',
        initialRoute: '/routes',
        state: 'unmeasured',
        connection: { ...CONN_BASE, state: 'disconnected', pointerValidDays: undefined },
        availableRoutes: [ROUTE_FRESH_UNMEASURED, ROUTE_UNSUPPORTED_WG],
        routeHealth: [
            { routeId: ROUTE_FRESH_UNMEASURED.routeId, label: 'Pars · Just imported' },
            { routeId: ROUTE_UNSUPPORTED_WG.routeId, label: 'Pars · Old WG' },
        ],
        pointer: POINTER_EMBEDDED,
        why: WHY_NOT_EVALUATED,
    },

    // --- Sources ---
    {
        id: 'sources-populated',
        title: 'Sources · populated',
        screen: 'network',
        initialRoute: '/sources',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'sources-empty',
        title: 'Sources · empty',
        screen: 'network',
        initialRoute: '/sources',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: [],
    },

    // --- Status ---
    {
        id: 'status-healthy',
        title: 'Status · healthy',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        why: WHY_CONNECTED,
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        id: 'status-degraded',
        title: 'Status · degraded',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_FRIEND_MAY6 },
        pointer: POINTER_EMBEDDED,
        routeHealth: [
            { routeId: ROUTE_FRIEND_MAY6.routeId, label: 'Friend · May 6', pct: 28, severity: 'bad' },
            { routeId: ROUTE_EMERGENCY_K3F.routeId, label: 'Emergency · K3F', pct: 50, severity: 'warn' },
        ],
    },
    {
        id: 'status-no-data',
        title: 'Status · no-data',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Settings ---
    {
        id: 'settings-default',
        title: 'Settings · default',
        screen: 'settings',
        initialRoute: '/settings',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Publisher ---
    {
        id: 'publisher-off',
        title: 'Publisher · off',
        screen: 'publisher',
        initialRoute: '/publisher',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'publisher-on',
        title: 'Publisher · on',
        screen: 'publisher',
        initialRoute: '/publisher',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
    },

    // --- Onboarding (step-targeted scenarios resolve in routes/Onboarding) ---
    {
        id: 'onboarding-step-1',
        title: 'Onboarding · step 1',
        screen: 'onboarding',
        initialRoute: '/onboarding?step=1',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'onboarding-step-5',
        title: 'Onboarding · step 5',
        screen: 'onboarding',
        initialRoute: '/onboarding?step=5',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'onboarding-step-10',
        title: 'Onboarding · step 10',
        screen: 'onboarding',
        initialRoute: '/onboarding?step=10',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Status accordions (v0.2.x extras) ---
    {
        id: 'status-scheduler',
        title: 'Status · scheduler accordion',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        schedulerStatusJson:
            '{"tick":4218,"queue":[{"id":"pars-rescue-03","delay_ms":120},{"id":"friend-may-6","delay_ms":820}],"in_flight":1,"last_pick":"pars-rescue-03"}',
    },
    {
        id: 'status-stats-redacted',
        title: 'Status · stats (redacted)',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        statsRedactedJson:
            '{"sessions":4,"bytes_up_bucket":"k","bytes_down_bucket":"M","redacted":true}',
    },
    {
        id: 'status-bootstrap-empty',
        title: 'Status · bootstrap (empty)',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'disconnected' },
        bootstrapStatusJson: '{"seeds":0,"last_refresh":null}',
    },
    {
        id: 'status-bootstrap-seeded',
        title: 'Status · bootstrap (seeded)',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        bootstrapStatusJson:
            '{"seeds":3,"last_refresh":"2026-05-22T11:48:02Z","ok":true}',
    },
    {
        id: 'status-network-test',
        title: 'Status · network test',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Settings (wasm / advanced) ---
    {
        id: 'settings-wasm-loaded',
        title: 'Settings · wasm loaded',
        screen: 'settings',
        initialRoute: '/settings',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        wasmModules: ['hello-https', 'censorship-canary'],
        wasmKillSwitchPubkey: 'a1b2c3d4e5f6'.repeat(4),
    },
    {
        id: 'settings-advanced',
        title: 'Settings · advanced toggles',
        screen: 'settings',
        initialRoute: '/settings',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Vault unlock ---
    {
        id: 'vault-locked',
        title: 'Vault · locked',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Publisher wizard (Phase C) ---
    {
        id: 'publisher-wizard-step-1',
        title: 'Publisher · welcome',
        screen: 'publisher',
        initialRoute: '/publisher?wizard=1',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'publisher-wizard-step-4',
        title: 'Publisher · keys',
        screen: 'publisher',
        initialRoute: '/publisher?wizard=4',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'publisher-wizard-step-7',
        title: 'Publisher · distribute',
        screen: 'publisher',
        initialRoute: '/publisher?wizard=7',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Recipient QR (Phase D) ---
    {
        id: 'recipient-qr-empty',
        title: 'Recipient · QR (idle)',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'recipient-qr-scanning',
        title: 'Recipient · QR (scanning)',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'recipient-qr-done',
        title: 'Recipient · QR (done)',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Modals & overlays ---
    {
        id: 'trust-prompt-new-publisher',
        title: 'Trust prompt · new publisher',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'panic-wipe-confirm',
        title: 'Panic-wipe · confirm',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
    },
    {
        id: 'mode-picker-open',
        title: 'Mode-picker · open',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
    },

    // --- Publisher, on the fake shell (publisherFake.ts) ---
    ...pub(
        {
            id: 'pub-relay-list',
            title: 'Relay list',
        }, {}),
    ...pub(
        {
            id: 'pub-relay-list-backup-stale',
            title: 'Relay list · backup out of date',
        }, { params: { backup: 'stale' } }),
    ...pub(
        {
            id: 'pub-relay-list-restored',
            title: 'Relay list · just restored from a backup',
        }, { params: { backup: 'notice' } }),
    ...pub(
        {
            id: 'pub-relay-remove',
            title: 'Relay list · remove the working relay',
        }, {
        steps: [{ click: 'key:pub.relays.decommission', nth: 0 }],
    }),
    ...pub(
        {
            id: 'pub-relay-remove-unfinished',
            title: 'Relay list · remove the unfinished setup',
        }, {
        steps: [{ click: 'key:pub.relays.decommission', nth: 1 }],
    }),
    ...pub(
        {
            id: 'pub-account-check',
            title: 'Relay list · check my hosting account',
        }, {
        steps: [{ click: 'key:pub.account.open' }, { sleep: 600 }],
    }),
    ...pub(
        {
            id: 'pub-relay-healthy',
            title: 'Relay page · working',
        }, { steps: OPEN_RELAY }),
    ...pub(
        {
            id: 'pub-relay-people',
            title: 'Relay page · People',
        }, {
        steps: [...OPEN_RELAY, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-relay-everyone',
            title: 'Relay page · one file for everyone',
        }, {
        steps: [...OPEN_RELAY, { scroll: 'key:pub.everyone.title' }],
    }),
    ...pub(
        {
            id: 'pub-relay-way-failing',
            title: 'Relay page · one way not answering',
        }, {
        health: 'way_failing',
        steps: OPEN_RELAY,
    }),
    ...pub(
        {
            id: 'pub-relay-unreachable',
            title: 'Relay page · relay does not answer',
        }, {
        health: 'unreachable',
        steps: OPEN_RELAY,
    }),
    ...pub(
        {
            id: 'pub-relay-waiting',
            title: 'Relay page · a person waits for an answer',
        }, {
        waiting: true,
        steps: OPEN_RELAY,
    }),
    ...pub(
        {
            id: 'pub-relay-relay-only',
            title: 'Relay page · someone only the relay knows',
        }, {
        relayOnly: true,
        steps: [...OPEN_RELAY, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-person-more',
            title: 'Person · "File lost, or shared by mistake?" open',
        }, {
        steps: [...OPEN_RELAY, { click: 'key:pub.people.more', nth: 0 }, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-person-sent',
            title: 'Person · after "Send file"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, { click: 'key:pub.people.send', nth: 0 }, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-person-saved',
            title: 'Person · after "Save file"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, { click: 'key:pub.people.save', nth: 0 }, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-person-copied',
            title: 'Person · after "Copy as text"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, { click: 'key:pub.person.copy', nth: 0 }, { scroll: 'key:pub.people.title' }],
    }),
    ...pub(
        {
            id: 'pub-person-add',
            title: 'Person · add a person',
        }, {
        steps: [...OPEN_RELAY, { click: 'key:pub.people.add' }],
    }),
    ...pub(
        {
            id: 'pub-person-remove',
            title: 'Person · remove access, confirm',
        }, {
        steps: [...OPEN_RELAY, { click: 'key:pub.people.remove_access', nth: 0 }],
    }),
    ...pub(
        {
            id: 'pub-qr-person',
            title: 'QR · one person\'s file',
        }, {
        steps: [...OPEN_RELAY, { click: 'key:pub.person.qr', nth: 0 }, { sleep: 800 }],
    }),
    ...pub(
        {
            id: 'pub-qr-everyone',
            title: 'QR · the file for everyone',
        }, {
        steps: [...OPEN_RELAY, { click: 'key:pub.everyone.qr' }, { sleep: 800 }],
    }),
    ...pub(
        {
            id: 'pub-everyone-copied',
            title: 'Everyone file · after "Copy as text"',
        }, {
        steps: [
            ...OPEN_RELAY,
            { keep: true },
            // Same words as each person's button: the third one
            // (Maman, Baba, then everyone; Ali's access is gone).
            { click: 'key:pub.everyone.copy', nth: 2 },
            { scroll: 'key:pub.everyone.title' },
        ],
    }),
    ...pub(
        {
            id: 'pub-backup-first',
            title: 'Backup · first time',
        }, {
        params: { backup: 'never' },
        steps: [{ click: 'btn:backup' }],
    }),
    ...pub(
        {
            id: 'pub-backup-words',
            title: 'Backup · the twelve words shown',
        }, {
        params: { backup: 'never' },
        steps: [{ click: 'btn:backup' }, { click: 'btn:create-words' }],
    }),
    ...pub(
        {
            id: 'pub-backup-confirm',
            title: 'Backup · check three of the words',
        }, {
        params: { backup: 'never' },
        steps: [{ click: 'btn:backup' }, { click: 'btn:create-words' }, { click: 'btn:wrote' }],
    }),
    ...pub(
        {
            id: 'pub-backup-stale',
            title: 'Backup · out of date',
        }, {
        params: { backup: 'stale' },
        steps: [{ click: 'btn:backup' }],
    }),
    ...pub(
        {
            id: 'pub-backup-saved',
            title: 'Backup · saved to Downloads',
        }, {
        params: { backup: 'last' },
        steps: [{ click: 'btn:backup' }, { click: 'btn:save-downloads' }],
    }),
    ...pub(
        {
            id: 'pub-restore',
            title: 'Restore · choose the file',
        }, {
        steps: [{ click: 'btn:restore-link' }],
    }),
    ...pub(
        {
            id: 'pub-restore-words',
            title: 'Restore · type the twelve words',
        }, {
        steps: [{ click: 'btn:restore-link' }, { click: 'btn:choose' }],
    }),
    ...pub(
        {
            id: 'pub-restore-preview',
            title: 'Restore · what the backup holds',
        }, {
        steps: [
            { click: 'btn:restore-link' },
            { click: 'btn:choose' },
            { type: 'css:textarea', text: 'legal winner thank year wave sausage worth useful legal winner thank yellow' },
            { click: 'btn:open' },
        ],
    }),
    ...pub(
        {
            id: 'pub-wizard-1',
            title: 'Wizard · 1 hosting account',
        }, { relays: 'none' }),
    ...pub(
        {
            id: 'pub-wizard-1-filled',
            title: 'Wizard · 1 key pasted',
        }, {
        relays: 'none',
        steps: [{ type: 'css:input', text: 'hcloud_Zx9VtQe1pL4mR7sK2wY8bN3cF6hJ0dA5' }],
    }),
    ...pub(
        {
            id: 'pub-wizard-2',
            title: 'Wizard · 2 name and size',
        }, {
        relays: 'none',
        steps: [...WIZARD_TO_2, { sleep: 600 }],
    }),
    ...pub(
        {
            id: 'pub-wizard-3-building',
            title: 'Wizard · 3 building',
        }, {
        relays: 'none',
        steps: [...WIZARD_TO_2, { click: 'key:wiz.plan.next' }, { waitFor: 'key:wiz.build.hint' }, { sleep: 700 }, { freeze: true }],
    }),
    ...pub(
        {
            id: 'pub-wizard-3-done',
            title: 'Wizard · 3 relay ready',
        }, {
        relays: 'none',
        // The 1.2 s pause before the hand-off to the relay page is held.
        steps: [...WIZARD_TO_2, { keep: 1000 }, { click: 'key:wiz.plan.next' }, { waitFor: 'key:wiz.build.done.eyebrow' }],
    }),

    // --- Recipient: import, scan, address (fake shell + taps) ---
    ...rcp(
        {
            id: 'rcp-add-sheet',
            title: 'Add a file · the sheet',
        }, 'connection', [{ click: 'key:auto.add_file' }]),
    ...rcp(
        {
            id: 'rcp-add-paste-tab',
            title: 'Add a file · "Paste" tab',
        }, 'connection', [
        { click: 'key:auto.add_file' },
        { click: 'key:add.tab.paste' },
    ]),
    ...rcp(
        {
            id: 'rcp-paste-ready',
            title: 'Add a file · text pasted',
        }, 'connection', PASTE),
    ...rcp(
        {
            id: 'rcp-import-trust',
            title: 'Add a file · new publisher, check the words',
        }, 'connection',
        [...PASTE, { click: 'key:add.import' }], { importVerdict: 'trust' }),
    ...rcp(
        {
            id: 'rcp-import-refused',
            title: 'Add a file · refused',
        }, 'connection',
        [...PASTE, { click: 'key:add.import' }], { importVerdict: 'refused' }),
    ...rcp(
        {
            id: 'rcp-import-done',
            title: 'Add a file · imported',
        }, 'connection',
        [...PASTE, { click: 'key:add.import' }], { importVerdict: 'imported' }),
    ...rcp(
        {
            id: 'rcp-import-partial',
            title: 'Add a file · imported, one way not usable here',
        }, 'connection',
        [...PASTE, { click: 'key:add.import' }], { importVerdict: 'partial' }),
    ...rcp(
        {
            id: 'rcp-network-add',
            title: 'Network · add from the Network tab',
        }, 'network', [{ click: 'key:network.add' }]),
    ...rcp(
        {
            id: 'rcp-scan',
            title: 'Scan · camera',
        }, 'network', [{ click: 'key:scan.open' }, { sleep: 600 }]),
    ...rcp(
        {
            id: 'rcp-scan-paste',
            title: 'Scan · paste frames tab',
        }, 'network', [
        { click: 'key:scan.open' },
        { click: 'key:scan.mode.paste' },
    ]),
    ...rcp(
        {
            id: 'rcp-scan-progress',
            title: 'Scan · part of the file read',
        }, 'network', scanFeed(5)),
    ...rcp(
        {
            id: 'rcp-scan-trust',
            title: 'Scan · done, new publisher',
        }, 'network', scanFeed(14), { importVerdict: 'trust' }),
    ...rcp(
        {
            id: 'rcp-scan-done',
            title: 'Scan · done, imported (the sheet closes by itself)',
        }, 'network', scanFeed(14), { importVerdict: 'imported' }),
    ...rcp(
        {
            id: 'rcp-scan-partial',
            title: 'Scan · done, one way not usable here',
        }, 'network', scanFeed(14), { importVerdict: 'partial' }),
    ...rcp(
        {
            id: 'rcp-scan-refused',
            title: 'Scan · done, refused',
        }, 'network', scanFeed(14), { importVerdict: 'refused' }),
    ...rcp(
        {
            id: 'rcp-address-before',
            title: 'My address · not made yet',
        }, 'network', [{ click: 'key:network.my_address' }, { sleep: 300 }]),
    ...rcp(
        {
            id: 'rcp-address-copied',
            title: 'My address · copied',
        }, 'network', [
        { click: 'key:network.my_address' },
        // "Copied" turns back after 1.5 s.
        { keep: 1000 },
        { click: 'key:recipient.address.copy' },
    ], { identity: 'made' }),
    ...rcp(
        {
            id: 'rcp-address-after',
            title: 'My address · made',
        }, 'network', [{ click: 'key:network.my_address' }, { sleep: 300 }], {
        identity: 'made',
    }),
];

// ---- builders for the fake-shell scenarios ----
//
// Declared as functions (hoisted) so the catalog above can use them.
// Each `id:` sits on its own line so tools/screenshot-harness.mjs, which
// reads ids from this file's text, finds them too.

function pub({ id, title }: { id: string; title: string }, fake: Partial<FakeShell>): Scenario[] {
    return [
        {
            id,
            title: `Publisher · ${title}`,
            screen: 'publisher',
            state: 'fake-shell',
            connection: { ...CONN_BASE, state: 'disconnected' },
            fake: { relays: 'two', health: 'good', open: 'publisher', ...fake },
        },
    ];
}

function rcp(
    { id, title }: { id: string; title: string },
    open: 'connection' | 'network',
    steps: DriveStep[],
    extra: Partial<FakeShell> = {},
): Scenario[] {
    return [
        {
            id,
            title: `Recipient · ${title}`,
            screen: 'modal',
            state: 'fake-shell',
            connection: { ...CONN_BASE, state: 'disconnected' },
            availableRoutes: open === 'connection' ? [] : DEFAULT_AVAILABLE_ROUTES,
            fake: { relays: 'none', open, steps, ...extra },
        },
    ];
}

/** Open the scanner, switch to pasted frames, feed `n` of them. */
function scanFeed(n: number): DriveStep[] {
    const lines: string[] = [];
    for (let i = 0; i < n; i++) {
        // 144 base64url characters: one 108-byte frame.
        lines.push(`AQ${String.fromCharCode(65 + i)}` + 'Lm4Rt8Vx2Bz6Nc0Qe3Gs7Jw1Hy5Ku9Pa'.repeat(4) + 'ABCDE');
    }
    return [
        { click: 'key:scan.open' },
        { click: 'key:scan.mode.paste' },
        { type: 'css:textarea', text: lines.join('\n') },
        { click: 'key:scan.paste.feed' },
        { sleep: 600 },
    ];
}

// ---- helpers ----

const DEFAULT_SCENARIO_ID = 'connection-connected';

/** Find the active scenario from the URL `?harness=` query param. */
export function scenarioFromUrl(): Scenario | null {
    try {
        const params = new URLSearchParams(window.location.search);
        const v = params.get('harness');
        if (!v) return null;
        return SCENARIOS.find((s) => s.id === v) ?? null;
    } catch {
        return null;
    }
}

/** True when the URL contains a valid `?harness=` query. */
export function isHarnessActive(): boolean {
    return scenarioFromUrl() !== null;
}

/** Active scenario; falls back to a default if a stale id is in the URL. */
export function activeScenario(): Scenario {
    return (
        scenarioFromUrl() ??
        SCENARIOS.find((s) => s.id === DEFAULT_SCENARIO_ID) ??
        SCENARIOS[0]
    );
}
