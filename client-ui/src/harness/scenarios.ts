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
import type { NetTestFake } from './netTestFake';
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
    family: 'websocket-tls',
    familyMaturity: 'stable',
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
    family: 'hysteria2',
    familyMaturity: 'stable',
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
    family: 'vless-reality',
    familyMaturity: 'stable',
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
    family: 'naive',
    familyMaturity: 'stable',
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
const WAY_UNTRIED = way(4, 'Way 4', 'naive', {
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

// One file as a real relay makes it (the Files tab, lib/fileFacts.ts):
// the publisher's relay names its ways r1..r4, two of them are the same
// kind, and the engine has seen each one differently on this network —
// one carried fast, one carried slowly, one failed three times and is
// resting, one is an experimental kind never tried here.
const RELAY_REST_UNTIL = Date.now() + 38 * 60 * 1000;
/** The engine's hour bucket `h` hours back, as parseMeasured keeps it. */
const lastHour = (h: number) => {
    const unix = Math.floor(Date.now() / 3600_000) * 3600 - h * 3600;
    return { last: lastBucketText(unix), lastUnix: unix };
};
const relayWay = (n: number, family: string, over: Partial<RouteDisplayRow>): RouteDisplayRow => ({
    routeId: `test-r${n}`,
    publisherId: 'b7e1c2d4f9a03e55',
    publisherName: 'Test',
    routeNickname: `r${n}`,
    trustClass: 'trusted',
    family,
    familyMaturity: 'stable',
    inCooldown: false,
    budgetExhausted: false,
    ...over,
});
const RELAY_R1 = relayWay(1, 'vless-reality', {
    healthPct: 94,
    proven: true,
    measured: { grade: 'good', setupMs: 380, samples: 7, carried: 7, failed: 0, ...lastHour(0) },
});
const RELAY_R2 = relayWay(2, 'vless-reality', {
    healthPct: 71,
    proven: true,
    measured: { grade: 'slow', setupMs: 2600, samples: 4, carried: 3, failed: 1, ...lastHour(2) },
});
const RELAY_R3 = relayWay(3, 'hysteria2', {
    healthPct: 22,
    inCooldown: true,
    cooldownUntilUnixMs: RELAY_REST_UNTIL,
    measured: { grade: 'failing', samples: 3, carried: 0, failed: 3, ...lastHour(1) },
});
const RELAY_R4 = relayWay(4, 'tuic', {
    familyMaturity: 'experimental',
    measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 },
});
// A second file, from a subscription, with names of its own.
const SUB_WAY = (n: number, nickname: string, family: string, over: Partial<RouteDisplayRow>): RouteDisplayRow => ({
    routeId: `pars-sub-${n}`,
    publisherId: 'pars-relays',
    publisherName: 'Pars Relays',
    routeNickname: nickname,
    trustClass: 'trusted',
    family,
    familyMaturity: 'stable',
    inCooldown: false,
    budgetExhausted: false,
    sourceName: 'Pars Relays',
    ...over,
});
const RELAY_FILE_ROUTES: RouteDisplayRow[] = [
    RELAY_R1,
    RELAY_R2,
    RELAY_R3,
    RELAY_R4,
    SUB_WAY(1, 'Rescue 03', 'websocket-tls', {
        healthPct: 88,
        proven: true,
        measured: { grade: 'ok', setupMs: 1150, samples: 2, carried: 2, failed: 0, ...lastHour(5) },
    }),
    SUB_WAY(2, 'shadowsocks', 'shadowsocks', {
        familyMaturity: 'experimental',
        measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 },
    }),
    SUB_WAY(3, 'Old WG', 'wireguard', { familyMaturity: 'unsupported' }),
];
// The same two files when the engine has no record for the network the
// phone is on now (the VPN service is not running): no `measured` block
// at all, so nothing is said about "here".
const RELAY_FILE_ROUTES_NO_NETWORK: RouteDisplayRow[] = RELAY_FILE_ROUTES.map(({ measured: _m, ...r }) => r);
const RELAY_AUTO_ON_R1 = {
    state: 'connected' as const,
    mode: true,
    trying: '',
    index: 0,
    total: 0,
    tried: [{ routeId: RELAY_R1.routeId, family: RELAY_R1.family, result: 'carried' as const, category: '', setupMs: 380 }],
    verdict: '',
    routeId: RELAY_R1.routeId,
};

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
    /** Developer mode held on for this page (never stored). */
    dev?: boolean;
    /** Taps on a plain scenario (no fake shell), after the screen that
     *  shell/harnessStart.ts opens has drawn (driver.ts runPlainDrive). */
    steps?: DriveStep[];
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
    | { keep: true | number }
    /** Developer mode on or off for this page from here (driver.ts). */
    | { dev: boolean };

/** What the fake shell holds, and how to reach the screen. */
export interface FakeShell {
    /** `two`: one working relay with three people (one removed), and
     *  one setup that never finished. `one`: only the working relay (the
     *  Publisher tab opens it directly). `none`: a first run. */
    relays: 'two' | 'one' | 'none';
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
    importVerdict?: 'imported' | 'partial' | 'trust' | 'refused' | 'changed';
    /** The engine did not start (`engine_status` says so): Home's first
     *  notice (MUST KEEP 16). */
    engineDown?: boolean;
    /** Pretend to be an Android phone (the share sheet exists, so My
     *  address offers "Send address" first). */
    android?: boolean;
    /** The file the system picker returns ("Choose a file"). */
    picked?: string;
    /** The file Android handed over ("Open with Daal"), taken once. */
    opened?: string;
    /** URL parameters other harness fakes read (`backup=stale`). */
    params?: Record<string, string>;
    /** The network test's pretend engine (harness/netTestFake.ts). */
    netTest?: NetTestFake;
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
    { routeId: ROUTE_PARS_RESCUE_03.routeId, label: 'Pars Relays · Rescue 03', pct: 96, severity: 'ok' },
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
// Home while connected, as a real engine answers today: the selector
// compared nothing (`skipped: null`), and the path manager is resting
// one kind of connection on this network (measured).
const whyLive = (active: RouteDisplayRow, decisionId: string): WhyThisRouteSummary => ({
    active,
    reasonText: `Tunnel up on ${active.routeId}.`,
    skipped: null,
    skippedFamilies: [
        { family: 'hysteria2', ladderStep: 2, untilUnixMs: Date.now() + 9 * 60 * 1000, reasonTag: 'udp_unavailable' },
    ],
    decisionId,
});

// The default file on Home, measured on this network: one way carried
// here quickly before, one did not, two were never tried.
const HOME_ROUTES: RouteDisplayRow[] = [
    { ...ROUTE_PARS_RESCUE_03, measured: { grade: 'good', setupMs: 610, samples: 6, carried: 6, failed: 0 } },
    { ...ROUTE_PARS_RESCUE_01, measured: { grade: 'failing', samples: 3, carried: 0, failed: 3 } },
    { ...ROUTE_FRIEND_MAY6, measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 } },
    { ...ROUTE_EMERGENCY_K3F, measured: { grade: 'unknown', samples: 0, carried: 0, failed: 0 } },
];

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

/** Publisher: the relay page's ⋯, then one of its items. */
const relayMenu = (item: string): DriveStep[] => [{ click: 'btn:relay-more' }, { click: `btn:${item}` }];
/** Publisher: the relay list's ⋯, then one of its items. */
const relaysMenu = (item: string): DriveStep[] => [{ click: 'btn:relays-more' }, { click: `btn:${item}` }];
/** Publisher: the first person's send button, then a way out. */
const sendPerson = (item: string): DriveStep[] => [{ click: 'btn:person-send', nth: 0 }, { click: `btn:${item}` }];
/** Publisher: the everyone row's send button, then a way out. */
const sendEveryone = (item: string): DriveStep[] => [{ click: 'btn:everyone-send' }, { click: `btn:${item}` }];
/** Publisher with no relay: the empty state's "Start" opens the wizard. */
const START_WIZARD: DriveStep[] = [{ click: 'btn:new-relay' }];

/** Past "Where should your relay live?" (Hetzner is already chosen). */
const WIZARD_TO_KEY: DriveStep[] = [...START_WIZARD, { click: 'btn:wiz-next' }];

/** Hosting key pasted, then on to "name and size". */
const WIZARD_TO_2: DriveStep[] = [
    ...WIZARD_TO_KEY,
    { type: 'css:input', text: 'hcloud_Zx9VtQe1pL4mR7sK2wY8bN3cF6hJ0dA5' },
    { click: 'key:wiz.nav.next' },
];

/** Something that reads as a pasted connection file (`UEsDB…`). */
const PASTED_FILE =
    'UEsDBBQAAAAIAA' + 'Kx3mQ9vT2bN8pLr4Wc7Zy1Hd6Fg0Js5Ae9Ui2Ok8Tn3Bv7Mq4Xw1Cs6Dp0Ga5Hf9Ej2Il8Ro'.repeat(9);

/** Home with no file: "Add my file" → "Paste text" → the text, which
 *  goes on by itself (detection settles in 400 ms). */
const PASTE: DriveStep[] = [
    { click: 'btn:add-my-file' },
    { click: 'btn:add-paste' },
    { type: 'css:textarea', text: PASTED_FILE },
    { sleep: 900 },
];

// ---- catalog ----

export const SCENARIOS: Scenario[] = [
    // --- Connection ---
    {
        // Automatic: the way that did not work here last time was tried
        // first this time too (its rest had ended) and did not get
        // through; the next one carried.
        id: 'connection-connected',
        title: 'Connection · connected',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            connectedSinceUnixMs: Date.now() - 8078 * 1000,
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: HOME_ROUTES[0],
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 2,
                total: 4,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply', refined: 'udp_blocked_here' },
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: ROUTE_PARS_RESCUE_03.family, result: 'carried', category: '', setupMs: 640 },
                ],
                verdict: 'moved_on',
                routeId: ROUTE_PARS_RESCUE_03.routeId,
            },
        },
        why: whyLive(HOME_ROUTES[0], 'harness-decision-010'),
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: HOME_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
    },
    {
        // The same, with the facts card's Details open: every way and
        // how it did here, the kind being rested, this pass's tries.
        id: 'connection-connected-details',
        title: 'Connection · connected, Details open',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: HOME_ROUTES[0],
            auto: {
                state: 'connected',
                mode: true,
                trying: '',
                index: 2,
                total: 4,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply', refined: 'udp_blocked_here' },
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: ROUTE_PARS_RESCUE_03.family, result: 'carried', category: '', setupMs: 640 },
                ],
                verdict: 'moved_on',
                routeId: ROUTE_PARS_RESCUE_03.routeId,
            },
        },
        why: whyLive(HOME_ROUTES[0], 'harness-decision-012'),
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: HOME_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
        steps: [{ click: 'btn:home-details' }, { scroll: 'btn:home-details' }],
    },
    {
        // Ready: four ways, one of which carried on this network before.
        id: 'connection-disconnected',
        title: 'Connection · disconnected',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: HOME_ROUTES,
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
        // Android keeps the VPN closed while it retries (MUST KEEP 18).
        id: 'connection-holding',
        title: 'Connection · holding: other apps have no internet',
        screen: 'connection',
        state: 'connecting',
        connection: { ...CONN_BASE, state: 'connecting', holding: true, routeRunning: false },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        // The saved files were reset (MUST KEEP 16, the store notice).
        id: 'home-notice-store',
        title: 'Connection · notice: saved files were reset',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected', storeRecovered: true } as ConnectionSummary,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        // A build with no data plane (MUST KEEP 16).
        id: 'home-notice-no-traffic',
        title: 'Connection · notice: this build cannot carry traffic',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected', dataPlane: 'none' },
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
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply' },
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
                // The way that was up (Hysteria 2) stopped carrying; the
                // engine put it back last ('was_connected') and moved on.
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply', why: 'was_connected' },
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: ROUTE_PARS_RESCUE_03.family, result: 'carried', category: '', setupMs: 720, why: 'ranked' },
                ],
                verdict: 'moved_on',
                routeId: ROUTE_PARS_RESCUE_03.routeId,
            },
        },
        why: whyLive(ROUTE_PARS_RESCUE_03, 'harness-decision-013'),
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
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
                total: 3,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: ROUTE_PARS_RESCUE_03.family, result: 'start_failed', category: 'tcp_connect_timeout', refined: 'relay_unreachable' },
                    { routeId: ROUTE_FRIEND_MAY6.routeId, family: ROUTE_FRIEND_MAY6.family, result: 'start_failed', category: 'tcp_connect_timeout', refined: 'relay_unreachable' },
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply' },
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
                tried: [{ routeId: WAY_GOOD.routeId, family: WAY_GOOD.family, result: 'carried', category: '', setupMs: 310, why: 'carried_here' }],
                verdict: '',
                routeId: WAY_GOOD.routeId,
            },
        },
        why: whyLive(WAY_GOOD, 'harness-decision-011'),
        availableRoutes: MEASURED_ROUTES,
        throughput: { upBytesPerSec: 41 * 1024, downBytesPerSec: Math.round(2.4 * 1024 * 1024), windowMs: 1000 },
    },
    {
        id: 'connection-connected-slow',
        title: 'Connection · connected, slow here',
        screen: 'connection',
        state: 'connected',
        // On metered mobile data, with the file's connection details
        // running out in two days.
        connection: {
            ...CONN_BASE,
            network: { fromHost: true, kind: 'cellular', validated: 1, metered: 1 },
            networkLabel: 'Cellular',
            pointerValidDays: 2,
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
        throughput: { upBytesPerSec: 3 * 1024, downBytesPerSec: 46 * 1024, windowMs: 1000 },
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
            label: `${r.publisherName} · ${r.routeNickname}`,
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
            { routeId: ROUTE_FRESH_UNMEASURED.routeId, label: 'Pars Relays · Just imported' },
            { routeId: ROUTE_UNSUPPORTED_WG.routeId, label: 'Pars · Old WG' },
        ],
        pointer: POINTER_EMBEDDED,
        why: WHY_NOT_EVALUATED,
    },

    // --- Files: one file as a real relay makes it (r1..r4) ---
    ...filesRelay({
        id: 'files-relay',
        title: 'Files · a relay file (r1..r4) and a subscription, connected',
    }, []),
    ...filesRelay({
        id: 'files-relay-sheet',
        title: 'Files · the relay file opened: kinds, state, setup time',
    }, [
        { click: 'text:Test' },
    ]),
    ...filesRelay({
        id: 'files-relay-way',
        title: 'Files · one way opened: what it is, what Daal saw here',
    }, [
        { click: 'text:Test' },
        { click: 'btn:way-row', nth: 0 },
    ]),
    ...filesRelay({
        id: 'files-relay-way-resting',
        title: 'Files · a way resting after failing here',
    }, [
        { click: 'text:Test' },
        { click: 'btn:way-row', nth: 2 },
    ]),
    ...filesRelay({
        id: 'files-relay-idle',
        title: 'Files · not connected, an experimental way opened',
    }, [
        { click: 'text:Test' },
        { click: 'btn:way-row', nth: 3 },
    ], { connection: { ...CONN_BASE, state: 'disconnected' } }),
    ...filesRelay({
        id: 'files-relay-sub',
        title: 'Files · the subscription file opened (named ways, unsupported kind)',
    }, [
        { click: 'text:Pars Relays' },
    ]),
    ...filesRelay({
        id: 'files-relay-dev',
        title: 'Files · the relay file opened, developer tools on',
    }, [
        { click: 'text:Test' },
    ], { dev: true }),
    ...filesRelay({
        id: 'files-relay-no-network',
        title: 'Files · no record for this network: nothing said about here',
    }, [], {
        connection: { ...CONN_BASE, state: 'disconnected' },
        availableRoutes: RELAY_FILE_ROUTES_NO_NETWORK,
    }),

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
        // The Publisher tab is hidden; Settings holds the switch.
        id: 'publisher-off',
        title: 'Publisher · off (the switch in Settings)',
        screen: 'publisher',
        initialRoute: '/publisher',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    // On, with one finished relay: the tab opens that relay (C7.0).
    ...pub(
        {
            id: 'publisher-on',
            title: 'on, one relay (opens it directly)',
        }, { relays: 'one', steps: [{ waitFor: 'css:[data-testid="health-panel"]' }, { sleep: 300 }] }),

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
        title: 'Status · scheduler (developer tools)',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        steps: [{ click: 'btn:dev-scheduler' }, { scroll: 'btn:dev-scheduler' }],
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        schedulerStatusJson:
            '{"tick":4218,"queue":[{"id":"pars-rescue-03","delay_ms":120},{"id":"friend-may-6","delay_ms":820}],"in_flight":1,"last_pick":"pars-rescue-03"}',
    },
    {
        id: 'status-stats-redacted',
        title: 'Status · stats, redacted (developer tools)',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        steps: [{ click: 'btn:dev-stats' }, { scroll: 'btn:dev-stats' }],
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        statsRedactedJson:
            '{"sessions":4,"bytes_up_bucket":"k","bytes_down_bucket":"M","redacted":true}',
    },
    {
        id: 'status-bootstrap-empty',
        title: 'Status · bootstrap, empty (developer tools)',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        steps: [{ click: 'btn:dev-bootstrap' }, { scroll: 'btn:dev-bootstrap' }],
        connection: { ...CONN_BASE, state: 'disconnected' },
        bootstrapStatusJson: '{"seeds":0,"last_refresh":null}',
    },
    {
        id: 'status-bootstrap-seeded',
        title: 'Status · bootstrap, seeded (developer tools)',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        steps: [{ click: 'btn:dev-bootstrap' }, { scroll: 'btn:dev-bootstrap' }],
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        bootstrapStatusJson:
            '{"seeds":3,"last_refresh":"2026-05-22T11:48:02Z","ok":true}',
    },
    {
        id: 'status-network-test',
        title: 'Status · network test (developer tools)',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        steps: [{ click: 'btn:dev-network' }, { scroll: 'btn:dev-network' }],
        connection: { ...CONN_BASE, state: 'disconnected' },
    },

    // --- Settings (wasm / advanced) ---
    {
        id: 'settings-wasm-loaded',
        title: 'Settings · Advanced, developer tools with WASM loaded',
        screen: 'settings',
        initialRoute: '/settings',
        dev: true,
        steps: [{ scroll: 'btn:dev-off' }],
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        wasmModules: ['hello-https', 'censorship-canary'],
        wasmKillSwitchPubkey: 'a1b2c3d4e5f6'.repeat(4),
    },
    {
        id: 'settings-advanced',
        title: 'Settings · Advanced',
        screen: 'settings',
        initialRoute: '/settings',
        connection: { ...CONN_BASE, state: 'disconnected' },
    },
    {
        id: 'settings-advanced-dev',
        title: 'Settings · Advanced, developer tools on',
        screen: 'settings',
        initialRoute: '/settings',
        dev: true,
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
    // The old seven-step wizard is three steps now (C7.8); these ids
    // open the nearest step.
    ...pub(
        {
            id: 'publisher-wizard-step-1',
            title: 'first run: no relay yet',
        }, { relays: 'none' }),
    ...pub(
        {
            id: 'publisher-wizard-step-4',
            title: 'wizard 2 (name and size)',
        }, { relays: 'none', steps: [...WIZARD_TO_2, { sleep: 600 }] }),
    ...pub(
        {
            id: 'publisher-wizard-step-7',
            title: 'wizard 3 done (check words, add the first person)',
        }, { relays: 'none', steps: [...WIZARD_TO_2, { click: 'key:wiz.plan.next' }, { waitFor: 'key:wiz.build.done.eyebrow' }] }),

    // --- Recipient QR (Phase D) ---
    // Scanning is a step of "Add my file" now (C3.4).
    ...rcp(
        {
            id: 'recipient-qr-empty',
            title: 'QR · the scanner, from Home',
        }, 'connection', [{ click: 'btn:add-my-file' }, { click: 'btn:add-scan' }, { sleep: 600 }]),
    ...rcp(
        {
            id: 'recipient-qr-scanning',
            title: 'QR · part of the file read',
        }, 'connection', scanFeed(5, 'btn:add-my-file')),
    ...rcp(
        {
            id: 'recipient-qr-done',
            title: 'QR · done, new publisher',
        }, 'connection', scanFeed(14, 'btn:add-my-file'), { importVerdict: 'trust' }),

    // --- Modals & overlays ---
    ...rcp(
        {
            id: 'trust-prompt-new-publisher',
            title: 'Trust prompt · new publisher (a pasted file)',
        }, 'connection', PASTE, { importVerdict: 'trust' }),
    {
        id: 'panic-wipe-confirm',
        title: 'Panic-wipe · confirm',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
    },
    {
        // Lifeline on: its badge on Home opens the picker.
        id: 'mode-picker-open',
        title: 'Mode-picker · open (from the Lifeline badge)',
        screen: 'modal',
        connection: { ...CONN_BASE, state: 'connected', mode: 'lifeline', activeRoute: ROUTE_PARS_RESCUE_03 },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        steps: [{ click: 'btn:badge-lifeline' }],
    },

    // --- Home: sheets, menus and developer mode (plain + taps) ---
    {
        id: 'connection-more',
        title: 'Connection · the ⋯ menu',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: WAY_GOOD,
        },
        availableRoutes: MEASURED_ROUTES,
        steps: [{ click: 'btn:home-more' }],
    },
    {
        id: 'connection-chooser',
        title: 'Connection · choose the way myself',
        screen: 'connection',
        state: 'connected',
        connection: {
            ...CONN_BASE,
            state: 'connected',
            routeRunning: true,
            routeCheck: 'ok',
            activeRoute: WAY_GOOD,
        },
        availableRoutes: MEASURED_ROUTES,
        steps: [{ click: 'btn:home-more' }, { click: 'btn:choose-way' }],
    },
    {
        id: 'connection-lifeline',
        title: 'Connection · ready, Lifeline on',
        screen: 'connection',
        state: 'disconnected',
        connection: { ...CONN_BASE, state: 'disconnected', mode: 'lifeline' },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
    },
    {
        id: 'connection-failed-details',
        title: 'Connection · nothing worked, Details open',
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
                total: 3,
                tried: [
                    { routeId: ROUTE_PARS_RESCUE_03.routeId, family: ROUTE_PARS_RESCUE_03.family, result: 'start_failed', category: 'tcp_connect_timeout', refined: 'relay_unreachable' },
                    { routeId: ROUTE_FRIEND_MAY6.routeId, family: ROUTE_FRIEND_MAY6.family, result: 'start_failed', category: 'tcp_connect_timeout', refined: 'relay_unreachable' },
                    { routeId: ROUTE_PARS_RESCUE_01.routeId, family: ROUTE_PARS_RESCUE_01.family, result: 'not_carrying', category: 'udp_no_reply' },
                ],
                verdict: 'relay_unreachable',
                routeId: '',
            },
        },
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        // On a computer the tries are in the side panel; no fold to open.
        steps: [{ click: 'btn:failure-details', optional: true }],
    },
    {
        id: 'connection-connected-dev',
        title: 'Connection · connected, developer tools on',
        screen: 'connection',
        state: 'connected',
        dev: true,
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
        why: WHY_CONNECTED,
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: MEASURED_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
        steps: [{ click: 'btn:helper-fold' }, { scroll: 'btn:helper-fold' }],
    },

    // --- Status: the summary, and how it is reached ---
    {
        id: 'status-from-home',
        title: 'Status · the summary, opened from Home\'s ⋯',
        screen: 'connection',
        state: 'connected',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        steps: [{ click: 'btn:home-more' }, { click: 'btn:status' }, { waitFor: 'btn:export' }],
    },
    {
        id: 'status-helper-open',
        title: 'Status · "For someone helping you" open',
        screen: 'status',
        initialRoute: '/status',
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        steps: [{ click: 'btn:helper-fold' }],
    },
    {
        id: 'status-dev',
        title: 'Status · developer tools on',
        screen: 'status',
        initialRoute: '/status',
        dev: true,
        connection: { ...CONN_BASE, state: 'connected', activeRoute: ROUTE_PARS_RESCUE_03 },
        pointer: POINTER_OK,
        routeHealth: DEFAULT_ROUTE_HEALTH,
        availableRoutes: DEFAULT_AVAILABLE_ROUTES,
        throughput: DEFAULT_THROUGHPUT,
        steps: [{ scroll: 'btn:dev-raw' }],
    },
    {
        id: 'settings-erase-from-row',
        title: 'Settings · the erase row opens the confirm',
        screen: 'settings',
        initialRoute: '/settings',
        connection: { ...CONN_BASE, state: 'disconnected' },
        steps: [{ click: 'btn:erase' }],
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
            id: 'pub-relay-list-empty',
            title: 'Relay list · none yet (first run)',
        }, { relays: 'none' }),
    ...pub(
        {
            id: 'pub-relays-more',
            title: 'Relay list · the ⋯ menu',
        }, { steps: [{ click: 'btn:relays-more' }] }),
    ...pub(
        {
            id: 'pub-relay-remove',
            title: 'Relay page · Danger zone → remove this relay',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:danger-zone' }, { click: 'btn:relay-remove' }],
    }),
    ...pub(
        {
            id: 'pub-relay-remove-unfinished',
            title: 'Relay list · remove the unfinished setup',
        }, {
        steps: [{ click: 'btn:relay-row-more' }, { click: 'btn:remove' }],
    }),
    ...pub(
        {
            id: 'pub-account-check',
            title: 'Relay list · check my hosting account',
        }, {
        steps: [...relaysMenu('check-account'), { sleep: 600 }],
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
            id: 'pub-relay-more',
            title: 'Relay page · the ⋯ menu',
        }, { steps: [...OPEN_RELAY, { click: 'btn:relay-more' }] }),
    ...pub(
        {
            id: 'pub-relay-everyone',
            title: 'Relay page · ⋯ → file for everyone',
        }, {
        steps: [...OPEN_RELAY, ...relayMenu('everyone')],
    }),
    ...pub(
        {
            id: 'pub-relay-keep',
            title: 'Relay page · ⋯ → keep files working (advanced)',
        }, {
        steps: [...OPEN_RELAY, ...relayMenu('keep')],
    }),
    ...pub(
        {
            id: 'pub-relay-details',
            title: 'Relay page · Details open',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:relay-details' }, { scroll: 'btn:relay-details' }],
    }),
    ...pub(
        {
            id: 'pub-relay-danger',
            title: 'Relay page · Danger zone open',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:danger-zone' }, { scroll: 'btn:danger-zone' }],
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
            title: 'Person · the ⋯ menu (new file, remove access)',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:person-more', nth: 0 }],
    }),
    ...pub(
        {
            id: 'pub-person-send',
            title: 'Person · the send sheet',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:person-send', nth: 0 }],
    }),
    ...pub(
        {
            id: 'pub-person-sent',
            title: 'Person · after "Send with an app" (no toast)',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, ...sendPerson('share'), { sleep: 400 }],
    }),
    ...pub(
        {
            id: 'pub-person-saved',
            title: 'Person · after "Save to phone"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, ...sendPerson('save'), { sleep: 400 }],
    }),
    ...pub(
        {
            id: 'pub-person-copied',
            title: 'Person · after "Copy as text"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, ...sendPerson('copy'), { sleep: 400 }],
    }),
    ...pub(
        {
            id: 'pub-person-add',
            title: 'Person · add a person',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:add-person' }],
    }),
    ...pub(
        {
            id: 'pub-person-add-filled',
            title: 'Person · add a person, name and pasted address',
        }, {
        steps: [
            ...OPEN_RELAY,
            { click: 'btn:add-person' },
            { type: 'css:input', text: 'Khaleh', nth: 0 },
            // Pasted from a chat, with its line breaks and spaces.
            { type: 'css:input, textarea', text: 'daal1 qm3n 8v2c\n5m3n 8v2c 5m3n 8v2c 5m3n 8v2c 5m3n 8v2c5', nth: 1 },
        ],
    }),
    ...pub(
        {
            id: 'pub-person-remove',
            title: 'Person · remove access, confirm',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:person-more', nth: 0 }, { click: 'btn:remove' }],
    }),
    ...pub(
        {
            id: 'pub-qr-person',
            title: 'QR · one person\'s file',
        }, {
        steps: [...OPEN_RELAY, ...sendPerson('qr'), { sleep: 800 }],
    }),
    ...pub(
        {
            id: 'pub-qr-everyone',
            title: 'QR · the file for everyone',
        }, {
        steps: [...OPEN_RELAY, ...sendEveryone('qr'), { sleep: 800 }],
    }),
    ...pub(
        {
            id: 'pub-everyone-send',
            title: 'Everyone file · the send sheet',
        }, {
        steps: [...OPEN_RELAY, { click: 'btn:everyone-send' }],
    }),
    ...pub(
        {
            id: 'pub-everyone-copied',
            title: 'Everyone file · after "Copy as text"',
        }, {
        steps: [...OPEN_RELAY, { keep: true }, ...sendEveryone('copy'), { sleep: 400 }],
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
        // A current backup has no badge: the list's ⋯ holds "Back up".
        steps: [...relaysMenu('backup'), { click: 'btn:save-downloads' }],
    }),
    ...pub(
        {
            id: 'pub-restore',
            title: 'Restore · choose the file',
        }, {
        steps: relaysMenu('restore-link'),
    }),
    ...pub(
        {
            id: 'pub-restore-fresh',
            title: 'Restore · from the first-run empty state',
        }, {
        relays: 'none',
        steps: [{ click: 'btn:restore-link' }],
    }),
    ...pub(
        {
            id: 'pub-restore-words',
            title: 'Restore · type the twelve words',
        }, {
        steps: [...relaysMenu('restore-link'), { click: 'btn:choose' }],
    }),
    ...pub(
        {
            id: 'pub-restore-preview',
            title: 'Restore · what the backup holds',
        }, {
        steps: [
            ...relaysMenu('restore-link'),
            { click: 'btn:choose' },
            { type: 'css:textarea', text: 'legal winner thank year wave sausage worth useful legal winner thank yellow' },
            { click: 'btn:open' },
        ],
    }),
    ...pub(
        {
            id: 'pub-wizard-1',
            title: 'Wizard · 1 where the relay lives (hosting companies)',
        }, { relays: 'none', steps: START_WIZARD }),
    ...pub(
        {
            id: 'pub-wizard-1-key',
            title: 'Wizard · 1 hosting account key',
        }, { relays: 'none', steps: WIZARD_TO_KEY }),
    ...pub(
        {
            id: 'pub-wizard-1-filled',
            title: 'Wizard · 1 key pasted',
        }, {
        relays: 'none',
        steps: [...WIZARD_TO_KEY, { type: 'css:input', text: 'hcloud_Zx9VtQe1pL4mR7sK2wY8bN3cF6hJ0dA5' }],
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
        // The done screen waits for "Add the first person" (no hand-off).
        steps: [...WIZARD_TO_2, { click: 'key:wiz.plan.next' }, { waitFor: 'key:wiz.build.done.eyebrow' }],
    }),
    ...pub(
        {
            id: 'pub-wizard-3-add-first',
            title: 'Wizard · 3 done → "Add the first person"',
        }, {
        relays: 'none',
        steps: [
            ...WIZARD_TO_2,
            { click: 'key:wiz.plan.next' },
            { waitFor: 'key:wiz.build.done.eyebrow' },
            { click: 'btn:add-first-person' },
            { sleep: 600 },
        ],
    }),

    // --- Recipient: import, scan, address (fake shell + taps) ---
    ...rcp(
        {
            id: 'rcp-add-sheet',
            title: 'Add a file · the sheet',
        }, 'connection', [{ click: 'btn:add-my-file' }]),
    ...rcp(
        {
            id: 'rcp-add-paste-tab',
            title: 'Add a file · "Paste text", nothing on the clipboard',
        }, 'connection', [
        { click: 'btn:add-my-file' },
        { click: 'btn:add-paste' },
    ]),
    ...rcp(
        {
            // The moment the text is recognised, before it goes on by
            // itself (the 400 ms settle is held).
            id: 'rcp-paste-ready',
            title: 'Add a file · text pasted, recognised',
        }, 'connection', [
        { click: 'btn:add-my-file' },
        { click: 'btn:add-paste' },
        { waitFor: 'css:textarea' },
        // Timers stop before the text lands, so the 400 ms settle that
        // would carry it on never fires.
        { freeze: true },
        { type: 'css:textarea', text: PASTED_FILE },
        { sleep: 300 },
    ]),
    ...rcp(
        {
            id: 'rcp-paste-unknown',
            title: 'Add a file · pasted text that is not a Daal file',
        }, 'connection', [
        { click: 'btn:add-my-file' },
        { click: 'btn:add-paste' },
        { type: 'css:textarea', text: 'Salam! See you on Friday.' },
        { sleep: 900 },
    ]),
    ...rcp(
        {
            id: 'rcp-import-trust',
            title: 'Add a file · new publisher, check the words',
        }, 'connection', PASTE, { importVerdict: 'trust' }),
    ...rcp(
        {
            id: 'rcp-import-trust-more',
            title: 'Add a file · new publisher, "Other choices" open',
        }, 'connection', [...PASTE, { click: 'btn:trust-more' }], { importVerdict: 'trust' }),
    ...rcp(
        {
            id: 'rcp-import-refused',
            title: 'Add a file · refused',
        }, 'connection', PASTE, { importVerdict: 'refused' }),
    ...rcp(
        {
            // MUST KEEP 10: a publisher whose key changed blocks the import.
            id: 'rcp-import-key-changed',
            title: 'Add a file · the publisher\'s key changed',
        }, 'connection', PASTE, { importVerdict: 'changed' }),
    ...rcp(
        {
            // MUST KEEP 16: Daal did not start.
            id: 'home-notice-engine',
            title: 'Home · notice: Daal did not start',
        }, 'connection', [{ sleep: 400 }], { engineDown: true }),
    ...rcp(
        {
            id: 'rcp-import-done',
            title: 'Add a file · imported',
        }, 'connection', PASTE, { importVerdict: 'imported' }),
    ...rcp(
        {
            id: 'rcp-import-partial',
            title: 'Add a file · imported, one way not usable here',
        }, 'connection', PASTE, { importVerdict: 'partial' }),
    ...rcp(
        {
            id: 'rcp-import-partial-open',
            title: 'Add a file · imported, "Some ways aren\'t in this file" open',
        }, 'connection', [...PASTE, { click: 'btn:import-partial' }], { importVerdict: 'partial' }),
    ...rcp(
        {
            // "Choose a file": the picker returns a file, and the sheet
            // goes on by itself to the result.
            id: 'rcp-file-done',
            title: 'Add a file · a chosen file, imported',
        }, 'connection', [
        { click: 'btn:add-my-file' },
        { click: 'btn:add-choose-file' },
        { sleep: 900 },
    ], { importVerdict: 'imported', picked: 'content://downloads/Maman.sbp' }),
    ...rcp(
        {
            id: 'rcp-file-trust',
            title: 'Add a file · a chosen file, new publisher',
        }, 'connection', [
        { click: 'btn:add-my-file' },
        { click: 'btn:add-choose-file' },
        { sleep: 900 },
    ], { importVerdict: 'trust', picked: 'content://downloads/Maman.sbp' }),
    ...rcp(
        {
            // Android "Open with Daal" / "Share to Daal" from a
            // messenger: Home opens the check by itself.
            id: 'rcp-opened-file',
            title: 'Opened from a messenger · new publisher',
        }, 'connection', [{ waitFor: 'btn:trust-yes' }], {
        importVerdict: 'trust',
        opened: '/staging/opened/opened-7f3a.sbp',
    }),
    ...rcp(
        {
            id: 'rcp-opened-file-known',
            title: 'Opened from a messenger · publisher already trusted',
        }, 'connection', [{ waitFor: 'btn:import-connect' }], {
        importVerdict: 'imported',
        opened: '/staging/opened/opened-7f3a.sbp',
    }),
    ...rcp(
        {
            id: 'rcp-opened-text',
            title: 'Shared to Daal · text that is not a Daal file',
        }, 'connection', [{ sleep: 900 }], {
        opened: '/staging/opened/opened-7f3a.txt',
    }),
    ...rcp(
        {
            id: 'rcp-network-add',
            title: 'Files · add from the Files tab',
        }, 'network', [{ click: 'btn:add' }]),
    ...rcp(
        {
            id: 'rcp-files-more',
            title: 'Files · the ⋯ menu',
        }, 'network', [{ click: 'btn:files-more' }]),
    ...rcp(
        {
            id: 'rcp-file-sheet',
            title: 'Files · one file opened',
        }, 'network', [{ click: 'btn:file-row', nth: 0 }]),
    ...rcp(
        {
            id: 'rcp-file-sheet-more',
            title: 'Files · one file, its ⋯ menu',
        }, 'network', [{ click: 'btn:file-row', nth: 0 }, { click: 'btn:file-more' }]),
    ...rcp(
        {
            id: 'rcp-scan',
            title: 'Scan · camera',
        }, 'network', [{ click: 'btn:add' }, { click: 'btn:add-scan' }, { sleep: 600 }]),
    ...rcp(
        {
            id: 'rcp-scan-paste',
            title: 'Scan · paste frames tab (developer tools)',
        }, 'network', [
        { dev: true },
        { click: 'btn:add' },
        { click: 'btn:add-scan' },
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
            title: 'Scan · done, imported',
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
            // The address is made when the sheet opens.
            id: 'rcp-address-before',
            title: 'My address · first open (made on open)',
        }, 'network', [{ click: 'btn:files-more' }, { click: 'btn:my-address' }, { sleep: 400 }]),
    ...rcp(
        {
            id: 'rcp-address-copied',
            title: 'My address · copied',
        }, 'network', [
        { click: 'btn:files-more' },
        { click: 'btn:my-address' },
        // The "Copied" toast hides itself after 3.5 s.
        { keep: 1000 },
        { click: 'btn:copy-address' },
    ], { identity: 'made' }),
    ...rcp(
        {
            id: 'rcp-address-after',
            title: 'My address · made',
        }, 'network', [{ click: 'btn:files-more' }, { click: 'btn:my-address' }, { sleep: 300 }], {
        identity: 'made',
    }),
    ...rcp(
        {
            // Android: the share sheet exists, "Send address" comes first.
            id: 'rcp-address-android',
            title: 'My address · on Android',
        }, 'network', [{ click: 'btn:files-more' }, { click: 'btn:my-address' }, { sleep: 300 }], {
        identity: 'made',
        android: true,
    }),
    ...rcp(
        {
            // Settings → Advanced with an address made: "Get a new
            // address" and its checkbox (MUST KEEP 15).
            id: 'settings-advanced-address',
            title: 'Settings · Advanced, this phone\'s address',
        }, 'connection', [
            { click: 'btn:tab-settings', optional: true },
            { click: 'btn:nav-settings', optional: true },
            { click: 'btn:advanced-row' },
            { sleep: 400 },
        ], { identity: 'made' }),
    ...rcp(
        {
            // No file yet: Home's link goes straight to the address.
            id: 'rcp-address-no-file',
            title: 'My address · from Home with no file',
        }, 'connection', [{ click: 'btn:no-file-address' }, { sleep: 400 }]),

    // --- Network test (Settings → Advanced → Network test, fake engine) ---
    ...nt(
        {
            id: 'settings-advanced-nettest',
            title: 'Advanced shows the row',
        }, { state: 'idle' }, [], { stop: 'advanced' }),
    ...nt(
        {
            id: 'nettest-consent',
            title: 'what is tested, before Start',
        }, { state: 'idle' }),
    ...nt(
        {
            id: 'nettest-consent-connected',
            title: 'Daal is connected: disconnect first',
        }, { state: 'idle' }, [{ scroll: 'css:[data-testid="nettest-connected"]' }], {
        connected: true,
    }),
    ...nt(
        {
            id: 'nettest-refused-rate',
            title: 'refused: run here recently',
        }, { state: 'idle', refuse: 'rate_limited' }, [
        { click: 'btn:nettest-start' },
        { waitFor: 'css:[data-testid="nettest-refused"]' },
        { scroll: 'css:[data-testid="nettest-refused"]' },
    ]),
    ...nt(
        {
            id: 'nettest-refused-shared',
            title: 'refused: test relay shares an address',
        }, { state: 'idle', refuse: 'test_relay_shared' }, [
        { click: 'btn:nettest-start' },
        { waitFor: 'css:[data-testid="nettest-refused"]' },
        { scroll: 'css:[data-testid="nettest-refused"]' },
    ]),
    ...nt(
        {
            id: 'nettest-running',
            title: 'running, step n of N',
        }, { state: 'idle' }, [
        { click: 'btn:nettest-start' },
        { sleep: 2600 },
        { freeze: 'css:[data-testid="nettest-running"]' },
    ]),
    ...nt(
        {
            id: 'nettest-result',
            title: 'result, Daal not connected',
        }, { state: 'done' }),
    ...nt(
        {
            id: 'nettest-result-connected',
            title: 'result, Daal connected again',
        }, { state: 'done' }, [], { connected: true }),
    ...nt(
        {
            id: 'nettest-aborted-vpn',
            title: 'stopped: another VPN came up',
        }, { state: 'aborted', abort: 'vpn_active' }),
    ...nt(
        {
            id: 'nettest-blackout',
            title: 'international internet cut',
        }, { state: 'blackout' }),
    ...nt(
        {
            id: 'nettest-run-again',
            title: 'stopped early: Run again shows the consent over the kept report',
        }, { state: 'aborted', abort: 'backgrounded' }, [
        { click: 'btn:nettest-again' },
        { waitFor: 'css:[data-testid="nettest-replaces"]' },
    ]),
    ...nt(
        {
            id: 'nettest-run-again-start',
            title: 'Run again: the strip right above Start',
        }, { state: 'aborted', abort: 'backgrounded' }, [
        { click: 'btn:nettest-again' },
        { waitFor: 'css:[data-testid="nettest-before"]' },
        { scroll: 'css:[data-testid="nettest-before"]' },
    ]),
    ...nt(
        {
            id: 'nettest-show-all',
            title: 'result: show everything',
        }, { state: 'done' }, [
        { click: 'btn:nettest-show-all' },
        { waitFor: 'css:[data-testid="nettest-report-json"]' },
        { scroll: 'css:[data-testid="nettest-report-json"]' },
    ], { connected: true }),
    ...nt(
        {
            id: 'nettest-consent-start',
            title: 'the strip right above Start',
        }, { state: 'idle' }, [{ scroll: 'css:[data-testid="nettest-before"]' }]),
    ...nt(
        {
            id: 'nettest-after-send',
            title: 'sent: delete it from this phone?',
        }, { state: 'done' }, [
        { click: 'btn:nettest-send' },
        { waitFor: 'css:[data-testid="nettest-ask-delete"]' },
        { scroll: 'css:[data-testid="nettest-ask-delete"]' },
    ], { connected: true }),
    ...nt(
        {
            id: 'nettest-deleted',
            title: 'report deleted',
        }, { state: 'done' }, [
        { click: 'btn:nettest-delete' },
        { waitFor: 'css:[data-testid="nettest-deleted"]' },
    ]),
    // Publisher: the test relay and the report opener.
    ...pub(
        {
            id: 'pub-relay-test-relay',
            title: 'Relay page · ⋯ → use as test relay',
        }, { netTest: { state: 'none' }, steps: [...OPEN_RELAY, ...relayMenu('test-relay'), { sleep: 300 }] }),
    ...pub(
        {
            id: 'pub-relay-test-relay-confirm',
            title: 'Relay page · people connect with it: asked a second time',
        }, {
        netTest: { state: 'none' },
        steps: [
            ...OPEN_RELAY,
            ...relayMenu('test-relay'),
            { click: 'btn:test-relay-on' },
            { waitFor: 'css:[data-testid="test-relay-confirm"]' },
        ],
    }),
    ...pub(
        {
            id: 'pub-relay-test-relay-done',
            title: 'Relay page · test relay made on a relay in use',
        }, {
        netTest: { state: 'none' },
        steps: [
            ...OPEN_RELAY,
            ...relayMenu('test-relay'),
            { click: 'btn:test-relay-on' },
            { click: 'btn:test-relay-on-anyway' },
            { waitFor: 'css:[data-testid="test-relay-done"]' },
        ],
    }),
    ...pub(
        {
            id: 'pub-relay-test-relay-separate',
            title: 'Relay page · a separate relay nobody uses',
        }, {
        netTest: { state: 'none', relayPeople: 0, relayEveryone: false },
        steps: [...OPEN_RELAY, ...relayMenu('test-relay'), { sleep: 300 }],
    }),
    ...pub(
        {
            id: 'pub-relay-test-relay-separate-done',
            title: 'Relay page · test relay made on a separate relay',
        }, {
        netTest: { state: 'none', relayPeople: 0, relayEveryone: false },
        steps: [
            ...OPEN_RELAY,
            ...relayMenu('test-relay'),
            { click: 'btn:test-relay-on' },
            { waitFor: 'css:[data-testid="test-relay-done"]' },
        ],
    }),
    ...pub(
        {
            id: 'pub-report-open',
            title: 'Relay list · ⋯ → open a network test report',
        }, {
        netTest: { state: 'none', testRelayOn: true },
        picked: 'content://downloads/net-ab12cd34.dat',
        steps: [...relaysMenu('open-report'), { click: 'btn:report-pick' }, { waitFor: 'css:[data-testid="report-head"]' }],
    }),
    ...pub(
        {
            id: 'pub-report-open-stage-c',
            title: 'Report · the test relay stage',
        }, {
        netTest: { state: 'none', testRelayOn: true },
        picked: 'content://downloads/net-ab12cd34.dat',
        steps: [
            ...relaysMenu('open-report'),
            { click: 'btn:report-pick' },
            { waitFor: 'css:[data-testid="report-stage-C"]' },
            { scroll: 'css:[data-testid="report-stage-C"]' },
        ],
    }),
    ...pub(
        {
            id: 'pub-report-not-ours',
            title: 'Report · no key on this phone opens it',
        }, {
        netTest: { state: 'none', testRelayOn: true, reportOpen: 'not_ours' },
        picked: 'content://downloads/net-ab12cd34.dat',
        steps: [...relaysMenu('open-report'), { click: 'btn:report-pick' }, { waitFor: 'css:[data-testid="report-failure"]' }],
    }),
];

// ---- builders for the fake-shell scenarios ----

/** Settings → Advanced (→ Network test) on the fake engine
 *  (harness/netTestFake.ts), with the relay file held, so the test relay
 *  belongs to "Pars Relays". */
function nt(
    { id, title }: { id: string; title: string },
    netTest: NetTestFake,
    steps: DriveStep[] = [],
    over: { connected?: boolean; stop?: 'advanced' } = {},
): Scenario[] {
    const open: DriveStep[] = [
        { click: 'btn:tab-settings', optional: true },
        { click: 'btn:nav-settings', optional: true },
        { click: 'btn:advanced-row' },
        { waitFor: 'btn:nettest-row' },
    ];
    if (over.stop !== 'advanced') open.push({ click: 'btn:nettest-row' }, { sleep: 300 });
    else open.push({ scroll: 'btn:nettest-row' });
    return [
        {
            id,
            title: `Network test · ${title}`,
            screen: 'settings',
            state: 'fake-shell',
            connection: over.connected
                ? { ...CONN_BASE, state: 'connected', routeRunning: true, routeCheck: 'ok', activeRoute: RELAY_R1, auto: RELAY_AUTO_ON_R1 }
                : { ...CONN_BASE, state: 'disconnected' },
            availableRoutes: RELAY_FILE_ROUTES,
            fake: { relays: 'none', open: 'connection', android: true, netTest, steps: [...open, ...steps] },
        },
    ];
}
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

/** The Files tab with the relay file (RELAY_FILE_ROUTES), connected
 *  automatically on r1 unless `over` says otherwise; `steps` open it. */
function filesRelay(
    { id, title }: { id: string; title: string },
    steps: DriveStep[],
    over: Partial<Scenario> = {},
): Scenario[] {
    return [
        {
            id,
            title,
            screen: 'network',
            initialRoute: '/routes',
            connection: {
                ...CONN_BASE,
                state: 'connected',
                routeRunning: true,
                routeCheck: 'ok',
                activeRoute: RELAY_R1,
                auto: RELAY_AUTO_ON_R1,
            },
            availableRoutes: RELAY_FILE_ROUTES,
            steps,
            ...over,
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

/** Open the scanner, feed `n` frames through the developer frame lane,
 *  then picture it as a recipient sees it: back on the camera with its
 *  ring, developer tools off. `from` opens the add sheet. */
function scanFeed(n: number, from = 'btn:add'): DriveStep[] {
    const lines: string[] = [];
    for (let i = 0; i < n; i++) {
        // 144 base64url characters: one 108-byte frame.
        lines.push(`AQ${String.fromCharCode(65 + i)}` + 'Lm4Rt8Vx2Bz6Nc0Qe3Gs7Jw1Hy5Ku9Pa'.repeat(4) + 'ABCDE');
    }
    return [
        { dev: true },
        { click: from },
        { click: 'btn:add-scan' },
        { click: 'key:scan.mode.paste' },
        { type: 'css:textarea', text: lines.join('\n') },
        { click: 'key:scan.paste.feed' },
        { sleep: 600 },
        // Still scanning: back to the camera lane (its tab is there while
        // developer tools are on). A finished scan has moved on already.
        { click: 'key:scan.mode.camera', optional: true },
        { dev: false },
        { sleep: 400 },
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
