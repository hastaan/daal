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
    publisherName: 'Emergency',
    routeNickname: 'K3F',
    trustClass: 'unknown',
    family: 'emergency',
    inCooldown: false,
    budgetExhausted: false,
    healthPct: 50,
    sourceName: 'Emergency Bulletin',
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

const POINTER_OK: PointerRotationSummary = {
    lastRotatedUnixMs: Date.now() - 86400 * 1000,
    validForDays: 14,
    rotatedSuccessfully: true,
};

const POINTER_FAILED: PointerRotationSummary = {
    lastRotatedUnixMs: Date.now() - 86400 * 1000,
    validForDays: 0,
    rotatedSuccessfully: false,
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

const CONN_BASE: ConnectionSummary = {
    state: 'disconnected',
    mode: 'normal',
    networkLabel: 'Wi-Fi',
    pointerValidDays: 14,
};

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
        pointer: POINTER_FAILED,
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

    // --- Routes ---
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
        pointer: POINTER_FAILED,
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
];

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
