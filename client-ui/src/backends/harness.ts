// HarnessContract — mock backend for browser preview + screenshot
// harness. Backed by the typed Scenario catalog in
// ../harness/scenarios.ts. The active scenario is read once at boot
// from ?harness=<id>.
//
// Adding a new screen state:
//   1. Add a Scenario to scenarios.ts with its canned payload.
//   2. The DevPicker (../harness/DevPicker.tsx) lists it automatically.
//   3. The screenshot harness iterates it automatically.

import type {
    AddSubscriptionRequest,
    AutoConnectResult,
    AutoStatus,
    AutoTried,
    Measured,
    BootstrapStatus,
    BurnpressureVerdict,
    ConnectionSummary,
    D2Contract,
    DiagnosticsBlob,
    LifecycleToken,
    PointerRotationSummary,
    PreviewedBundle,
    ProbeResult,
    PublisherTreeRow,
    RedistributeResult,
    RouteDisplayRow,
    RouteHealthDisplayRow,
    SchedulerStatus,
    SkippedFamilyRow,
    StatsRedacted,
    StatusPagePayload,
    SubscriptionRow,
    ThroughputSnapshot,
    TrustDecision,
    UnlockResult,
    UriDetectResult,
    UriImportResult,
    VersionInfo,
    WhyThisRouteSummary,
} from '../contract/D2Contract';
import { buildPublisherTree, deriveBurnpressureVerdict } from '../contract/derive_tree';
import { activeScenario, type Scenario } from '../harness/scenarios';
import { lastBucketText } from '../lib/measured';

const AUTO_IDLE: AutoStatus = {
    state: 'idle',
    mode: false,
    trying: '',
    index: 0,
    total: 0,
    tried: [],
    verdict: '',
    routeId: '',
};

/** Would this canned route carry traffic? The harness has no network,
 *  so the scenario's own numbers decide: a route graded 'failing' on
 *  this network does not, one graded better does; where no grade says,
 *  a route scored below 50 is one that "does not work here". Anything
 *  else carries. */
function harnessCarries(r: RouteDisplayRow): boolean {
    const g = r.measured?.grade;
    if (g !== undefined && g !== 'unknown') return g !== 'failing';
    return typeof r.healthPct !== 'number' || r.healthPct >= 50;
}

/** Carried on this network before and is not failing now: the engine
 *  tries such a route first, and ALONE. */
function remembered(r: RouteDisplayRow): boolean {
    const m = r.measured;
    return !!m && m.carried > 0 && m.grade !== 'failing';
}

/** How long a canned route takes to prove it carries. */
function harnessSetupMs(r: RouteDisplayRow): number {
    return r.measured?.setupMs ?? 400;
}

/** The engine's order and grouping, in miniature (contract 2 of the
 *  measuring wave). With routes that carry a `measured` block: the one
 *  remembered here first and alone, then the rest TWO AT A TIME — never
 *  more — with those that failed here last. Routes without the block
 *  model an engine that predates measurement: one after another, in
 *  listed order. */
export function harnessSteps(candidates: readonly RouteDisplayRow[]): RouteDisplayRow[][] {
    if (!candidates.some((r) => r.measured !== undefined)) return candidates.map((r) => [r]);
    const rank = (r: RouteDisplayRow) => (remembered(r) ? 0 : r.measured?.grade === 'failing' ? 2 : 1);
    const order = [...candidates].sort((a, b) => rank(a) - rank(b));
    const steps: RouteDisplayRow[][] = [];
    let i = 0;
    if (order.length > 0 && remembered(order[0])) steps.push([order[i++]]);
    for (; i < order.length; i += 2) steps.push(order.slice(i, i + 2));
    return steps;
}

/** What one more attempt does to a route's record here. A first result
 *  gives a first grade; after that one sample does not flip it. */
function afterAttempt(m: Measured, carried: boolean, setupMs: number): Measured {
    const next: Measured = {
        ...m,
        samples: m.samples + 1,
        carried: m.carried + (carried ? 1 : 0),
        failed: m.failed + (carried ? 0 : 1),
        last: lastBucketText(Math.floor(Date.now() / 3600_000) * 3600),
    };
    if (carried && m.setupMs === undefined) next.setupMs = setupMs;
    if (m.grade === 'unknown') next.grade = carried ? 'ok' : 'failing';
    return next;
}

export class HarnessContract implements D2Contract {
    private cellLabels = new Map<string, string>();
    // What the person did in this harness session, laid over the
    // scenario's canned connection: connect, connectAuto and disconnect
    // move a small state machine shaped like the engine's, so the main
    // screen can be driven in a browser. null = untouched scenario.
    private sim: ConnectionSummary | null = null;
    // Bumped by every connect/disconnect: an automatic connect in
    // flight sees it changed and stops (how the engine's cancel looks
    // from here).
    private gen = 0;
    // What this session's attempts added to the scenario's canned
    // measurements, per route — so a row that said "Not tried here yet"
    // says something else after Daal has tried it.
    private measuredNow = new Map<string, Measured>();

    /** The scenario's routes with this session's measurements laid
     *  over them. */
    private rows(): RouteDisplayRow[] {
        return (this.s.availableRoutes ?? []).map((r) => {
            const m = this.measuredNow.get(r.routeId);
            return m ? { ...r, measured: m } : r;
        });
    }

    private record(r: RouteDisplayRow, carried: boolean): void {
        const m = this.measuredNow.get(r.routeId) ?? r.measured;
        if (m) this.measuredNow.set(r.routeId, afterAttempt(m, carried, harnessSetupMs(r)));
    }

    /** `stepMs`: how long each simulated route check takes. Tests pass
     *  a few ms; the browser default is long enough to read "Trying way
     *  2 of 4…". `scenario`: a fixed scenario instead of the one named
     *  in the URL (tests). */
    constructor(private readonly opts: { stepMs?: number; scenario?: Scenario } = {}) {}

    private get s(): Scenario {
        return this.opts.scenario ?? activeScenario();
    }

    private wait(): Promise<void> {
        const ms = this.opts.stepMs ?? 900;
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    async connectionSummary(): Promise<ConnectionSummary> {
        return this.sim ?? this.s.connection;
    }

    async whyThisRoute(): Promise<WhyThisRouteSummary | null> {
        return this.s.why ?? null;
    }

    async pointerRotation(): Promise<PointerRotationSummary | null> {
        return this.s.pointer ?? null;
    }

    async routeHealth(): Promise<RouteHealthDisplayRow[]> {
        return this.s.routeHealth ?? [];
    }

    async availableRoutes(): Promise<RouteDisplayRow[]> {
        return this.rows();
    }

    async routeSummary(routeId: string): Promise<RouteDisplayRow | null> {
        const rows = this.rows();
        return rows.find((r) => r.routeId === routeId) ?? null;
    }

    async throughputSnapshot(): Promise<ThroughputSnapshot> {
        return (
            this.s.throughput ?? {
                upBytesPerSec: 0,
                downBytesPerSec: 0,
                windowMs: 1000,
            }
        );
    }

    async statusPagePayload(): Promise<StatusPagePayload> {
        return {
            connection: await this.connectionSummary(),
            why: this.s.why ?? null,
            pointer: this.s.pointer ?? null,
            routeHealth: this.s.routeHealth ?? [],
            rawDiagnosticsJson: this.s.rawDiagnosticsJson ?? '{}',
        };
    }

    // A connect by hand: that route, checked, up. Ends automatic mode,
    // as engine_set_route does.
    async connect(routeId: string): Promise<void> {
        this.gen++;
        const row = this.rows().find((r) => r.routeId === routeId);
        if (!row) throw new Error('harness: no such route');
        this.sim = {
            ...this.s.connection,
            state: 'connected',
            activeRoute: row,
            routeCheck: 'ok',
            routeRunning: true,
            connectRefused: undefined,
            auto: AUTO_IDLE,
        };
    }

    // The engine's engine_connect_auto, in miniature: every usable route
    // in listed order, one check each, the first that carries stays up.
    // Blocks until it is over, like the desktop command; the `auto`
    // block of connectionSummary says where it is meanwhile.
    async connectAuto(): Promise<AutoConnectResult | null> {
        const now = await this.connectionSummary();
        if (now.state === 'connected' && now.activeRoute) {
            // Already connected: nothing is started, the running route
            // is named — and, as in the engine, automatic connect takes
            // charge of it from here on.
            this.sim = {
                ...now,
                auto: { ...AUTO_IDLE, state: 'connected', mode: true, routeId: now.activeRoute.routeId },
            };
            return {
                connected: true,
                routeId: now.activeRoute.routeId,
                family: now.activeRoute.family,
                tried: [],
                verdict: '',
                candidates: 0,
            };
        }
        const gen = ++this.gen;
        const base = this.s.connection;
        const all = this.rows();
        const dialable = all.filter((r) => r.familyMaturity !== 'unsupported');
        const candidates = dialable.filter((r) => r.inCooldown !== true);
        const tried: AutoTried[] = [];
        const fail = (verdict: string): AutoConnectResult => {
            this.sim = {
                ...base,
                state: 'error',
                activeRoute: undefined,
                routeCheck: undefined,
                routeRunning: false,
                auto: { ...AUTO_IDLE, state: 'failed', tried: [...tried], verdict, total: candidates.length },
            };
            return { connected: false, routeId: '', family: '', tried: [...tried], verdict, candidates: candidates.length };
        };
        if (all.length === 0) return fail('no_routes');
        if (candidates.length === 0) return fail(dialable.length > 0 ? 'all_cooling_down' : 'all_failed');
        // One step is one route, or two tried at the same moment (never
        // more). The first of a pair that carries wins; the other is
        // stopped.
        let done = 0;
        // Did a way Daal came to BEFORE the one that connected fail?
        let movedOn = false;
        for (const step of harnessSteps(candidates)) {
            const first = step[0];
            const racing = step.length === 2 ? step.map((r) => r.routeId) : [];
            const other = (r: RouteDisplayRow) =>
                step.length === 2 ? step.find((x) => x !== r)!.routeId : undefined;
            const entry = (r: RouteDisplayRow, result: string, category: string): AutoTried => ({
                routeId: r.routeId,
                family: r.family,
                result,
                category,
                ...(result === 'carried' ? { setupMs: harnessSetupMs(r) } : {}),
                ...(other(r) ? { racedWith: other(r) } : {}),
            });
            this.sim = {
                ...base,
                state: 'connecting',
                activeRoute: first,
                routeCheck: 'verifying',
                routeRunning: true,
                auto: {
                    state: 'trying',
                    mode: true,
                    trying: first.routeId,
                    racing,
                    index: done + 1,
                    total: candidates.length,
                    tried: [...tried],
                    verdict: '',
                    routeId: '',
                },
            };
            await this.wait();
            if (gen !== this.gen) {
                // Cancelled (a disconnect, or a newer connect): whoever
                // did that owns the state now.
                for (const r of step) tried.push(entry(r, 'cancelled', ''));
                return { connected: false, routeId: '', family: '', tried, verdict: '', candidates: candidates.length };
            }
            // Of a pair that both carry, the quicker one proves first.
            const winner = step
                .filter(harnessCarries)
                .sort((x, y) => harnessSetupMs(x) - harnessSetupMs(y))[0];
            for (const r of step) {
                if (r === winner) continue;
                if (harnessCarries(r)) {
                    // Stopped because the other one won: nothing was
                    // learned about it. The engine's word for this is
                    // 'stopped'; 'cancelled' is the person's cancel.
                    tried.push(entry(r, 'stopped', ''));
                } else {
                    // A partner that failed beside the way that then
                    // connected is not something Daal moved on from
                    // (the engine's rule: core/abi deriveAuto).
                    if (!(winner && r === step[1])) movedOn = true;
                    tried.push(entry(r, 'not_carrying', 'no_reply'));
                    this.record(r, false);
                }
            }
            done += step.length;
            if (winner) {
                tried.push(entry(winner, 'carried', ''));
                this.record(winner, true);
                const up = this.rows().find((x) => x.routeId === winner.routeId) ?? winner;
                const verdict = movedOn ? 'moved_on' : '';
                this.sim = {
                    ...base,
                    state: 'connected',
                    activeRoute: up,
                    routeCheck: 'ok',
                    routeRunning: true,
                    auto: {
                        state: 'connected',
                        mode: true,
                        trying: '',
                        index: done,
                        total: candidates.length,
                        tried: [...tried],
                        verdict,
                        routeId: up.routeId,
                    },
                };
                return {
                    connected: true,
                    routeId: up.routeId,
                    family: up.family,
                    tried: [...tried],
                    verdict,
                    candidates: candidates.length,
                };
            }
        }
        return fail('all_failed');
    }

    async routesStrict(): Promise<RouteDisplayRow[] | undefined> {
        return this.rows();
    }

    // Stops whatever is running and cancels an automatic connect in
    // flight; ends automatic mode.
    async disconnect(): Promise<void> {
        this.gen++;
        this.sim = {
            ...this.s.connection,
            state: 'disconnected',
            activeRoute: undefined,
            routeCheck: undefined,
            routeRunning: false,
            auto: AUTO_IDLE,
        };
    }

    async setMode(_mode: ConnectionSummary['mode']): Promise<void> { /* no-op */ }

    async panicWipe(): Promise<void> { /* no-op */ }

    async exportDiagnostics(): Promise<string> {
        return this.s.rawDiagnosticsJson ?? '{"harness":true}';
    }

    async diagnostics(): Promise<DiagnosticsBlob> {
        const c = this.s.connection;
        return {
            version: 'daal-core 0.9.0+v3-share',
            mode: c.mode,
            posture: 'harness',
            state: c.state,
            routeCount: this.s.availableRoutes?.length ?? 0,
            bucket: new Date().toISOString().slice(0, 13),
            currentNetworkId: 'harness-network',
            secretsUnlocked: true,
            storageProfile: 'vault',
            sessionAllowsBulkCapable: false,
        };
    }

    async versionInfo(): Promise<VersionInfo> {
        return { engineVersion: 'daal-core 0.9.0+v3-share', guiVersion: 'harness' };
    }

    async heartbeatTick(): Promise<boolean> {
        return true;
    }

    async subscriptionList(): Promise<SubscriptionRow[]> {
        // Cheap projection from availableRoutes — one row per distinct publisher.
        const counts = new Map<string, number>();
        for (const r of this.s.availableRoutes ?? []) {
            counts.set(r.publisherName, (counts.get(r.publisherName) ?? 0) + 1);
        }
        const rows: SubscriptionRow[] = [];
        let i = 0;
        for (const [publisherName, routeCount] of counts) {
            i++;
            rows.push({
                subscriptionId: `harness-${i}`,
                publisherId: publisherName,
                displayName: publisherName,
                profileTitle: `Rescue (${publisherName})`,
                lastRefreshBucket: new Date().toISOString().slice(0, 13),
                lastRefreshOutcome: 'success',
                lastGoodRefreshBucket: new Date().toISOString().slice(0, 13),
                routeCount,
            });
        }
        return rows;
    }

    async subscriptionAdd(_req: AddSubscriptionRequest): Promise<string> {
        return 'harness-added';
    }

    async subscriptionRemove(_subscriptionId: string): Promise<void> { /* no-op */ }
    async routeDelete(_routeId: string): Promise<void> { /* no-op */ }
    async publisherDelete(_publisherId: string): Promise<number> { return 0; }

    async subscriptionRefresh(_subscriptionId: string, _timeoutMs: number): Promise<string> {
        return 'harness-refreshed';
    }

    async previewBundle(_path: string): Promise<PreviewedBundle> {
        return {
            fingerprintHex: 'aa'.repeat(16),
            fingerprintEN: 'phoenix rescue may sky honest stone river hill',
            fingerprintFA: 'ققنوس نجات اردیبهشت آسمان درست سنگ رود تپه',
            fingerprintVisualDataUri:
                'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMjgiIGhlaWdodD0iMTI4Ii8+',
            publisherName: 'Pars Relays',
            bundleId: 'harness-bundle',
            specVersion: 4,
            routeCount: 3,
        };
    }

    async importSbp(_path: string): Promise<string> {
        return 'harness-imported';
    }

    // Step 11: the harness has no decoder, so it answers the same way
    // it answers for a file. The real acceptance rules live in Rust
    // (`daal-wizard/src/recipient_paste.rs`) and are tested there.
    async importSbpBytes(_text: string): Promise<string> {
        return 'harness-imported';
    }

    async resolveTrustPrompt(_fingerprintHex: string, _decision: TrustDecision): Promise<string> {
        return 'harness-trusted';
    }

    // ---- v0.2.x extras ---------------------------------------------

    async schedulerStatus(): Promise<SchedulerStatus> {
        return {
            json: this.s.schedulerStatusJson ??
                '{"tick":0,"queue":[],"in_flight":0,"last_pick":"harness-route"}',
        };
    }
    async statsRedacted(): Promise<StatsRedacted> {
        return {
            json: this.s.statsRedactedJson ??
                '{"sessions":0,"bytes_up":0,"bytes_down":0,"redacted":true}',
        };
    }
    async lifecycleEvent(_t: LifecycleToken): Promise<void> { /* no-op */ }
    async applyCooldown(_r: string, _d: number, _why: string): Promise<void> { /* no-op */ }
    async redistributeRoute(_r: string, _fp?: string): Promise<RedistributeResult> {
        return { envelope: 'harness-envelope', raw: 'harness' };
    }
    async setRouteBudget(_r: string, _tag: string): Promise<string> {
        return 'harness-budget-set';
    }

    async probeUdp(_t: number): Promise<ProbeResult> { return { ok: true, raw: 42 }; }
    async probeDns(_t: number): Promise<ProbeResult> { return { ok: true, raw: 18 }; }
    async probeTcp443(_t: number): Promise<ProbeResult> { return { ok: true, raw: 27 }; }

    async networkChanged(_k: string, _c: string, _s: string): Promise<string> {
        return '{"network_id":"harness","fresh":true}';
    }

    async unlockSecrets(_pin: string): Promise<UnlockResult> { return 'not_required'; }
    async setAllowBulkCapable(_v: boolean): Promise<void> { /* no-op */ }

    async bootstrapInstallSeeds(): Promise<string> { return '{"installed":2}'; }
    async bootstrapRefresh(_t: number): Promise<string> { return '{"refreshed":true}'; }
    async bootstrapStatus(): Promise<BootstrapStatus> {
        return {
            json: this.s.bootstrapStatusJson ??
                '{"seeds":2,"last_refresh":"2026-05-22T12:00:00Z"}',
        };
    }

    async setRendezvousPriority(_order: string[]): Promise<void> { /* no-op */ }
    async setPushRendezvousEnabled(_v: boolean): Promise<void> { /* no-op */ }
    async setAutoPromotion(_v: boolean): Promise<void> { /* no-op */ }
    async setMasqueSubmodeOverride(_v: string): Promise<void> { /* no-op */ }
    async setExperimentalFamiliesEnabled(_v: boolean): Promise<void> { /* no-op */ }

    async loadedWasmModules(): Promise<string[]> {
        return this.s.wasmModules ?? ['hello-https'];
    }
    async wasmKillSwitchPubkey(): Promise<string> {
        return this.s.wasmKillSwitchPubkey ?? 'a1b2c3d4e5f6'.repeat(4);
    }

    async revocationRefreshAll(_t: number): Promise<string> {
        return '{"checked":3,"updated":0}';
    }

    async uriDetect(text: string): Promise<UriDetectResult> {
        return {
            hits: [
                { scheme: 'vless', uri: text, preview: 'vless://•••@relay.example:443' },
            ],
            raw: text,
        };
    }
    async uriImport(text: string): Promise<UriImportResult> {
        return { fingerprintHex: 'aa'.repeat(16), bundleId: 'harness', raw: text };
    }

    // ---- D-2 Connections page (M1: derive client-side) -------------

    async listPublishers(): Promise<PublisherTreeRow[]> {
        const routes = await this.availableRoutes();
        const subs = await this.subscriptionList();
        const skipped = await this.skippedFamilies();
        return buildPublisherTree(routes, subs, skipped, (k) =>
            this.cellLabels.get(k) ?? '',
        );
    }

    async skippedFamilies(): Promise<SkippedFamilyRow[]> {
        return this.s.skippedFamilies ?? [];
    }

    async burnpressureVerdict(): Promise<BurnpressureVerdict> {
        return deriveBurnpressureVerdict(await this.skippedFamilies());
    }

    async cellLabelGet(cellIdFpHex: string): Promise<string> {
        return this.cellLabels.get(cellIdFpHex) ?? '';
    }

    async cellLabelSet(cellIdFpHex: string, label: string): Promise<void> {
        if (label) this.cellLabels.set(cellIdFpHex, label);
        else this.cellLabels.delete(cellIdFpHex);
    }
}
