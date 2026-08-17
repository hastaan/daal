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

export class HarnessContract implements D2Contract {
    private cellLabels = new Map<string, string>();

    private get s(): Scenario {
        return activeScenario();
    }

    async connectionSummary(): Promise<ConnectionSummary> {
        return this.s.connection;
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
        return this.s.availableRoutes ?? [];
    }

    async routeSummary(routeId: string): Promise<RouteDisplayRow | null> {
        const rows = this.s.availableRoutes ?? [];
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
            connection: this.s.connection,
            why: this.s.why ?? null,
            pointer: this.s.pointer ?? null,
            routeHealth: this.s.routeHealth ?? [],
            rawDiagnosticsJson: this.s.rawDiagnosticsJson ?? '{}',
        };
    }

    async connect(_routeId: string): Promise<void> {
        // In harness mode actions are no-ops. A future iteration may
        // tick scenario.connection.state across a fake "connecting"
        // sequence via a manual state machine.
    }

    async disconnect(): Promise<void> { /* no-op */ }

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
