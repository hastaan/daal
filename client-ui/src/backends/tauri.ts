// TauriContract — the real backend. Every method invokes a Tauri
// #[tauri::command] in client-shell/tauri/src-tauri and parses the
// resulting JSON into the contract shapes.
//
// This is the ONLY file in client-ui/ that imports from
// @tauri-apps/api/core. Screens never call invoke() directly.

import { invoke } from '@tauri-apps/api/core';
import type {
    AddSubscriptionRequest,
    BootstrapStatus,
    ConnectionSummary,
    ConnMode,
    ConnState,
    D2Contract,
    DiagnosticsBlob,
    LifecycleToken,
    PointerRotationSummary,
    PreviewedBundle,
    ProbeResult,
    RedistributeResult,
    RouteDisplayRow,
    RouteHealthDisplayRow,
    SchedulerStatus,
    Severity,
    SkippedRouteEntry,
    StatsRedacted,
    StatusPagePayload,
    SubscriptionRow,
    ThroughputSnapshot,
    TrustClass,
    TrustDecision,
    UnlockResult,
    UriDetectResult,
    UriImportResult,
    VersionInfo,
    WhyThisRouteSummary,
} from '../contract/D2Contract';

// Bridge to the legacy lib/bridge.ts file. The plan is to fold those
// invoke() wrappers into this backend file once the legacy code paths
// are all retired; until then this is the only legitimate consumer.
import {
    diagnostics as bridgeDiagnostics,
    diagnosticsExplain,
    pointerRotationStatus,
    exportDiagnostics as bridgeExportDiag,
    connect as bridgeConnect,
    disconnect as bridgeDisconnect,
    setMode as bridgeSetMode,
    parseExplanation,
    type Mode as BridgeMode,
    versionInfo as bridgeVersionInfo,
    heartbeatTick as bridgeHeartbeat,
    subscriptionList as bridgeSubList,
    subscriptionAdd as bridgeSubAdd,
    subscriptionRemove as bridgeSubRemove,
    subscriptionRefresh as bridgeSubRefresh,
    previewBundle as bridgePreviewBundle,
    importSbp as bridgeImportSbp,
    resolveTrustPrompt as bridgeResolveTrustPrompt,
} from '../lib/bridge';

// ---- internal shapes (engine JSON, snake_case)

interface RawRouteSummary {
    route_id: string;
    publisher_name: string;
    route_nickname: string;
    trust_class: string;
    family: string;
    in_cooldown: boolean;
    cooldown_until_unix_ms?: number;
    budget_exhausted: boolean;
    health_pct?: number;
}

// ---- derivations

function deriveConnState(s: string): ConnState {
    switch (s) {
        case 'connected':
            return 'connected';
        case 'connecting':
            return 'connecting';
        case 'error':
        case 'failed':
            return 'error';
        default:
            return 'disconnected';
    }
}

function deriveSeverity(pct: number): Severity {
    if (pct >= 80) return 'ok';
    if (pct >= 50) return 'warn';
    return 'bad';
}

function deriveTrustClass(t: unknown): TrustClass {
    const s = String(t ?? '').toLowerCase();
    if (s === 'trusted' || s === 'pinned' || s === 'lan' || s === 'unknown') {
        return s as TrustClass;
    }
    return 'unknown';
}

function deriveNetworkLabel(networkIdHash?: string): string | undefined {
    if (!networkIdHash) return undefined;
    return 'Network';
}

function rawToRow(r: RawRouteSummary): RouteDisplayRow {
    return {
        routeId: r.route_id,
        publisherName: r.publisher_name,
        routeNickname: r.route_nickname,
        trustClass: deriveTrustClass(r.trust_class),
        family: r.family,
        inCooldown: !!r.in_cooldown,
        cooldownUntilUnixMs: r.cooldown_until_unix_ms,
        budgetExhausted: !!r.budget_exhausted,
        healthPct: typeof r.health_pct === 'number' ? r.health_pct : undefined,
    };
}

// ---- raw command wrappers

async function rawRouteSummary(routeId: string): Promise<RawRouteSummary | null> {
    try {
        const body = await invoke<string>('route_summary', { routeId });
        if (!body) return null;
        return JSON.parse(body) as RawRouteSummary;
    } catch {
        return null;
    }
}

async function rawAvailableRoutes(): Promise<RawRouteSummary[]> {
    try {
        const body = await invoke<string>('available_routes');
        if (!body) return [];
        const parsed = JSON.parse(body) as { routes?: RawRouteSummary[] };
        return parsed.routes ?? [];
    } catch {
        return [];
    }
}

async function rawThroughputSnapshot(): Promise<ThroughputSnapshot> {
    try {
        const body = await invoke<string>('throughput_snapshot');
        const j = JSON.parse(body) as {
            up_bps: number;
            down_bps: number;
            window_ms: number;
        };
        return {
            upBytesPerSec: j.up_bps,
            downBytesPerSec: j.down_bps,
            windowMs: j.window_ms,
        };
    } catch {
        return { upBytesPerSec: 0, downBytesPerSec: 0, windowMs: 1000 };
    }
}

// ---- backend implementation

export class TauriContract implements D2Contract {
    async connectionSummary(): Promise<ConnectionSummary> {
        const d = await bridgeDiagnostics();
        const state = deriveConnState((d as { state?: string }).state ?? 'disconnected');
        const mode = ((d.mode as ConnMode) ?? 'normal');
        let activeRoute: RouteDisplayRow | undefined;
        try {
            const exp = parseExplanation(await diagnosticsExplain());
            if (exp?.pick?.route_id) {
                const r = await rawRouteSummary(exp.pick.route_id);
                if (r) activeRoute = rawToRow(r);
            }
        } catch { /* ignore */ }

        let pointerValidDays: number | undefined;
        try {
            const pr = await pointerRotationStatus();
            const obj = pr as { valid_for_days?: number; valid_days?: number };
            pointerValidDays = obj.valid_for_days ?? obj.valid_days;
        } catch { /* ignore */ }

        return {
            state,
            mode,
            connectedSinceUnixMs: undefined,
            activeRoute,
            networkLabel: deriveNetworkLabel(d.current_network_id),
            pointerValidDays,
            netStatusLine: undefined,
        };
    }

    async whyThisRoute(): Promise<WhyThisRouteSummary | null> {
        try {
            const exp = parseExplanation(await diagnosticsExplain());
            if (!exp) return null;
            const active = await rawRouteSummary(exp.pick.route_id);
            if (!active) return null;
            const skipped: SkippedRouteEntry[] = [];
            for (const f of exp.failures ?? []) {
                const r = await rawRouteSummary(f.route_id);
                if (r) {
                    skipped.push({
                        route: rawToRow(r),
                        reason: f.classification,
                        reasonToken: f.tag ?? f.classification,
                    });
                }
            }
            return {
                active: rawToRow(active),
                reasonText: exp.reason ?? '',
                skipped,
                decisionId: exp.decision_id,
            };
        } catch {
            return null;
        }
    }

    async pointerRotation(): Promise<PointerRotationSummary | null> {
        try {
            const pr = (await pointerRotationStatus()) as {
                last_rotated_unix_ms?: number;
                valid_for_days?: number;
                ok?: boolean;
            };
            return {
                lastRotatedUnixMs: pr.last_rotated_unix_ms ?? 0,
                validForDays: pr.valid_for_days ?? 0,
                rotatedSuccessfully: pr.ok ?? true,
            };
        } catch {
            return null;
        }
    }

    async routeHealth(): Promise<RouteHealthDisplayRow[]> {
        const d = await bridgeDiagnostics();
        const out: RouteHealthDisplayRow[] = [];
        for (const r of d.route_health ?? []) {
            const summary = await rawRouteSummary(r.route_id);
            const label = summary
                ? `${summary.publisher_name} · ${summary.route_nickname}`
                : r.route_id;
            const pct = summary?.health_pct ?? (r.in_cooldown ? 30 : 90);
            out.push({
                routeId: r.route_id,
                label,
                pct,
                severity: deriveSeverity(pct),
            });
        }
        return out;
    }

    async availableRoutes(): Promise<RouteDisplayRow[]> {
        const raw = await rawAvailableRoutes();
        return raw.map(rawToRow);
    }

    async routeSummary(routeId: string): Promise<RouteDisplayRow | null> {
        const r = await rawRouteSummary(routeId);
        return r ? rawToRow(r) : null;
    }

    async throughputSnapshot(): Promise<ThroughputSnapshot> {
        return rawThroughputSnapshot();
    }

    async statusPagePayload(): Promise<StatusPagePayload> {
        const [connection, why, pointer, routeHealthRows] = await Promise.all([
            this.connectionSummary(),
            this.whyThisRoute(),
            this.pointerRotation(),
            this.routeHealth(),
        ]);
        const rawDiagnosticsJson = await bridgeExportDiag();
        return {
            connection,
            why,
            pointer,
            routeHealth: routeHealthRows,
            rawDiagnosticsJson,
        };
    }

    async connect(routeId: string): Promise<void> {
        return bridgeConnect(routeId);
    }

    async disconnect(): Promise<void> {
        return bridgeDisconnect();
    }

    async setMode(mode: ConnMode): Promise<void> {
        return bridgeSetMode(mode as BridgeMode);
    }

    async panicWipe(): Promise<void> {
        await invoke<void>('panic_wipe');
    }

    async exportDiagnostics(): Promise<string> {
        return bridgeExportDiag();
    }

    async diagnostics(): Promise<DiagnosticsBlob> {
        const d = await bridgeDiagnostics();
        return {
            version: d.version,
            mode: String(d.mode),
            posture: d.posture,
            state: d.state,
            why: d.why,
            routeCount: d.route_count,
            bucket: d.bucket,
            currentNetworkId: d.current_network_id,
            secretsUnlocked: d.secrets_unlocked,
            storageProfile: d.storage_profile,
            sessionAllowsBulkCapable: d.session_allows_bulk_capable,
        };
    }

    async versionInfo(): Promise<VersionInfo> {
        const v = await bridgeVersionInfo();
        return { engineVersion: v.engine_version, guiVersion: v.gui_version };
    }

    async heartbeatTick(): Promise<boolean> {
        return bridgeHeartbeat();
    }

    async subscriptionList(): Promise<SubscriptionRow[]> {
        const rows = await bridgeSubList();
        return rows.map((r) => ({
            subscriptionId: r.subscription_id,
            publisherId: r.publisher_id,
            displayName: r.display_name,
            profileTitle: r.profile_title,
            lastRefreshBucket: r.last_refresh_bucket,
            lastRefreshOutcome: r.last_refresh_outcome,
            lastGoodRefreshBucket: r.last_good_refresh_bucket,
        }));
    }

    async subscriptionAdd(req: AddSubscriptionRequest): Promise<string> {
        return bridgeSubAdd({
            publisher_fingerprint: req.publisherFingerprint,
            url: req.url,
            display_name: req.displayName,
        });
    }

    async subscriptionRemove(subscriptionId: string): Promise<void> {
        return bridgeSubRemove(subscriptionId);
    }

    async subscriptionRefresh(subscriptionId: string, timeoutMs: number): Promise<string> {
        return bridgeSubRefresh(subscriptionId, timeoutMs);
    }

    async previewBundle(path: string): Promise<PreviewedBundle> {
        const p = await bridgePreviewBundle(path);
        return {
            fingerprintHex: p.fingerprint_hex,
            fingerprintEN: p.fingerprint_en,
            fingerprintFA: p.fingerprint_fa,
            fingerprintVisualDataUri: p.fingerprint_visual_data_uri,
            publisherName: p.publisher_name,
            bundleId: p.bundle_id,
            specVersion: p.spec_version,
            routeCount: p.route_count,
        };
    }

    async importSbp(path: string): Promise<string> {
        return bridgeImportSbp(path);
    }

    async resolveTrustPrompt(fingerprintHex: string, decision: TrustDecision): Promise<string> {
        return bridgeResolveTrustPrompt(fingerprintHex, decision);
    }

    // ---- v0.2.x extras ----------------------------------------------

    async schedulerStatus(): Promise<SchedulerStatus> {
        try {
            const json = await invoke<string>('scheduler_status');
            return { json };
        } catch {
            return { json: '' };
        }
    }

    async statsRedacted(): Promise<StatsRedacted> {
        try {
            const json = await invoke<string>('stats_redacted');
            return { json };
        } catch {
            return { json: '' };
        }
    }

    async lifecycleEvent(token: LifecycleToken): Promise<void> {
        await invoke<void>('lifecycle_event', { token });
    }

    async applyCooldown(
        routeId: string,
        durationMs: number,
        _reason: string,
    ): Promise<void> {
        await invoke<void>('apply_cooldown', {
            routeId,
            seconds: Math.max(1, Math.round(durationMs / 1000)),
        });
    }

    async redistributeRoute(
        routeId: string,
        recipientFp = '',
    ): Promise<RedistributeResult> {
        try {
            const raw = await invoke<string>('redistribute_route', {
                routeId,
                recipientFp,
            });
            try {
                const parsed = JSON.parse(raw) as {
                    error?: string;
                    envelope?: string;
                };
                return { ...parsed, raw };
            } catch {
                return { envelope: raw, raw };
            }
        } catch (e) {
            return { error: String(e), raw: '' };
        }
    }

    async setRouteBudget(routeId: string, budgetTag: string): Promise<string> {
        return invoke<string>('set_route_budget', { routeId, budgetTag });
    }

    async probeUdp(timeoutMs: number): Promise<ProbeResult> {
        const raw = await invoke<number>('probe_udp', { timeoutMs });
        return { ok: raw >= 0, raw };
    }
    async probeDns(timeoutMs: number): Promise<ProbeResult> {
        const raw = await invoke<number>('probe_dns', { timeoutMs });
        return { ok: raw >= 0, raw };
    }
    async probeTcp443(timeoutMs: number): Promise<ProbeResult> {
        const raw = await invoke<number>('probe_tcp443', { timeoutMs });
        return { ok: raw >= 0, raw };
    }

    async networkChanged(kind: string, carrier: string, ssid: string): Promise<string> {
        return invoke<string>('network_changed', { kind, carrier, ssid });
    }

    async unlockSecrets(pin: string): Promise<UnlockResult> {
        const r = await invoke<string>('unlock_secrets', { pin });
        // The Rust shim returns the snake_case-serialized enum.
        if (r === 'unlocked') return 'unlocked';
        if (r === 'not_required') return 'not_required';
        return 'wrong_pin';
    }

    async setAllowBulkCapable(allow: boolean): Promise<void> {
        await invoke<void>('set_allow_bulk_capable', { allow });
    }

    async bootstrapInstallSeeds(): Promise<string> {
        return invoke<string>('bootstrap_install_seeds');
    }
    async bootstrapRefresh(timeoutMs: number): Promise<string> {
        return invoke<string>('bootstrap_refresh', { timeoutMs });
    }
    async bootstrapStatus(): Promise<BootstrapStatus> {
        try {
            const json = await invoke<string>('bootstrap_status');
            return { json };
        } catch {
            return { json: '' };
        }
    }

    async setRendezvousPriority(order: string[]): Promise<void> {
        await invoke<void>('set_rendezvous_priority', {
            priorityJson: JSON.stringify(order),
        });
    }
    async setPushRendezvousEnabled(enabled: boolean): Promise<void> {
        await invoke<void>('set_push_rendezvous_enabled', { enabled });
    }
    async setAutoPromotion(enabled: boolean): Promise<void> {
        await invoke<void>('set_auto_promotion', { enabled });
    }
    async setMasqueSubmodeOverride(submode: string): Promise<void> {
        await invoke<void>('set_masque_submode_override', { submode });
    }
    async setExperimentalFamiliesEnabled(enabled: boolean): Promise<void> {
        await invoke<void>('set_experimental_families_enabled', { enabled });
    }

    async loadedWasmModules(): Promise<string[]> {
        try {
            const raw = await invoke<string>('loaded_wasm_modules');
            const parsed = JSON.parse(raw) as Array<{ slug?: string }>;
            return parsed.map((m) => m.slug ?? '').filter(Boolean);
        } catch {
            return [];
        }
    }
    async wasmKillSwitchPubkey(): Promise<string> {
        try { return await invoke<string>('wasm_kill_switch_pubkey'); }
        catch { return ''; }
    }

    async revocationRefreshAll(timeoutMs: number): Promise<string> {
        return invoke<string>('revocation_refresh_all', { timeoutMs });
    }

    async uriDetect(text: string): Promise<UriDetectResult> {
        const raw = await invoke<string>('uri_detect', { text });
        try {
            const parsed = JSON.parse(raw) as { kind?: string; payload?: string };
            return { kind: parsed.kind ?? '', payload: parsed.payload ?? '', raw };
        } catch {
            return { kind: '', payload: '', raw };
        }
    }
    async uriImport(rawUri: string): Promise<UriImportResult> {
        const raw = await invoke<string>('uri_import', { rawUri });
        try {
            const parsed = JSON.parse(raw) as {
                fingerprint_hex?: string;
                bundle_id?: string;
                error?: string;
            };
            return {
                fingerprintHex: parsed.fingerprint_hex,
                bundleId: parsed.bundle_id,
                error: parsed.error,
                raw,
            };
        } catch {
            return { raw };
        }
    }
}
