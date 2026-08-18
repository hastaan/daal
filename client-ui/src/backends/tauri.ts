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
    BurnpressureVerdict,
    ConnectionSummary,
    ConnMode,
    ConnState,
    D2Contract,
    DiagnosticsBlob,
    LifecycleToken,
    FamilyMaturity,
    PointerRotationSummary,
    PointerSource,
    PreviewedBundle,
    ProbeResult,
    PublisherTreeRow,
    RedistributeResult,
    RouteDisplayRow,
    RouteHealthDisplayRow,
    SchedulerStatus,
    Severity,
    SkippedFamilyRow,
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
import { buildPublisherTree, deriveBurnpressureVerdict } from '../contract/derive_tree';

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
    routeDelete as bridgeRouteDelete,
    publisherDelete as bridgePublisherDelete,
    subscriptionRefresh as bridgeSubRefresh,
    previewBundle as bridgePreviewBundle,
    importSbp as bridgeImportSbp,
    importSbpBytes as bridgeImportSbpBytes,
    resolveTrustPrompt as bridgeResolveTrustPrompt,
} from '../lib/bridge';

// ---- internal shapes (engine JSON, snake_case)

// Mirrors core/abi.RouteSummaryDisplay. The three nullable fields are
// the engine's measured/unmeasured seam: `null` means the engine has
// observed nothing, and must never be coerced to false/0 on this side.
interface RawRouteSummary {
    route_id: string;
    publisher_id: string;
    publisher_name: string;
    route_nickname: string;
    trust_class: string;
    family: string;
    family_maturity?: string;
    in_cooldown: boolean | null;
    cooldown_until_unix_ms?: number;
    budget_exhausted: boolean | null;
    health_pct: number | null;
    proven?: boolean;
}

// Mirrors core/bootstrap.PointerRotationStatus, field for field. Every
// key here exists in the Go struct; nothing is invented.
interface RawPointerRotationStatus {
    have_persisted?: boolean;
    primary_valid_until?: string;
    fallback_valid_until?: string;
    primary_source?: string;
    fallback_source?: string;
    embedded_primary_until?: string;
    embedded_fallback_until?: string;
}

// ---- derivations

// Map core engine FSM `posture` (8 states, see core/pathmanager/posture.go)
// to the UI `ConnState`. The deprecated `state` field was removed from the
// ABI diagnostics blob per Phase-3-Soak locked decision #13
// (see core/abi/abi.go:ExportDiagnostics) — every consumer MUST read
// `posture`.
//
// Posture taxonomy:
//   NoRoute            — no candidate routes at all
//   BootstrapDiscovery — discovering routes via bootstrap rendezvous
//   ImportedActive     — an imported route is the active path
//   SharedActive       — a shared route is the active path
//   Recovery           — engine is recovering / retrying
//   Lifeline           — only the lifeline path is up (degraded but live)
//   OfflineSharing     — sharing locally, no tunnel
//   Experimental       — experimental-family path is active
function postureToConnState(p: string): ConnState {
    switch (p) {
        case 'ImportedActive':
        case 'SharedActive':
        case 'Lifeline':
        case 'Experimental':
            return 'connected';
        case 'Recovery':
            return 'connecting';
        case 'NoRoute':
        case 'BootstrapDiscovery':
        case 'OfflineSharing':
            return 'disconnected';
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

// Engine sentinel (core/abi.ProbeUnimplemented): the probe ABI isn't wired
// yet. Map it to `unavailable` so the UI shows "unavailable" not fake success.
const PROBE_UNIMPLEMENTED = -1000;
function toProbeResult(raw: number): ProbeResult {
    if (raw === PROBE_UNIMPLEMENTED) {
        return { ok: false, raw, unavailable: true };
    }
    return { ok: raw >= 0, raw };
}

const MATURITIES: readonly FamilyMaturity[] = [
    'stable',
    'promotion-candidate',
    'experimental',
    'unsupported',
    'unhandled',
];

function deriveMaturity(m: unknown): FamilyMaturity | undefined {
    const s = String(m ?? '');
    return (MATURITIES as readonly string[]).includes(s)
        ? (s as FamilyMaturity)
        : undefined;
}

function rawToRow(r: RawRouteSummary): RouteDisplayRow {
    return {
        routeId: r.route_id,
        publisherId: r.publisher_id,
        publisherName: r.publisher_name,
        routeNickname: r.route_nickname,
        trustClass: deriveTrustClass(r.trust_class),
        family: r.family,
        familyMaturity: deriveMaturity(r.family_maturity),
        // `?? undefined` and NOT `!!` — a null from the engine means
        // "never observed" and has to stay distinguishable from a
        // measured false all the way to the renderer.
        inCooldown: r.in_cooldown ?? undefined,
        cooldownUntilUnixMs: r.cooldown_until_unix_ms,
        budgetExhausted: r.budget_exhausted ?? undefined,
        healthPct: typeof r.health_pct === 'number' ? r.health_pct : undefined,
        proven: !!r.proven,
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

// ---- pointer rotation ------------------------------------------------

function derivePointerSource(s: unknown): PointerSource | undefined {
    return s === 'embedded' || s === 'persisted' ? s : undefined;
}

// Whole days from now until an RFC3339 instant. Returns undefined for
// an absent or unparseable timestamp — the caller must then say
// nothing, because 0 legitimately means "expires today".
function daysUntil(rfc3339?: string): number | undefined {
    if (!rfc3339) return undefined;
    const t = Date.parse(rfc3339);
    if (Number.isNaN(t)) return undefined;
    return Math.floor((t - Date.now()) / 86_400_000);
}

function toPointerSummary(
    raw: RawPointerRotationStatus,
): PointerRotationSummary {
    return {
        havePersisted: raw.have_persisted === true,
        primarySource: derivePointerSource(raw.primary_source),
        fallbackSource: derivePointerSource(raw.fallback_source),
        primaryValidUntil: raw.primary_valid_until || undefined,
        fallbackValidUntil: raw.fallback_valid_until || undefined,
        validForDays: daysUntil(raw.primary_valid_until),
    };
}

async function rawThroughputSnapshot(): Promise<ThroughputSnapshot> {
    try {
        const body = await invoke<string>('throughput_snapshot');
        const j = JSON.parse(body) as {
            up_bps: number | null;
            down_bps: number | null;
            window_ms: number;
        };
        return {
            upBytesPerSec: j.up_bps ?? null,
            downBytesPerSec: j.down_bps ?? null,
            windowMs: j.window_ms,
        };
    } catch {
        // The call failed, so we know nothing about throughput. Zero is
        // a measurement; null is the truth.
        return { upBytesPerSec: null, downBytesPerSec: null, windowMs: 1000 };
    }
}

// ---- backend implementation

export class TauriContract implements D2Contract {
    async connectionSummary(): Promise<ConnectionSummary> {
        const d = await bridgeDiagnostics();
        const state = postureToConnState(d.posture ?? '');
        const mode = ((d.mode as ConnMode) ?? 'normal');
        let activeRoute: RouteDisplayRow | undefined;
        try {
            const exp = parseExplanation(await diagnosticsExplain());
            if (exp?.pick?.route_id) {
                const r = await rawRouteSummary(exp.pick.route_id);
                if (r) activeRoute = rawToRow(r);
            }
        } catch { /* ignore */ }

        // The engine emits neither `valid_for_days` nor `valid_days` —
        // reading them meant this was always undefined. Derive the day
        // count from the RFC3339 horizon the engine DOES emit, and
        // carry which pointer set is actually in play so the status
        // line stops asserting "using rotated pointers" unconditionally.
        let pointer: PointerRotationSummary | undefined;
        try {
            pointer = toPointerSummary(
                (await pointerRotationStatus()) as RawPointerRotationStatus,
            );
        } catch { /* engine not up yet; claim nothing */ }

        return {
            state,
            mode,
            connectedSinceUnixMs: undefined,
            activeRoute,
            networkLabel: deriveNetworkLabel(d.current_network_id),
            pointerSource: pointer?.primarySource,
            pointerValidDays: pointer?.validForDays,
            netStatusLine: undefined,
            // Only 'none' and 'singbox' are meaningful. Anything else —
            // including the absent field an older engine emits — stays
            // undefined so the UI claims nothing rather than accusing a
            // working engine of being a stub.
            dataPlane:
                d.data_plane === 'none' || d.data_plane === 'singbox'
                    ? d.data_plane
                    : undefined,
        };
    }

    async whyThisRoute(): Promise<WhyThisRouteSummary | null> {
        try {
            const exp = parseExplanation(await diagnosticsExplain());
            if (!exp) return null;
            const active = await rawRouteSummary(exp.pick.route_id);
            if (!active) return null;

            // Did the selector actually compare anything?
            //
            // core/abi/refresh.go's DiagnosticsExplain hands
            // selection.Decide a ONE-ELEMENT Routes slice holding the
            // already-active route. With nothing to reject,
            // `exp.failures` comes back empty on every device — and an
            // empty skipped[] rendered as "the engine weighed your
            // other routes and skipped none", which is a claim no code
            // ever evaluated. The shortlist is the honest witness: if
            // it is smaller than the route set the device actually
            // holds, the comparison did not happen and the answer is
            // null ("not evaluated"), not [] ("nothing was skipped").
            //
            // This test is self-clearing: once Decide is fed the full
            // route set (Wave 3, §5), the shortlist covers it and the
            // real list starts rendering with no change here.
            const known = await rawAvailableRoutes();
            const shortlisted = exp.shortlist?.length ?? 0;
            const comparisonRan = known.length > 1 && shortlisted >= known.length;

            let skipped: SkippedRouteEntry[] | null = null;
            if (comparisonRan) {
                skipped = [];
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
            }

            // Family cooldowns, by contrast, ARE measured: the path
            // manager writes them and export_diagnostics carries them.
            // Surface them so the panel still has something true to say
            // while the per-route comparison is unevaluated.
            const skippedFamilies = await this.skippedFamilies();

            return {
                active: rawToRow(active),
                reasonText: exp.reason ?? '',
                skipped,
                skippedFamilies: skippedFamilies ?? undefined,
                decisionId: exp.decision_id,
            };
        } catch {
            return null;
        }
    }

    // The old body read three keys the engine has never emitted and
    // defaulted the most important one to success:
    //   rotatedSuccessfully: pr.ok ?? true
    // core/bootstrap/pointer_rotation.go's PointerRotationStatus has no
    // `ok` field, no `last_rotated_unix_ms` and no `valid_for_days`, so
    // every device rendered "Pointers rotated successfully. Valid for 0
    // more days." — a success claim manufactured entirely from missing
    // data. This version projects only keys the Go struct marshals.
    async pointerRotation(): Promise<PointerRotationSummary | null> {
        try {
            return toPointerSummary(
                (await pointerRotationStatus()) as RawPointerRotationStatus,
            );
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
            // Honest value only — never fabricate a number the engine
            // didn't produce. The old fallback of 0 leaked into
            // deriveSeverity() and painted a red "0%" bar on a route
            // nobody had ever tried. Absent stays absent; the renderer
            // shows "not measured yet" instead of a bar.
            const pct =
                typeof summary?.health_pct === 'number'
                    ? summary.health_pct
                    : undefined;
            out.push({
                routeId: r.route_id,
                label,
                pct,
                severity: pct === undefined ? undefined : deriveSeverity(pct),
                proven: !!summary?.proven,
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

    async routeDelete(routeId: string): Promise<void> {
        return bridgeRouteDelete(routeId);
    }

    async publisherDelete(publisherId: string): Promise<number> {
        return bridgePublisherDelete(publisherId);
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

    // Step 11: pasted text. Same verification, same verdict JSON —
    // the only difference is how the bytes reached the phone.
    async importSbpBytes(text: string): Promise<string> {
        return bridgeImportSbpBytes(text);
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
        return toProbeResult(await invoke<number>('probe_udp', { timeoutMs }));
    }
    async probeDns(timeoutMs: number): Promise<ProbeResult> {
        return toProbeResult(await invoke<number>('probe_dns', { timeoutMs }));
    }
    async probeTcp443(timeoutMs: number): Promise<ProbeResult> {
        return toProbeResult(await invoke<number>('probe_tcp443', { timeoutMs }));
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

    // engine_uri_detect returns `{"hits":[{Scheme,URI,Preview}]}` —
    // core/abi/share.go:307 marshals a []share.ClipboardHit, and
    // ClipboardHit carries no json tags, so the keys are Go field names.
    // This used to be parsed as `{kind, payload}`, keys the engine has
    // never emitted, so `kind` was always '' and the paste box reported
    // "nothing recognised" for every valid URI a user pasted.
    async uriDetect(text: string): Promise<UriDetectResult> {
        const raw = await invoke<string>('uri_detect', { text });
        try {
            const parsed = JSON.parse(raw) as {
                hits?: Array<{ Scheme?: string; URI?: string; Preview?: string }>;
            };
            return {
                hits: (parsed.hits ?? []).map((h) => ({
                    scheme: h.Scheme ?? '',
                    uri: h.URI ?? '',
                    preview: h.Preview ?? '',
                })),
                raw,
            };
        } catch {
            return { hits: [], raw };
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

    // ---- D-2 Connections page (M1: derive client-side) -------------
    //
    // Until the engine grows a dedicated `list_publishers` aggregator
    // (deferred to M5 alongside FRP-11 cell labels), the tree is built
    // from the same data the old Routes + Sources pages already
    // consume. No new engine commands; ABI stays frozen.

    private cellLabelCache = new Map<string, string>();

    async listPublishers(): Promise<PublisherTreeRow[]> {
        const [routes, subs, skipped] = await Promise.all([
            this.availableRoutes(),
            this.subscriptionList(),
            this.skippedFamilies(),
        ]);
        return buildPublisherTree(routes, subs, skipped, (k) =>
            this.cellLabelCache.get(k) ?? '',
        );
    }

    // Real data, from the real producer.
    //
    // This used to invoke a `skipped_families` Tauri command that DOES
    // NOT EXIST (there is no such #[tauri::command] anywhere in
    // src-tauri), so every call threw and returned []. That silently
    // meant: no family ever showed a cooled badge, and the burn-pressure
    // detector below was fed an empty list forever.
    //
    // The path manager's snapshot has been in the diagnostics blob the
    // whole time — core/abi/abi.go:603 emits `skipped_families` from
    // `c.pm.SkippedFamilies()`. Read it there.
    //
    // Returns null (not []) when the blob carries no `skipped_families`
    // key at all, which is the difference between "the engine says no
    // family is cooled" and "the engine did not answer".
    async skippedFamilies(): Promise<SkippedFamilyRow[]> {
        return (await this.rawSkippedFamilies()) ?? [];
    }

    private async rawSkippedFamilies(): Promise<SkippedFamilyRow[] | null> {
        try {
            const d = await bridgeDiagnostics();
            if (!Array.isArray(d.skipped_families)) return null;
            return d.skipped_families.map((p) => ({
                family: p.family,
                // pathmanager.SkippedFamily omits ladder_step when 0.
                ladderStep: p.ladder_step ?? 0,
                // Go marshals time.Time as RFC3339, not epoch ms.
                untilUnixMs: p.until ? Date.parse(p.until) || undefined : undefined,
                reasonTag: p.reason,
            }));
        } catch {
            return null;
        }
    }

    // Feeds the detector null when the engine did not answer, so the
    // verdict comes back `evaluated:false` rather than a confident
    // "no burn pressure" derived from an empty list nobody produced.
    async burnpressureVerdict(): Promise<BurnpressureVerdict> {
        return deriveBurnpressureVerdict(await this.rawSkippedFamilies());
    }

    async cellLabelGet(cellIdFpHex: string): Promise<string> {
        // M5 swaps this for the engine LabelStore call. In M1 we keep
        // labels in memory so the UI plumbing is testable and the
        // Connections page render stays deterministic.
        return this.cellLabelCache.get(cellIdFpHex) ?? '';
    }

    async cellLabelSet(cellIdFpHex: string, label: string): Promise<void> {
        if (label) this.cellLabelCache.set(cellIdFpHex, label);
        else this.cellLabelCache.delete(cellIdFpHex);
    }
}
