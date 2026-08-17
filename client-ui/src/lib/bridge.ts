// bridge.ts — typed wrappers around the Tauri command surface.
// Each function corresponds to a #[tauri::command] in src-tauri/src/main.rs
// which in turn delegates to daal-desktop-core::commands.

import { invoke } from '@tauri-apps/api/core';

export interface VersionInfo {
    engine_version: string;
    gui_version: string;
}

export async function versionInfo(): Promise<VersionInfo> {
    return invoke<VersionInfo>('version_info');
}

export interface PreviewedBundle {
    fingerprint_hex: string;
    fingerprint_en: string;
    fingerprint_fa: string;
    fingerprint_visual_data_uri: string;
    publisher_name: string;
    bundle_id: string;
    spec_version: number;
    route_count: number;
}

export async function previewBundle(path: string): Promise<PreviewedBundle> {
    return invoke<PreviewedBundle>('preview_bundle', { path });
}

export async function importSbp(path: string): Promise<string> {
    return invoke<string>('import_sbp', { path });
}

export async function resolveTrustPrompt(
    fingerprint: string,
    decision: 0 | 1 | 2,
): Promise<string> {
    return invoke<string>('resolve_trust_prompt', { fingerprint, decision });
}

// Phase 45 — On Android, Connect goes through the daal-platform plugin
// so the VpnService consent dialog can fire and the in-process engine
// receives the TUN fd before set_route is called. The plugin's
// vpn_start command runs VpnService.prepare(), starts DaalVpnService,
// which calls engine_set_tun_fd(fd) and then engine_set_route(routeId)
// in the right order. Desktop falls through to the existing connect
// command, which calls engine_set_route directly because the
// daal-tun-helper has already delivered the fd at GUI startup.
function isAndroid(): boolean {
    if (typeof navigator === 'undefined') return false;
    // Tauri's Android WebView reports "Android" in the UA string; the
    // desktop wry shells (GTK / WebView2 / WKWebView) do not. This is
    // cheap and synchronous, which lets connect() stay a thin shim.
    return /Android/i.test(navigator.userAgent);
}

export async function connect(routeId: string): Promise<void> {
    if (isAndroid()) {
        await invoke<unknown>('plugin:daal-platform|vpn_start', {
            request: { routeId },
        });
        return;
    }
    return invoke<void>('connect', { routeId });
}

export async function disconnect(): Promise<void> {
    if (isAndroid()) {
        try {
            await invoke<unknown>('plugin:daal-platform|vpn_stop');
        } catch (_) {
            /* best-effort; fall through to engine_clear_route */
        }
    }
    return invoke<void>('disconnect');
}

export async function diagnosticsExplain(): Promise<unknown> {
    const body = await invoke<string>('diagnostics_explain');
    return JSON.parse(body);
}

export async function exportDiagnostics(): Promise<string> {
    return invoke<string>('export_diagnostics');
}

// Phase 2B + 2D: budget mode dial + typed diagnostics. The 2D mode
// `lifeline-strict` widens the set; the engine accepts it from
// 2D onward.
export type Mode = 'lifeline' | 'lifeline-strict' | 'normal' | 'bulk';

export async function setMode(mode: Mode): Promise<void> {
    return invoke<void>('set_mode', { mode });
}

export interface BudgetRow {
    route_id: string;
    budget_tag: string;
    hourly_cap_bytes: number;
    consumed_bytes: number;
    session_cap_bytes: number;
    session_consumed_bytes: number;
    modes_allowed: string[];
    exhausted: boolean;
}

export interface RouteHealthRow {
    route_id: string;
    in_cooldown: boolean;
    cooldown_reason?: string;
    cooldown_until?: string;
    budget_exhausted: boolean;
}

export interface SkippedFamilyRow {
    family: string;
    until?: string;
    ladder_step?: number;
    reason?: string;
}

export interface DiagnosticsBlob {
    version: string;
    mode: Mode | string;
    posture: string;
    // Phase-3-Soak removed `state` from the ABI diagnostics blob in favour of
    // `posture` (8-state FSM). Field kept as optional for backward-compat
    // with any older engine still emitting it; new code MUST read `posture`.
    state?: string;
    why?: string;
    route_count: number;
    bucket: string;
    budgets?: BudgetRow[];
    route_health?: RouteHealthRow[];
    skipped_families?: SkippedFamilyRow[];
    // Phase 2C: hashed network ID. Never the raw SSID/carrier.
    current_network_id?: string;
    // Phase 2D: PIN-vault state and lifeline-strict markers. The
    // `storage_profile` label is behavioural ("vault" =
    // PIN-encrypted on-disk identity, "keystore" = platform
    // keystore); it is intentionally NOT a user-class label.
    secrets_unlocked?: boolean;
    storage_profile?: 'vault' | 'keystore' | string;
    lifeline_strict_active_since?: string;
    session_allows_bulk_capable?: boolean;
}

// Phase 2D: PIN-vault unlock outcome.
export type UnlockOutcome = 'unlocked' | 'not_required' | 'wrong_pin';

export async function unlockSecrets(pin: string): Promise<UnlockOutcome> {
    return invoke<UnlockOutcome>('unlock_secrets', { pin });
}

// Phase 2D: lifeline-strict bulk-capable session opt-in.
export async function setAllowBulkCapable(allow: boolean): Promise<void> {
    return invoke<void>('set_allow_bulk_capable', { allow });
}

// Phase 2C: per-network memory.
export type NetworkKind = 'wifi' | 'cell' | 'eth' | 'unknown';

export interface NetworkChangedResult {
    network_id: string;
    mode: Mode | string;
    restored_routes: number;
    fresh: boolean;
}

export async function networkChanged(
    kind: NetworkKind,
    carrier: string,
    ssid: string,
): Promise<NetworkChangedResult> {
    const body = await invoke<string>('network_changed', { kind, carrier, ssid });
    return JSON.parse(body) as NetworkChangedResult;
}

export async function diagnostics(): Promise<DiagnosticsBlob> {
    const body = await invoke<string>('export_diagnostics');
    return JSON.parse(body) as DiagnosticsBlob;
}

export async function pointerRotationStatus(): Promise<unknown> {
    const body = await invoke<string>('pointer_rotation_status');
    return JSON.parse(body);
}

export interface AddSubscriptionRequest {
    publisher_fingerprint: string;
    url: string;
    display_name: string;
}

export async function subscriptionAdd(req: AddSubscriptionRequest): Promise<string> {
    return invoke<string>('subscription_add', { req });
}

export async function subscriptionRefresh(
    subscriptionId: string,
    timeoutMs: number,
): Promise<string> {
    return invoke<string>('subscription_refresh', { subscriptionId, timeoutMs });
}

/** Hard-delete one imported route from the device store. */
export async function routeDelete(routeId: string): Promise<void> {
    return invoke<void>('route_delete', { routeId });
}

/** Hard-delete a publisher and all its routes; resolves to the count removed. */
export async function publisherDelete(publisherId: string): Promise<number> {
    return invoke<number>('publisher_delete', { publisherId });
}

export async function subscriptionRemove(subscriptionId: string): Promise<void> {
    return invoke<void>('subscription_remove', { subscriptionId });
}

export interface SubscriptionRow {
    subscription_id: string;
    publisher_id: string;
    display_name: string;
    profile_title: string;
    last_refresh_bucket: string;
    last_refresh_outcome: string;
    last_good_refresh_bucket: string;
}

export async function subscriptionList(): Promise<SubscriptionRow[]> {
    const body = await invoke<string>('subscription_list');
    const parsed = JSON.parse(body) as { subscriptions?: SubscriptionRow[] };
    return parsed.subscriptions ?? [];
}

export async function startSidecar(): Promise<void> {
    return invoke<void>('start_sidecar');
}

export async function stopSidecar(): Promise<void> {
    return invoke<void>('stop_sidecar');
}

export async function heartbeatTick(): Promise<boolean> {
    return invoke<boolean>('heartbeat_tick');
}

// ---- FRP-6: Explanation struct (locked at FRP-3 selection-v1) -----

export interface PickedCandidate {
    route_id: string;
    family: string;
    exposure_mode: string;
    family_class: string;
    probing_risk_class: string;
}

export interface ShortlistEntry {
    route_id: string;
    position: number;
    started_at_ms: number;
    outcome: string;
}

export interface FailureRecord {
    route_id: string;
    classification: string;
    tag?: string;
}

export interface CooldownEntry {
    tag: string;
    expires_at_unix: number;
    reason: string;
}

export interface MemoryHint {
    signature: string;
    last_outcome: string;
    last_seen_unix: number;
}

/**
 * Explanation mirrors `core/internal/selection/explain.go` field-for-
 * field. The 7 deterministic goldens at
 * `specs/test-vectors/explanation/` are the cross-language reference
 * fixtures the TS renderer (and the Kotlin one) bind against.
 */
export interface Explanation {
    pick: PickedCandidate;
    shortlist: ShortlistEntry[];
    failures: FailureRecord[];
    active_cooldowns: CooldownEntry[];
    network_signals: string[];
    memory_hint?: MemoryHint;
    reason: string;
    decision_id: string;
    phase: string;
}

/**
 * Parse an FRP-3 diagnostics blob into the locked Explanation shape.
 * Returns `null` when no `pick` field is present (legacy FRP-1.5A
 * shape) so callers can fall back gracefully.
 */
export function parseExplanation(json: unknown): Explanation | null {
    if (!json || typeof json !== 'object') return null;
    const obj = json as Record<string, unknown>;
    if (!obj.pick) return null;
    return obj as unknown as Explanation;
}

// ---- FRP-6: recipient surface --------------------------------------

export interface RecipientSessionStatus {
    session_id: string;
    received: number;
    total_frames: number;
    complete: boolean;
    verdict?: unknown;
}

// ---------------------------------------------------------------------
// D-2.1 — display-summary surface
// ---------------------------------------------------------------------

export interface RouteSummaryRow {
    route_id: string;
    publisher_name: string;
    publisher_fp_en: string;
    route_nickname: string;
    trust_class: 'trusted' | 'pinned' | 'lan' | 'unknown';
    health_pct: number;
    in_cooldown: boolean;
    last_success_bucket: string;
    last_failure_bucket: string;
    consecutive_failures: number;
    expires_bucket: string;
}

/** Returns a display projection for a single route. JSON returned
 *  by the engine is parsed into a typed object here. */
export async function routeSummary(routeId: string): Promise<RouteSummaryRow> {
    const json = await invoke<string>('route_summary', { routeId });
    return JSON.parse(json) as RouteSummaryRow;
}

/** Returns `{routes:[...]}` ordered by health desc; revoked / cooldown
 *  rows are excluded. */
export async function availableRoutes(): Promise<{ routes: RouteSummaryRow[] }> {
    const json = await invoke<string>('available_routes');
    return JSON.parse(json) as { routes: RouteSummaryRow[] };
}

/** Returns `{up_bps,down_bps,window_ms}`. Reading resets counters. */
export async function throughputSnapshot(): Promise<{
    up_bps: number;
    down_bps: number;
    window_ms: number;
}> {
    const json = await invoke<string>('throughput_snapshot');
    return JSON.parse(json) as { up_bps: number; down_bps: number; window_ms: number };
}

/** Shuts the engine down and removes the state directory.
 *  The GUI should reload to onboarding once this resolves. */
export async function panicWipe(): Promise<void> {
    return invoke<void>('panic_wipe');
}
