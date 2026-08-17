// D-2.1 functional contract — TypeScript reference shape.
// This is the cross-platform shape that the UI binds to. The Tauri
// backend (`client-ui/src/backends/tauri.ts`) and the harness backend
// (`client-ui/src/backends/harness.ts`) MUST match these field names
// and types. The UI never reaches into raw engine JSON.

export type ConnState  = 'disconnected' | 'connecting' | 'connected' | 'error';
export type ConnMode   = 'lifeline' | 'lifeline-strict' | 'normal' | 'bulk';
export type TrustClass = 'trusted' | 'pinned' | 'lan' | 'unknown';
export type Severity   = 'ok' | 'warn' | 'bad';

export interface RouteDisplayRow {
  /** Engine route_id (opaque). */
  routeId: string;
  /** Engine publisher_id (fingerprint hex) — the id delete/forget use. */
  publisherId: string;
  /** Localizable: "Pars Relays". */
  publisherName: string;
  /** Localizable: "Rescue 03". */
  routeNickname: string;
  trustClass: TrustClass;
  /** Engine family token (e.g. "wg-pars"). */
  family: string;
  inCooldown: boolean;
  cooldownUntilUnixMs?: number;
  budgetExhausted: boolean;
  /** 0..100, computed from engine route_health over the last hour.
   *  Only meaningful when `proven` is true; otherwise it is a placeholder
   *  (the engine caps unproven routes at 50) and the UI must show
   *  "not tested yet" rather than the number. */
  healthPct?: number;
  /** True once the route has recorded at least one success. Until then
   *  `healthPct` is a placeholder — render an untested state, not a score. */
  proven?: boolean;
  /** Subscription display name that produced this route, when known.
   *  When absent the route was pinned manually via Add Route. */
  sourceName?: string;
}

export interface ConnectionSummary {
  state: ConnState;
  mode: ConnMode;
  /** Set when state transitions to 'connected'; UI renders "Connected · 02:14:38". */
  connectedSinceUnixMs?: number;
  activeRoute?: RouteDisplayRow;
  /** Pre-rendered "On Wi-Fi" / "On Cellular" / etc — derived from current_network_id. */
  networkLabel?: string;
  /** From pointer_rotation_status. */
  pointerValidDays?: number;
  /** Pre-rendered fallback used when individual fragments aren't enough. */
  netStatusLine?: string;
}

export interface SkippedRouteEntry {
  route: RouteDisplayRow;
  /** Localized reason (e.g. "rate-limited", "recent failure", "last-resort tier"). */
  reason: string;
  /** Engine reason token used for i18n key resolution. */
  reasonToken?: string;
}

export interface WhyThisRouteSummary {
  active: RouteDisplayRow;
  /** Localized reason text. */
  reasonText: string;
  skipped: SkippedRouteEntry[];
  decisionId: string;
}

export interface PointerRotationSummary {
  lastRotatedUnixMs: number;
  validForDays: number;
  rotatedSuccessfully: boolean;
}

export interface RouteHealthDisplayRow {
  routeId: string;
  /** "Pars · Rescue 03" — ready to render. */
  label: string;
  pct: number;
  severity: Severity;
  /** True once the route has recorded a success. When false, `pct` is a
   *  placeholder and the UI should show "not tested yet". */
  proven?: boolean;
}

export interface ThroughputSnapshot {
  upBytesPerSec: number;
  downBytesPerSec: number;
  windowMs: number;
}

/** Full Status-page payload. */
export interface StatusPagePayload {
  connection: ConnectionSummary;
  why: WhyThisRouteSummary | null;
  pointer: PointerRotationSummary | null;
  routeHealth: RouteHealthDisplayRow[];
  /** Raw engine diagnostics for the "Diagnostics" accordion. */
  rawDiagnosticsJson: string;
}

// ---- Subscription / bundle ingestion shapes ---------------------

export interface PreviewedBundle {
  fingerprintHex: string;
  fingerprintEN: string;
  fingerprintFA: string;
  fingerprintVisualDataUri: string;
  publisherName: string;
  bundleId: string;
  specVersion: number;
  routeCount: number;
}

export interface SubscriptionRow {
  subscriptionId: string;
  publisherId: string;
  displayName: string;
  profileTitle: string;
  lastRefreshBucket: string;
  lastRefreshOutcome: string;
  lastGoodRefreshBucket: string;
  /** Routes currently produced by this subscription. Optional —
   *  filled in by backends that can compute it cheaply. */
  routeCount?: number;
}

export interface AddSubscriptionRequest {
  publisherFingerprint: string;
  url: string;
  displayName: string;
}

// ---- Connections page tree (FRP-14 / D-2 redesign) ---------------

/** Trust badge + provenance kind for a publisher row. */
export type SourceKind = 'sbpx' | 'sbp' | 'subscription' | 'pasted' | 'mixed';

/** One transport-family chip inside a cell. Counts come from routes,
 *  health is averaged across that family's routes, cooled is the
 *  count of those routes currently on the family cooldown ladder. */
export interface FamilyChip {
  family: string;            // engine family token, e.g. "vless-reality"
  count: number;
  healthPct: number;         // averaged across PROVEN family routes (0..100)
  proven: boolean;           // at least one route in the family has succeeded;
                             // when false, healthPct is a placeholder (render untested)
  cooledCount: number;       // how many of `count` are currently cooled
  experimental: boolean;     // from routestore.FamilyMaturity
  lastErrorTag?: string;     // engine token for "why cooled" (when cooled>0)
}

/** A cell groups routes belonging to one publisher under a user-
 *  renamable label (FRP-11). When the engine hasn't supplied a real
 *  cell fingerprint the UI synthesises a single "default" cell so the
 *  tree shape stays uniform. */
export interface CellRow {
  cellIdFpHex: string;       // hex fingerprint; "default" when synthesised
  label: string;             // FRP-11 label; empty string means "no label"
  families: FamilyChip[];
  routes: RouteDisplayRow[];
}

/** One top-level row in the new Connections page. */
export interface PublisherTreeRow {
  publisherId: string;       // fingerprint hex
  displayName: string;
  trustLevel: string;        // 'trusted' | 'pinned' | 'unknown' | ...
  sourceKind: SourceKind;
  revoked: boolean;
  routeCount: number;
  cells: CellRow[];
  /** When this publisher's routes came (in part) from one or more
   *  subscriptions, this carries the most-recent refresh meta. */
  subscription?: {
    subscriptionId: string;
    profileTitle: string;
    lastRefreshBucket: string;
    lastRefreshOutcome: string;
  };
}

/** One family cooled-down on the active network. Mirrors
 *  pathmanager.SkippedFamily diagnostics. */
export interface SkippedFamilyRow {
  family: string;
  ladderStep: number;       // 1..5; see family.FamilyCooldownStep
  untilUnixMs?: number;
  reasonTag?: string;       // engine token, e.g. "udp_unavailable"
}

/** burnpressure.Verdict projection — drives the auto-promotion banner. */
export interface BurnpressureVerdict {
  promote: boolean;
  distinctFamilies: number;
  highestLadderStep: number;
}

/** Trust prompt decision values (locked at FRP-1.5A). */
export type TrustDecision = 0 | 1 | 2;

/** Diagnostics blob — a narrow projection over the raw engine JSON
 *  used by Status & Diagnostics panels. */
export interface DiagnosticsBlob {
  version: string;
  mode: string;
  posture: string;
  /** @deprecated Removed from ABI per Phase-3-Soak decision #13. Read `posture` instead. */
  state?: string;
  why?: string;
  routeCount: number;
  bucket: string;
  currentNetworkId?: string;
  secretsUnlocked?: boolean;
  storageProfile?: string;
  sessionAllowsBulkCapable?: boolean;
}

/** Engine + GUI version pair. Used by the boot probe. */
export interface VersionInfo {
  engineVersion: string;
  guiVersion: string;
}

// ---- v0.2.x extras --------------------------------------------------

export type LifecycleToken =
  | 'will_sleep'
  | 'did_wake'
  | 'memory_pressure_warning';

export interface ProbeResult {
  ok: boolean;
  /** Engine return value (positive = latency ms, 0 = ok, negative = error code). */
  raw: number;
  /** True when the engine reported the probe isn't implemented yet
   *  (raw === -1000). The UI shows "unavailable" rather than a fake result. */
  unavailable?: boolean;
}

export interface SchedulerStatus {
  json: string;
}

export interface StatsRedacted {
  json: string;
}

export interface BootstrapStatus {
  json: string;
}

export interface UriDetectResult {
  kind: string;
  payload: string;
  raw: string;
}

export interface UriImportResult {
  fingerprintHex?: string;
  bundleId?: string;
  error?: string;
  raw: string;
}

export interface RedistributeResult {
  envelope?: string;
  error?: string;
  raw: string;
}

export interface WasmModule {
  slug: string;
  sha256Prefix: string;
  loadedAt: string;
}

export type UnlockResult = 'unlocked' | 'not_required' | 'wrong_pin';

/** Adapter interface — every platform implements this. */
export interface D2Contract {
  // ---- read-only summaries
  connectionSummary(): Promise<ConnectionSummary>;
  whyThisRoute(): Promise<WhyThisRouteSummary | null>;
  pointerRotation(): Promise<PointerRotationSummary | null>;
  routeHealth(): Promise<RouteHealthDisplayRow[]>;
  availableRoutes(): Promise<RouteDisplayRow[]>;
  routeSummary(routeId: string): Promise<RouteDisplayRow | null>;
  throughputSnapshot(): Promise<ThroughputSnapshot>;
  statusPagePayload(): Promise<StatusPagePayload>;
  diagnostics(): Promise<DiagnosticsBlob>;
  schedulerStatus(): Promise<SchedulerStatus>;
  statsRedacted(): Promise<StatsRedacted>;

  // ---- engine/process
  versionInfo(): Promise<VersionInfo>;
  heartbeatTick(): Promise<boolean>;
  lifecycleEvent(token: LifecycleToken): Promise<void>;

  // ---- connection actions
  connect(routeId: string): Promise<void>;
  disconnect(): Promise<void>;
  setMode(mode: ConnMode): Promise<void>;
  panicWipe(): Promise<void>;
  exportDiagnostics(): Promise<string>;
  applyCooldown(routeId: string, durationMs: number, reason: string): Promise<void>;
  redistributeRoute(routeId: string, recipientFp?: string): Promise<RedistributeResult>;
  setRouteBudget(routeId: string, budgetTag: string): Promise<string>;

  // ---- network probes
  probeUdp(timeoutMs: number): Promise<ProbeResult>;
  probeDns(timeoutMs: number): Promise<ProbeResult>;
  probeTcp443(timeoutMs: number): Promise<ProbeResult>;
  networkChanged(kind: string, carrier: string, ssid: string): Promise<string>;

  // ---- secrets / posture
  unlockSecrets(pin: string): Promise<UnlockResult>;
  setAllowBulkCapable(allow: boolean): Promise<void>;

  // ---- bootstrap
  bootstrapInstallSeeds(): Promise<string>;
  bootstrapRefresh(timeoutMs: number): Promise<string>;
  bootstrapStatus(): Promise<BootstrapStatus>;

  // ---- advanced toggles
  setRendezvousPriority(order: string[]): Promise<void>;
  setPushRendezvousEnabled(enabled: boolean): Promise<void>;
  setAutoPromotion(enabled: boolean): Promise<void>;
  setMasqueSubmodeOverride(submode: string): Promise<void>;
  setExperimentalFamiliesEnabled(enabled: boolean): Promise<void>;

  // ---- wasm intro
  loadedWasmModules(): Promise<string[]>;
  wasmKillSwitchPubkey(): Promise<string>;

  // ---- subscriptions / sources
  subscriptionList(): Promise<SubscriptionRow[]>;
  subscriptionAdd(req: AddSubscriptionRequest): Promise<string>;
  subscriptionRemove(subscriptionId: string): Promise<void>;
  /** Hard-delete one imported route from the device store. */
  routeDelete(routeId: string): Promise<void>;
  /** Hard-delete a publisher and all its routes; resolves to the count removed. */
  publisherDelete(publisherId: string): Promise<number>;
  subscriptionRefresh(subscriptionId: string, timeoutMs: number): Promise<string>;
  revocationRefreshAll(timeoutMs: number): Promise<string>;

  // ---- Connections page tree (D-2 redesign, FRP-14 follow-up)
  /** Publisher-rooted tree the new Network page renders. M1 implementations
   *  derive this client-side from availableRoutes + subscriptionList; later
   *  milestones may back it with a dedicated engine aggregator. */
  listPublishers(): Promise<PublisherTreeRow[]>;
  /** Families currently on the cooldown ladder for the active network.
   *  M1 may return an empty list when the engine doesn't expose it yet. */
  skippedFamilies(): Promise<SkippedFamilyRow[]>;
  /** Auto-promotion verdict from burnpressure. M1 returns a deterministic
   *  no-promote stub when the engine ABI isn't wired yet. */
  burnpressureVerdict(): Promise<BurnpressureVerdict>;
  /** Read a FRP-11 cell trust label. Returns empty string when unset.
   *  M1 stubs this in memory; M5 plumbs it to the engine LabelStore. */
  cellLabelGet(cellIdFpHex: string): Promise<string>;
  cellLabelSet(cellIdFpHex: string, label: string): Promise<void>;

  // ---- bundle / publisher trust flow
  previewBundle(path: string): Promise<PreviewedBundle>;
  importSbp(path: string): Promise<string>;
  resolveTrustPrompt(fingerprintHex: string, decision: TrustDecision): Promise<string>;
  uriDetect(text: string): Promise<UriDetectResult>;
  uriImport(rawUri: string): Promise<UriImportResult>;
}
