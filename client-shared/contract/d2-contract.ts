// D-2.1 functional contract — TypeScript reference shape.
// This is the cross-platform shape that the UI binds to. The Tauri
// backend (`client-ui/src/backends/tauri.ts`) and the harness backend
// (`client-ui/src/backends/harness.ts`) MUST match these field names
// and types. The UI never reaches into raw engine JSON.
//
// PROVENANCE: nothing imports this file — the shape the shipped UI
// actually compiles against is `client-ui/src/contract/D2Contract.ts`,
// which has since grown the whole D-2 Connections-page tree (publisher
// rows, family chips, cooled families) that is absent here. Treat this
// as a documentary mirror for a *second* platform implementer, and
// read the client-ui copy when the two disagree. The measured/unmeasured
// rule below is kept in sync deliberately: it is the one part of the
// contract where getting it wrong makes the client state a falsehood.
//
// THE MEASURED/UNMEASURED RULE. A field describing something the engine
// OBSERVES is optional (or nullable), and its absence means "not
// measured yet" — never "measured zero". Renderers must branch on
// presence, not on truthiness. A non-optional number here is a promise
// that some Go code writes it; do not add one without a writer.

export type ConnState  = 'disconnected' | 'connecting' | 'connected' | 'error';
export type ConnMode   = 'lifeline' | 'lifeline-strict' | 'normal' | 'bulk';
export type TrustClass = 'trusted' | 'pinned' | 'lan' | 'unknown';
export type Severity   = 'ok' | 'warn' | 'bad';

export interface RouteDisplayRow {
  /** Engine route_id (opaque). */
  routeId: string;
  /** Localizable: "Pars Relays". */
  publisherName: string;
  /** Localizable: "Rescue 03". */
  routeNickname: string;
  trustClass: TrustClass;
  /** Engine family token (e.g. "wg-pars"). */
  family: string;
  /** MEASURED. `undefined` = the path manager has not attempted this
   *  route this session, so nothing is known either way. */
  inCooldown?: boolean;
  cooldownUntilUnixMs?: number;
  /** MEASURED. `undefined` = no budget accounting has run. */
  budgetExhausted?: boolean;
  /** MEASURED, 0..100, from engine route_health over the last hour.
   *  `undefined` = no outcome has ever been recorded for this route.
   *  Render "not measured yet"; do NOT substitute 0, which reads as a
   *  measured failure. */
  healthPct?: number;
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
  /** Per-route rejections from the selector. `null` means THE
   *  COMPARISON NEVER RAN — not "nothing was skipped". An empty array
   *  is a positive claim that the engine saw the full route set and
   *  rejected none of it, which no backend may make until it actually
   *  feeds the selector every route. */
  skipped: SkippedRouteEntry[] | null;
  decisionId: string;
}

/** Projection of bootstrap.PointerRotationStatus.
 *
 *  There is deliberately no `rotatedSuccessfully` and no
 *  `lastRotatedUnixMs`: core/bootstrap/pointer_rotation.go has never
 *  emitted either, and defaulting them (`ok ?? true`, `?? 0`) turned
 *  two absent fields into a banner that read "Pointers rotated
 *  successfully" on a device that had never rotated anything. Every
 *  field below maps 1:1 onto a key the Go struct marshals. */
export interface PointerRotationSummary {
  /** True when a rotated pointer set exists in the secret store. */
  havePersisted: boolean;
  primarySource?: PointerSource;
  fallbackSource?: PointerSource;
  /** RFC3339 validity horizon of the pointer set that will be used. */
  primaryValidUntil?: string;
  fallbackValidUntil?: string;
  /** Derived from `primaryValidUntil`. `undefined` when there is no
   *  horizon to derive from; negative when already expired. Never
   *  0-as-unknown: 0 legitimately means "expires today". */
  validForDays?: number;
}

/** Which pointer set the engine will use on next boot. */
export type PointerSource = 'embedded' | 'persisted';

export interface RouteHealthDisplayRow {
  routeId: string;
  /** "Pars · Rescue 03" — ready to render. */
  label: string;
  /** MEASURED, 0..100. `undefined` = never measured; render the
   *  "not measured yet" state instead of a bar. */
  pct?: number;
  /** Present only when `pct` is. */
  severity?: Severity;
}

export interface PublisherHandoffSummary {
  publisherFingerprintHex: string;
  fingerprintEN: string[];
  fingerprintFA: string[];
  visualDataUri: string;
}

export interface TrayState {
  state: ConnState;
  routeLabel: string;
  /** Nullable for the same reason as ThroughputSnapshot below. */
  upBytesPerSec: number | null;
  downBytesPerSec: number | null;
  modeLabel: string;
  connectedSinceUnixMs?: number;
}

export interface ThroughputSnapshot {
  /**
   * Bytes per second, or `null` when nobody is counting. Null is NOT
   * zero: zero means the engine counted and nothing moved. Today every
   * shipped build reports null (engine.HasByteAccounting is false on
   * both the stub and the sing-box driver, whose platform counters are
   * declared but never written), so a renderer that treats these as
   * plain numbers prints a permanent "0 B/s".
   */
  upBytesPerSec: number | null;
  downBytesPerSec: number | null;
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

/** Trust prompt decision values (locked at FRP-1.5A). */
export type TrustDecision = 0 | 1 | 2;

/** Diagnostics blob — a narrow projection over the raw engine JSON
 *  used by Status & Diagnostics panels. */
export interface DiagnosticsBlob {
  version: string;
  mode: string;
  posture: string;
  state: string;
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

/** One recognised route URI found in pasted text. Mirrors
 *  core/share.ClipboardHit, which marshals with Go field names (no
 *  json tags): {"Scheme","URI","Preview"}. */
export interface UriDetectHit {
  scheme: string;
  uri: string;
  /** Userinfo-redacted preview — safe to display. */
  preview: string;
}

/** Result of engine_uri_detect. The engine returns `{"hits":[…]}`
 *  (core/abi/share.go). This used to declare `{kind, payload}`, which
 *  the engine has never emitted, so the paste box reported "nothing
 *  recognised" for every valid URI a user pasted. */
export interface UriDetectResult {
  hits: UriDetectHit[];
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
  subscriptionRefresh(subscriptionId: string, timeoutMs: number): Promise<string>;
  revocationRefreshAll(timeoutMs: number): Promise<string>;

  // ---- bundle / publisher trust flow
  previewBundle(path: string): Promise<PreviewedBundle>;
  importSbp(path: string): Promise<string>;
  resolveTrustPrompt(fingerprintHex: string, decision: TrustDecision): Promise<string>;
  uriDetect(text: string): Promise<UriDetectResult>;
  uriImport(rawUri: string): Promise<UriImportResult>;
}
