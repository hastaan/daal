// wizardCommands.ts — thin typed wrappers around the publisher-side
// Tauri commands registered in client-shell/tauri/src-tauri/src/lib.rs
// (40+ of them: the wizard_* surface plus the publisher_* custody
// surface).
//
// Lives in client-ui/src/publisher/ (NOT under contract/) because the
// publisher surface is a separate functional namespace from D2Contract.
//
// NO COMMAND HERE TAKES A PIN. Publisher secrets live under device
// custody — hardware-backed on Android via the AndroidKeyStore device
// wrap key, the OS keyring on desktop, a session passphrase only where
// neither exists. Rust reads them itself; nothing secret crosses this
// boundary in either direction.
//
// Likewise no command takes a helper IP. It is persisted server-side on
// the operator row (V012) and read there; see `helperIp.ts` for the
// detect-and-persist half.

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
// Type-only: the shape of a fountain frame belongs with the codec
// constants that consume it, and importing it as a type keeps this
// module free of the QR encoder at runtime.
import type { FountainFrame as QrFountainFrame } from '../qr/fountainStream';
import type {
    AddonOutcome,
    AddonProgress,
    AddonRemoveReport,
    AddonRow,
    CdnAccount,
    CdnBuildInput,
    CdnConnectInput,
    CdnPlainFallbackInput,
    CdnPosture,
    CdnPostureInput,
    CdnTokenCheck,
    CdnTokenInput,
    GoogleAccount,
    GoogleAccountAttachInput,
    GoogleCheck,
    GoogleCheckInput,
    GoogleOnInput,
    GoogleScript,
    StandbyAddInput,
    StandbyKey,
    StandbyKeyInput,
    StandbyPrice,
    StandbyPriceInput,
    StandbyPromoteInput,
    StandbyPromoteResult,
} from './addons/addonTypes';

export type { QrFountainFrame };

export interface RecipientSummary {
    id: number;
    name: string;
    display_name: string;
    address_str: string;
    fingerprint_hex: string;
    provisioned_at_unix: number;
    revoked_at_unix: number;
    /** FRP-14 Layer 3b.5: absolute path to the per-recipient
     *  `.sbpx` envelope, or empty string when not yet produced. */
    sbpx_path: string;
}

/**
 * Wave 3 Step 7 — the outcome of a PER-RECIPIENT credential rotation.
 * Mirrors `relay_rotation::RotateCredentialsSummary`.
 */
export interface RotateCredentialsSummary {
    recipient_id: number;
    /** Box-side name (`r1`, `r7`, …). */
    name: string;
    display_name: string;
    rotated_at_unix: number;
    /** Path to the freshly built `.sbpx`. Empty means the rebuild
     *  failed — NOT that nothing happened: the relay has already moved
     *  by then, so `warnings` explains and the roster row is updated so
     *  the existing Rebuild affordance can finish the job. */
    sbpx_path: string;
    /** Every inbound the relay says it actually rewrote. Empty means the
     *  relay would not say, and therefore that nothing confirmed the
     *  revocation reached all of them — the gap BUG-6 lived in. */
    updated_inbounds: string[];
    /** True if the relay ALSO replaced its own key material. Must be
     *  false. True means this stopped being a per-recipient action and
     *  became a fleet-wide one, so the result panel escalates instead of
     *  showing "one person needs a new file". */
    box_keys_rotated: boolean;
    /** Rendered verbatim. Never summarise these. */
    warnings: string[];
}

/**
 * Wave 3 Step 7 — the outcome of a RELAY-LEVEL TLS rotation.
 * Mirrors `relay_rotation::RotateTlsSummary`.
 */
export interface RotateTlsSummary {
    applied_at_unix: number;
    /** The cover host the relay advertises now — what the pack minter
     *  will use from here on. */
    cover_sni: string;
    previous_cover_sni: string;
    /** The rotation landed, but the relay did not ECHO the host it
     *  landed on, so `cover_sni` is what was requested rather than what
     *  was verified. The UI must carry that difference. */
    cover_sni_unknown: boolean;
    /** Whether the new cover host was written back to the stored relay
     *  record, so packs built from here on name the right host. */
    record_updated: boolean;
    /** How many people hold a file from this relay. NOT "how many are
     *  cut off" — that is `needs_file`. */
    live_recipients: number;
    /** Whether an everyone-pack built before this change is on disk. It
     *  still connects; it should be rebuilt before it is sent to anyone
     *  new. */
    shared_pack_stale: boolean;
    /** Who, if anyone, has to be sent a new file. The result panel
     *  leads with this. A disguise change costs ONE route (the only one
     *  that carries the cover host), and that route heals by itself on
     *  phones whose file carries refresh addresses — so "everyone" is
     *  true in exactly one case, and the app says which case this is. */
    needs_file: RotateTlsNeedsFile;
    /** The relay's file was signed again from its new identity. */
    pack_resigned: boolean;
    /** The refresh note naming the newly signed file reached enough
     *  mirrors. */
    refresh_note_published: boolean;
    /** Where the newly signed file is — for the one step that stays the
     *  operator's: putting it at the download address. */
    signed_pack_path: string;
    warnings: string[];
}

/** Mirrors `relay_rotation::NeedsFile`. */
export type RotateTlsNeedsFile =
    | 'nobody'
    | 'nobody_heals_itself'
    | 'nobody_heals_itself_offline_meanwhile'
    | 'one_route_until_new_file'
    | 'everyone';

// ---- Stable error codes -------------------------------------------
//
// Every publisher command that can fail for a custody or helper-IP
// reason returns an error string that BEGINS with one of these tokens,
// followed by ": " and human-readable text. The prefix is a contract
// with the Rust side (daal-wizard/src/commands.rs), not log noise: it
// decides which recovery affordance the user is offered, so branch on
// it rather than pattern-matching the prose.

export type PublisherErrorCode =
    | 'E_CUSTODY_LOCKED'
    | 'E_CUSTODY_WRONG_PASS'
    | 'E_CUSTODY_BACKEND'
    | 'E_LEGACY_PIN_REQUIRED'
    | 'E_SECRET_MISSING'
    | 'E_HELPER_IP_MISSING'
    | 'E_HELPER_IP_STALE'
    | 'E_RELAY_TOO_OLD'
    | 'E_RELAY_KEYS_CHANGED'
    // Publisher-alone wave (D1-D5). See the contract in the wave notes.
    | 'E_SETUP_RUNNING'
    | 'E_SERVER_EXISTS'
    | 'E_NOT_SUPPORTED'
    | 'E_RELAY_UNREACHABLE'
    | 'E_FILE_MISSING'
    | 'E_DEPLOY_TOO_OLD'
    // Backup and restore wave. See `Backup` below.
    | 'E_BACKUP_NOT_A_BACKUP'
    | 'E_BACKUP_DAMAGED'
    | 'E_BACKUP_NEWER'
    | 'E_BACKUP_WORDS_INVALID'
    | 'E_BACKUP_WRONG_WORDS'
    | 'E_BACKUP_NO_WORDS'
    | 'E_BACKUP_WORDS_MISMATCH'
    | 'E_BACKUP_NOTHING'
    | 'E_BACKUP_SECRET_UNREADABLE'
    | 'E_BACKUP_SAVE_FAILED'
    | 'E_RESTORE_WOULD_REPLACE'
    | 'E_RESTORE_STATE_CHANGED'
    | 'E_RESTORE_UNFINISHED'
    | 'E_BACKUP_READ_FAILED'
    | 'E_RESTORE_FAILED'
    | 'E_HOSTING_KEY_REJECTED'
    | 'E_HOSTING_KEY_WRONG_ACCOUNT'
    // After a restore (PB-1 / PB-2).
    | 'E_RESTORE_UNANSWERED'
    | 'E_RESTORE_NOT_ASKED'
    | 'E_RESTORE_ALREADY_ANSWERED'
    | 'E_RELAY_USER_INVALID'
    | 'E_RELAY_USER_IN_LIST'
    // Optional add-ons. See `Addons` below.
    | 'E_NOT_BUILT'
    | null;

const PUBLISHER_ERROR_CODES: Exclude<PublisherErrorCode, null>[] = [
    'E_CUSTODY_LOCKED',
    'E_CUSTODY_WRONG_PASS',
    'E_CUSTODY_BACKEND',
    'E_LEGACY_PIN_REQUIRED',
    'E_SECRET_MISSING',
    'E_HELPER_IP_MISSING',
    'E_HELPER_IP_STALE',
    // The relay answered, but its management service predates the
    // operation — so NOTHING was changed. Distinct from every other
    // code here because it is not the user's device or network at
    // fault: the box binary is hash-pinned at provision time and only
    // a human re-release moves it. The UI must say that plainly rather
    // than showing a raw Go error, and must not offer a retry.
    'E_RELAY_TOO_OLD',
    // The relay stated a different REALITY key or TLS key than the one
    // the signed file commits to, without having been rebuilt — which
    // nothing legitimate does. The app signed and published NOTHING.
    // Not retryable and not a network problem: the UI must say what it
    // means (the server, or the path to it, may be someone else's) and
    // that the way forward is a rebuild.
    'E_RELAY_KEYS_CHANGED',
    // A setup is still running for this relay (its journal is locked).
    // Not a failure: the answer is "wait, then look again".
    'E_SETUP_RUNNING',
    // Provision refused because a server for this relay already exists.
    // The tail after ": " starts with the server id. The wizard answers
    // it by asking `setupRecovery` what is there — never by retrying.
    'E_SERVER_EXISTS',
    // This hosting company cannot do this (finish in place on Vultr).
    'E_NOT_SUPPORTED',
    // The relay's management did not answer, so nothing was changed.
    'E_RELAY_UNREACHABLE',
    // The requested file does not exist on this phone.
    'E_FILE_MISSING',
    // The app's bundled setup helper is older than this screen and lacks
    // the verb. Not retryable: only an app update fixes it.
    'E_DEPLOY_TOO_OLD',
    // Backup and restore. Every one is a refusal that changed NOTHING,
    // except E_RESTORE_UNFINISHED (a restore committed and its last
    // steps must be finished before anything else runs).
    'E_BACKUP_NOT_A_BACKUP',
    'E_BACKUP_DAMAGED',
    'E_BACKUP_NEWER',
    'E_BACKUP_WORDS_INVALID',
    'E_BACKUP_WRONG_WORDS',
    'E_BACKUP_NO_WORDS',
    'E_BACKUP_WORDS_MISMATCH',
    'E_BACKUP_NOTHING',
    'E_BACKUP_SECRET_UNREADABLE',
    'E_BACKUP_SAVE_FAILED',
    'E_RESTORE_WOULD_REPLACE',
    'E_RESTORE_STATE_CHANGED',
    'E_RESTORE_UNFINISHED',
    // The file could not be opened or read (not a verdict on it).
    'E_BACKUP_READ_FAILED',
    // This phone's database could not take the restore; it rolled back.
    'E_RESTORE_FAILED',
    // A new hosting key was not accepted, or opens another account; the
    // key this phone had is still the one in use.
    'E_HOSTING_KEY_REJECTED',
    'E_HOSTING_KEY_WRONG_ACCOUNT',
    // After a restore. UNANSWERED: a per-person action on someone who
    // still waits for the "removed or keep" answer, refused, nothing
    // done. NOT_ASKED / ALREADY_ANSWERED: an answer for someone not
    // waiting, or the other answer a second time. RELAY_USER_*: a
    // relay-only removal for a name that is not a relay user, or that
    // IS in this phone's list (those go through their own row).
    'E_RESTORE_UNANSWERED',
    'E_RESTORE_NOT_ASKED',
    'E_RESTORE_ALREADY_ANSWERED',
    'E_RELAY_USER_INVALID',
    'E_RELAY_USER_IN_LIST',
    // An optional add-on (standby address, Cloudflare, Google channel)
    // whose code has not landed in this build. Nothing was changed; not
    // retryable. The card says "in development", never a raw error.
    'E_NOT_BUILT',
];

/** The server id carried by an `E_SERVER_EXISTS: <id> ...` rejection,
 *  or "" when the error is not one or names no id. */
export function serverIdFromExists(e: unknown): string {
    const msg =
        typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
    const m = /^E_SERVER_EXISTS:\s*(\S+)/.exec(msg);
    return m ? m[1] : '';
}

/**
 * Classify a thrown Tauri error by its stable prefix. Returns null for
 * anything unrecognised — callers must treat null as "show the raw
 * message", never as "no error".
 */
export function classifyPublisherError(e: unknown): PublisherErrorCode {
    const msg =
        typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
    for (const code of PUBLISHER_ERROR_CODES) {
        if (msg.startsWith(code)) return code;
    }
    return null;
}

// ---- Types mirrored from Rust ----

/** daal_wizard::report_key::TestRelayStatus */
export interface TestRelayStatus {
    operator_id: number;
    is_test_relay: boolean;
    has_key: boolean;
    /** People on this relay who are not removed. */
    people_on_relay: number;
    /** An everyone file was made for this relay. */
    everyone_file: boolean;
}

/** daal_wizard::report_key::TestRelaySet */
export interface TestRelaySet {
    operator_id: number;
    is_test_relay: boolean;
    key_made: boolean;
    /** People on this relay who hold a file made before and need a new one. */
    people_to_send: number;
    /** An everyone file exists and was left exactly as it was (it keeps
     *  working and does not offer the test). Never made again here. */
    everyone_file_kept: boolean;
    refresh_note_published: boolean;
}

/**
 * One relay, with enough identity to tell it apart from another on the
 * same provider and region — which the previous shape could not do.
 */
export interface OperatorSummary {
    id: number;
    /** Lifecycle, NOT health: "pre-provision" | "provisioned" | "decommissioned". */
    status: string;
    provider: string;
    region: string;
    server_type: string;
    publisher_pub_hex: string;
    created_at_unix: number;
    /** User's name for this relay; "" when unset. */
    nickname: string;
    /** "" until provisioned. */
    public_ip: string;
    public_ipv6: string;
    server_id: string;
    /** Publisher's own public IP; "" when never detected. */
    helper_ip: string;
    last_provisioned_at_unix: number;
    decommissioned_at_unix: number;
    has_signed_sbp: boolean;
    signed_sbp_at_unix: number;
    live_recipient_count: number;
    total_recipient_count: number;
    /** Wave 3 Step 9 (L3): provider-side id of the floating IP attached
     *  to this relay, or "" when it has none.
     *
     *  NOT a gate on the address swap. Before Step 9 nothing could mint
     *  a floating IP, so empty did mean "nothing to re-point" — and the
     *  relay screen disabled the rung on that basis. Step 9 made empty
     *  the SELF-SERVICE path (the CLI reserves one in the relay's own
     *  region), and since no relay in the field could ever have had an
     *  address, gating on this disabled the wave's headline capability
     *  on all of them. Use `can_reserve_address` for availability; use
     *  this to show which address the relay is on and to refuse a
     *  re-attach of the same one. */
    floating_ip_id: string;
    /** Whether this relay's provider adapter can reserve an address by
     *  itself (Hetzner can; adapters that only attach an operator-owned
     *  one cannot). This is what decides whether "leave it empty" is an
     *  offer the UI can make. */
    can_reserve_address: boolean;
    /** The toolbox profile slug this relay was built with. L6 rotates
     *  to a DIFFERENT one and the wizard refuses the rung when they
     *  match, so a screen without this can only offer a choice that
     *  contains a guaranteed error. */
    toolbox_profile: string;
    /** The transport families this relay actually serves — computed on
     *  the Rust side by the same rule the rebuild uses.
     *
     *  This is what an L4/L6 rebuild is handed, and the Go side keeps
     *  only the ones the TARGET profile also carries. Intersection only
     *  shrinks, so an L6 can drop a family and can never add one back;
     *  the confirm sheet projects the result from this array and
     *  refuses a profile change that would remove nothing. */
    served_families: string[];
    // ---- Publisher-alone wave. Optional on this side only because a
    // shell built before the wave does not send them; absent reads as
    // the safe answer (no token, nothing interrupted, nothing owed).
    /** A cloud token is stored for this relay (custody is not read). */
    has_cloud_token?: boolean;
    /** The row is pre-provision and a setup journal exists: a setup
     *  started and did not finish, so a server may be billing. */
    setup_interrupted?: boolean;
    /** Live people whose credentials were minted on a server that is no
     *  longer this relay's (D2). */
    people_needing_renewal?: number;
    /** People restored from a backup who wait for the "removed or keep"
     *  answer on this relay (PB-1). */
    people_needing_answer?: number;
    /** Addresses Daal reserved for this relay that a delete could not
     *  release; they still cost money (D4). */
    unreleased_addresses?: string[];
}

/**
 * Wave 3 Step 8 — one configured freshness mirror.
 *
 * Carries NO credential and never can: the R2 secret key and the
 * GitHub PAT live in device custody on the Rust side, and
 * `has_credential` is a probe result, not a copy.
 */
export interface FreshnessEndpointSummary {
    id: number;
    /** Provider label: "r2" | "ghpages". The unit of independence. */
    kind: string;
    public_url: string;
    /** "bucket/key" or "owner/repo@branch" — enough to tell two apart. */
    target: string;
    has_credential: boolean;
    /** 0 = never published. Render as "never", never as "fine". */
    last_publish_at_unix: number;
    /** The ONLY field that may be used to claim a publish worked. */
    last_publish_ok: boolean;
    /** The provider's own words. Shown verbatim. */
    last_publish_detail: string;
    last_published_url: string;
}

/** Wave 3 Step 8 — the whole freshness panel state in one call. */
export interface FreshnessStatus {
    endpoints: FreshnessEndpointSummary[];
    /** DISTINCT providers, not endpoints. Two buckets at one provider
     *  fall over together, so this is the number the single-point-of-
     *  censorship warning is computed from. */
    distinct_providers: number;
    /** Floor below which packs get no freshness path at all. */
    min_mirrors: number;
    pack_url: string;
    /** The mirror set inside the pack recipients are holding RIGHT NOW.
     *  Empty means the files already handed out cannot learn about a
     *  rotation — which is true of every pack signed before this
     *  existed. Never inferred from `endpoints`. */
    mirrors_in_pack: string[];
    pack_signed_at_unix: number;
    /** The only refresh address is the Google update channel (owner
     *  decision D-3): accepted alone (min_mirrors is then 1), and the
     *  card says a Google suspension stops updates. */
    google_only?: boolean;
}

/** What the operator types to add one mirror. Credentials travel this
 *  way exactly once, inbound; nothing sends them back. */
export interface FreshnessEndpointInput {
    kind: 'r2' | 'ghpages';
    public_url: string;
    account_id?: string;
    bucket?: string;
    object_key?: string;
    access_key_id?: string;
    secret_access_key?: string;
    gh_owner?: string;
    gh_repo?: string;
    gh_path?: string;
    gh_branch?: string;
    gh_pat?: string;
}

/** One provider's outcome from a publish run. */
export interface PublishOutcome {
    endpoint_id: number;
    kind: string;
    url: string;
    ok: boolean;
    detail: string;
}

/**
 * The result of one publish run.
 *
 * `blocked_reason` is non-empty when the run could not even be
 * attempted; it is a stable token ("no_signed_pack" | "no_pack_url" |
 * "too_few_providers") so the UI can point at the field that fixes it.
 * When it is empty the CLI ran, and the per-provider truth is in
 * `results` — including the case where every one of them failed.
 */
export interface PublishReport {
    results: PublishOutcome[];
    succeeded: number;
    min_mirrors: number;
    sequence: number;
    not_after: string;
    blocked_reason: string;
}

export interface OperatorState {
    id: number;
    status: string;
    provider: string;
    region: string;
    server_type: string;
    publisher_pub_hex: string;
    has_cloud_token: boolean;
    has_publisher_key: boolean;
    is_provisioned: boolean;
    has_signed_sbp: boolean;
    /**
     * Resume point, in Rust's stable 7-step vocabulary:
     * "provider" | "pricing" | "keys" | "provision" | "sign" |
     * "distribute" | "done". The 3-screen wizard maps these onto screen
     * indices in exactly one place.
     */
    wizard_step: string;
    created_at_unix: number;
    nickname: string;
    public_ip: string;
    helper_ip: string;
}

/** Honest report of where this device keeps publisher secrets. */
export interface PublisherCustodyStatus {
    level: 'hardware' | 'os_keystore' | 'session_passphrase';
    /** Whether custody claims to be usable. Not a signing gate. */
    unlocked: boolean;
    /**
     * TRUE only if a live write→read→erase probe succeeded. Gate every
     * publisher action on this, never on `unlocked`: both the Android
     * and the desktop providers report themselves ready unconditionally,
     * so a wholly broken keystore looks unlocked right up until the
     * first real operation fails.
     */
    ok: boolean;
    /** Non-empty when ok === false: the raw custody error. */
    error: string;
    /** A legacy PIN-sealed secret still exists with no custody copy. */
    legacy_pending: boolean;
    /** Which aliases await migration. Empty when !legacy_pending. */
    legacy_aliases: string[];
    /**
     * TRUE when a custody blob already exists on this device — i.e. a
     * session passphrase has been chosen here before.
     *
     * The passphrase sheet is both "create one" and "enter yours", and
     * the backend accepts *anything* on a first run because there is no
     * stored blob to be wrong about. Without this flag the UI shows
     * "enter your passphrase" to someone who has never set one, and
     * whatever they type — typo included — silently becomes the wrap
     * key for a signing key generated minutes later, with no escrow.
     */
    passphrase_set: boolean;
}

export interface CustodyMigrationReport {
    /** Moved, verified by read-back, legacy copy then erased. */
    migrated: string[];
    /** Already in custody; nothing to do. */
    skipped: string[];
    /** "alias: reason" — the legacy copy was left INTACT for these. */
    failed: string[];
    /**
     * TRUE iff every publisher signing key now reads from custody. The
     * migration gate must stay blocking while this is false: a signing
     * key that fails to migrate is unrecoverable, and the relay it
     * signs for can never gain or drop another recipient.
     */
    signing_keys_safe: boolean;
}

/** One distributable file belonging to a relay. */
export interface ArtifactInfo {
    kind: 'shared_sbp' | 'raw_sbp' | 'sbpx';
    path: string;
    /**
     * False means the file is missing, not that the row is irrelevant —
     * Rust returns missing artifacts deliberately so the UI can explain
     * the gap and offer a rebuild instead of hiding a row the user is
     * looking for.
     */
    exists: boolean;
    size_bytes: number;
    modified_at_unix: number;
    /** Only for kind === 'sbpx'. */
    recipient_id: number | null;
    /** Display name, falling back to the on-box name; "" otherwise. */
    recipient_label: string;
}

export interface Fingerprint {
    hex: string;
    en_words: string;
    fa_words: string;
}

export interface Pricing {
    monthly_usd: number;
    bandwidth_tib: number;
}

/** One resource `account-audit` found carrying Daal's ownership marks. */
export interface AuditedResourceRow {
    kind: string;
    id: string;
    name: string;
    verdict: string;
    reason: string;
    hint: string;
    reclaimable: boolean;
    /** Whether this resource costs money for as long as it exists.
     *
     *  Mirrors provider.AuditedResource.Billing. This used to be a
     *  `monthly_eur` the Go auditor never emits — always 0.00, and it
     *  displaced the one field the gone-panel exists to report. */
    billing: boolean;
}

export interface AccountAuditReport {
    provider: string;
    resources: AuditedResourceRow[];
    /** Whether the account's servers could be enumerated at all.
     *
     *  Carried, never dropped: a resource is an orphan because NO
     *  server stands behind it, so if the server list could not be read
     *  the claim cannot be made about anything. A UI that ignores this
     *  turns "could not look" into "nothing found". */
    server_list_complete: boolean;
    warnings: string[];
}

export interface ServerTypeOption {
    id: string;
    description: string;
    cpus: number;
    memory_gb: number;
    disk_gb: number;
    /** DESPITE THE NAME, this is the plan's price in `currency`, which
     *  is not always EUR. The field name is the frozen wire contract
     *  with `daal-deploy`; `currency` is the part that makes it true.
     *  Never render this behind a hard-coded symbol. */
    monthly_eur: number;
    hourly_eur: number;
    location: string;
    arch: string;
    /** "EUR" (Hetzner) or "USD" (Vultr). Optional because a
     *  `daal-deploy` older than Wave 6 does not send it; absent means
     *  EUR, which is what every build that predates the second provider
     *  could possibly have meant. */
    currency?: string;
}

export interface ExistingServer {
    id: string;
    name: string;
    status: string;
    server_type: string;
    region: string;
    public_ip: string;
    public_ipv6: string;
}

export interface SubkeyRow {
    subkey_id: number;
    operator_id: number;
    label: string;
    fingerprint_hex: string;
    valid_from_unix: number;
    valid_until_unix: number;
}

export interface SignedSbpRow {
    id: number;
    operator_id: number;
    fingerprint_hex: string;
    phase: string;
    active: boolean;
    created_unix: number;
}

export interface CdnFrontRow {
    front_id: number;
    operator_id: number;
    hostname: string;
    origin_ip: string;
    origin_ipv6: string;
    origin_path: string;
    public_path: string;
}

export interface RotationRecommendation {
    /** "L1".."L6". */
    level: string;
    /** "high" | "medium" | "low".
     *
     *  This was typed `number` and never was one: the Go side emits
     *  `rotation.Confidence`, a three-value string enum. Nothing read
     *  it, so the lie cost nothing — until a screen rendered it. */
    confidence: string;
    reason: string;
    /** The rule that fired, as a stable code from the Go side's closed
     *  vocabulary — `reason`'s machine-readable parallel.
     *
     *  `reason` is English prose built in Go and is the most decisive
     *  sentence the advice panel renders. Key this to say it in the
     *  operator's own language; fall back to `reason` when the catalog
     *  has no key, so a new rule degrades to English, never to
     *  silence. Optional because an older daal-deploy emits neither. */
    reason_code?: string;
    /** The machine-specific fragment some reason codes interpolate —
     *  the concrete blocker behind a refused address swap, or the
     *  inputs that matched no rung. Substituted for `{detail}`, and
     *  deliberately untranslated: provider notes and closed-vocabulary
     *  identifiers. */
    reason_detail?: string;
    /** The rung's wall-clock estimate AS THE RECOMMENDER COMPUTED IT.
     *
     *  Render this string; never look the figure up again from the
     *  level. The Go side deliberately overrides the optimistic column
     *  when the relay can only reach the same outcome by
     *  destroy-and-rebuild ("~3min (reprovision fallback: …)") or when
     *  the rung will refuse outright ("not available on this relay"). A
     *  UI-side table would quote 90 seconds for a 3-minute rebuild. */
    est_wallclock: string;
    /** Other rungs that would also address what was observed. Advice
     *  for the operator's own choice — never buttons: L4/L5/L6 destroy
     *  and rebuild the relay. */
    override?: string[];
    /** False means the recommender chose `level` from NOTHING and this
     *  is not a recommendation. Render the reason as a refusal. */
    grounded?: boolean;
    /** What the recommender saw — and what it could not see. */
    evidence?: RotationEvidence;
    /** Step 7: the concrete operation behind the named rung. Optional
     *  because an older daal-deploy emits no `action` at all.
     *
     *  `availability` is "unknown" on everything the wizard can produce
     *  today — the recommender is offline by design and nothing here
     *  probes the relay yet — so this must render as "not verified",
     *  never as a confident one-tap button. The rotation's own
     *  capability interlock is what refuses an old relay. */
    action?: RotationAction;
}

export interface RotationEvidence {
    /** "explanation" (a selector record) | "context" (typed by hand). */
    source: string;
    classifications: string[];
    signals: string[];
    cooldown_tags: string[];
    /** Present inputs that no rung addresses. */
    unrecognised: string[];
    /** Structurally unavailable inputs, each with the reason. This is
     *  the half a renderer must not drop: leaving it out turns
     *  "unmeasured" into "measured and fine". */
    absent: string[];
    /** One stable code per `absent` entry, same order and same length
     *  (pinned by TestAbsentCodesParallelAbsentProse on the Go side).
     *
     *  The panel keys these so a Farsi operator reads the absences in
     *  their own language. `absent` stays as the fallback for a code
     *  this catalog does not carry yet — a new absence must degrade to
     *  English, never to silence, because these sentences are what
     *  separate "measured and fine" from "never measured". */
    absent_codes?: string[];
}

export interface RotationAction {
    kind: string;
    cli_verb: string;
    /** "recipient" | "relay" | "server" */
    scope: string;
    in_place: boolean;
    needs_recipient_name: boolean;
    destroys_server: boolean;
    /** After this runs, every distributed file must be rebuilt and
     *  hand-delivered before anyone can connect. */
    invalidates_every_pack: boolean;
    /** "ready" | "unknown" | "unsupported" */
    availability: string;
    note?: string;
}

export interface ProgressEvent {
    step: string;
    message: string;
    ts?: string;
    extra?: Record<string, unknown>;
    // Legacy aliases used by fake/mock progress:
    phase?: string;
    detail?: string;
    pct?: number;
}

export interface FountainFrame {
    index: number;
    total_frames: number;
    frame_b64: string;
}

export interface BindResult {
    sbp_path: string;
    sbp_sha256?: string;
    relay_pack_id?: string;
    fingerprint_hex: string;
    fingerprint_en?: string;
    fingerprint_fa?: string;
    output_path?: string; // legacy mock alias
}

export interface RotateExecuteOutput {
    summary: string;
    new_active_id?: number;
    /** Non-fatal facts the operator must hear after a rotation that
     *  otherwise succeeded — chiefly an address that is still attached
     *  and still billing. The success sheet says the old address no
     *  longer serves; when the release leg could not make that true,
     *  it says so here instead of the UI quietly asserting it. */
    warnings?: string[];
    /** The address the relay moved OFF, when it keeps answering after
     *  the swap; absent when it was released and is genuinely gone.
     *
     *  Set on a relay's FIRST L3, which moves off the server's own
     *  primary address — a provider will not release that to anyone,
     *  and the release leg is gated on a prior floating IP existing, so
     *  nothing is attempted. Verified on hardware 2026-08-18: the
     *  primary and the new floating IP both answered TLS afterwards. */
    prior_address_still_serves?: string | null;
}

/**
 * What `Wizard.relayDestroy` actually accomplished, resource by
 * resource. Mirrors Rust `commands::DestroyReport`.
 *
 * "Deleted" is not one bit of information here: the server, the
 * ephemeral SSH key and the cloud firewall are three separate objects
 * in the provider account, each of which can survive a teardown on its
 * own. A surviving server keeps billing; a surviving SSH key breaks the
 * user's next provision in that region on a name collision. The UI has
 * to report which of them are actually gone rather than round a partial
 * sweep up to success.
 */
export interface DestroyReport {
    server_deleted: boolean;
    ssh_key_deleted: boolean;
    firewall_deleted: boolean;
    local_removed: boolean;
    /** Non-fatal provider errors. Details disclosure only — some carry a
     *  command line, which the main copy must never show. */
    warnings: string[];
    /** D4: every address Daal reserved for this relay and what became of
     *  it. Optional because an older shell does not send it. */
    addresses?: AddressOutcome[];
    /** D4: the server is gone but an address is still reserved and
     *  billing; the same `relayDestroy(op, true)` call is the retry. */
    retry_needed?: boolean;
    /** PA-3: the server id Daal had is gone, but the hosting account
     *  still has a Daal-labelled server with this relay's name and a
     *  different id. Daal did NOT delete it, and kept the relay. "" or
     *  absent when there is none. Details only. */
    other_server_id?: string;
    other_server_name?: string;
    /** V019: what became of each add-on (standby address, Cloudflare,
     *  Google channel). One with `keeps_relay` kept the relay, as an
     *  address that still bills does. Absent from an older shell. */
    addons?: AddonOutcome[];
}

export interface AddressOutcome {
    id: string;
    ip: string;
    released: boolean;
    code: 'released' | 'not_daal' | 'still_attached' | 'release_failed' | 'in_use';
}

/** PA-1: giving back one address left reserved on a live relay.
 *  Mirrors `wizard_release_address`. */
export interface ReleaseAddressResult {
    address: string;
    code: 'released' | 'in_use' | 'not_daal' | 'still_attached' | 'release_failed';
    /** The hosting company's own words on a failure. Details only. */
    error?: string;
    /** What the relay row still lists as costing money afterwards. */
    still_billing: string[];
}

// ---- Backup and restore (D1/D2) ---------------------------------------
//
// The backup format lives in Rust only. Nothing here sees a key or a
// token. The twelve recovery words DO cross this boundary twice: once
// out (shown once, `wordsNew`) and once in (typed, `open`/`restore`).
// They live in React state for one flow and are dropped on leaving;
// never logged, never in localStorage.

export type BackupBlocked =
    | ''
    | 'setup_running'
    | 'secret_unreadable'
    | 'custody_locked'
    | 'legacy_pending'
    | 'custody_backend';

export interface RelayLine {
    id: number;
    nickname: string;
    public_ip: string;
    status: string;
    provider: string;
    people: number;
    removed_people: number;
    has_hosting_key: boolean;
}

export interface BackupContents {
    relays: RelayLine[];
    people_total: number;
    files: number;
    includes_hosting_key: boolean;
    unfinished_setups: number;
}

export interface RestoreNotice {
    restored_at_unix: number;
    backup_made_at_unix: number;
    relays: RelayLine[];
    has_refresh_keys: boolean;
}

export interface BackupStatus {
    has_publisher_data: boolean;
    words_set: boolean;
    /** 0 = never. */
    last_backup_at_unix: number;
    stale: boolean;
    /** What a backup made now would hold. */
    contents: BackupContents;
    blocked: BackupBlocked;
    /** Details fold only. */
    blocked_detail: string;
    /** A restore committed but not finished. */
    restore_pending: boolean;
    /** Until dismissed. */
    restore_notice: RestoreNotice | null;
    /** New words were made and never confirmed: backups still use the
     *  old (confirmed) words. */
    words_pending?: boolean;
    /** New words were confirmed after the last backup: that file opens
     *  only with the old words (implies `stale`). */
    words_changed?: boolean;
    /** A backup handed to another app that the person has not yet said
     *  arrived; 0 = none. It is not the last backup until they do. */
    share_unconfirmed_at_unix?: number;
}

export interface MadeBackup {
    file_name: string;
    made_at_unix: number;
    contents: BackupContents;
    destination: 'downloads' | 'share';
    /** Downloads: recorded as the last backup. Share: waits for
     *  `Backup.confirmShared`. */
    confirmed?: boolean;
}

export interface ExistingData {
    relays: RelayLine[];
    people_total: number;
    digest: string;
}

export interface BackupInspect {
    existing: ExistingData | null;
}

export interface BackupPreview {
    made_at_unix: number;
    app_version: string;
    contents: BackupContents;
    replace: null | { this_phone: RelayLine[]; only_on_this_phone: RelayLine[]; digest: string };
}

export interface RestoreResult {
    contents: BackupContents;
    notice: RestoreNotice;
}

export const Backup = {
    /** Finishes a committed restore first. */
    status: () => invoke<BackupStatus>('publisher_backup_status'),
    /** Twelve new words; replaces any earlier unconfirmed ones. */
    wordsNew: () => invoke<{ words: string[] }>('publisher_backup_words_new'),
    /** At least three distinct positions (0-based) and what was typed. */
    wordsConfirm: (answers: { index: number; word: string }[]) =>
        invoke<unknown>('publisher_backup_words_confirm', { answers }),
    /** "Check my words": true when they are the stored words. */
    wordsCheck: (words: string) => invoke<boolean>('publisher_backup_words_check', { words }),
    make: (destination: 'downloads' | 'share', fileName?: string, chooserTitle?: string) =>
        invoke<MadeBackup>('publisher_backup_make', {
            destination,
            fileName: fileName ?? null,
            chooserTitle: chooserTitle ?? null,
        }),
    /** Did the file handed to another app arrive? Yes records it as the
     *  last backup; no forgets it. Resolves true when one was recorded. */
    confirmShared: (arrived: boolean) => invoke<boolean>('publisher_backup_confirm_shared', { arrived }),
    /** A new hosting key for these relays, tested with one read-only
     *  account call first; refused (and nothing stored) when the company
     *  does not accept it or it opens another account. */
    replaceHostingKey: (provider: string, token: string, operatorIds: number[]) =>
        invoke<number[]>('publisher_replace_hosting_key', { provider, token, operatorIds }),
    /** Header only, plus what this phone already has. */
    inspect: (path: string) => invoke<BackupInspect>('publisher_backup_inspect', { path }),
    /** Full check; writes nothing. */
    open: (path: string, words: string) =>
        invoke<BackupPreview>('publisher_backup_open', { path, words }),
    restore: (path: string, words: string, replaceDigest: string | null) =>
        invoke<RestoreResult>('publisher_backup_restore', { path, words, replaceDigest }),
    finishRestore: () => invoke<unknown>('publisher_backup_finish_restore'),
    dismissNotice: () => invoke<unknown>('publisher_backup_dismiss_notice'),
};

// ---- Publisher-alone wave: D1 interrupted setup + account check ----

export interface SetupRecovery {
    state: 'none' | 'running' | 'finished_unsaved' | 'server_running' | 'nothing_billing' | 'unknown';
    provider: string;
    server_origin: 'created' | 'yours' | '';
    /** true only for hetzner + created + server_running, or finished_unsaved */
    can_finish_here: boolean;
    server_id: string; // "" if unknown
    public_ip: string; // "" if unknown
    billing: 'yes' | 'no' | 'unknown';
    leftovers: {
        kind: 'server' | 'floating-ip' | 'ssh-key' | 'firewall';
        id: string;
        name: string;
        billing: boolean;
    }[];
    check_error: '' | 'no_token' | 'offline' | 'account_unreadable' | 'custody_locked' | 'failed';
    started_at_unix: number; // journal begin ts, 0 if none
    details: string[]; // raw, Details disclosure only
}

export interface ResourceRef {
    kind: 'server' | 'floating-ip' | 'ssh-key' | 'firewall';
    id: string;
}

export interface AccountItem extends ResourceRef {
    name: string;
    address: string;
    billing: boolean;
    verdict: 'in-use' | 'unclaimed' | 'orphan' | 'unproven';
    finding:
        | 'yours_in_use'
        | 'unfinished_setup'
        | 'not_on_this_phone'
        | 'second_server_for_relay'
        | 'leftover'
        | 'cannot_tell';
    belongs_to_relay_id: number | null;
    can_delete: boolean;
    /** The add-on this item is (setup_recovery::AccountItem.addon):
     *  'standby' for a relay's standby address, '' otherwise. */
    addon?: string;
    /** What the add-on bills each month, as read when it was rented;
     *  0 with an empty currency when unknown. */
    monthly_cost_cents?: number;
    cost_currency?: string;
}

/** One hosting company on this phone (`hosting_account.rs`). */
export interface HostingAccountState {
    /** A key Daal can use is here: the account's, or a live relay's. */
    connected: boolean;
    /** The account key itself is here (what Disconnect forgets). */
    account: boolean;
}

/** Per hosting company id ("hetzner", …). */
export type HostingAccountStatus = Record<string, HostingAccountState>;

export interface AccountCheckAccount {
    account_key: string;
    provider: string;
    relay_ids: number[];
    /** server list could be read; false ⇒ nothing deletable */
    complete: boolean;
    error_code: '' | 'offline' | 'token_rejected' | 'unsupported_provider' | 'custody_locked' | 'failed';
    items: AccountItem[];
    details: string[];
}

export interface AccountCheck {
    accounts: AccountCheckAccount[];
    checked_at_unix: number;
}

export type AccountCleanupCode =
    | 'deleted'
    | 'released'
    | 'kept_in_use'
    | 'kept_claimed'
    | 'kept_not_daal'
    | 'kept_unproven'
    | 'kept_list_unreadable'
    | 'kept_unsupported'
    | 'delete_failed'
    | 'already_gone';

export interface AccountCleanupReport {
    outcomes: (ResourceRef & { name: string; deleted: boolean; code: AccountCleanupCode })[];
    details: string[];
}

// ---- D2: renew everyone's files ----

export interface RenewItem {
    /** null = the everyone file */
    recipient_id: number | null;
    name: string;
    display_name: string;
    /** `needs_answer`: restored from a backup, the relay did not know
     *  them, and the person has not yet said whether they were removed
     *  (PB-1). Not created, no file. */
    status: 'done' | 'already_done' | 'failed' | 'not_attempted' | 'removed_from_server' | 'needs_answer';
    reason:
        | ''
        | 'relay_unreachable'
        | 'relay_full'
        | 'relay_too_old'
        | 'file_write_failed'
        | 'signing_failed'
        | 'restore_unanswered'
        | 'other';
    /** "" for the everyone file / failures */
    sbpx_path: string;
    /** raw, Details only */
    detail: string;
}

export interface RenewReport {
    operator_id: number;
    items: RenewItem[];
    everyone_file: RenewItem | null;
    all_done: boolean;
}

export interface RenewEvent {
    operator_id: number;
    index: number;
    total: number;
    recipient_id: number | null;
    display_name: string;
    status: 'working' | RenewItem['status'];
}

// ---- D3: health check ----

export type HealthWayState = 'answers' | 'no_answer' | 'wrong_server' | 'not_testable_here';

export interface RelayHealth {
    operator_id: number;
    checked_at_unix: number;
    from_cache: boolean;
    overall: 'working' | 'partly' | 'not_working' | 'unknown';
    server: 'running' | 'stopped' | 'starting' | 'missing' | 'not_checked' | 'error';
    management: 'answers' | 'no_answer' | 'refused' | 'too_old' | 'not_checked' | 'error';
    management_reason: '' | 'address_may_have_changed' | 'timeout' | 'refused';
    keys_match: boolean | null;
    people_missing: number | null;
    everyone_missing: boolean | null;
    /** People the relay lets in that this phone's list never had (added
     *  on another phone after the backup restored here). */
    people_unknown?: number | null;
    /** PB-2. Their relay names (`r7`, ...), from the same read as
     *  `people_unknown` and cached with it. The People list shows them
     *  from here, so the page never asks the relay a second time. */
    relay_only?: string[] | null;
    /** People restored from a backup whom the relay did not know, waiting
     *  for the "removed or keep" answer (PB-1). The shell already leaves
     *  them OUT of `people_missing`. Absent from a shell built before the
     *  wave. */
    people_needing_answer?: number;
    ways: { family: string; state: HealthWayState }[];
    details: string[];
}

// ---- After a restore (PB-1 / PB-2) ----

/** PB-1. People in this phone's list whom the relay no longer knows,
 *  on a relay restored from a backup and not yet settled. Each must be
 *  answered by name before anything re-creates them. `checked: false`
 *  with a `check_error` means the relay could not be asked: nothing is
 *  assumed either way (`people` is then empty). `checked: true` with no
 *  people: nothing to ask (never restored, or settled). */
export interface RestoreUnsettledPerson {
    recipient_id: number;
    /** The name the person gave them, else their relay name. */
    name: string;
    /** Their relay name (`r3`). Details only. */
    relay_user?: string;
}
export interface RestoreUnsettled {
    people: RestoreUnsettledPerson[];
    checked: boolean;
    check_error: string | null;
}

// ---- D5: which file a QR / paste carries ----

/** `'shared'` is the everyone file, `'raw'` the credential-free build
 *  artifact, `recipient:<id>` one person's own sealed file. */
export type PackArtifact = 'shared' | 'raw' | `recipient:${number}`;

export function recipientArtifact(recipient_id: number): PackArtifact {
    return `recipient:${recipient_id}`;
}

// ---- Commands (one wrapper per #[tauri::command]) ----

export const Wizard = {
    listOperators: () => invoke<OperatorSummary[]>('wizard_list_operators'),
    /** Absolute path of the canonical signed .sbp file for an operator. */
    getSbpPath: (operator_id: number) =>
        invoke<string>('wizard_get_sbp_path', { operatorId: operator_id }),
    /**
     * Copy an operator's signed .sbp into a cache dir under the
     * given user-friendly name and open the system share-sheet
     * (Android) / reveal in file manager (desktop). Returns the
     * staged file path. iOS is a TODO.
     *
     * Pass a per-relay name (the nickname, or `daal-relay-<id>`):
     * a constant here makes two relays overwrite each other's staged
     * file.
     */
    shareInvite: (operator_id: number, friendly_name: string) =>
        invoke<string>('share_invite', {
            operatorId: operator_id,
            friendlyName: friendly_name,
        }),
    /**
     * Mint the shared `r0` box user and rewrite the signed .sbp with
     * its working creds, producing the pack any phone can import and
     * connect.
     *
     * NOT the same action as `shareInvite`. This RE-KEYS the shared
     * user, so every shared pack already handed out stops working. Put
     * it behind a confirm that says so.
     */
    produceSharedSbp: (operator_id: number) =>
        invoke<{ sbp_path: string; server: string }>('wizard_produce_shared_sbp', {
            operatorId: operator_id,
        }),
    /** FRP-14 Layer 3b.5: open the share-sheet for a specific
     *  per-recipient `.sbpx` file produced by Add-recipient. */
    shareInviteSbpx: (sbpx_path: string, friendly_name: string) =>
        invoke<string>('share_invite_sbpx', {
            sbpxPath: sbpx_path,
            friendlyName: friendly_name,
        }),
    /** Save the operator's shared `.sbp` into the phone's Downloads.
     *  Resolves to the name it was STORED under (PB-3: Android may store
     *  "x (1).sbp"); a shell built before that resolves to nothing. */
    saveSharedSbpToDownloads: (operator_id: number, file_name: string) =>
        invoke<string | null>('save_shared_sbp_to_downloads', {
            operatorId: operator_id,
            fileName: file_name,
        }),
    /** Save a per-recipient `.sbpx` into the phone's Downloads.
     *  Resolves to the name it was stored under (see above). */
    saveSbpxToDownloads: (sbpx_path: string, file_name: string) =>
        invoke<string | null>('save_sbpx_to_downloads', {
            sbpxPath: sbpx_path,
            fileName: file_name,
        }),
    getOperatorState: (operator_id: number) =>
        invoke<OperatorState>('wizard_get_operator_state', { operatorId: operator_id }),
    cancelAndCleanup: (operator_id: number) =>
        invoke<void>('wizard_cancel_and_cleanup', { operatorId: operator_id }),

    /**
     * Remove a relay — optionally destroying the cloud server behind it.
     *
     * `deleteServer = false` is exactly `cancelAndCleanup`: forget the
     * keys, drop the row, leave the VPS running and billing. Keep it for
     * the escape hatches (a stuck custody migration has no readable API
     * token, so it cannot authenticate a cloud delete).
     *
     * `deleteServer = true` destroys the cloud resources FIRST and only
     * then erases local state, because the token and the record are the
     * only handles on those resources — once they are gone the server is
     * unreachable forever. So a cloud failure REJECTS with the relay
     * still fully intact and retryable; it never half-succeeds. Show the
     * rejection as "still running, try again", not "deleted".
     *
     * On success, check every flag: `server_deleted` without
     * `ssh_key_deleted` means an orphaned key is left in the account,
     * and that orphan makes the next provision in the same region fail
     * on a name collision. `warnings` is provider text — show verbatim.
     */
    relayDestroy: (operator_id: number, delete_server: boolean, delete_own_server = false) =>
        invoke<DestroyReport>('wizard_relay_destroy', {
            operatorId: operator_id,
            deleteServer: delete_server,
            // The person's answer to "Delete my server" for a server they
            // brought themselves. Only then may the shell take that
            // server's id from the setup journal.
            deleteOwnServer: delete_own_server,
        }),

    /**
     * Store the cloud-provider API token.
     *
     * Pass `operator_id` when resuming or re-entering an existing
     * relay: omitting it INSERTs a new operator row, which is how
     * Back→Next used to litter the relay list with duplicates.
     */
    storeCloudToken: (provider: string, token: string, operator_id?: number) =>
        invoke<number>('wizard_store_cloud_token', {
            provider,
            token,
            operatorId: operator_id ?? null,
        }),

    /**
     * A relay that already holds a readable hosting key for `provider`
     * (null when none). Carries no secret.
     */
    savedCloudToken: (provider: string) =>
        invoke<{ operator_id: number; nickname: string; account?: boolean } | null>(
            'wizard_saved_cloud_token',
            { provider },
        ),

    /**
     * Start a NEW relay with the hosting key another relay already
     * saved. The key is copied inside the shell and never reaches JS.
     */
    reuseCloudToken: (provider: string) =>
        invoke<number>('wizard_reuse_cloud_token', { provider }),

    /**
     * The Accounts page: check a pasted hosting key with one read-only
     * call to the hosting company and keep it for every new relay. An
     * empty key rejects with "cloud token must not be empty"; a refused
     * one with the company's words. Nothing is kept on a refusal.
     */
    hostingAccountConnect: (provider: string, token: string) =>
        invoke<HostingAccountState>('wizard_hosting_account_connect', {
            input: { provider, token },
        }),

    /** Per hosting company: whether a key is on this phone. Local. */
    hostingAccountStatus: () =>
        invoke<HostingAccountStatus>('wizard_hosting_account_status'),

    /** Forget the account key. Relays keep their own copies. */
    hostingAccountDisconnect: (provider: string) =>
        invoke<void>('wizard_hosting_account_disconnect', { provider }),

    listExistingServers: (operator_id: number) =>
        invoke<ExistingServer[]>('wizard_list_existing_servers', {
            operatorId: operator_id,
        }),

    listServerTypes: (operator_id: number, region: string) =>
        invoke<ServerTypeOption[]>('wizard_list_server_types', {
            operatorId: operator_id,
            region,
        }),

    /**
     * What is left on this relay's cloud account, with no record
     * needed. READ-ONLY — its destructive counterpart
     * (`account-reclaim`) is deliberately not exposed to the app.
     *
     * This is the answer to the failure with the worst outcome on the
     * ladder: a rebuild that deleted the server and could not build the
     * replacement can leave a half-built box billing and an SSH key
     * that blocks the next attempt. The record-driven screens cannot
     * find either — the record write is exactly what did not happen.
     */
    accountAudit: (operator_id: number) =>
        invoke<AccountAuditReport>('wizard_account_audit', {
            operatorId: operator_id,
        }),

    /**
     * The catalogue of a provider this relay does NOT live on.
     *
     * L5's sheet needs it: the destination is an account Daal has never
     * talked to, so there is no stored credential to look anything up
     * with and no stored provider to look it up on. One read-only call
     * answers all three of the questions that otherwise kill the rung —
     * does the credential authenticate, is that a region this provider
     * has, is that plan sold there — and all three are otherwise
     * discovered by the create leg, which runs after the old relay has
     * been deleted.
     *
     * The token is passed, used once, and NOT stored. Daal only takes
     * custody of a second provider's credential after the rebuild has
     * produced a live server.
     */
    listServerTypesFor: (provider: string, region: string, token: string) =>
        invoke<ServerTypeOption[]>('wizard_list_server_types_for', {
            provider,
            region,
            token,
        }),

    pricingLookup: (operator_id: number, region: string, server_type: string) =>
        invoke<Pricing>('wizard_pricing_lookup', {
            operatorId: operator_id,
            region,
            serverType: server_type,
        }),

    selectProfile: (
        operator_id: number,
        region: string,
        server_type: string,
        toolbox_profile: string,
        enabled_families: string[],
    ) =>
        invoke<void>('wizard_select_profile', {
            operatorId: operator_id,
            region,
            serverType: server_type,
            toolboxProfile: toolbox_profile,
            enabledFamilies: enabled_families,
        }),

    publisherKeygen: (operator_id: number) =>
        invoke<Fingerprint>('wizard_publisher_keygen', { operatorId: operator_id }),

    /**
     * Import an existing publisher key from base64 raw bytes. Also the
     * restore path for a blob written by `saveRecoveryKey`.
     */
    publisherKeyimport: (operator_id: number, priv_bytes_b64: string) =>
        invoke<Fingerprint>('wizard_publisher_keyimport', {
            operatorId: operator_id,
            privBytesB64: priv_bytes_b64,
        }),

    finalizePreProvision: (operator_id: number) =>
        invoke<string>('wizard_finalize_pre_provision', {
            operatorId: operator_id,
        }),

    /** Streams progress on the `wizard-provision-event` channel. */
    provisionRun: (operator_id: number, existing_server_id?: string) =>
        invoke<void>('wizard_provision_run', {
            operatorId: operator_id,
            existingServerId: existing_server_id ?? null,
        }),

    /** Streams progress on the `wizard://sign-event` channel. */
    signRelaypack: (
        operator_id: number,
        phase: string,
        output_dir: string,
        publisher_name: string,
    ) =>
        invoke<BindResult>('wizard_sign_relaypack', {
            operatorId: operator_id,
            phase,
            outputDir: output_dir,
            publisherName: publisher_name,
        }),

    /**
     * Stream one bounded batch of animated-QR fountain frames for a
     * relay's pack. Frames arrive on the `wizard://qr-frame` event (see
     * `onQrFrame`), NOT as a return value; the promise resolves when the
     * batch has finished emitting, which is also how the caller knows it
     * may ask for the next one.
     *
     * `artifact` is `'shared'` for the everyone pack — the only one that
     * can connect anybody — or `'raw'` for the credential-free build
     * artifact. There is no default: streaming the wrong file produces a
     * perfect transfer of a file the receiver cannot use, and nothing
     * downstream can tell the difference.
     */
    qrRender: (
        operator_id: number,
        artifact: PackArtifact,
        block_size: number,
        max_frames: number,
        seed: number,
    ) =>
        invoke<void>('wizard_qr_render', {
            operatorId: operator_id,
            artifact,
            blockSize: block_size,
            maxFrames: max_frames,
            seed,
        }),

    /**
     * The same artifact `qrRender` streams, rendered as base64 text the
     * operator can paste into a chat message.
     *
     * This is the SENDING half of the base64-paste lane. The recipient
     * side (AddSheet's paste tab → `importSbpBytes`) shipped first, so
     * for a while the app could eat a pasted bundle but no Daal app
     * could produce one — the only way to make the text was to open a
     * terminal and run `base64 -w0`. On the day the messenger bans
     * files, this is the affordance that still works.
     *
     * `artifact` carries the same meaning, and the same absence of a
     * default, as in `qrRender`.
     */
    copyPasteable: (operator_id: number, artifact: PackArtifact) =>
        invoke<string>('wizard_copy_pasteable', {
            operatorId: operator_id,
            artifact,
        }),

    // ---- Relay identity, artifacts, helper IP ----

    /** Set the relay's display name. "" clears it. */
    setOperatorNickname: (operator_id: number, nickname: string) =>
        invoke<void>('wizard_set_operator_nickname', {
            operatorId: operator_id,
            nickname,
        }),

    /**
     * Every distributable file for a relay. Read-only and cheap — safe
     * to call on each render of the relay-detail screen. Index 0 is
     * always the shared pack, index 1 the raw bundle, then one row per
     * recipient by ascending id.
     */
    listArtifacts: (operator_id: number) =>
        invoke<ArtifactInfo[]>('wizard_list_artifacts', { operatorId: operator_id }),

    /** Persisted helper IP, or "" if never detected. */
    getHelperIp: (operator_id: number) =>
        invoke<string>('wizard_get_helper_ip', { operatorId: operator_id }),

    /**
     * Persist the helper IP. Rejects anything that is not a textual
     * IPv4/IPv6 address, so a captive-portal page can never be stored
     * as one. `source` is diagnostic only.
     */
    setHelperIp: (
        operator_id: number,
        helper_ip: string,
        source: 'auto' | 'manual' | 'whoami',
    ) =>
        invoke<void>('wizard_set_helper_ip', {
            operatorId: operator_id,
            helperIp: helper_ip,
            source,
        }),

    // ---- Device custody ----

    /** Where publisher secrets live, whether that works, and whether a
     *  one-time migration is outstanding. Safe to call on mount. */
    custodyStatus: () => invoke<PublisherCustodyStatus>('publisher_custody_status'),

    /**
     * One-time upgrade from the old PIN store to device custody.
     *
     * A legacy blob is deleted only after the same bytes have been
     * written to custody AND read back identical, so a failure leaves
     * the old copy exactly where it was. Keep the gate blocking until
     * `signing_keys_safe` comes back true.
     */
    migrateFromPin: (pin: string) =>
        invoke<CustodyMigrationReport>('publisher_migrate_from_pin', { pin }),

    /** Unlock session-passphrase custody. Throws E_CUSTODY_WRONG_PASS
     *  immediately on a bad passphrase rather than failing later. */
    custodyUnlock: (passphrase: string) =>
        invoke<PublisherCustodyStatus>('publisher_custody_unlock', { passphrase }),

    /**
     * Write a recovery copy of the relay's signing key to Downloads and
     * return the file name. The key bytes never cross this boundary.
     *
     * This is the only defence against the one thing custody is worse
     * at than a PIN: the device wrap key cannot be exported, so a
     * factory reset destroys every relay this device publishes.
     */
    saveRecoveryKey: (operator_id: number, file_name: string) =>
        invoke<string>('publisher_save_recovery_key', {
            operatorId: operator_id,
            fileName: file_name,
        }),

    // CDN
    storeCloudflareToken: (operator_id: number, token: string) =>
        invoke<void>('wizard_store_cloudflare_token', {
            operatorId: operator_id,
            token,
        }),
    provisionCdnFront: (args: {
        operatorId: number;
        hostname: string;
        originIp: string;
        originIpv6: string;
        originPath: string;
        publicPath: string;
    }) => invoke<number>('wizard_provision_cdn_front', args),
    listCdnFronts: (operator_id: number) =>
        invoke<CdnFrontRow[]>('wizard_list_cdn_fronts', {
            operatorId: operator_id,
        }),
    verifyCdnPosture: (front_id: number) =>
        invoke<void>('wizard_verify_cdn_posture', { frontId: front_id }),

    // Rotation
    rotateRecommend: (
        operator_id: number,
        args: {
            mode: 'explanation' | 'context';
            explanation_json?: string;
            failure_classifications?: string[];
            network_signals?: string[];
            exposure_mode?: string;
            credential_leak_suspected?: boolean;
        },
    ) =>
        invoke<RotationRecommendation>('wizard_rotate_recommend', {
            operatorId: operator_id,
            args,
        }),
    /**
     * Run one rung of the rotation ladder.
     *
     * `newFloatingIpId` is OPTIONAL for L3 and meaningless elsewhere.
     * Empty means "reserve a new address for this relay in its own
     * region", which is what makes the rung reachable at all on a
     * relay that has never had one — i.e. every relay in the field.
     * Supplying the id the relay is ALREADY on is refused rather than
     * performed: it completes, changes nothing a censor can see, and
     * would report a successful rotation.
     *
     * `newRegion` / `newProvider` are the same shape one rung up, and
     * the wizard REFUSES the rung without them rather than quietly
     * rebuilding into the same place: an L4 with no new region and an
     * L5 with no new provider are both L1 wearing a bigger warning.
     *
     * `newToolboxProfile` is L6's whole payload, and it was the one
     * field this wrapper dropped. `wizard_rotate_execute` has taken it
     * since FRP-7 (src-tauri/src/lib.rs) and `rotate_execute` refuses
     * an L6 without it (commands.rs:2559) — but the argument object
     * built here never carried the key, so Tauri passed `undefined`,
     * serde saw `None`, and the rung was unreachable from this side of
     * the boundary no matter what a screen asked for. A missing key in
     * an object literal is invisible in a way a missing parameter is
     * not, which is how a fully-implemented rung sat dark.
     */
    rotateExecute: (
        operator_id: number,
        level: string,
        reason: string,
        opts?: {
            newFloatingIpId?: string;
            newRegion?: string;
            newProvider?: string;
            /**
             * L5 only, and required by the backend before it touches
             * the provider. The operator row holds ONE cloud token and
             * it belongs to the provider being left; the rebuild leg
             * runs against the one being moved to. Omitting this is
             * refused rather than defaulted, because the leg it feeds
             * runs after the old relay has already been deleted.
             */
            newProviderToken?: string;
            /** L5 only: server types are provider-scoped ("cx22" is
             *  Hetzner's, Vultr sells "vc2-1c-1gb"). */
            newServerType?: string;
            newToolboxProfile?: string;
        },
    ) =>
        invoke<RotateExecuteOutput>('wizard_rotate_execute', {
            operatorId: operator_id,
            level,
            reason,
            newFloatingIpId: opts?.newFloatingIpId ?? null,
            newRegion: opts?.newRegion ?? null,
            newProvider: opts?.newProvider ?? null,
            newProviderToken: opts?.newProviderToken ?? null,
            newServerType: opts?.newServerType ?? null,
            newToolboxProfile: opts?.newToolboxProfile ?? null,
        }),
    rotateRevert: (operator_id: number) =>
        invoke<SignedSbpRow>('wizard_rotate_revert', { operatorId: operator_id }),
    rotateHistory: (operator_id: number) =>
        invoke<SignedSbpRow[]>('wizard_rotate_history', { operatorId: operator_id }),

    // Wave 3 Step 8 — freshness (remote pack replacement).
    //
    // Four verbs, deliberately not one. Configuring a mirror, saying
    // where the pack will live, and publishing are three acts that fail
    // independently; one combined call would have to report one outcome
    // for three different problems.
    freshnessStatus: (operator_id: number) =>
        invoke<FreshnessStatus>('wizard_freshness_status', {
            operatorId: operator_id,
        }),
    /** The credential crosses this boundary once, inbound. */
    addFreshnessEndpoint: (operator_id: number, endpoint: FreshnessEndpointInput) =>
        invoke<number>('wizard_freshness_add_endpoint', {
            operatorId: operator_id,
            endpoint,
        }),
    /** Deletes the mirror AND forgets its write-key. */
    deleteFreshnessEndpoint: (endpoint_id: number) =>
        invoke<void>('wizard_freshness_delete_endpoint', {
            endpointId: endpoint_id,
        }),
    setFreshnessPackUrl: (operator_id: number, url: string) =>
        invoke<void>('wizard_freshness_set_pack_url', {
            operatorId: operator_id,
            url,
        }),
    /** Returns a report, not a throw: "one provider took it, the other
     *  refused" is the interesting case and it is neither. */
    publishFreshness: (operator_id: number) =>
        invoke<PublishReport>('wizard_freshness_publish', {
            operatorId: operator_id,
        }),

    // Sub-key rotation
    subkeyRotate: (operator_id: number, validity?: string, label?: string) =>
        invoke<unknown>('wizard_subkey_rotate', {
            operatorId: operator_id,
            validity: validity ?? null,
            label: label ?? null,
        }),
    subkeyActive: (operator_id: number) =>
        invoke<SubkeyRow | null>('wizard_subkey_active', {
            operatorId: operator_id,
        }),
    subkeyHistory: (operator_id: number) =>
        invoke<SubkeyRow[]>('wizard_subkey_history', {
            operatorId: operator_id,
        }),

    // FRP-14 per-recipient surface
    recipientProvision: (
        operator_id: number,
        address: string,
        display_name: string,
    ) =>
        invoke<RecipientSummary>('wizard_recipient_provision', {
            operatorId: operator_id,
            address,
            displayName: display_name,
        }),
    /**
     * Rebuild the `.sbpx` for a recipient already on the roster.
     *
     * NOT `recipientProvision` again: that has no upsert path, so it
     * burns a fresh `r<n>`, mints a second live user on the box, and
     * only then fails on the roster's UNIQUE constraint — leaving an
     * orphan credential the app can never revoke. This re-mints the
     * recipient's existing box user and repacks in place.
     */
    recipientRepackSbpx: (operator_id: number, recipient_id: number) =>
        invoke<RecipientSummary>('wizard_recipient_repack_sbpx', {
            operatorId: operator_id,
            recipientId: recipient_id,
        }),
    recipientRevoke: (operator_id: number, recipient_id: number) =>
        invoke<RecipientSummary>('wizard_recipient_revoke', {
            operatorId: operator_id,
            recipientId: recipient_id,
        }),
    recipientList: (operator_id: number) =>
        invoke<RecipientSummary[]>('wizard_recipient_list', {
            operatorId: operator_id,
        }),
    recipientListRemote: (operator_id: number) =>
        invoke<string[]>('wizard_recipient_list_remote', {
            operatorId: operator_id,
        }),
    // Hard-remove an already-revoked recipient from the local roster.
    // No box round-trip; the row must be revoked first (the Rust side
    // guards live rows). Purges the greyed-out row + its .sbpx.
    recipientDelete: (operator_id: number, recipient_id: number) =>
        invoke<void>('wizard_recipient_delete', {
            operatorId: operator_id,
            recipientId: recipient_id,
        }),

    // ---- Wave 3 Step 7: heal a relay in place ----------------------
    //
    // Two calls, two blast radii, and keeping them apart is the point.
    // There is no combined "rotate everything" wrapper and there must
    // never be one: the relay's mgmt service used to do both in a
    // single handler, which is how a targeted revocation and a
    // fleet-wide outage ended up sharing one button.

    /**
     * Re-key ONE recipient on the relay and rebuild their `.sbpx`.
     *
     * `name` is the box-side name (`r1`), not the roster row id —
     * that is what `/rotate-credentials` scopes on, and an empty one
     * is an error on both ends rather than "rotate all".
     *
     * Blast radius: exactly this person. Their current file stops
     * working and they need the new one; every other recipient keeps
     * connecting with what they already hold.
     */
    rotateCredentials: (operator_id: number, name: string) =>
        invoke<RotateCredentialsSummary>('wizard_rotate_credentials', {
            operatorId: operator_id,
            recipientName: name,
        }),

    /**
     * Move the relay's cover hostname / TLS parameters.
     *
     * Touches no credentials and no REALITY keypair. It DOES invalidate
     * every connection file already handed out, and Step 8 (remote pack
     * replacement) is not built — so nothing repairs itself over the
     * network; the result says who, if anyone, needs a new file.
     * The returned counts exist so the UI can say that with numbers.
     */
    rotateTls: (operator_id: number) =>
        invoke<RotateTlsSummary>('wizard_rotate_tls', {
            operatorId: operator_id,
        }),

    // ---- Publisher-alone wave ----------------------------------------

    /** D1. Read-only: what an interrupted setup left behind, from the
     *  setup journal and (when a token is stored) the hosting account. */
    setupRecovery: (operator_id: number) =>
        invoke<SetupRecovery>('wizard_setup_recovery', { operatorId: operator_id }),
    /** D1. Deletes the cloud side of an unfinished setup and KEEPS the
     *  relay row, so setup can start again without the token. */
    setupRemoveServer: (operator_id: number) =>
        invoke<DestroyReport>('wizard_setup_remove_server', { operatorId: operator_id }),
    /** D1. "Is anything of Daal's still running in my account?" */
    accountCheck: () => invoke<AccountCheck>('wizard_account_check'),
    /** D1. Delete the chosen Daal-labelled leftovers in one account. */
    accountCleanup: (account_key: string, items: ResourceRef[]) =>
        invoke<AccountCleanupReport>('wizard_account_cleanup', {
            accountKey: account_key,
            items,
        }),
    /** D2. Re-create every non-revoked person on the relay's current
     *  server and rewrite their files. Safe to press twice. Progress on
     *  `wizard://renew-event` (see `onRenewEvent`). */
    renewEveryone: (operator_id: number) =>
        invoke<RenewReport>('wizard_renew_everyone', { operatorId: operator_id }),
    /** Network test: is this relay the Test relay (its pack carries the
     *  report address)? Read-only. */
    testRelayStatus: (operator_id: number) =>
        invoke<TestRelayStatus>('wizard_test_relay_status', { operatorId: operator_id }),
    /** Network test: "Use as test relay" (`on`) or stop. Makes the
     *  report key on this phone the first time and signs the relay's
     *  pack again with (or without) its address. Nobody on the relay is
     *  touched and no file is made again. Turning it on for a relay
     *  people connect with is refused (E_TEST_RELAY_IN_USE) unless
     *  `confirmInUse`, which the sheet sends only after its second
     *  confirmation naming the count. Reaches the relay. */
    testRelaySet: (operator_id: number, on: boolean, confirmInUse = false) =>
        invoke<TestRelaySet>('wizard_test_relay_set', { operatorId: operator_id, on, confirmInUse }),
    /** Network test: open one received report (`net-xxxxxxxx.dat`, a
     *  path `PickedFile.stage` returned) with a report key on this
     *  phone. Answers the report JSON, validated; UNTRUSTED. */
    reportOpen: (path: string) => invoke<string>('wizard_report_open', { path }),
    /** D3. Rust returns a cached result younger than 10 minutes unless
     *  `force` is true. Read-only. */
    relayHealth: (operator_id: number, force: boolean) =>
        invoke<RelayHealth>('wizard_relay_health', { operatorId: operator_id, force }),
    /** PA-1. Give back ONE address left reserved on a live relay. Never
     *  touches the server: an address that is in use, attached, or not
     *  Daal's is kept and said so. */
    releaseAddress: (operator_id: number, address: string) =>
        invoke<ReleaseAddressResult>('wizard_release_address', {
            operatorId: operator_id,
            address,
        }),

    // ---- After a restore (PB-1 / PB-2) -------------------------------

    /** PB-1. Who in this phone's list the relay does not know, while the
     *  relay is "restored, not yet settled". Read-only. */
    restoreUnsettled: (operator_id: number) =>
        invoke<RestoreUnsettled>('wizard_restore_unsettled', { operatorId: operator_id }),
    /** PB-1. The person's answer for one of them: `keep` = they should
     *  still have access (renew may now re-create them); otherwise they
     *  are marked removed on this phone and never created. Stored, so it
     *  is asked once. */
    restoreAnswer: (operator_id: number, recipient_id: number, keep: boolean) =>
        invoke<void>('wizard_restore_answer', {
            operatorId: operator_id,
            recipientId: recipient_id,
            keep,
        }),
    /** PB-2. Remove ONE such relay user's access, by relay user name.
     *  The shell refuses a name that is in this phone's list. */
    relayOnlyRevoke: (operator_id: number, relay_user: string) =>
        invoke<void>('wizard_relay_only_revoke', {
            operatorId: operator_id,
            relayUser: relay_user,
        }),
};

/**
 * Optional add-ons (docs/optional-addons-plan.md, X2): every command the
 * standby address, the way in through Cloudflare and the Google update
 * channel will need, registered once in src-tauri/src/lib.rs. Each
 * add-on command takes one `input` object and returns one value; their
 * shapes live in ./addons/addonTypes.ts. Until an add-on's lane lands,
 * its commands reject with `E_NOT_BUILT: …`. Steps stream on
 * `onAddonProgress`.
 */
export const Addons = {
    /** A relay's add-ons (the ledger). Read-only, no network. */
    list: (operator_id: number) =>
        invoke<AddonRow[]>('wizard_addons_list', { operatorId: operator_id }),
    /** Take one add-on down; its kind decides the order. */
    remove: (addon_id: number) =>
        invoke<AddonRemoveReport>('wizard_addon_remove', { addonId: addon_id }),

    // ---- standby address
    standbyPrice: (input: StandbyPriceInput) =>
        invoke<StandbyPrice>('wizard_addon_standby_price', { input }),
    standbyAdd: (input: StandbyAddInput) =>
        invoke<AddonRow>('wizard_addon_standby_add', { input }),
    /** "Switch to standby": answers the key to send. */
    standbyPromote: (input: StandbyPromoteInput) =>
        invoke<StandbyPromoteResult>('wizard_addon_standby_promote', { input }),
    /** The standby key again, after the sheet that showed it closed. */
    standbyKey: (input: StandbyKeyInput) =>
        invoke<StandbyKey>('wizard_addon_standby_key', { input }),

    // ---- way in through Cloudflare
    /** The pasted token crosses this boundary once, inbound. */
    cdnSetToken: (input: CdnTokenInput) =>
        invoke<CdnTokenCheck>('wizard_addon_cdn_set_token', { input }),
    /** The Accounts page: check and keep a key for every relay. */
    cdnConnect: (input: CdnConnectInput) =>
        invoke<CdnTokenCheck>('wizard_addon_cdn_connect', { input }),
    /** Whether an account key is kept, and its zone. Local. */
    cdnAccount: () => invoke<CdnAccount>('wizard_addon_cdn_account'),
    /** Forget the account key; relays keep their own copies. */
    cdnDisconnect: () => invoke<void>('wizard_addon_cdn_disconnect'),
    cdnBuild: (input: CdnBuildInput) =>
        invoke<AddonRow>('wizard_addon_cdn_build', { input }),
    cdnPosture: (input: CdnPostureInput) =>
        invoke<CdnPosture>('wizard_addon_cdn_posture', { input }),
    cdnSetPlainFallback: (input: CdnPlainFallbackInput) =>
        invoke<AddonRow>('wizard_addon_cdn_set_plain_fallback', { input }),

    // ---- update channel through Google
    /** Accounts → Google: connected or not, and whether this build may
     *  offer "Sign in with Google". Local. */
    googleAccount: () => invoke<GoogleAccount>('wizard_google_account'),
    /** The account's script to paste, with its write key in it. */
    googleAccountScript: () => invoke<GoogleScript>('wizard_google_account_script'),
    /** The web-app address pasted back: written to and read back
     *  through Google before it counts as connected. */
    googleAccountAttach: (input: GoogleAccountAttachInput) =>
        invoke<GoogleAccount>('wizard_google_account_attach', { input }),
    /** The same step by signing in (only when `sign_in`). The token
     *  never reaches the page. */
    googleAccountSignIn: () => invoke<GoogleAccount>('wizard_google_account_sign_in'),
    /** Forget the account; relays that use it keep their own copies. */
    googleAccountDisconnect: () => invoke<void>('wizard_google_account_disconnect'),
    /** A relay's switch, on: a slot in the account's script. */
    googleOn: (input: GoogleOnInput) => invoke<AddonRow>('wizard_addon_google_on', { input }),
    googleCheck: (input: GoogleCheckInput) =>
        invoke<GoogleCheck>('wizard_addon_google_check', { input }),
};

/** PB-20. The platform side of screens that show secrets. */
export const Platform = {
    /** Android: FLAG_SECURE on the activity window (no screenshots, no
     *  screen recording, a blank recent-apps thumbnail). Desktop: a
     *  no-op that succeeds. Use through `useSecureScreen`. */
    secureScreen: (on: boolean) => invoke<void>('platform_secure_screen', { on }),
};

// ---- Streaming events ----

export const onProvisionEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard-provision-event', (e) => cb(e.payload));

export const onSignEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://sign-event', (e) => cb(e.payload));

/**
 * Animated-QR frames from `Wizard.qrRender`. The Rust side emits these
 * as fast as the `daal-deploy qr-fountain` subprocess writes them —
 * hundreds a second — so a subscriber MUST buffer rather than render on
 * the event. `client-ui/src/qr/fountainStream.ts` is that buffer.
 */
export const onQrFrame = (
    cb: (frame: QrFountainFrame) => void,
): Promise<UnlistenFn> =>
    listen<QrFountainFrame>('wizard://qr-frame', (e) => cb(e.payload));

/** Optional add-ons: one step of an add-on operation. */
export const onAddonProgress = (cb: (ev: AddonProgress) => void): Promise<UnlistenFn> =>
    listen<AddonProgress>('wizard://addon-progress', (e) => cb(e.payload));

/** D2: one line per person while `renewEveryone` runs. */
export const onRenewEvent = (cb: (ev: RenewEvent) => void): Promise<UnlistenFn> =>
    listen<RenewEvent>('wizard://renew-event', (e) => cb(e.payload));

/** PB-3. The name to tell the person after a save to Downloads: the one
 *  the file was stored under when the shell reports it (Android may
 *  de-duplicate "Maman.sbpx" to "Maman (1).sbpx"), else the one asked
 *  for (a shell built before PB-3 reports nothing). */
export function storedFileName(stored: unknown, asked: string): string {
    return typeof stored === 'string' && stored.trim() !== '' ? stored : asked;
}
