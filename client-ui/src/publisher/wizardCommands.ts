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
    /** How many people are now holding a file that stopped working. */
    live_recipients: number;
    /** Whether an everyone-pack exists and is now dead too. */
    shared_pack_stale: boolean;
    warnings: string[];
}

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
];

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

export interface ServerTypeOption {
    id: string;
    description: string;
    cpus: number;
    memory_gb: number;
    disk_gb: number;
    monthly_eur: number;
    hourly_eur: number;
    location: string;
    arch: string;
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
    level: string;
    confidence: number;
    reason: string;
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
    /** Non-fatal provider errors. Show verbatim — do not summarise. */
    warnings: string[];
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
    /** Save the operator's shared `.sbp` into the phone's Downloads. */
    saveSharedSbpToDownloads: (operator_id: number, file_name: string) =>
        invoke<void>('save_shared_sbp_to_downloads', {
            operatorId: operator_id,
            fileName: file_name,
        }),
    /** Save a per-recipient `.sbpx` into the phone's Downloads. */
    saveSbpxToDownloads: (sbpx_path: string, file_name: string) =>
        invoke<void>('save_sbpx_to_downloads', {
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
    relayDestroy: (operator_id: number, delete_server: boolean) =>
        invoke<DestroyReport>('wizard_relay_destroy', {
            operatorId: operator_id,
            deleteServer: delete_server,
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

    listExistingServers: (operator_id: number) =>
        invoke<ExistingServer[]>('wizard_list_existing_servers', {
            operatorId: operator_id,
        }),

    listServerTypes: (operator_id: number, region: string) =>
        invoke<ServerTypeOption[]>('wizard_list_server_types', {
            operatorId: operator_id,
            region,
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

    qrRender: (
        operator_id: number,
        block_size: number,
        max_frames: number,
        seed: number,
    ) =>
        invoke<void>('wizard_qr_render', {
            operatorId: operator_id,
            blockSize: block_size,
            maxFrames: max_frames,
            seed,
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
     * No screen drives L4/L5 yet — they are passed here so the
     * boundary carries them the day one does, not so the UI can omit
     * them and get a silent no-op.
     */
    rotateExecute: (
        operator_id: number,
        level: string,
        reason: string,
        opts?: { newFloatingIpId?: string; newRegion?: string; newProvider?: string },
    ) =>
        invoke<RotateExecuteOutput>('wizard_rotate_execute', {
            operatorId: operator_id,
            level,
            reason,
            newFloatingIpId: opts?.newFloatingIpId ?? null,
            newRegion: opts?.newRegion ?? null,
            newProvider: opts?.newProvider ?? null,
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
     * network and every recipient needs a new file delivered by hand.
     * The returned counts exist so the UI can say that with numbers.
     */
    rotateTls: (operator_id: number) =>
        invoke<RotateTlsSummary>('wizard_rotate_tls', {
            operatorId: operator_id,
        }),
};

// ---- Streaming events ----

export const onProvisionEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard-provision-event', (e) => cb(e.payload));

export const onSignEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://sign-event', (e) => cb(e.payload));
