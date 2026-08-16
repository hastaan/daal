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
    | null;

const PUBLISHER_ERROR_CODES: Exclude<PublisherErrorCode, null>[] = [
    'E_CUSTODY_LOCKED',
    'E_CUSTODY_WRONG_PASS',
    'E_CUSTODY_BACKEND',
    'E_LEGACY_PIN_REQUIRED',
    'E_SECRET_MISSING',
    'E_HELPER_IP_MISSING',
    'E_HELPER_IP_STALE',
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

/** Strip the `CODE: ` prefix so the UI can show just the human tail. */
export function publisherErrorText(e: unknown): string {
    const msg =
        typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
    const code = classifyPublisherError(e);
    return code ? msg.slice(code.length + 2) : msg;
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
    rotateExecute: (operator_id: number, level: string, reason: string) =>
        invoke<RotateExecuteOutput>('wizard_rotate_execute', {
            operatorId: operator_id,
            level,
            reason,
        }),
    rotateRevert: (operator_id: number) =>
        invoke<SignedSbpRow>('wizard_rotate_revert', { operatorId: operator_id }),
    rotateHistory: (operator_id: number) =>
        invoke<SignedSbpRow[]>('wizard_rotate_history', { operatorId: operator_id }),

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
};

// ---- Streaming events ----

export const onProvisionEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard-provision-event', (e) => cb(e.payload));

export const onSignEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://sign-event', (e) => cb(e.payload));

export const onQrFrame = (cb: (frame: FountainFrame) => void): Promise<UnlistenFn> =>
    listen<FountainFrame>('wizard://qr-frame', (e) => cb(e.payload));

export const onRotateEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://rotate-event', (e) => cb(e.payload));
