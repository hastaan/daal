// wizardCommands.ts — thin typed wrappers around the 22 wizard_*
// Tauri commands registered in client-shell/tauri/src-tauri/src/lib.rs.
//
// Lives in client-ui/src/publisher/ (NOT under contract/) because the
// publisher surface is a separate functional namespace from D2Contract.

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

// ---- Types mirrored from Rust ----

export interface OperatorSummary {
    id: number;
    status: string;
    provider: string;
    region: string;
    server_type: string;
    publisher_pub_hex: string;
    created_at_unix: number;
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
    wizard_step: string;
    created_at_unix: number;
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
     */
    shareInvite: (operator_id: number, friendly_name: string) =>
        invoke<string>('share_invite', {
            operatorId: operator_id,
            friendlyName: friendly_name,
        }),
    /** FRP-14 Layer 3b.5: open the share-sheet for a specific
     *  per-recipient `.sbpx` file produced by Add-recipient. */
    shareInviteSbpx: (sbpx_path: string, friendly_name: string) =>
        invoke<string>('share_invite_sbpx', {
            sbpxPath: sbpx_path,
            friendlyName: friendly_name,
        }),
    getOperatorState: (operator_id: number) =>
        invoke<OperatorState>('wizard_get_operator_state', { operatorId: operator_id }),
    cancelAndCleanup: (operator_id: number) =>
        invoke<void>('wizard_cancel_and_cleanup', { operatorId: operator_id }),

    storeCloudToken: (provider: string, token: string, pin: string) =>
        invoke<number>('wizard_store_cloud_token', { provider, token, pin }),

    listExistingServers: (operator_id: number, pin: string) =>
        invoke<ExistingServer[]>('wizard_list_existing_servers', {
            operatorId: operator_id,
            pin,
        }),

    listServerTypes: (
        operator_id: number,
        region: string,
        pin: string,
    ) =>
        invoke<ServerTypeOption[]>('wizard_list_server_types', {
            operatorId: operator_id,
            region,
            pin,
        }),

    pricingLookup: (
        operator_id: number,
        region: string,
        server_type: string,
        pin: string,
    ) =>
        invoke<Pricing>('wizard_pricing_lookup', {
            operatorId: operator_id,
            region,
            serverType: server_type,
            pin,
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

    publisherKeygen: (operator_id: number, pin: string) =>
        invoke<Fingerprint>('wizard_publisher_keygen', {
            operatorId: operator_id,
            pin,
        }),
    publisherKeyimport: (
        operator_id: number,
        pin: string,
        priv_bytes_b64: string,
    ) =>
        invoke<Fingerprint>('wizard_publisher_keyimport', {
            operatorId: operator_id,
            pin,
            privBytesB64: priv_bytes_b64,
        }),

    finalizePreProvision: (operator_id: number) =>
        invoke<string>('wizard_finalize_pre_provision', {
            operatorId: operator_id,
        }),

    provisionRun: (
        operator_id: number,
        pin: string,
        helper_ip: string,
        existing_server_id?: string,
    ) =>
        invoke<void>('wizard_provision_run', {
            operatorId: operator_id,
            pin,
            helperIp: helper_ip,
            existingServerId: existing_server_id || null,
        }),
    signRelaypack: (
        operator_id: number,
        pin: string,
        phase: string,
        output_dir: string,
        publisher_name: string,
    ) =>
        invoke<BindResult>('wizard_sign_relaypack', {
            operatorId: operator_id,
            pin,
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

    // CDN
    storeCloudflareToken: (operator_id: number, token: string, pin: string) =>
        invoke<void>('wizard_store_cloudflare_token', {
            operatorId: operator_id,
            token,
            pin,
        }),
    provisionCdnFront: (args: {
        operatorId: number;
        hostname: string;
        originIp: string;
        originIpv6: string;
        originPath: string;
        publicPath: string;
        pin: string;
    }) => invoke<number>('wizard_provision_cdn_front', args),
    listCdnFronts: (operator_id: number) =>
        invoke<CdnFrontRow[]>('wizard_list_cdn_fronts', {
            operatorId: operator_id,
        }),
    verifyCdnPosture: (front_id: number, pin: string) =>
        invoke<void>('wizard_verify_cdn_posture', { frontId: front_id, pin }),

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
    rotateExecute: (operator_id: number, pin: string, level: string, reason: string) =>
        invoke<RotateExecuteOutput>('wizard_rotate_execute', {
            operatorId: operator_id,
            pin,
            level,
            reason,
        }),
    rotateRevert: (operator_id: number) =>
        invoke<SignedSbpRow>('wizard_rotate_revert', { operatorId: operator_id }),
    rotateHistory: (operator_id: number) =>
        invoke<SignedSbpRow[]>('wizard_rotate_history', { operatorId: operator_id }),

    // Sub-key rotation
    subkeyRotate: (
        operator_id: number,
        pin: string,
        validity?: string,
        label?: string,
    ) =>
        invoke<unknown>('wizard_subkey_rotate', {
            operatorId: operator_id,
            pin,
            validity,
            label,
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
        pin: string,
        helper_ip: string,
        address: string,
        display_name: string,
    ) =>
        invoke<RecipientSummary>('wizard_recipient_provision', {
            operatorId: operator_id,
            pin,
            helperIp: helper_ip,
            address,
            displayName: display_name,
        }),
    recipientRevoke: (
        operator_id: number,
        pin: string,
        helper_ip: string,
        recipient_id: number,
    ) =>
        invoke<RecipientSummary>('wizard_recipient_revoke', {
            operatorId: operator_id,
            pin,
            helperIp: helper_ip,
            recipientId: recipient_id,
        }),
    recipientList: (operator_id: number) =>
        invoke<RecipientSummary[]>('wizard_recipient_list', {
            operatorId: operator_id,
        }),
    recipientListRemote: (
        operator_id: number,
        pin: string,
        helper_ip: string,
    ) =>
        invoke<string[]>('wizard_recipient_list_remote', {
            operatorId: operator_id,
            pin,
            helperIp: helper_ip,
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
