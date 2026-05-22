// wizardCommands.ts — thin typed wrappers around the 22 wizard_*
// Tauri commands registered in client-shell/tauri/src-tauri/src/lib.rs.
//
// Lives in client-ui/src/publisher/ (NOT under contract/) because the
// publisher surface is a separate functional namespace from D2Contract.

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

// ---- Types mirrored from Rust ----

export interface OperatorSummary {
    operator_id: number;
    label: string;
    region: string;
    server_type: string;
    created_unix: number;
}

export interface Fingerprint {
    hex: string;
    en: string[];
    fa: string[];
    visual_data_uri: string;
}

export interface Pricing {
    monthly_usd: number;
    bandwidth_tib: number;
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
    phase: string;
    detail: string;
    pct?: number;
}

export interface FountainFrame {
    index: number;
    total_frames: number;
    frame_b64: string;
}

export interface BindResult {
    fingerprint_hex: string;
    output_path: string;
}

export interface RotateExecuteOutput {
    summary: string;
    new_active_id?: number;
}

// ---- Commands (one wrapper per #[tauri::command]) ----

export const Wizard = {
    listOperators: () => invoke<OperatorSummary[]>('wizard_list_operators'),
    cancelAndCleanup: (operator_id: number) =>
        invoke<void>('wizard_cancel_and_cleanup', { operatorId: operator_id }),

    storeCloudToken: (provider: string, token: string, pin: string) =>
        invoke<number>('wizard_store_cloud_token', { provider, token, pin }),

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

    provisionRun: (operator_id: number, pin: string, helper_ip: string) =>
        invoke<void>('wizard_provision_run', {
            operatorId: operator_id,
            pin,
            helperIp: helper_ip,
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
};

// ---- Streaming events ----

export const onProvisionEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://provision-event', (e) => cb(e.payload));

export const onSignEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://sign-event', (e) => cb(e.payload));

export const onQrFrame = (cb: (frame: FountainFrame) => void): Promise<UnlistenFn> =>
    listen<FountainFrame>('wizard://qr-frame', (e) => cb(e.payload));

export const onRotateEvent = (cb: (ev: ProgressEvent) => void): Promise<UnlistenFn> =>
    listen<ProgressEvent>('wizard://rotate-event', (e) => cb(e.payload));
