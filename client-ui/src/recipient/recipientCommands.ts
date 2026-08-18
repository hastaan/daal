// recipientCommands.ts — thin wrappers around the 5 recipient_qr_*
// Tauri commands.

import { invoke } from '@tauri-apps/api/core';
import { parseSessionStatus, type SessionStatus } from './sessionStatus';

export type { SessionStatus } from './sessionStatus';

// Every status the shell returns is validated against the contract in
// client-shared/contracts/recipient-session-status-v1.json before the
// UI is allowed to look at it. See sessionStatus.ts for why a plain
// `interface` was not enough.
export const Recipient = {
    newSession: (): Promise<string> => invoke<string>('recipient_qr_session_new'),
    feedFrame: async (
        session_id: string,
        index: number,
        total_frames: number,
        data_b64: string,
    ): Promise<SessionStatus> =>
        parseSessionStatus(
            await invoke<unknown>('recipient_qr_feed_frame', {
                sessionId: session_id,
                index,
                totalFrames: total_frames,
                dataB64: data_b64,
            }),
        ),
    status: async (session_id: string): Promise<SessionStatus> =>
        parseSessionStatus(
            await invoke<unknown>('recipient_qr_status', { sessionId: session_id }),
        ),
    cancel: (session_id: string): Promise<void> =>
        invoke<void>('recipient_qr_cancel', { sessionId: session_id }),
    /** Consume a COMPLETE session and return the importer verdict JSON.
     *  Calling this early is safe: the shell refuses and keeps every
     *  block decoded so far. */
    finalize: (session_id: string): Promise<string> =>
        invoke<string>('recipient_qr_finalize', { sessionId: session_id }),
};

// FRP-14 Layer 3c: recipient-side X25519 identity.
//
// `identityGet` returns null when the device has no identity row
// yet; the UI uses that to render the "Create my Daal address"
// CTA. `identityGetOrCreate` lazily mints the keypair on first
// call (PIN-wrapped via the same keystore the publisher uses).
export interface RecipientIdentitySummary {
    address: string;          // daal1…
    fingerprint_hex: string;  // 64 lowercase hex chars (hex sha256)
    created_at_unix: number;
}

export const RecipientIdentity = {
    get: (): Promise<RecipientIdentitySummary | null> =>
        invoke<RecipientIdentitySummary | null>('recipient_identity_get'),
    /** Device Custody v1: no PIN at the identity layer. The recipient
     *  X25519 priv is wrapped at rest by the Device Wrap Key (held in
     *  Hardware / OS Keystore / session passphrase). For
     *  session-passphrase devices the caller must have unlocked
     *  custody first via `DeviceCustody.unlock`. */
    getOrCreate: (): Promise<RecipientIdentitySummary> =>
        invoke<RecipientIdentitySummary>('recipient_identity_get_or_create'),
};

/** Device Custody v1 status + unlock surface. Hardware/os-keystore
 *  devices report `is_unlocked === true` from boot. Session-passphrase
 *  devices stay locked until `unlock(passphrase)` succeeds.
 *
 *  Device Custody B4 adds rotate + history + audit-events surface. */

export type CustodyLevel = 'hardware' | 'os_keystore' | 'session_passphrase';

export interface RecipientIdentityHistoryRow {
    id: number;
    version: number;
    pubkey_x25519_hex: string;
    keystore_alias: string;
    address_str: string;
    fingerprint_hex: string;
    created_at_unix: number;
    retired_at_unix: number;
}

export interface CustodyEventRow {
    id: number;
    at_unix: number;
    kind: 'created' | 'rotated' | 'locked' | 'unlocked' | 'panic_wipe' | string;
    level: string;
    detail_json: string;
}

export const DeviceCustody = {
    level: (): Promise<CustodyLevel> =>
        invoke<CustodyLevel>('device_custody_level'),
    isUnlocked: (): Promise<boolean> =>
        invoke<boolean>('device_custody_is_unlocked'),
    unlock: (passphrase?: string): Promise<void> =>
        invoke<void>('device_custody_unlock', { passphrase: passphrase ?? null }),
    lock: (): Promise<void> => invoke<void>('device_custody_lock'),
    /** Mint a fresh X25519 identity. The old key is retained under
     *  a versioned alias so existing `.sbpx` packs still open. */
    rotate: (): Promise<RecipientIdentitySummary> =>
        invoke<RecipientIdentitySummary>('device_custody_rotate'),
    /** All retired identities, newest first. */
    history: (): Promise<RecipientIdentityHistoryRow[]> =>
        invoke<RecipientIdentityHistoryRow[]>('device_custody_history'),
    /** Audit events, newest first. */
    events: (limit?: number): Promise<CustodyEventRow[]> =>
        invoke<CustodyEventRow[]>('device_custody_events', { limit: limit ?? 200 }),
};

// FRP-14 Layer 3d: recipient-side `.sbpx` import.
//
// Device Custody v1: the recipient X25519 priv that unwraps the
// envelope is held by device custody (hardware / OS keystore /
// session passphrase). There is no PIN at this layer. On
// session-passphrase devices the caller must have unlocked
// custody first via `DeviceCustody.unlock(passphrase)`.
//
// Caller flow (file tab in AddSheet):
//   const isSbpx = await Sbpx.sniff(path);
//   if (isSbpx) {
//     const plaintextPath = await Sbpx.import(path);
//     await contract.previewBundle(plaintextPath);
//     await contract.importSbp(plaintextPath);
//   } else {
//     // legacy plain .sbp path (existing flow)
//   }
export const Sbpx = {
    sniff: (path: string): Promise<boolean> =>
        invoke<boolean>('recipient_sbpx_sniff', { path }),
    import: (path: string): Promise<string> =>
        invoke<string>('recipient_import_sbpx', { path }),
};

// Pre-process a path returned by the system file picker. On Android
// the result is typically a `content://` SAF URI that std::fs cannot
// open; this command resolves it into a real file under the app's
// private staging dir and returns that real path. On desktop it is a
// no-op (the dialog plugin already yields real paths).
export const PickedFile = {
    stage: (path: string): Promise<string> =>
        invoke<string>('stage_picked_file', { path }),
};
