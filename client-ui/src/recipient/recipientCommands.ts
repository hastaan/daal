// recipientCommands.ts — thin wrappers around the 5 recipient_qr_*
// Tauri commands.

import { invoke } from '@tauri-apps/api/core';

export interface SessionStatus {
    session_id: string;
    state: string;
    frames_in: number;
    bytes_decoded: number;
    /** When non-empty, the engine has produced an importer verdict. */
    verdict?: string;
}

export const Recipient = {
    newSession: (): Promise<string> => invoke<string>('recipient_qr_session_new'),
    feedFrame: (
        session_id: string,
        index: number,
        total_frames: number,
        data_b64: string,
    ): Promise<SessionStatus> =>
        invoke<SessionStatus>('recipient_qr_feed_frame', {
            sessionId: session_id,
            index,
            totalFrames: total_frames,
            dataB64: data_b64,
        }),
    status: (session_id: string): Promise<SessionStatus> =>
        invoke<SessionStatus>('recipient_qr_status', { sessionId: session_id }),
    cancel: (session_id: string): Promise<void> =>
        invoke<void>('recipient_qr_cancel', { sessionId: session_id }),
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
    getOrCreate: (pin: string): Promise<RecipientIdentitySummary> =>
        invoke<RecipientIdentitySummary>('recipient_identity_get_or_create', { pin }),
};

// FRP-14 Layer 3d: recipient-side `.sbpx` import.
//
// Caller flow (file tab in AddEntryModal):
//   const isSbpx = await Sbpx.sniff(path);
//   if (isSbpx) {
//     const plaintextPath = await Sbpx.import(path, pin);
//     await contract.previewBundle(plaintextPath);
//     await contract.importSbp(plaintextPath);
//   } else {
//     // legacy plain .sbp path (existing flow)
//   }
export const Sbpx = {
    sniff: (path: string): Promise<boolean> =>
        invoke<boolean>('recipient_sbpx_sniff', { path }),
    import: (path: string, pin: string): Promise<string> =>
        invoke<string>('recipient_import_sbpx', { path, pin }),
};
