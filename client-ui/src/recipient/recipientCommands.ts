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
