// sessionStatus.ts — the TS mirror of the recipient session contract.
//
// THE ONE TRUTH lives in Rust:
//   client-shell/tauri/src-tauri/src/recipient.rs :: struct SessionStatus
// and is written down for both languages in
//   client-shared/contracts/recipient-session-status-v1.json
//
// WHY THIS FILE VALIDATES INSTEAD OF JUST DECLARING
//
// This interface previously read `{ session_id, state, frames_in,
// bytes_decoded }` while Rust sent `{ session_id, received,
// total_frames, complete }`. TypeScript cannot see across the `invoke()`
// boundary, so every one of those fields was `undefined` at runtime and
// the completion check `state === 'complete'` could never be true. A
// scan would decode perfectly and then hang forever with no error.
//
// A type alone cannot prevent that recurring — only a runtime check can.
// `parseSessionStatus` therefore rejects anything that is not the
// contract, loudly, at the first frame rather than never.

/** Mirrors Rust `SessionStatus` field-for-field. */
export interface SessionStatus {
    session_id: string;
    /** Source blocks recovered so far (engine `progress`). */
    received: number;
    /** Source blocks required for a complete decode (engine `total`). */
    total_frames: number;
    /** Payload bytes recovered (engine `decoded_size`). */
    bytes_decoded: number;
    /** True once the fountain decoder has reconstructed the payload. */
    complete: boolean;
    /** Importer verdict; non-null exactly when `complete` is true. */
    verdict: unknown | null;
}

export class SessionContractError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SessionContractError';
    }
}

function num(o: Record<string, unknown>, key: string): number {
    const v = o[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new SessionContractError(
            `recipient session contract: expected numeric \`${key}\`, got ${JSON.stringify(v)}. ` +
                `The Rust SessionStatus and client-shared/contracts/recipient-session-status-v1.json have drifted.`,
        );
    }
    return v;
}

/**
 * Validate a raw `recipient_qr_*` result against the contract.
 * Throws `SessionContractError` rather than returning a half-read
 * object, because a half-read status is what made completion
 * unreachable in the first place.
 */
export function parseSessionStatus(raw: unknown): SessionStatus {
    if (raw === null || typeof raw !== 'object') {
        throw new SessionContractError(
            `recipient session contract: expected an object, got ${typeof raw}`,
        );
    }
    const o = raw as Record<string, unknown>;

    if (typeof o.session_id !== 'string' || o.session_id === '') {
        throw new SessionContractError(
            'recipient session contract: missing `session_id`',
        );
    }
    if (typeof o.complete !== 'boolean') {
        throw new SessionContractError(
            `recipient session contract: expected boolean \`complete\`, got ${JSON.stringify(
                o.complete,
            )}. This is the exact field whose absence used to make a finished scan hang.`,
        );
    }

    const status: SessionStatus = {
        session_id: o.session_id,
        received: num(o, 'received'),
        total_frames: num(o, 'total_frames'),
        bytes_decoded: num(o, 'bytes_decoded'),
        complete: o.complete,
        verdict: o.verdict ?? null,
    };

    // The engine only emits a verdict on completion, and Rust refuses a
    // done-without-verdict response. Mirror that invariant here so a
    // future regression cannot produce a "complete" the UI can never
    // finalize.
    if (status.complete && status.verdict === null) {
        throw new SessionContractError(
            'recipient session contract: complete=true with no verdict',
        );
    }
    return status;
}

/** The completion predicate. One place, so it cannot drift again. */
export function isComplete(s: SessionStatus): boolean {
    return s.complete;
}

/**
 * Fraction of the payload recovered, in [0,1], or null when the
 * decoder has not yet seen enough to know how big the payload is.
 *
 * This is the DECODER's progress (source blocks recovered / required),
 * not a count of frames the camera happened to see. Frames that carry
 * no new information move the camera counter and not this one — which
 * is precisely what the user needs to see when a scan is stalling.
 */
export function decodeProgress(s: SessionStatus | null): number | null {
    if (!s || s.total_frames <= 0) return null;
    return Math.min(1, s.received / s.total_frames);
}

/** Source blocks still missing, or null when not yet known. */
export function blocksRemaining(s: SessionStatus | null): number | null {
    if (!s || s.total_frames <= 0) return null;
    return Math.max(0, s.total_frames - s.received);
}
