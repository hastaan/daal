// The completion path must be provably reachable.
//
// The bug this file exists to prevent: the TS mirror of the recipient
// session contract declared fields Rust never sent, so the completion
// check could never be true and a fully decoded scan hung forever with
// no error anywhere. TypeScript could not catch it — the mismatch is
// on the far side of `invoke()`. Only a runtime assertion can.

import { describe, expect, it } from 'vitest';
// Imported as a module (not read off disk) so this suite needs no Node
// types in the browser app's tsconfig.
import contractJson from '../../../client-shared/contracts/recipient-session-status-v1.json';
import {
    blocksRemaining,
    decodeProgress,
    isComplete,
    parseSessionStatus,
    SessionContractError,
} from './sessionStatus';

/** The same fixture the Rust tests assert against. */
const contract = contractJson as unknown as {
    incomplete: Record<string, unknown>;
    complete: Record<string, unknown>;
};

describe('the shared contract fixture', () => {
    it('parses as the shape the UI consumes', () => {
        const mid = parseSessionStatus(contract.incomplete);
        expect(mid.received).toBe(2);
        expect(mid.total_frames).toBe(7);
        expect(mid.complete).toBe(false);
        expect(mid.verdict).toBeNull();
    });

    // THE regression test. If this ever fails, a finished scan hangs.
    it('makes completion REACHABLE from a real completed status', () => {
        const done = parseSessionStatus(contract.complete);
        expect(isComplete(done)).toBe(true);
        expect(done.verdict).not.toBeNull();
        expect(done.bytes_decoded).toBeGreaterThan(0);
        expect(blocksRemaining(done)).toBe(0);
        expect(decodeProgress(done)).toBe(1);
    });

    it('reports decoder progress, not a spinner', () => {
        expect(decodeProgress(parseSessionStatus(contract.incomplete))).toBeCloseTo(2 / 7);
        expect(blocksRemaining(parseSessionStatus(contract.incomplete))).toBe(5);
        // Before the first frame the decoder does not know the size.
        expect(decodeProgress(null)).toBeNull();
        expect(
            decodeProgress(
                parseSessionStatus({ ...contract.incomplete, received: 0, total_frames: 0 }),
            ),
        ).toBeNull();
    });
});

describe('contract drift is loud, not silent', () => {
    // The exact historical shape: `{state, frames_in, bytes_decoded}`.
    // Under the old code this produced `undefined` everywhere and the
    // scan hung. It must now throw.
    it('rejects the old {state, frames_in} shape that caused the hang', () => {
        const legacy = {
            session_id: 'rs-1-2',
            state: 'complete',
            frames_in: 7,
            bytes_decoded: 1792,
        };
        expect(() => parseSessionStatus(legacy)).toThrow(SessionContractError);
    });

    it.each([
        ['missing complete', { session_id: 'a', received: 1, total_frames: 2, bytes_decoded: 0 }],
        ['missing received', { session_id: 'a', total_frames: 2, bytes_decoded: 0, complete: false }],
        ['missing total_frames', { session_id: 'a', received: 1, bytes_decoded: 0, complete: false }],
        ['missing bytes_decoded', { session_id: 'a', received: 1, total_frames: 2, complete: false }],
        ['missing session_id', { received: 1, total_frames: 2, bytes_decoded: 0, complete: false }],
        ['renamed complete', { session_id: 'a', received: 1, total_frames: 2, bytes_decoded: 0, done: true }],
    ])('rejects: %s', (_label, raw) => {
        expect(() => parseSessionStatus(raw)).toThrow(SessionContractError);
    });

    it('rejects a completion that could never be finalized', () => {
        // Rust refuses done-without-verdict; the UI must agree, or it
        // would show "complete" and then fail on finalize.
        expect(() =>
            parseSessionStatus({
                session_id: 'a',
                received: 2,
                total_frames: 2,
                bytes_decoded: 10,
                complete: true,
                verdict: null,
            }),
        ).toThrow(SessionContractError);
    });

    it.each([null, undefined, 42, 'nope'])('rejects non-objects: %s', (raw) => {
        expect(() => parseSessionStatus(raw)).toThrow(SessionContractError);
    });
});
