// fountainStream.ts — the numbers, and the buffering, behind QR send.
//
// Everything here is deliberately free of React, of Tauri and of the
// DOM, because it is the half that can be tested without a camera:
// `tools/check-qr-send.mjs` runs this module under plain Node against
// frames produced by the REAL Go codec (`bundle/go/fountain`) and feeds
// what this module would put on screen back into the REAL Go decoder.
//
// ---------------------------------------------------------------
// THE PHYSICAL SITUATION DECIDES EVERY NUMBER BELOW
// ---------------------------------------------------------------
// One person holds a phone up to another person's phone. The screen may
// be cracked. The light is bad. Nobody can ask "did that work?" — there
// is no back-channel, which is the entire point of using a screen.
//
// QR_BLOCK_SIZE = 96 bytes of fountain payload per frame.
//   The codec adds a 12-byte header, so a frame is 108 bytes, and the
//   receiver expects it base64url-encoded (that is what
//   `daal-deploy qr-fountain` emits and what
//   `engine_fountain_feed_frame` eats), i.e. exactly 144 characters.
//   144 characters in byte mode at ECC Q fits QR version 10 with 7
//   characters of headroom — and, because the frame length never
//   varies, EVERY frame in a stream is version 10. That is the reason
//   for pinning a block size rather than maximising it: a constant
//   57x57 geometry means the receiving camera acquires the symbol once
//   and never has to re-acquire mid-stream. A bigger block would buy
//   fewer frames at the cost of a denser symbol (256-byte blocks land
//   at version 17, 85x85), and a denser symbol is the thing that fails
//   first on a cracked screen in bad light.
//
// QR_ECC = 'Q' (25% recovery).
//   The usual argument for the LOWEST error correction in an animated
//   QR is that the fountain code already recovers from a dropped frame,
//   so per-frame redundancy is wasted. That argument breaks on the
//   device we are actually aiming at. A crack, a scratch, a smear or a
//   glare hotspot occludes the SAME region of EVERY frame; the fountain
//   code cannot recover from damage that is identical on all frames,
//   because the frames all arrive equally broken. Only per-frame ECC
//   can. Q recovers a quarter of the symbol and costs one QR version
//   over M; H (30%) would cost two more versions (73x73) and give the
//   modules back to the crack. Q is the compromise that survives a
//   damaged screen without shrinking the modules into the noise.
//
// FPS_STEADY = 5 frames/second (200 ms per frame).
//   A phone camera runs at ~30 fps, so 200 ms is ~6 capture frames per
//   displayed symbol — enough for autofocus and auto-exposure to settle
//   and for at least one clean, unblurred capture. A software scanner
//   on a mid-range phone gets through roughly 10-20 decode attempts a
//   second on downscaled frames, so 5 fps gives every displayed frame
//   two or more decode attempts. Higher rates trade that margin for
//   throughput we do not need: the whole transfer is under two minutes
//   either way, and a transfer that fails silently costs far more than
//   a slow one.
//
// FPS_SLOW = 2.5 frames/second, offered as a switch on the screen for
//   cracked glass, dim rooms and older cameras. It is the honest thing
//   to expose given we cannot measure the receiver.

import type { Ecl } from './qrcodegen';
import { byteModeCapacity } from './qrcodegen';

/** Fountain payload bytes per frame. */
export const QR_BLOCK_SIZE = 96;

/** 12-byte fountain header + payload. */
export const QR_FRAME_BYTES = 12 + QR_BLOCK_SIZE;

/** base64url, unpadded — what the receiver is fed verbatim. */
export const QR_FRAME_CHARS = Math.ceil((QR_FRAME_BYTES * 4) / 3);

export const QR_ECC: Ecl = 'Q';

/** Pinned so every frame of a stream is the same size on screen. */
export const QR_VERSION = 10;

export const FPS_STEADY = 5;
export const FPS_SLOW = 2.5;

/**
 * Frames requested per `wizard_qr_render` call. Each call is a bounded
 * `daal-deploy qr-fountain` subprocess, so a finite batch is what stops
 * a closed screen from leaving an unbounded QR process alive; the
 * screen simply asks for the next batch before the current one runs
 * out. 180 frames is 36 s of steady playback — long enough that the
 * next request is never urgent, short enough that the process is gone
 * seconds after the screen closes.
 */
export const BATCH_FRAMES = 180;

/** Ask for the next batch once fewer than this many unseen remain. */
export const LOW_WATER = 60;

/** Hard cap on retained frames (~350 KB of strings at 144 chars). */
export const MAX_BUFFERED = 1200;

/** One JSON line of the `qr-fountain` stream, as Rust re-emits it. */
export interface FountainFrame {
    /** 0-based index within one `qr_render` call. */
    i: number;
    /** Source-block count. Same for every frame of a given pack. */
    k: number;
    /** base64url, unpadded. */
    frame_b64: string;
}

/**
 * How many frames one full pass shows: the point past which a receiver
 * that has been watching from the start has, in every decode we have
 * measured, finished.
 *
 * `3k + 96`, and it is measured, not guessed. Decoding the shipped Go
 * LT codec 300 times per size across payloads of 1-32 KB needed a
 * median of 1.2-1.5 x k frames — but the tail of belief propagation is
 * heavy, and the worst of 2,400 decodes ran to 4.5 x k on a small pack.
 * `3k + 96` covered every one of those worst cases. It is deliberately
 * the pessimistic number: overshooting costs the sender seconds,
 * stopping early costs the receiver the whole transfer.
 * `tools/check-qr-send.mjs` re-measures this against the real decoder
 * so the constant cannot rot.
 *
 * It is still guidance, not a promise. Only the RECEIVER knows when it
 * has decoded — there is no back-channel off a screen, which is the
 * whole reason this path exists — so the screen says so in as many
 * words and keeps looping until the sender stops it.
 */
export function framesPerPass(k: number): number {
    if (k <= 0) return 0;
    return 3 * k + 96;
}

/**
 * The point where most receivers are already done: at or above the
 * median decode across every size measured, and well below a full
 * pass. The screen marks it so a sender holding a phone steady gets
 * told "most phones have finished by now" instead of staring at a bar
 * that looks two-thirds empty when the transfer has in fact worked.
 */
export function framesTypical(k: number): number {
    if (k <= 0) return 0;
    return Math.ceil(1.6 * k) + 24;
}

/**
 * The buffer between a producer that emits frames as fast as a
 * subprocess can write them and a screen that shows 5 a second.
 *
 * Frames already shown are RECYCLED rather than dropped: if the
 * producer stalls (subprocess died, app backgrounded), replaying old
 * frames still helps a receiver that missed them the first time —
 * that is the property of a fountain code — and a frozen QR helps
 * nobody. The recycle path is what makes the screen survive a pack
 * needing thousands of frames on a fixed memory budget.
 */
export class FrameStream {
    /** Frames received and not yet shown. */
    private fresh: string[] = [];
    /** Frames already shown, oldest first, kept for replay. */
    private seen: string[] = [];
    /** Source-block count, learned from the first frame. 0 until then. */
    k = 0;
    /** Total frames put on screen, across passes. */
    shown = 0;
    /** Frames that arrived but did not fit the cap. */
    dropped = 0;

    push(frame: FountainFrame): void {
        if (this.k === 0 && frame.k > 0) this.k = frame.k;
        if (this.fresh.length + this.seen.length >= MAX_BUFFERED) {
            // Prefer new entropy over an old replayable frame, but
            // never grow without bound.
            if (this.seen.length > 0) this.seen.shift();
            else {
                this.dropped++;
                return;
            }
        }
        this.fresh.push(frame.frame_b64);
    }

    /** The next frame to display, or null when nothing has arrived yet. */
    next(): string | null {
        let s = this.fresh.shift();
        if (s === undefined) s = this.seen.shift();
        if (s === undefined) return null;
        this.seen.push(s);
        this.shown++;
        return s;
    }

    /** True when the screen should request another batch. */
    get needsMore(): boolean {
        return this.fresh.length < LOW_WATER;
    }

    /** Unseen frames in hand. */
    get pending(): number {
        return this.fresh.length;
    }

    /** 1-based pass number currently being shown. */
    get pass(): number {
        const per = framesPerPass(this.k);
        if (per === 0) return 1;
        return Math.floor(this.shown === 0 ? 0 : (this.shown - 1) / per) + 1;
    }

    /** 1-based position within the current pass; 0 before anything shows. */
    get positionInPass(): number {
        const per = framesPerPass(this.k);
        if (per === 0 || this.shown === 0) return 0;
        return ((this.shown - 1) % per) + 1;
    }

    /** True once at least one full pass has been displayed. */
    get passComplete(): boolean {
        const per = framesPerPass(this.k);
        return per > 0 && this.shown >= per;
    }
}

/**
 * Guard the pinned geometry at module load rather than discovering a
 * mismatch on a stranger's screen: if anyone changes the block size
 * without re-checking the QR version, this throws in the build and in
 * the check script instead of silently emitting frames of two
 * different sizes, which is precisely what breaks a camera lock.
 */
export function assertGeometry(): void {
    const cap = byteModeCapacity(QR_VERSION, QR_ECC);
    if (cap < QR_FRAME_CHARS) {
        throw new Error(
            `qr geometry: ${QR_FRAME_CHARS} chars do not fit version ` +
                `${QR_VERSION} at ECC ${QR_ECC} (cap ${cap})`,
        );
    }
    const smaller = byteModeCapacity(QR_VERSION - 1, QR_ECC);
    if (smaller >= QR_FRAME_CHARS) {
        throw new Error(
            `qr geometry: version ${QR_VERSION - 1} would also fit ` +
                `${QR_FRAME_CHARS} chars; pin the smaller version`,
        );
    }
}

assertGeometry();
