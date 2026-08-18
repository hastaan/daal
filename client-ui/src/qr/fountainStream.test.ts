// fountainStream.test.ts — the buffering and the counters, which are
// what the person holding the phone actually reads.
//
// The end-to-end proof (real Go frames in, real Go decode out) is in
// tools/check-qr-send.mjs. These are the invariants that must hold
// without any toolchain at all.

import { describe, expect, it } from 'vitest';
import {
    BATCH_FRAMES,
    FPS_SLOW,
    FPS_STEADY,
    FrameStream,
    LOW_WATER,
    MAX_BUFFERED,
    QR_BLOCK_SIZE,
    QR_ECC,
    QR_FRAME_BYTES,
    QR_FRAME_CHARS,
    QR_VERSION,
    assertGeometry,
    framesPerPass,
    framesTypical,
} from './fountainStream';
import { byteModeCapacity } from './qrcodegen';

const frame = (i: number, k: number) => ({
    i,
    k,
    frame_b64: `f${i}`.padEnd(QR_FRAME_CHARS, 'a'),
});

describe('the pinned geometry', () => {
    it('holds a whole frame with headroom, and no smaller version would', () => {
        expect(QR_FRAME_BYTES).toBe(12 + QR_BLOCK_SIZE);
        expect(QR_FRAME_CHARS).toBe(144);
        expect(byteModeCapacity(QR_VERSION, QR_ECC)).toBeGreaterThanOrEqual(
            QR_FRAME_CHARS,
        );
        expect(byteModeCapacity(QR_VERSION - 1, QR_ECC)).toBeLessThan(
            QR_FRAME_CHARS,
        );
        expect(() => assertGeometry()).not.toThrow();
    });

    it('keeps the display slower than the camera it is aimed at', () => {
        // Phone cameras run at ~30 fps. Anything at or above ~10 fps
        // stops giving a scanner more than one settled exposure per
        // frame, which is the whole reliability argument.
        expect(FPS_STEADY).toBeLessThanOrEqual(6);
        expect(FPS_SLOW).toBeLessThan(FPS_STEADY);
    });
});

describe('framesPerPass', () => {
    it('is zero before k is known, so no progress is invented', () => {
        expect(framesPerPass(0)).toBe(0);
        expect(framesTypical(0)).toBe(0);
    });

    it('leaves room between "usually done" and "a whole pass"', () => {
        for (const k of [1, 11, 22, 64, 128, 192, 342, 5462]) {
            expect(framesTypical(k)).toBeLessThan(framesPerPass(k));
            // The pass has to beat the worst LT decode we measured
            // (4.6x k at small k, ~2.5x k above k=100).
            expect(framesPerPass(k)).toBeGreaterThanOrEqual(3 * k);
        }
    });
});

describe('FrameStream', () => {
    it('learns k from the first frame and never re-learns it', () => {
        const s = new FrameStream();
        expect(s.k).toBe(0);
        s.push(frame(0, 42));
        expect(s.k).toBe(42);
        s.push({ ...frame(1, 99) });
        expect(s.k).toBe(42);
    });

    it('shows each frame once while fresh ones are in hand', () => {
        const s = new FrameStream();
        for (let i = 0; i < 20; i++) s.push(frame(i, 5));
        const seen = new Set<string>();
        for (let i = 0; i < 20; i++) seen.add(s.next()!);
        expect(seen.size).toBe(20);
        expect(s.shown).toBe(20);
    });

    it('replays instead of freezing when the producer stalls', () => {
        const s = new FrameStream();
        for (let i = 0; i < 3; i++) s.push(frame(i, 5));
        const out: (string | null)[] = [];
        for (let i = 0; i < 9; i++) out.push(s.next());
        expect(out.every((x) => x !== null)).toBe(true);
        expect(new Set(out).size).toBe(3);
    });

    it('returns null only when nothing has ever arrived', () => {
        const s = new FrameStream();
        expect(s.next()).toBeNull();
    });

    it('asks for more only when it is running low', () => {
        const s = new FrameStream();
        expect(s.needsMore).toBe(true);
        for (let i = 0; i < LOW_WATER; i++) s.push(frame(i, 5));
        expect(s.needsMore).toBe(false);
        for (let i = 0; i < LOW_WATER; i++) s.next();
        expect(s.needsMore).toBe(true);
    });

    it('stays inside its memory budget for a pack of any size', () => {
        const s = new FrameStream();
        // Ten thousand frames arrive and only a quarter are shown —
        // the producer always wins, because it is a subprocess and the
        // display is a 5 fps timer.
        for (let i = 0; i < 10_000; i++) {
            s.push(frame(i, 5462));
            if (i % 4 === 0) expect(s.next()).not.toBeNull();
        }
        expect(s.pending).toBeLessThanOrEqual(MAX_BUFFERED);
        expect(s.shown).toBe(2500);
    });

    it('counts passes and position the way the screen reports them', () => {
        const s = new FrameStream();
        const k = 4;
        const per = framesPerPass(k); // 3*4 + 96 = 108
        for (let i = 0; i < per + 3; i++) s.push(frame(i, k));
        expect(s.pass).toBe(1);
        expect(s.positionInPass).toBe(0);
        for (let i = 0; i < per; i++) s.next();
        expect(s.positionInPass).toBe(per);
        expect(s.pass).toBe(1);
        expect(s.passComplete).toBe(true);
        s.next();
        expect(s.pass).toBe(2);
        expect(s.positionInPass).toBe(1);
    });

    it('sizes a batch so a request is never urgent', () => {
        // A batch must outlast the low-water mark by a wide margin,
        // otherwise the screen is always waiting on a subprocess.
        expect(BATCH_FRAMES).toBeGreaterThan(LOW_WATER * 2);
        expect(MAX_BUFFERED).toBeGreaterThan(BATCH_FRAMES * 2);
    });
});
