// The camera lane, proved without a camera.
//
// The fixture here is real: bundle/go/share renders REAL LT fountain
// frames (from bundle/go/fountain) through the same QR construction
// `EncodeFountainFrameQR` uses, and records the module grid a screen
// would display. This test scales that grid to pixels and decodes it
// with jsQR — the very library the scanner runs — then pushes the
// result through the same `normalizeFrameText` the camera loop calls.
//
// So the whole receive chain is exercised:
//
//   real frame -> real QR -> jsQR -> normalizeFrameText -> real frame
//
// If this passes, a scan that fails on real hardware is an optics or
// permissions problem, not a format problem.

import { describe, expect, it } from 'vitest';
import jsQR from 'jsqr';
import qrGolden from '../../../bundle/go/share/testdata/qr_frames_v1.json';
import goldenFrames from '../../../bundle/go/fountain/testdata/fountain_frames_v1.json';
import { normalizeFrameText } from './frames';

interface QRGolden {
    codes: { text: string; modules: string[] }[];
}
const golden = qrGolden as unknown as QRGolden;
const frames = goldenFrames as unknown as { frames_b64url: string[] };

/**
 * Paint a QR module grid into an RGBA buffer, the way a screen does.
 * `scale` is pixels per module; `quiet` adds extra white margin in
 * modules, because the fixture's own quiet zone is narrower than the
 * 4 modules the spec recommends.
 */
function render(
    modules: string[],
    scale = 8,
    quiet = 4,
): { data: Uint8ClampedArray; width: number; height: number } {
    const n = modules.length;
    const side = (n + quiet * 2) * scale;
    const data = new Uint8ClampedArray(side * side * 4).fill(255);
    for (let my = 0; my < n; my++) {
        for (let mx = 0; mx < n; mx++) {
            if (modules[my][mx] !== '1') continue;
            for (let dy = 0; dy < scale; dy++) {
                for (let dx = 0; dx < scale; dx++) {
                    const x = (mx + quiet) * scale + dx;
                    const y = (my + quiet) * scale + dy;
                    const i = (y * side + x) * 4;
                    data[i] = 0;
                    data[i + 1] = 0;
                    data[i + 2] = 0;
                    data[i + 3] = 255;
                }
            }
        }
    }
    return { data, width: side, height: side };
}

describe('real QR codes of real fountain frames', () => {
    it('the fixture holds genuine square module grids', () => {
        expect(golden.codes.length).toBeGreaterThan(1);
        for (const c of golden.codes) {
            expect(c.modules.length).toBeGreaterThan(20);
            for (const row of c.modules) {
                expect(row).toHaveLength(c.modules.length);
                expect(row).toMatch(/^[01]+$/);
            }
        }
    });

    it('encodes the same frames the fountain fixture carries', () => {
        golden.codes.forEach((c, i) => {
            expect(c.text).toBe(frames.frames_b64url[i]);
        });
    });

    // THE end-to-end proof.
    it('jsQR reads every code back to the exact frame the UI must send', () => {
        for (const c of golden.codes) {
            const { data, width, height } = render(c.modules);
            const code = jsQR(data, width, height, {
                inversionAttempts: 'dontInvert',
            });
            expect(code, `jsQR failed to read the QR for ${c.text.slice(0, 16)}…`).not.toBeNull();
            // Verbatim: the QR carries the frame text itself.
            expect(code!.data).toBe(c.text);
            // And the camera loop's transform must not disturb it.
            expect(normalizeFrameText(code!.data)).toBe(c.text);
        }
    });

    it('survives the scale a phone camera actually sees', () => {
        // A QR filling a modest part of the frame still has to read.
        for (const scale of [4, 6, 12]) {
            const c = golden.codes[0];
            const { data, width, height } = render(c.modules, scale);
            const code = jsQR(data, width, height, {
                inversionAttempts: 'dontInvert',
            });
            expect(code?.data, `failed at ${scale}px per module`).toBe(c.text);
        }
    });
});
