// paint.ts — put one fountain frame on a surface.
//
// Separated from the screen so the drawing itself can be tested: a
// correct encoder painted wrongly (missing quiet zone, fractional
// module size, inverted colours, themed background) is unreadable in
// exactly the same way a wrong encoder is, and only the encoder half
// would have been covered. `qr/paint.test.ts` paints through this
// function into a pixel buffer and reads it back with jsQR.

import { encodeText } from './qrcodegen';
import { QR_ECC, QR_VERSION } from './fountainStream';

/** The subset of CanvasRenderingContext2D this needs. `fillStyle` is
 *  widened to the canvas' own union type so a real 2D context is
 *  assignable, while a two-field stub in a test still satisfies it. */
export interface FillSurface {
    fillStyle: string | CanvasGradient | CanvasPattern;
    fillRect(x: number, y: number, w: number, h: number): void;
}

/** Quiet zone in modules. Four is what the spec requires; scanners
 *  that manage with less do so by luck, and this screen has no way to
 *  learn whether the one in front of it is lucky. */
export const QUIET_MODULES = 4;

/** Modules per side including the quiet zone, at the pinned version. */
export function paintedModules(): number {
    return 17 + 4 * QR_VERSION + 2 * QUIET_MODULES;
}

/**
 * Paint `frameB64` at `modulePx` device pixels per module.
 *
 * Always light-on-dark-free: pure white ground, pure black modules,
 * whatever the app theme is. A QR is not a themed element — a dark card
 * showing through the quiet zone is a scan failure, and the receiving
 * phone has no way to tell the user that is what went wrong.
 *
 * Throws if the frame does not fit the pinned QR version, rather than
 * silently drawing a bigger symbol: a mid-stream geometry change is
 * what breaks a camera's lock on the code.
 */
export function paintFrame(
    surface: FillSurface,
    frameB64: string,
    modulePx: number,
): { sidePx: number; symbolModules: number } {
    const code = encodeText(frameB64, QR_ECC, QR_VERSION);
    const modules = code.size + 2 * QUIET_MODULES;
    const sidePx = modules * modulePx;

    surface.fillStyle = '#ffffff';
    surface.fillRect(0, 0, sidePx, sidePx);
    surface.fillStyle = '#000000';
    for (let y = 0; y < code.size; y++) {
        for (let x = 0; x < code.size; x++) {
            if (!code.modules[y * code.size + x]) continue;
            surface.fillRect(
                (x + QUIET_MODULES) * modulePx,
                (y + QUIET_MODULES) * modulePx,
                modulePx,
                modulePx,
            );
        }
    }
    return { sidePx, symbolModules: code.size };
}

/**
 * Whole device pixels per module for a target CSS width. Fractional
 * module sizes are resampling blur on a symbol another camera has to
 * read, so this always rounds DOWN to an integer and never below 2.
 */
export function modulePxFor(targetCssPx: number, dpr: number): number {
    return Math.max(2, Math.floor((targetCssPx * dpr) / paintedModules()));
}
