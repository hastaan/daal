// paint.test.ts — what the screen actually draws, read back by the
// same scanner the receiving side uses.
//
// The encoder being right is not enough: a symbol drawn without a
// quiet zone, at a fractional module size, or on a themed background
// is unreadable in precisely the way a wrong encoder is. So this paints
// through the SAME function the canvas calls, into a pixel buffer, and
// decodes the buffer with jsQR.

import { describe, expect, it } from 'vitest';
import jsQR from 'jsqr';
import { QUIET_MODULES, modulePxFor, paintFrame, paintedModules } from './paint';
import { QR_FRAME_CHARS, QR_VERSION } from './fountainStream';

/** A canvas stand-in that records pixels into an RGBA buffer. */
class PixelSurface {
    fillStyle: string | CanvasGradient | CanvasPattern = '#000000';
    readonly data: Uint8ClampedArray;
    constructor(readonly width: number) {
        this.data = new Uint8ClampedArray(width * width * 4).fill(0);
        // Alpha opaque everywhere; jsQR ignores it, but a real canvas
        // would be opaque and the fixture should not differ.
        for (let i = 3; i < this.data.length; i += 4) this.data[i] = 255;
    }
    fillRect(x: number, y: number, w: number, h: number): void {
        const dark = this.fillStyle === '#000000';
        const v = dark ? 0 : 255;
        for (let yy = y; yy < y + h; yy++) {
            for (let xx = x; xx < x + w; xx++) {
                if (xx < 0 || yy < 0 || xx >= this.width || yy >= this.width) continue;
                const p = (yy * this.width + xx) * 4;
                this.data[p] = v;
                this.data[p + 1] = v;
                this.data[p + 2] = v;
            }
        }
    }
    at(x: number, y: number): number {
        return this.data[(y * this.width + x) * 4];
    }
}

const sampleFrame = (seedIn: number): string => {
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let seed = seedIn;
    let out = '';
    for (let i = 0; i < QR_FRAME_CHARS; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        out += alphabet[Math.floor((seed / 0x7fffffff) * alphabet.length)];
    }
    return out;
};

describe('paintFrame', () => {
    it('draws a symbol jsQR reads back exactly', () => {
        const px = 4;
        for (let trial = 0; trial < 5; trial++) {
            const frame = sampleFrame(101 + trial * 7);
            const surface = new PixelSurface(paintedModules() * px);
            const { sidePx, symbolModules } = paintFrame(surface, frame, px);
            expect(symbolModules).toBe(17 + 4 * QR_VERSION);
            expect(sidePx).toBe(surface.width);
            const read = jsQR(surface.data, surface.width, surface.width);
            expect(read?.data).toBe(frame);
        }
    });

    it('leaves a full quiet zone of white on every side', () => {
        const px = 3;
        const surface = new PixelSurface(paintedModules() * px);
        paintFrame(surface, sampleFrame(5), px);
        const edge = QUIET_MODULES * px;
        const last = surface.width - 1;
        for (let i = 0; i < surface.width; i++) {
            for (let d = 0; d < edge; d++) {
                expect(surface.at(i, d)).toBe(255);
                expect(surface.at(i, last - d)).toBe(255);
                expect(surface.at(d, i)).toBe(255);
                expect(surface.at(last - d, i)).toBe(255);
            }
        }
    });

    it('refuses to paint something the pinned version cannot hold', () => {
        const surface = new PixelSurface(paintedModules() * 2);
        expect(() => paintFrame(surface, 'x'.repeat(400), 2)).toThrow();
    });
});

describe('modulePxFor', () => {
    it('always yields whole device pixels per module', () => {
        for (const dpr of [1, 1.5, 2, 2.625, 3, 3.5]) {
            for (const css of [200, 280, 340, 420]) {
                const px = modulePxFor(css, dpr);
                expect(Number.isInteger(px)).toBe(true);
                expect(px).toBeGreaterThanOrEqual(2);
                // Never overflow the space it was given.
                expect((px * paintedModules()) / dpr).toBeLessThanOrEqual(css);
            }
        }
    });

    it('keeps a phone-sized symbol comfortably above the scan floor', () => {
        // A 340 CSS px symbol on a 3x phone: 65 modules across, so a
        // camera filling half its frame with this still gets several
        // sensor pixels per module. Below ~4 device px per module the
        // symbol starts failing on cheap cameras.
        expect(modulePxFor(340, 3)).toBeGreaterThanOrEqual(4);
    });
});
