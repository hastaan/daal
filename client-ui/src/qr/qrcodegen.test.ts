// qrcodegen.test.ts — the parts of QR send that `npm test` can prove
// with no Go toolchain and no network.
//
// The deep comparison lives in `tools/check-qr-send.mjs`, which
// compares thousands of symbols against github.com/skip2/go-qrcode and
// drives the real Go fountain codec. What is here is the subset that
// must never need a toolchain to catch a regression:
//
//   * golden symbols captured FROM that independent implementation, so
//     a change to the tables, the Reed-Solomon maths, the interleave or
//     the module placement fails immediately;
//   * a round trip through jsQR — the same decoder the receiving half
//     of this feature uses — so "the scanner can read what we draw" is
//     asserted rather than assumed.

import { describe, expect, it } from 'vitest';
import jsQR from 'jsqr';
import {
    byteModeCapacity,
    encodeText,
    numDataCodewords,
    smallestVersionFor,
    type Ecl,
} from './qrcodegen';
import { QR_ECC, QR_FRAME_CHARS, QR_VERSION } from './fountainStream';

const GOLDEN = [
    {
        text: "hello daal",
        ecl: 'M' as Ecl,
        version: 1,
        mask: 2,
        // Produced by github.com/skip2/go-qrcode, an independent
        // implementation, via tools/check-qr-send.mjs.
        modules:
            "111111100010001111111100000100010001000001101110101110001011101101110101000001011101101110101101101011101100000101000101000001111111101010101111111000000001001100000000101111100110101111100001101011010100111101100100101001010001110001110001110010101100011001111001001000001000000001011100111001111111100100110000110100000101011110101101101110101000101100001101110101010111111000101110101111000100100100000100010000011100111111101111000010010",
    },
    {
        text: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
        ecl: 'L' as Ecl,
        version: 4,
        mask: 2,
        // Produced by github.com/skip2/go-qrcode, an independent
        // implementation, via tools/check-qr-send.mjs.
        modules:
            "111111100100010010011101001111111100000101101100111101000001000001101110100111000010100100101011101101110101101011101001010101011101101110100010110010011101001011101100000101010000101100000101000001111111101010101010101010101111111000000000000101010000111100000000111110111110111101001011010101010110111010100010010011101011001101111000110101110110001110000011110000110010111000110111100100011100111101101101011101010011010110010110000000110110010011101011001101000011111110010100000110100110010001011001010101110011110110011111001010110100111101010011010110000001111001010010010011101011001101000110101111101111001010000001010000100000001000000101101001011101110100110001000101010010010110000100010001000110010011101011000001100001101100011101000010100100110101110011010110000001111011011110100100111110101101010010111110000000000001100000011011001100010001111111101001100110101101101011110100000100101001100110101100011100101110101111000101010010111110000101110101010111011011001110110000101110101110011100100101111000010100000101000110000010111010011100111111101010101011010011100110010",
    },];

/** Render a symbol the way the screen does, as an RGBA image. */
function renderRgba(
    modules: Uint8Array,
    size: number,
    quiet = 4,
    scale = 4,
): { data: Uint8ClampedArray; width: number } {
    const width = (size + 2 * quiet) * scale;
    const data = new Uint8ClampedArray(width * width * 4).fill(255);
    for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
            if (!modules[y * size + x]) continue;
            for (let dy = 0; dy < scale; dy++) {
                for (let dx = 0; dx < scale; dx++) {
                    const px =
                        ((y + quiet) * scale + dy) * width +
                        ((x + quiet) * scale + dx);
                    data[px * 4] = 0;
                    data[px * 4 + 1] = 0;
                    data[px * 4 + 2] = 0;
                }
            }
        }
    }
    return { data, width };
}

describe('qrcodegen', () => {
    it('reproduces symbols from an independent implementation', () => {
        for (const g of GOLDEN) {
            const code = encodeText(g.text, g.ecl, g.version, g.mask);
            expect(code.size).toBe(17 + 4 * g.version);
            expect(Array.from(code.modules).join('')).toBe(g.modules);
        }
    });

    it('picks the same version those golden symbols used', () => {
        for (const g of GOLDEN) {
            expect(smallestVersionFor(g.text.length, g.ecl)).toBe(g.version);
        }
    });

    it('agrees with the standard on a few capacity anchors', () => {
        // Version 1-L is 19 data codewords; version 40-H is 1276. Both
        // are quoted constants of ISO/IEC 18004, so a table typo shows
        // up here without a toolchain.
        expect(numDataCodewords(1, 'L')).toBe(19);
        expect(numDataCodewords(1, 'H')).toBe(9);
        expect(numDataCodewords(40, 'L')).toBe(2956);
        expect(numDataCodewords(40, 'H')).toBe(1276);
        expect(byteModeCapacity(40, 'L')).toBe(2953);
    });

    it('refuses a payload that does not fit the pinned version', () => {
        const tooBig = 'a'.repeat(byteModeCapacity(QR_VERSION, QR_ECC) + 1);
        expect(() => encodeText(tooBig, QR_ECC, QR_VERSION)).toThrow();
    });

    it('is read back character-for-character by jsQR', () => {
        // Shaped like a real fountain frame: 144 base64url characters.
        const alphabet =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        let seed = 7;
        const rand = () => {
            seed = (seed * 1103515245 + 12345) & 0x7fffffff;
            return seed / 0x7fffffff;
        };
        for (let trial = 0; trial < 8; trial++) {
            let frame = '';
            for (let i = 0; i < QR_FRAME_CHARS; i++) {
                frame += alphabet[Math.floor(rand() * alphabet.length)];
            }
            const code = encodeText(frame, QR_ECC, QR_VERSION);
            expect(code.version).toBe(QR_VERSION);
            const { data, width } = renderRgba(code.modules, code.size);
            const read = jsQR(data, width, width);
            expect(read?.data).toBe(frame);
        }
    });
});
