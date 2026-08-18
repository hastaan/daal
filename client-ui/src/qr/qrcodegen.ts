// qrcodegen.ts — a complete, dependency-free QR Code encoder.
//
// WHY THIS FILE EXISTS AT ALL
//
// Daal is used in the places where fetching anything is the failure. A
// QR encoder pulled from a CDN at runtime, or a package whose install
// step needs a registry, is a transport that stops working exactly when
// the app is needed. So the encoder is source in this repository: it
// compiles into the same bundle as the rest of the UI, has zero imports,
// touches no network, no DOM and no globals, and works identically in
// the Tauri webview, in a browser preview and under plain Node (which is
// what lets `tools/check-qr-send.mjs` test it).
//
// It is a byte-mode-only implementation of ISO/IEC 18004, structured
// after Project Nayuki's QR Code generator (MIT) — the same algorithm,
// written out here rather than depended upon.
//
// Byte mode only, deliberately: every payload this app encodes is a
// base64url fountain frame, which contains lowercase letters, `-` and
// `_`, none of which exist in QR's alphanumeric alphabet. Adding the
// other modes would be untested code on a path nothing takes.
//
// The two capacity tables below are the load-bearing constants. They
// were not typed from memory: they were extracted from the version
// table of `github.com/skip2/go-qrcode` (already a dependency of
// bundle/go, so it was available offline) and are re-derived and
// re-compared on every run of `tools/check-qr-send.mjs`, which also
// compares finished matrices module-for-module against that library.

export type Ecl = 'L' | 'M' | 'Q' | 'H';

export interface QrCode {
    /** 1..40 */
    version: number;
    /** modules per side, excluding the quiet zone: 17 + 4*version */
    size: number;
    ecl: Ecl;
    /** 0..7 */
    mask: number;
    /** row-major `size*size`; 1 = dark module. */
    modules: Uint8Array;
}

const ECL_ORDER: Ecl[] = ['L', 'M', 'Q', 'H'];

/** Format-info bits per ECC level (not the same order as ECL_ORDER). */
const ECL_FORMAT_BITS: Record<Ecl, number> = { L: 1, M: 0, Q: 3, H: 2 };

/** Error-correction codewords per block, indexed [ecl][version-1]. */
const ECC_CODEWORDS_PER_BLOCK: Record<Ecl, number[]> = {
    L: [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30,
        28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
        30, 30, 30, 30],
    M: [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26,
        26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        28, 28, 28, 28],
    Q: [13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28,
        26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
        30, 30, 30, 30],
    H: [17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28,
        26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
        30, 30, 30, 30],
};

/** Number of error-correction blocks, indexed [ecl][version-1]. */
const NUM_ECC_BLOCKS: Record<Ecl, number[]> = {
    L: [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10,
        12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    M: [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17,
        17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47,
        49],
    Q: [1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23,
        23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65,
        68],
    H: [1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
        25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74,
        77, 81],
};

/** Total data modules for a version, before ECC — Annex D formula. */
function rawDataModules(version: number): number {
    let result = (16 * version + 128) * version + 64;
    if (version >= 2) {
        const numAlign = Math.floor(version / 7) + 2;
        result -= (25 * numAlign - 10) * numAlign - 55;
        if (version >= 7) result -= 36;
    }
    return result;
}

/** Data codewords (excluding ECC) available at this version + level. */
export function numDataCodewords(version: number, ecl: Ecl): number {
    return (
        Math.floor(rawDataModules(version) / 8) -
        ECC_CODEWORDS_PER_BLOCK[ecl][version - 1] *
            NUM_ECC_BLOCKS[ecl][version - 1]
    );
}

/** Byte-mode payload capacity, in bytes, at this version + level. */
export function byteModeCapacity(version: number, ecl: Ecl): number {
    const headerBits = 4 + (version <= 9 ? 8 : 16);
    return Math.floor((numDataCodewords(version, ecl) * 8 - headerBits) / 8);
}

/**
 * Smallest version that fits `byteLen` bytes at `ecl`, or 0 if it does
 * not fit at any version. Exported because the sender screen pins one
 * version for the whole stream and needs to assert that up front.
 */
export function smallestVersionFor(byteLen: number, ecl: Ecl): number {
    for (let v = 1; v <= 40; v++) {
        if (byteModeCapacity(v, ecl) >= byteLen) return v;
    }
    return 0;
}

// ---- GF(256) arithmetic -------------------------------------------

function gfMul(x: number, y: number): number {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
        z = (z << 1) ^ ((z >>> 7) * 0x11d);
        z ^= ((y >>> i) & 1) * x;
    }
    return z & 0xff;
}

function rsDivisor(degree: number): Uint8Array {
    const result = new Uint8Array(degree);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
        for (let j = 0; j < result.length; j++) {
            result[j] = gfMul(result[j], root);
            if (j + 1 < result.length) result[j] ^= result[j + 1];
        }
        root = gfMul(root, 0x02);
    }
    return result;
}

function rsRemainder(data: Uint8Array, divisor: Uint8Array): Uint8Array {
    const result = new Uint8Array(divisor.length);
    for (const b of data) {
        const factor = b ^ result[0];
        result.copyWithin(0, 1);
        result[result.length - 1] = 0;
        for (let i = 0; i < result.length; i++) {
            result[i] ^= gfMul(divisor[i], factor);
        }
    }
    return result;
}

// ---- bit stream ---------------------------------------------------

class BitBuffer {
    readonly bits: number[] = [];
    append(value: number, len: number): void {
        for (let i = len - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
    }
}

function getBit(x: number, i: number): boolean {
    return ((x >>> i) & 1) !== 0;
}

// ---- the encoder --------------------------------------------------

class Builder {
    readonly size: number;
    readonly modules: Uint8Array;
    private readonly isFunction: Uint8Array;

    constructor(readonly version: number, readonly ecl: Ecl) {
        this.size = version * 4 + 17;
        this.modules = new Uint8Array(this.size * this.size);
        this.isFunction = new Uint8Array(this.size * this.size);
    }

    private set(x: number, y: number, dark: boolean): void {
        this.modules[y * this.size + x] = dark ? 1 : 0;
        this.isFunction[y * this.size + x] = 1;
    }

    drawFunctionPatterns(): void {
        for (let i = 0; i < this.size; i++) {
            this.set(6, i, i % 2 === 0);
            this.set(i, 6, i % 2 === 0);
        }
        this.drawFinder(3, 3);
        this.drawFinder(this.size - 4, 3);
        this.drawFinder(3, this.size - 4);

        const align = alignmentPatternPositions(this.version);
        const n = align.length;
        for (let i = 0; i < n; i++) {
            for (let j = 0; j < n; j++) {
                // The three finder corners have no alignment pattern.
                if (
                    (i === 0 && j === 0) ||
                    (i === 0 && j === n - 1) ||
                    (i === n - 1 && j === 0)
                ) {
                    continue;
                }
                this.drawAlignment(align[i], align[j]);
            }
        }
        this.drawFormatBits(0);
        this.drawVersionBits();
    }

    private drawFinder(cx: number, cy: number): void {
        for (let dy = -4; dy <= 4; dy++) {
            for (let dx = -4; dx <= 4; dx++) {
                const dist = Math.max(Math.abs(dx), Math.abs(dy));
                const x = cx + dx;
                const y = cy + dy;
                if (x >= 0 && x < this.size && y >= 0 && y < this.size) {
                    this.set(x, y, dist !== 2 && dist !== 4);
                }
            }
        }
    }

    private drawAlignment(cx: number, cy: number): void {
        for (let dy = -2; dy <= 2; dy++) {
            for (let dx = -2; dx <= 2; dx++) {
                this.set(
                    cx + dx,
                    cy + dy,
                    Math.max(Math.abs(dx), Math.abs(dy)) !== 1,
                );
            }
        }
    }

    drawFormatBits(mask: number): void {
        const data = (ECL_FORMAT_BITS[this.ecl] << 3) | mask;
        let rem = data;
        for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
        const bits = ((data << 10) | rem) ^ 0x5412;

        for (let i = 0; i <= 5; i++) this.set(8, i, getBit(bits, i));
        this.set(8, 7, getBit(bits, 6));
        this.set(8, 8, getBit(bits, 7));
        this.set(7, 8, getBit(bits, 8));
        for (let i = 9; i < 15; i++) this.set(14 - i, 8, getBit(bits, i));

        for (let i = 0; i < 8; i++) {
            this.set(this.size - 1 - i, 8, getBit(bits, i));
        }
        for (let i = 8; i < 15; i++) {
            this.set(8, this.size - 15 + i, getBit(bits, i));
        }
        this.set(8, this.size - 8, true); // the always-dark module
    }

    private drawVersionBits(): void {
        if (this.version < 7) return;
        let rem = this.version;
        for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
        const bits = (this.version << 12) | rem;
        for (let i = 0; i < 18; i++) {
            const bit = getBit(bits, i);
            const a = this.size - 11 + (i % 3);
            const b = Math.floor(i / 3);
            this.set(a, b, bit);
            this.set(b, a, bit);
        }
    }

    drawCodewords(data: Uint8Array): void {
        let i = 0;
        for (let right = this.size - 1; right >= 1; right -= 2) {
            if (right === 6) right = 5;
            for (let vert = 0; vert < this.size; vert++) {
                for (let j = 0; j < 2; j++) {
                    const x = right - j;
                    const upward = ((right + 1) & 2) === 0;
                    const y = upward ? this.size - 1 - vert : vert;
                    const idx = y * this.size + x;
                    if (!this.isFunction[idx] && i < data.length * 8) {
                        this.modules[idx] = getBit(data[i >>> 3], 7 - (i & 7))
                            ? 1
                            : 0;
                        i++;
                    }
                    // Remaining modules stay light, per the spec's
                    // remainder-bit rule.
                }
            }
        }
    }

    applyMask(mask: number): void {
        for (let y = 0; y < this.size; y++) {
            for (let x = 0; x < this.size; x++) {
                const idx = y * this.size + x;
                if (this.isFunction[idx]) continue;
                if (maskAt(mask, x, y)) this.modules[idx] ^= 1;
            }
        }
    }

    /** ISO/IEC 18004 §8.8.2 penalty score of the current matrix. */
    penaltyScore(): number {
        const size = this.size;
        const at = (x: number, y: number) => this.modules[y * size + x] === 1;
        let result = 0;

        // Rule 1: runs of 5+ same-coloured modules in a line.
        for (let y = 0; y < size; y++) {
            let runColor = false;
            let runLen = 0;
            const runHistory = new Array<number>(7).fill(0);
            for (let x = 0; x < size; x++) {
                if (at(x, y) === runColor) {
                    runLen++;
                    if (runLen === 5) result += 3;
                    else if (runLen > 5) result++;
                } else {
                    this.finderPenaltyAddHistory(runLen, runHistory);
                    if (!runColor) {
                        result += this.finderPenaltyCountPatterns(runHistory) * 40;
                    }
                    runColor = at(x, y);
                    runLen = 1;
                }
            }
            result +=
                this.finderPenaltyTerminateAndCount(runColor, runLen, runHistory) *
                40;
        }
        for (let x = 0; x < size; x++) {
            let runColor = false;
            let runLen = 0;
            const runHistory = new Array<number>(7).fill(0);
            for (let y = 0; y < size; y++) {
                if (at(x, y) === runColor) {
                    runLen++;
                    if (runLen === 5) result += 3;
                    else if (runLen > 5) result++;
                } else {
                    this.finderPenaltyAddHistory(runLen, runHistory);
                    if (!runColor) {
                        result += this.finderPenaltyCountPatterns(runHistory) * 40;
                    }
                    runColor = at(x, y);
                    runLen = 1;
                }
            }
            result +=
                this.finderPenaltyTerminateAndCount(runColor, runLen, runHistory) *
                40;
        }

        // Rule 2: 2x2 blocks of one colour.
        for (let y = 0; y < size - 1; y++) {
            for (let x = 0; x < size - 1; x++) {
                const c = at(x, y);
                if (
                    c === at(x + 1, y) &&
                    c === at(x, y + 1) &&
                    c === at(x + 1, y + 1)
                ) {
                    result += 3;
                }
            }
        }

        // Rule 4: deviation of dark module proportion from 50%.
        let dark = 0;
        for (let i = 0; i < this.modules.length; i++) dark += this.modules[i];
        const total = size * size;
        const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
        result += k * 10;
        return result;
    }

    private finderPenaltyAddHistory(
        currentRunLength: number,
        runHistory: number[],
    ): void {
        if (runHistory[0] === 0) currentRunLength += this.size; // light margin
        runHistory.pop();
        runHistory.unshift(currentRunLength);
    }

    private finderPenaltyCountPatterns(runHistory: number[]): number {
        const n = runHistory[1];
        const core =
            n > 0 &&
            runHistory[2] === n &&
            runHistory[3] === n * 3 &&
            runHistory[4] === n &&
            runHistory[5] === n;
        return (
            (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) +
            (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0)
        );
    }

    private finderPenaltyTerminateAndCount(
        currentRunColor: boolean,
        currentRunLength: number,
        runHistory: number[],
    ): number {
        if (currentRunColor) {
            this.finderPenaltyAddHistory(currentRunLength, runHistory);
            currentRunLength = 0;
        }
        currentRunLength += this.size; // light margin
        this.finderPenaltyAddHistory(currentRunLength, runHistory);
        return this.finderPenaltyCountPatterns(runHistory);
    }
}

function maskAt(mask: number, x: number, y: number): boolean {
    switch (mask) {
        case 0:
            return (x + y) % 2 === 0;
        case 1:
            return y % 2 === 0;
        case 2:
            return x % 3 === 0;
        case 3:
            return (x + y) % 3 === 0;
        case 4:
            return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
        case 5:
            return ((x * y) % 2) + ((x * y) % 3) === 0;
        case 6:
            return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
        case 7:
            return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
        default:
            throw new Error(`qr: bad mask ${mask}`);
    }
}

function alignmentPatternPositions(version: number): number[] {
    if (version === 1) return [];
    const numAlign = Math.floor(version / 7) + 2;
    const step =
        version === 32
            ? 26
            : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
    const result: number[] = [6];
    for (let pos = version * 4 + 10; result.length < numAlign; pos -= step) {
        result.splice(1, 0, pos);
    }
    return result;
}

/** Split data into blocks, append ECC to each, interleave. */
function addEccAndInterleave(
    data: Uint8Array,
    version: number,
    ecl: Ecl,
): Uint8Array {
    const numBlocks = NUM_ECC_BLOCKS[ecl][version - 1];
    const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl][version - 1];
    const rawCodewords = Math.floor(rawDataModules(version) / 8);
    const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    const shortBlockLen = Math.floor(rawCodewords / numBlocks);

    // Every block is stored at the SAME length (shortBlockLen + 1).
    // Short blocks carry a zero padding byte at the last data index,
    // which the interleave below skips — that padding is what keeps the
    // column-major read below aligned across blocks of two lengths.
    const blockLen = shortBlockLen + 1;
    const blocks: Uint8Array[] = [];
    const divisor = rsDivisor(blockEccLen);
    for (let i = 0, k = 0; i < numBlocks; i++) {
        const datLen =
            shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
        const dat = data.subarray(k, k + datLen);
        k += datLen;
        const block = new Uint8Array(blockLen);
        block.set(dat, 0);
        block.set(rsRemainder(dat, divisor), blockLen - blockEccLen);
        blocks.push(block);
    }

    const result = new Uint8Array(rawCodewords);
    let outIdx = 0;
    for (let i = 0; i < blockLen; i++) {
        for (let j = 0; j < blocks.length; j++) {
            // Skip the padding byte that short blocks carry.
            if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) {
                result[outIdx++] = blocks[j][i];
            }
        }
    }
    return result;
}

/**
 * Encode `data` as a byte-mode QR Code.
 *
 * `forceVersion` pins the symbol geometry; the sender screen uses it so
 * every frame of a stream is the exact same size on screen and the
 * receiving camera never has to re-acquire. `forceMask` (0..7) exists
 * for tests; -1 selects the lowest-penalty mask as the spec requires.
 */
export function encodeBytes(
    data: Uint8Array,
    ecl: Ecl,
    forceVersion = 0,
    forceMask = -1,
): QrCode {
    let version = forceVersion;
    if (version === 0) {
        version = smallestVersionFor(data.length, ecl);
        if (version === 0) {
            throw new Error(
                `qr: ${data.length} bytes does not fit any version at ECC ${ecl}`,
            );
        }
    } else if (byteModeCapacity(version, ecl) < data.length) {
        throw new Error(
            `qr: ${data.length} bytes exceeds version ${version} ECC ${ecl} capacity ` +
                `(${byteModeCapacity(version, ecl)})`,
        );
    }

    // Bit stream: mode indicator, character count, payload.
    const bb = new BitBuffer();
    bb.append(0x4, 4);
    bb.append(data.length, version <= 9 ? 8 : 16);
    for (const b of data) bb.append(b, 8);

    const dataCapacityBits = numDataCodewords(version, ecl) * 8;
    // Terminator, then pad to a byte boundary, then alternating pad bytes.
    bb.append(0, Math.min(4, dataCapacityBits - bb.bits.length));
    bb.append(0, (8 - (bb.bits.length % 8)) % 8);
    for (let pad = 0xec; bb.bits.length < dataCapacityBits; pad ^= 0xec ^ 0x11) {
        bb.append(pad, 8);
    }

    const codewords = new Uint8Array(bb.bits.length >>> 3);
    bb.bits.forEach((bit, i) => {
        if (bit) codewords[i >>> 3] |= 0x80 >>> (i & 7);
    });

    const b = new Builder(version, ecl);
    b.drawFunctionPatterns();
    b.drawCodewords(addEccAndInterleave(codewords, version, ecl));

    let mask = forceMask;
    if (mask === -1) {
        let minPenalty = Infinity;
        for (let m = 0; m < 8; m++) {
            b.applyMask(m);
            b.drawFormatBits(m);
            const penalty = b.penaltyScore();
            if (penalty < minPenalty) {
                minPenalty = penalty;
                mask = m;
            }
            b.applyMask(m); // undo
        }
    }
    b.applyMask(mask);
    b.drawFormatBits(mask);

    return {
        version,
        size: b.size,
        ecl,
        mask,
        modules: b.modules,
    };
}

/** ASCII/latin-1 convenience wrapper. Throws above U+00FF. */
export function encodeText(
    text: string,
    ecl: Ecl,
    forceVersion = 0,
    forceMask = -1,
): QrCode {
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c > 0xff) {
            throw new Error('qr: encodeText is byte-oriented (latin-1 only)');
        }
        bytes[i] = c;
    }
    return encodeBytes(bytes, ecl, forceVersion, forceMask);
}

export const _internals = { ECL_ORDER, alignmentPatternPositions, rawDataModules };
