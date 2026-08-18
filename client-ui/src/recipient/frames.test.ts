// Sender/receiver compatibility, proved without a camera.
//
// The fixture read here is produced by the REAL LT encoder in
// bundle/go/fountain (see golden_frames_test.go, which regenerates it
// with `-update-golden` and separately proves the same frames decode
// back to the payload through the real Go decoder).
//
// So: Go proves the frames decode. This file proves the UI forwards
// exactly those bytes. Together that is an end-to-end compatibility
// proof for the QR lane with no camera, no second phone and no
// running app.

import { describe, expect, it } from 'vitest';
// Imported as a module (not read off disk) so this suite needs no Node
// types in the browser app's tsconfig.
import goldenJson from '../../../bundle/go/fountain/testdata/fountain_frames_v1.json';
import {
    b64urlDecode,
    b64urlEncode,
    canonicalizeB64,
    FrameFormatError,
    normalizeFrameText,
    parseFrameLines,
} from './frames';

interface Golden {
    payload_hex: string;
    block_size: number;
    source_blocks: number;
    frames_b64url: string[];
    frames_hex: string[];
}

const golden = goldenJson as unknown as Golden;

const toHex = (b: Uint8Array) =>
    [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const fromHex = (h: string) =>
    new Uint8Array((h.match(/../g) ?? []).map((p) => parseInt(p, 16)));

describe('real frames from bundle/go/fountain', () => {
    it('the fixture is a genuine multi-frame set', () => {
        expect(golden.frames_b64url.length).toBeGreaterThan(1);
        expect(golden.frames_b64url).toHaveLength(golden.frames_hex.length);
        expect(golden.source_blocks).toBeGreaterThan(1);
    });

    it('decodes every frame to exactly the bytes Go encoded', () => {
        golden.frames_b64url.forEach((f, i) => {
            expect(toHex(b64urlDecode(f))).toBe(golden.frames_hex[i]);
        });
    });

    it('round-trips every frame back to the identical wire string', () => {
        golden.frames_b64url.forEach((f, i) => {
            expect(b64urlEncode(fromHex(golden.frames_hex[i]))).toBe(f);
        });
    });

    // The frame text a QR carries must be forwarded VERBATIM. This is
    // the btoa() double-encode regression test.
    it('forwards a scanned frame unchanged', () => {
        for (const f of golden.frames_b64url) {
            expect(normalizeFrameText(f)).toBe(f);
        }
    });

    it('btoa() around a scanned frame would have corrupted it', () => {
        const f = golden.frames_b64url[0];
        // Exactly what the camera loop used to send.
        const doubleEncoded = btoa(unescape(encodeURIComponent(f)));
        expect(doubleEncoded).not.toBe(f);
        // It is ~4/3 the size, because it encodes the ENCODING.
        expect(doubleEncoded.length).toBeGreaterThan(f.length);
        // The fatal part: what the engine would decode is the ASCII of
        // the frame text, not the frame bytes. The LT decoder would
        // read a garbage 12-byte header off it.
        expect(toHex(b64urlDecode(doubleEncoded))).not.toBe(golden.frames_hex[0]);
        expect(new TextDecoder().decode(b64urlDecode(doubleEncoded))).toBe(f);

        // Concretely: the LT header the decoder would read off those
        // bytes is nonsense. Bytes 0..3 are the payload length, and
        // the double-encoded frame claims a wildly different one.
        const bogus = b64urlDecode(doubleEncoded);
        const claimed =
            bogus[0] | (bogus[1] << 8) | (bogus[2] << 16) | (bogus[3] << 24);
        expect(claimed).not.toBe(golden.payload_hex.length / 2);
    });

    it('carries a payload of the size the header claims', () => {
        // bytes 0..3 of every frame are the payload length, LE.
        const payloadLen = golden.payload_hex.length / 2;
        for (const hex of golden.frames_hex) {
            const b = fromHex(hex);
            const len = b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
            expect(len).toBe(payloadLen);
            expect(b[4] | (b[5] << 8)).toBe(golden.block_size);
        }
    });
});

describe('base64url round-trip on real bytes', () => {
    it('survives every byte value', () => {
        const all = new Uint8Array(256);
        for (let i = 0; i < 256; i++) all[i] = i;
        expect(b64urlDecode(b64urlEncode(all))).toEqual(all);
    });

    it.each([1, 2, 3, 4, 5, 17, 63, 64, 65, 255, 1024])(
        'survives a %i-byte payload (all padding alignments)',
        (n) => {
            const b = new Uint8Array(n);
            for (let i = 0; i < n; i++) b[i] = (i * 37 + 11) & 0xff;
            const enc = b64urlEncode(b);
            expect(enc).not.toMatch(/[+/=]/);
            expect(b64urlDecode(enc)).toEqual(b);
        },
    );

    it('encodes nothing to nothing, and refuses to call that a frame', () => {
        expect(b64urlEncode(new Uint8Array(0))).toBe('');
        // An empty frame is not a frame; it must not be fed onward.
        expect(() => canonicalizeB64('')).toThrow(FrameFormatError);
    });

    it('accepts standard-alphabet and padded input too', () => {
        const bytes = fromHex(golden.frames_hex[0]);
        const std = btoa(String.fromCharCode(...bytes)); // '+', '/', '='
        expect(b64urlDecode(std)).toEqual(bytes);
        expect(canonicalizeB64(std)).toBe(golden.frames_b64url[0]);
    });

    it('tolerates line-wrapped whitespace inside a frame', () => {
        const f = golden.frames_b64url[0];
        const wrapped = `${f.slice(0, 20)}\n  ${f.slice(20)}`;
        expect(canonicalizeB64(wrapped)).toBe(f);
    });
});

describe('bad input is refused, not silently mangled', () => {
    it.each([
        ['empty', ''],
        ['whitespace only', '   \n '],
        ['illegal characters', 'abcd$$$$'],
        ['truncated length', 'abcde'],
    ])('rejects %s', (_l, raw) => {
        expect(() => canonicalizeB64(raw)).toThrow(FrameFormatError);
    });
});

describe('paste and file input', () => {
    it('reads a plain frames file', () => {
        const { frames, rejected } = parseFrameLines(golden.frames_b64url.join('\n'));
        expect(frames).toEqual(golden.frames_b64url);
        expect(rejected).toHaveLength(0);
    });

    // `daal-deploy qr-fountain` prints JSON lines, so a saved frames
    // file is JSON lines. Accepting them means the CLI's own output
    // can be pasted straight in.
    it('reads the JSON lines daal-deploy qr-fountain prints', () => {
        const jsonl = golden.frames_b64url
            .map((f, i) => JSON.stringify({ i, k: golden.source_blocks, frame_b64: f }))
            .join('\n');
        const { frames, rejected } = parseFrameLines(jsonl);
        expect(frames).toEqual(golden.frames_b64url);
        expect(rejected).toHaveLength(0);
    });

    it('skips blanks and comments', () => {
        const text = ['# frames', '', golden.frames_b64url[0], '  ', golden.frames_b64url[1]].join(
            '\n',
        );
        expect(parseFrameLines(text).frames).toEqual(golden.frames_b64url.slice(0, 2));
    });

    // A half-corrupt paste must say which lines were dropped, or the
    // scan just quietly never completes.
    it('reports unusable lines instead of dropping them silently', () => {
        const text = [golden.frames_b64url[0], 'not a frame $$$', golden.frames_b64url[1]].join(
            '\n',
        );
        const { frames, rejected } = parseFrameLines(text);
        expect(frames).toHaveLength(2);
        expect(rejected).toHaveLength(1);
        expect(rejected[0].line).toBe(2);
        expect(rejected[0].reason).toMatch(/base64/);
    });

    it('rejects a JSON line with no frame_b64', () => {
        expect(() => normalizeFrameText('{"i":1,"k":8}')).toThrow(FrameFormatError);
    });
});
