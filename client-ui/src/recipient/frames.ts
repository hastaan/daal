// frames.ts — the wire format of one QR-fountain frame, on the UI side.
//
// A frame on the wire is the raw LT frame bytes encoded as base64url
// WITHOUT padding (Go `base64.RawURLEncoding`). That is what
// `bundle/go/share.EncodeFountainFrameQR` puts inside the QR, what
// `daal-deploy qr-fountain` prints as `frame_b64`, and what
// `core/abi/share.go FountainFeedFrame` decodes on the way in.
//
// THE btoa() BUG THIS FILE REPLACES
//
// The camera loop used to do:
//     btoa(unescape(encodeURIComponent(qr.rawValue)))
// `qr.rawValue` is ALREADY the base64url frame text. Wrapping it in
// btoa() base64-encoded the base64 a second time, so the engine
// received the ASCII of the encoding rather than the frame. Worse,
// btoa() emits the STANDARD alphabet ('+', '/', '='), which
// RawURLEncoding rejects outright — so even a single-encoded payload
// would have failed. The correct action is to forward rawValue
// verbatim (after validating it is in the wire alphabet at all).
//
// Everything here is pure and dependency-free so it can be tested
// without a camera, a Tauri host, or a DOM.

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export class FrameFormatError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'FrameFormatError';
    }
}

/** Encode bytes as base64url without padding (the wire format). */
export function b64urlEncode(bytes: Uint8Array): string {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url (or standard-base64) string to bytes.
 * Padding is optional. Throws `FrameFormatError` on anything else.
 */
export function b64urlDecode(s: string): Uint8Array {
    const canon = canonicalizeB64(s);
    // atob needs padding and the standard alphabet.
    const std = canon.replace(/-/g, '+').replace(/_/g, '/');
    const pad = std.length % 4 === 0 ? '' : '='.repeat(4 - (std.length % 4));
    let bin: string;
    try {
        bin = atob(std + pad);
    } catch {
        throw new FrameFormatError('not valid base64');
    }
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

/**
 * Normalise any base64-ish string into the canonical base64url,
 * no-padding form the engine accepts.
 *
 * Accepting the standard alphabet and stripping padding is a pure
 * widening: a frame copied through a tool that re-encoded it with
 * '+'/'/'/'=' still works, and nothing that used to be accepted stops
 * being accepted. Whitespace inside a line (line-wrapped pastes) is
 * removed. Anything left outside the alphabet is an error, not a
 * silent best effort.
 */
export function canonicalizeB64(s: string): string {
    const stripped = s.replace(/\s+/g, '').replace(/=+$/, '');
    if (stripped === '') throw new FrameFormatError('empty frame');
    const url = stripped.replace(/\+/g, '-').replace(/\//g, '_');
    if (!B64URL_RE.test(url)) {
        const bad = [...url].find((c) => !/[A-Za-z0-9_-]/.test(c));
        throw new FrameFormatError(
            `frame is not base64 (unexpected character ${JSON.stringify(bad)})`,
        );
    }
    // base64 length % 4 === 1 can never be produced by any encoder.
    if (url.length % 4 === 1) {
        throw new FrameFormatError('frame is truncated');
    }
    return url;
}

/**
 * Turn one scanned/pasted line into the exact string to hand to
 * `recipient_qr_feed_frame`, or throw.
 *
 * Two on-the-wire shapes are accepted:
 *   1. a bare base64url frame — what a QR carries;
 *   2. one JSON line from `daal-deploy qr-fountain`, i.e.
 *      {"i":3,"k":8,"frame_b64":"..."} — what the CLI prints, and
 *      therefore what lands in a saved frames file.
 */
export function normalizeFrameText(raw: string): string {
    const line = raw.trim();
    if (line === '') throw new FrameFormatError('empty frame');

    if (line.startsWith('{')) {
        let parsed: unknown;
        try {
            parsed = JSON.parse(line);
        } catch {
            throw new FrameFormatError('line looks like JSON but does not parse');
        }
        const obj = parsed as Record<string, unknown>;
        const v = obj?.frame_b64;
        if (typeof v !== 'string') {
            throw new FrameFormatError('JSON line has no string `frame_b64`');
        }
        return canonicalizeB64(v);
    }
    return canonicalizeB64(line);
}

export interface ParsedFrames {
    frames: string[];
    /** 1-based line numbers that were not usable, with the reason. */
    rejected: { line: number; reason: string }[];
}

/**
 * Parse a whole pasted blob or dropped file into frames.
 *
 * Unusable lines are REPORTED, not silently dropped — if a paste is
 * half-corrupt the user has to be told which part, otherwise the scan
 * just quietly never completes.
 */
export function parseFrameLines(text: string): ParsedFrames {
    const frames: string[] = [];
    const rejected: { line: number; reason: string }[] = [];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (line === '' || line.startsWith('#')) continue;
        try {
            frames.push(normalizeFrameText(line));
        } catch (e) {
            rejected.push({
                line: i + 1,
                reason: e instanceof Error ? e.message : String(e),
            });
        }
    }
    return { frames, rejected };
}
