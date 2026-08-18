// pastedBundle.ts — "is there a Daal bundle in what the user pasted?"
//
// This is the UI-side twin of `daal-wizard/src/recipient_paste.rs`. It
// answers ONLY the display question — which pill to show and whether
// the Import button is live. It never decodes, never verifies, and is
// never trusted: the Rust decoder re-derives everything from the same
// raw text, and the signature/revocation/expiry verdict comes from the
// engine. If the two ever disagree, Rust wins and the user sees the
// engine's error.
//
// Keep the two in step. The rules are, in both places:
//
//   • whitespace, `=`, soft hyphen, zero-width characters, the BOM and
//     the bidi control marks are dropped WITHOUT breaking the blob —
//     that is what makes a hard-wrapped, RTL-chat-mangled paste work;
//   • `-` and `_` are read as the URL-safe alphabet's `+` and `/`;
//   • anything else ends the current run of base64, so a sentence or a
//     typed `daal:` prefix in front of the blob is simply skipped;
//   • the blob is located by the base64 spelling of the container
//     magic, which is fixed because the magic starts the file:
//     `.sbp` is a zip (`PK\x03\x04` → `UEsDB…`) and `.sbpx` is the
//     sealed envelope (`DSBP\x00\x01` → `RFNCUAAB…`).

/** base64 of the first bytes of a `.sbp` (zip local file header). */
const SBP_B64_PREFIX = 'UEsDB';
/** base64 of the first bytes of a `.sbpx` (envelope magic). */
const SBPX_B64_PREFIX = 'RFNCUAAB';

/** Characters dropped without ending a run — transport damage, not
 *  content. Mirrors `is_joiner` in recipient_paste.rs. */
const JOINER =
    /[\s=\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;

const BASE64_CHAR = /[A-Za-z0-9+/]/;

export type PastedContainer = 'sbp' | 'sbpx' | null;

/** Split the text into runs of base64 symbols, normalising the
 *  URL-safe alphabet and swallowing joiners. */
function base64Runs(text: string): string[] {
    const runs: string[] = [];
    let cur = '';
    for (const ch of text) {
        if (JOINER.test(ch)) continue;
        const mapped = ch === '-' ? '+' : ch === '_' ? '/' : ch;
        if (BASE64_CHAR.test(mapped)) {
            cur += mapped;
        } else if (cur) {
            runs.push(cur);
            cur = '';
        }
    }
    if (cur) runs.push(cur);
    return runs;
}

/** Which Daal container the pasted text appears to hold, or null.
 *  Longest match wins so a stray `UEsDB` inside prose cannot beat the
 *  real payload. */
export function detectPastedContainer(text: string): PastedContainer {
    let best: { kind: PastedContainer; len: number } = { kind: null, len: 0 };
    for (const run of base64Runs(text)) {
        for (const [prefix, kind] of [
            [SBPX_B64_PREFIX, 'sbpx'],
            [SBP_B64_PREFIX, 'sbp'],
        ] as const) {
            const i = run.indexOf(prefix);
            if (i < 0) continue;
            const len = run.length - i;
            if (len > best.len) best = { kind, len };
        }
    }
    return best.kind;
}
