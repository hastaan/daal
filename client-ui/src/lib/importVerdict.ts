// importVerdict.ts — the ONE reading of an engine importer verdict.
//
// Three intake lanes end in the same JSON: the file picker and the
// base64 paste (`import_sbp` / `import_sbp_bytes`), and the animated-QR
// receive (`recipient_qr_finalize`). All three are handed a
// `bundle/go/importer.Verdict`, and all three must do the same three
// things with it:
//
//   Kind 1 — first-seen publisher. The EN+FA word grid MUST be shown
//            and `resolveTrustPrompt` MUST be called, or the routes
//            never commit and the bundle sits in the engine's pending
//            store forever. This is the NORMAL outcome offline: a pack
//            that arrives by QR or by chat is, by construction, from a
//            publisher this device has not seen.
//   Kind 3 — rejected. Say why, in the user's language.
//   else   — imported (or accepted via rotation). Refresh and close.
//
// It lived only inside AddSheet, so the QR lane — which had no copy of
// it — discarded the verdict, closed its sheet and asked the page to
// reload, showing the user nothing and committing nothing.

import type { PreviewedBundle, TrustDecision } from '../contract/D2Contract';

/** Verdict shape returned by the engine's importer ABI. Mirrors
 *  `bundle/go/importer.Verdict`. */
export interface ImportVerdict {
    Kind: number; // 0=Imported, 1=TrustPromptNeeded, 2=RotationAccepted, 3=Rejected
    Fingerprint?: string;
    /** Publisher fingerprint rendered with the AUTHORITATIVE wordlists
     *  (publisher.DefaultWordlists on the Go side). These are the words
     *  the publisher reads out; see `trustFromVerdict`. */
    HexEN?: string;
    HexFA?: string;
    BundleID?: string;
    RouteCount?: number;
    Reason?: string;
}

/** Engine VerdictKind enum (mirrors bundle/go/importer.VerdictKind):
 *  0 = Imported (silent), 1 = TrustPromptNeeded, 2 = RotationAccepted
 *  (silent), 3 = Rejected. Only the two non-silent kinds need
 *  branching logic. */
export const KIND_TRUST_PROMPT_NEEDED = 1;
export const KIND_REJECTED = 3;

/** Parse a verdict string, or null if the host returned something that
 *  is not a verdict (older ABI or an error path). Callers treat null as
 *  "silent success" so the desktop scenario does not regress. */
export function parseVerdict(raw: string): ImportVerdict | null {
    try {
        const v = JSON.parse(raw) as ImportVerdict;
        return v && typeof v.Kind === 'number' ? v : null;
    } catch {
        return null;
    }
}

/** Build the trust-prompt view from an engine verdict.
 *
 *  The word grid is the whole trust decision: the user reads it aloud
 *  and the publisher confirms it. It therefore has to be the grid the
 *  publisher sees. The engine renders it with the real EN/FA
 *  wordlists and returns it on the verdict, so whenever a verdict
 *  carries words they win over `previewBundle`'s — desktop-core's
 *  `preview_bundle` still renders with four-word PLACEHOLDER lists
 *  (see daal-desktop-core/src/commands.rs), which can never match
 *  what the publisher is reading. `base` supplies the fields the
 *  verdict has no opinion about (publisher name, visual grid). */
export function trustFromVerdict(
    base: PreviewedBundle | null,
    v: ImportVerdict,
): PreviewedBundle {
    return {
        fingerprintHex: v.Fingerprint || base?.fingerprintHex || '',
        fingerprintEN: v.HexEN || base?.fingerprintEN || '',
        fingerprintFA: v.HexFA || base?.fingerprintFA || '',
        fingerprintVisualDataUri: base?.fingerprintVisualDataUri || '',
        publisherName: base?.publisherName || '',
        bundleId: v.BundleID || base?.bundleId || '',
        specVersion: base?.specVersion ?? 0,
        routeCount: v.RouteCount ?? base?.routeCount ?? 0,
    };
}

/** Turn an engine rejection token into copy a person can act on.
 *
 *  An unrecognised token must NOT fall through verbatim. The tokens are
 *  Go identifiers — `lookup_failed`, `freshness_fp_mismatch` — and
 *  showing one to a Farsi reader produces an untranslated Latin string
 *  inside an RTL panel, with no action attached. The generic rejection
 *  copy is less specific but it is at least true and translated, and
 *  the caller still has the raw token on the verdict if it wants to
 *  show it as a diagnostic detail. */
export function friendlyReason(t: (k: string) => string, reason: string): string {
    if (!reason) return t('add.err.rejected');
    // Every relaypack failure carries its own RPxxx code; they share
    // one piece of user-facing copy.
    const token = reason.startsWith('relaypack_') ? 'relaypack_invalid' : reason;
    const copy = t(`add.err.reason.${token}`);
    if (copy && copy !== `add.err.reason.${token}`) return copy;
    return t('add.err.rejected');
}

/** Map a raw error message from the Tauri bridge into friendly copy.
 *
 *  The Rust side prefixes bundle-rs errors with their stable `code()`
 *  (e.g. `ErrInvalidSignature: invalid bundle signature`) so we can
 *  intercept and replace the user-facing text.
 *
 *  This lives in lib/ because THREE surfaces need it: the file picker
 *  and the paste box in AddSheet, and the QR-receive screen. The QR
 *  screen used to paint `e.message` verbatim, which is how Go's
 *  `illegal base64 data at input byte 7` ended up rendered in English,
 *  in a Latin string, inside a Farsi RTL panel.
 *
 *  Anything unrecognised still falls through unchanged: an untranslated
 *  message the user can quote is better than a generic one that hides
 *  which of a dozen bridge failures occurred. Callers that have a
 *  translated fallback should prefer it. */
export function friendlyError(t: (k: string) => string, raw: string): string {
    if (!raw) return raw;
    const m = raw.match(/^(Err[A-Z][A-Za-z]+):\s*/);
    if (m) {
        const key = `add.err.${m[1]}`;
        const copy = t(key);
        if (copy && copy !== key) return copy;
    }
    if (/alias not found/i.test(raw)) return t('add.err.identity_missing');
    if (/identity not yet created/i.test(raw)) return t('add.err.identity_missing');
    if (/device custody is locked/i.test(raw)) return t('add.err.custody_locked');
    if (/not an \.sbpx file/i.test(raw)) return t('add.err.not_envelope');
    if (/envelope corrupt or not addressed/i.test(raw))
        return t('add.err.envelope_corrupt');
    return raw;
}

/** What actually happened when the user answered the trust prompt.
 *
 *  `resolveTrustPrompt` is not a fire-and-forget notification — it is
 *  the call that COMMITS the routes, and it re-parses and re-verifies
 *  the pending bundle before doing so (importer.AcceptTrustPrompt). It
 *  can therefore reject at tap time: a revocation that arrived while
 *  the word grid was on screen, a bundle that expired in between, or a
 *  `save_failed` because the device is out of storage. It can also
 *  fail outright — the engine returns `abi: no pending prompt for <fp>`
 *  once the pending body is gone from memory and off disk.
 *
 *  TrustPrompt used to discard the return value AND swallow the
 *  exception, then report success regardless, so a rejected pack and a
 *  trusted pack looked identical on a screen whose entire premise is
 *  that they must not. */
export interface TrustResolution {
    decision: TrustDecision;
    /** Parsed verdict from `resolveTrustPrompt`, or null when the host
     *  returned something that is not a verdict (the harness backend
     *  returns a sentinel string). Null means "no opinion", which is
     *  treated as success so the dev/harness path does not regress. */
    verdict: ImportVerdict | null;
    /** Non-null when the resolve call itself threw. */
    error: string | null;
}

/** The user-facing failure for a trust resolution, or null if the
 *  routes really did commit (or the user deliberately cancelled).
 *
 *  Callers must report success ONLY when this returns null and the
 *  decision was not "cancel". */
export function trustFailure(
    t: (k: string) => string,
    r: TrustResolution,
): string | null {
    // Cancel is a choice, not a failure. The engine reports it as
    // Kind 3 / user_cancelled, which must not be shown as an error.
    if (r.decision === 2) return null;
    if (r.error) return friendlyError(t, r.error);
    if (r.verdict && r.verdict.Kind === KIND_REJECTED) {
        return friendlyReason(t, r.verdict.Reason || '');
    }
    return null;
}
