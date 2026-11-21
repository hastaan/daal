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
    /** Routes whose NEW signed endpoint was applied to access this
     *  device already held (a freshness merge). */
    Merged?: number;
    /** Routes of the pack that were NOT stored, and why. They are not
     *  routes on this device: nothing can list or select them. */
    Unavailable?: UnavailableRoute[] | null;
}

/** One pack route that did not become a route on the device. Mirrors
 *  `bundle/go/importer.UnavailableRoute`; `Reason` is one of
 *  `not_offered`, `no_credentials`, `needs_new_file`,
 *  `older_than_device`. */
export interface UnavailableRoute {
    RouteID: string;
    Family: string;
    Reason: string;
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

/** The reasons a pack route is left out, as the engine names them
 *  (bundle/go/importer: UnavailableNotOffered …). CLOSED: the sentence a
 *  person reads is chosen from OUR strings by one of these codes, and by
 *  nothing else.
 *
 *  Why that matters here in particular: `not_offered` is decided by a
 *  marker inside the route's profile, and profile bytes are not covered
 *  by the publisher's signature. Whoever can alter the file in transit
 *  can therefore choose the CODE — which only selects between two
 *  harmless sentences of ours — but must never be able to choose the
 *  WORDS. The marker also carries a free-text reason; it is not in the
 *  verdict, and nothing here would show it if it were. */
const UNAVAILABLE_REASONS = new Set([
    'not_offered',
    'no_credentials',
    'needs_new_file',
    'older_than_device',
    // A route whose add-on data (a CDN-fronted commitment) this build
    // cannot read: that route only, never the pack (optional add-ons §8).
    'needs_newer_app',
]);

/** The transport families a route can name. The family in a verdict
 *  comes from the signed manifest, but it is still a string from a
 *  file: only a name from this list is ever put on the screen, and
 *  anything else is described instead of quoted. */
const KNOWN_FAMILIES = new Set([
    'vless-reality',
    'websocket-tls',
    'naive',
    'hysteria2',
    'shadowsocks',
    'anytls',
    'tuic',
    'tor',
    'wireguard',
    'masque',
    'psiphon',
    'conjure',
]);

/** One plain-language line per pack route that was NOT added, for the
 *  surface that shows an import's result. Empty when the pack gave this
 *  device everything it lists.
 *
 *  These routes do not exist on the device — the engine never stores a
 *  route it cannot connect on — so this is the only place a person can
 *  learn that the file held fewer ways to connect than it could have,
 *  and whether that is something to ask the sender about.
 *
 *  Nothing from the file is displayed. The reason must be one of the
 *  closed codes above or the line is the generic sentence; the family
 *  must be a known family name or it is described generically. */
export function unavailableLines(
    t: (k: string) => string,
    v: ImportVerdict | null,
    familyLabel: (family: string) => string = (f) => f,
): string[] {
    const rows = Array.isArray(v?.Unavailable) ? v!.Unavailable! : [];
    return rows.map((r) => {
        const reason = typeof r?.Reason === 'string' && UNAVAILABLE_REASONS.has(r.Reason) ? r.Reason : 'other';
        const key = `add.unavailable.${reason}`;
        const copy = t(key);
        const template = copy && copy !== key ? copy : t('add.unavailable.other');
        const family =
            typeof r?.Family === 'string' && KNOWN_FAMILIES.has(r.Family)
                ? familyLabel(r.Family)
                : t('add.unavailable.family_other');
        return template.replace('{family}', family);
    });
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
