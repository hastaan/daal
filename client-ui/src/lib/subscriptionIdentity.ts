// subscriptionIdentity — Gap 4-recipient bug fix.
//
// `engine.subscription_add` rejects an empty publisher_fingerprint:
//
//   core/refresh/subscription.go ~line 90:
//       if pubFp == "" { return errors.New("...") }
//
// The paste flow has no real publisher fingerprint to provide — the
// user just typed a URL. We synthesise a stable, deterministic id
// derived from the URL itself, so:
//
//   1. The same URL always produces the same id (idempotent add).
//   2. Different URLs don't collide.
//   3. The id has a recognisable prefix so the diagnostics blob and
//      the routestore's derive_tree group these rows visibly.
//
// The synthetic id is NOT a real cryptographic publisher identity —
// when the engine later receives a real signed-by-publisher
// subscription body, the importer's fingerprint reconciliation can
// upgrade these rows. Until then, this lets the paste-URL flow
// actually work.

/** Lowercase hex of SHA-256(input). 64 chars. */
async function sha256Hex(input: string): Promise<string> {
    const enc = new TextEncoder().encode(input);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    const bytes = new Uint8Array(buf);
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        const hex = bytes[i].toString(16);
        out += hex.length === 1 ? '0' + hex : hex;
    }
    return out;
}

/** Synthetic publisher fingerprint for a pasted subscription URL.
 *  Format: "sub:" + first 16 chars of sha256(url). The "sub:" prefix
 *  is the engine-visible marker; the truncated hash gives us
 *  collision-resistance for the per-device URL set.
 */
export async function syntheticSubscriptionFingerprint(url: string): Promise<string> {
    const trimmed = url.trim().toLowerCase();
    const hex = await sha256Hex(trimmed);
    return 'sub:' + hex.slice(0, 16);
}

/** Best-effort display name for a pasted URL: its host. Falls back
 *  to the trimmed URL itself if it doesn't parse. */
export function subscriptionDisplayName(url: string): string {
    const trimmed = url.trim();
    try {
        const u = new URL(trimmed);
        return u.host || trimmed;
    } catch {
        return trimmed;
    }
}
