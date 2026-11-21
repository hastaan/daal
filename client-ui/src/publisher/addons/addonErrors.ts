// addonErrors.ts — what an add-on command's failure means, in words.
//
// The Rust side prefixes every refusal with a stable code
// (`E_STANDBY_LIMIT: …`). The add-on codes live in the add-on modules
// (addon_standby.rs, addon_cdn.rs, addon_google.rs); the shared ones in
// wizardCommands.ts. This file knows both, so a row can say what
// happened in one line and keep the raw text for Details only.
//
// E_STANDBY_OPEN_REFUSED is not here: the UI only ever asks for a sealed
// standby, so the shell has no reason to answer it.

import { classifyPublisherError } from '../wizardCommands';

/** Every code an add-on module can answer, besides the shared ones. */
export const ADDON_ERROR_CODES = [
    // addon_standby.rs
    'E_STANDBY_LIMIT',
    'E_STANDBY_STILL_BILLING',
    'E_STANDBY_NOT_PUBLISHED',
    // addon_cdn.rs
    'E_CDN_NO_TOKEN',
    'E_CDN_NEEDS_REBUILD',
    'E_CDN_TEST_FAILED',
    'E_CDN_LEFT_BEHIND',
    'E_CDN_PROVISION',
    // addon_google.rs
    'E_GOOGLE_NOT_CONFIGURED',
    'E_GOOGLE_API_NOT_ENABLED',
    'E_GOOGLE_UNAUTHORIZED',
    'E_GOOGLE_SIGN_IN_CANCELLED',
    'E_GOOGLE_PARTIAL',
    'E_GOOGLE_API',
    'E_GOOGLE_BAD_ADDRESS',
    'E_GOOGLE_CHECK_FAILED',
] as const;

export type AddonErrorCode = (typeof ADDON_ERROR_CODES)[number];

/** The shared codes an add-on card has its own sentence for. Anything
 *  else falls to `pub.addons.err.other` with the raw text in Details. */
export const SHARED_CODES_WITH_COPY = [
    'E_NOT_BUILT',
    'E_DEPLOY_TOO_OLD',
    'E_RELAY_TOO_OLD',
    'E_RELAY_UNREACHABLE',
    'E_CUSTODY_LOCKED',
    'E_SECRET_MISSING',
    'E_HELPER_IP_MISSING',
    'E_NOT_SUPPORTED',
] as const;

function messageOf(e: unknown): string {
    return typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
}

/** The stable code at the front of a refusal, or null. */
export function classifyAddonError(e: unknown): string | null {
    const msg = messageOf(e);
    for (const c of ADDON_ERROR_CODES) {
        // `E_GOOGLE_API` is a prefix of `E_GOOGLE_API_NOT_ENABLED`: the
        // code ends at the colon.
        if (msg.startsWith(`${c}:`) || msg === c) return c;
    }
    const shared = classifyPublisherError(e);
    if (shared === 'E_HELPER_IP_STALE') return 'E_HELPER_IP_MISSING';
    return shared;
}

export interface AddonErrorText {
    code: string | null;
    /** The sentence for the card. */
    line: string;
    /** The raw text, for the Details fold only. */
    detail: string;
}

/** What to show for a failed add-on command. */
export function addonErrorText(t: (k: string) => string, e: unknown): AddonErrorText {
    const code = classifyAddonError(e);
    const raw = messageOf(e);
    const known =
        code != null &&
        ((ADDON_ERROR_CODES as readonly string[]).includes(code) ||
            (SHARED_CODES_WITH_COPY as readonly string[]).includes(code));
    let line = t(known ? `pub.addons.err.${code}` : 'pub.addons.err.other');
    if (code === 'E_GOOGLE_CHECK_FAILED') {
        // The tail starts with the check's reason word.
        const reason = raw.replace(/^E_GOOGLE_CHECK_FAILED:\s*/, '').split(/[:\s]/)[0] ?? '';
        const rk = `pub.addons.google.reason.${reason}`;
        const r = t(rk);
        if (r && r !== rk) line = `${line} ${r}`;
    }
    return { code, line, detail: raw };
}

/** "€3.00" / "۳٫۰۰ یورو" from cents and an ISO currency. The digits
 *  follow the catalogue the caller's `t` reads. */
export function money(t: (k: string) => string, cents: number, currency: string): string {
    const persian = /[؀-ۿ]/.test(t('pub.addons.title'));
    let amount = (Math.max(0, cents) / 100).toFixed(2);
    if (persian) {
        amount = amount.replace('.', '٫').replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);
    }
    const cur = (currency || '').toUpperCase();
    const key = cur === 'EUR' || cur === 'USD' ? `pub.addons.money.${cur}` : 'pub.addons.money.other';
    return t(key).replace('{amount}', amount).replace('{currency}', cur);
}
