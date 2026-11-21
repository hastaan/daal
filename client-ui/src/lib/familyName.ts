// The readable name of a kind of connection ("VLESS Reality", "Hysteria
// 2"), from the engine's family token ("vless-reality", "hysteria2").
//
// People in Iran know these names (V2Ray clients print them), so the
// main screen says which kind of connection is in use instead of an id.
// Only a token on this list is ever put on the screen; anything else
// is "undefined" here and the caller says nothing about the kind (a
// family string comes from a file, and a file is not trusted to choose
// words for the page).
//
// The words live in the catalog as `network.family.<token>` (dashes as
// underscores), the same keys the Files page reads for a way with no
// name of its own.

const KNOWN = new Set([
    'vless-reality',
    'websocket-tls',
    'naive',
    'hysteria2',
    'tuic',
    'anytls',
    'shadowsocks',
    'wireguard',
    'amneziawg',
    'tor-bridge',
    'tor',
    'trojan',
    'vmess',
    'webtunnel',
    'snowflake',
    'masque',
    'psiphon',
    'conjure',
]);

/** i18n key of the family's name, or `undefined` for a token this app
 *  does not know. */
export function familyKey(family: string | undefined): string | undefined {
    const f = family?.trim().toLowerCase();
    if (!f || !KNOWN.has(f)) return undefined;
    return `network.family.${f.replace(/-/g, '_')}`;
}

/** The family's readable name, or `undefined` (say nothing). */
export function familyLabel(t: (k: string) => string, family: string | undefined): string | undefined {
    const k = familyKey(family);
    if (!k) return undefined;
    const v = t(k);
    return v && v !== k ? v : undefined;
}

/** The family's readable name for a list or a chip, where a row must
 *  say something: a token this app does not know reads "Other kind"
 *  (never the raw string). Home and Files both use this one, so a kind
 *  of connection is named the same on every screen. */
export function familyName(t: (k: string) => string, family: string | undefined): string {
    return familyLabel(t, family) ?? t('files.fam.unknown');
}

function squash(s: string): string {
    return s.toLowerCase().replace(/[\s_\-·.]/g, '');
}

const MONTHS =
    'jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec|january|february|march|april|june|july|august|september|october|november|december';
/** "May 6", "6 May", "Nov 19 2026": the day a file was made, not a name. */
const MONTH_DAY = new RegExp(`^(?:(?:${MONTHS})\\.?[\\s\\-]*\\d{1,2}(?:st|nd|rd|th)?(?:[,\\s\\-]+\\d{2,4})?|\\d{1,2}(?:st|nd|rd|th)?[\\s\\-]*(?:${MONTHS})\\.?(?:[,\\s\\-]+\\d{2,4})?)$`, 'i');
/** "2026-11-19", "19/11", "11.19.26". */
const NUMERIC_DATE = /^\d{1,4}[\/\-.]\d{1,2}(?:[\/\-.]\d{1,4})?$/;

/** A way's own name from its file, when it tells the person something.
 *  A relay names its ways "r1".."r4" (or "route-1", "Way 2"); a name
 *  that only repeats the kind ("vless-reality", "VLESS Reality") or the
 *  route id says nothing the kind does not already say. Nor does a date
 *  ("May 6", "2026-11-19") or a short code of letters and digits
 *  ("K3F", "a7"): those are how a tool labelled the way, not a name a
 *  person gave it. "Rescue 03" and "Home" get through. */
export function meaningfulNickname(
    r: { routeNickname?: string | null; family: string; routeId: string },
    famName?: string,
): string | undefined {
    const n = (r.routeNickname ?? '').trim();
    if (!n) return undefined;
    if (/^(r|route|way|relay|path|w)[\s_\-#]*\d{1,3}$/i.test(n)) return undefined;
    if (/^\d{1,3}$/.test(n)) return undefined;
    if (MONTH_DAY.test(n) || NUMERIC_DATE.test(n)) return undefined;
    // Up to five letters and digits, digits among them, no space.
    if (/^[a-z0-9]{1,5}$/i.test(n) && /\d/.test(n)) return undefined;
    const s = squash(n);
    if (s === squash(r.family) || s === squash(r.routeId)) return undefined;
    if (famName && s === squash(famName)) return undefined;
    return n;
}
