// pasteItems — one paste box takes anything (wave 1, lane B).
//
// A person pastes what they were sent: one link, a channel post with a
// dozen links, a Daal file that came as a long block of text, a
// WireGuard .conf, a Telegram proxy, a sentence around any of these.
// This file splits that text into ITEMS and says what each one is. It
// is pure and display-only: it decides which engine call each item is
// handed to and what its row says. The engine re-checks everything
// (signature, revocation and expiry for a Daal file; its own strict
// parse for a link); nothing here is a trust decision.
//
// Splitting rules:
//   • new lines, spaces and tabs always separate items;
//   • a comma or semicolon separates items ONLY when a known scheme
//     follows it at once ("vless://a,vless://b"): a hysteria2 port list
//     (hy2://p@h:443,8443-8450) and an ALPN list (alpn=h2,http/1.1)
//     contain commas that belong to the link;
//   • a WireGuard .conf block ([Interface] … [Peer] …) is ONE item, as
//     the engine's uri.ParseAny reads it (bundle/go/uri/uri.go: a text
//     that starts with "[Interface]");
//   • a Daal file is ONE item: everything in the paste that is not a
//     link, found by the same base64 container magic the decoder uses
//     (lib/pastedBundle.ts ⇄ daal-wizard/src/recipient_paste.rs). The
//     decoder skips chatter around the blob, so the chatter goes with it;
//   • surrounding quotes and punctuation are trimmed; exact duplicates
//     are dropped, first one kept;
//   • words that are not understood and stand next to each other on one
//     line are ONE not-understood item, so a sentence is one muted line
//     and not six.

import { detectPastedContainer } from './pastedBundle';

/** Route kinds the paste box names. The engine decides what it can
 *  dial (uri.ParseURI); a kind it cannot is refused per item. */
export type RouteKind =
    | 'vless'
    | 'vmess'
    | 'trojan'
    | 'shadowsocks'
    | 'hysteria2'
    | 'hysteria'
    | 'tuic'
    | 'wireguard'
    | 'amneziawg'
    | 'naive'
    | 'brook'
    | 'snowflake';

export type MessengerApp = 'telegram' | 'signal';

export type PasteItem =
    /** `importable`: the engine can turn this kind into a route today
     *  (IMPORTABLE). Any other kind is named, shown muted with "Daal
     *  can't add this kind of link yet", and never counted in "Add all". */
    | {
          kind: 'route';
          route: RouteKind;
          text: string;
          importable: boolean;
          /** A pasted WireGuard conf: kept as a route Daal uses only when
           *  the person picks it (core/abi/share.go URIImport stores it
           *  manual-only; the automatic connect never tries it). */
          manualOnly?: boolean;
      }
    | { kind: 'file'; container: 'sbp' | 'sbpx'; text: string }
    | { kind: 'web'; text: string }
    /** A proxy for another app. `open` is the link rebuilt from the
     *  checked parts only, in its https form, for the OS to hand over. */
    | { kind: 'messenger'; app: MessengerApp; text: string; open: string }
    | { kind: 'unknown'; text: string };

/** Protocol names as people know them (Latin in both languages). */
export const ROUTE_KIND_NAME: Record<RouteKind, string> = {
    vless: 'VLESS',
    vmess: 'VMess',
    trojan: 'Trojan',
    shadowsocks: 'Shadowsocks',
    hysteria2: 'Hysteria 2',
    hysteria: 'Hysteria',
    tuic: 'TUIC',
    wireguard: 'WireGuard',
    amneziawg: 'AmneziaWG',
    naive: 'NaïveProxy',
    brook: 'Brook',
    snowflake: 'Snowflake',
};

/** The LINK kinds core/abi URIImport can import (uri.ParseURI: vless,
 *  vmess, trojan, ss, hy2/hysteria2, tuic). A wg:// or wireguard:// link
 *  has no parser in the engine; a pasted WireGuard CONF does
 *  (`confItem`): URIImport reads it with uri.ParseAny and keeps it as a
 *  manual-only route. */
export const IMPORTABLE: ReadonlySet<RouteKind> = new Set<RouteKind>(['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'tuic']);

function routeItem(route: RouteKind, text: string): PasteItem {
    return { kind: 'route', route, text, importable: IMPORTABLE.has(route) };
}

/** One `[Interface]` … block: addable, and used only when picked. */
function confItem(text: string): PasteItem {
    return { kind: 'route', route: 'wireguard', text, importable: true, manualOnly: true };
}

/** At most this many items are read from one paste. */
export const MAX_ITEMS = 200;

const ROUTE_SCHEMES: ReadonlyArray<[string, RouteKind]> = [
    ['vless://', 'vless'],
    ['vmess://', 'vmess'],
    ['trojan://', 'trojan'],
    ['ss://', 'shadowsocks'],
    ['hy2://', 'hysteria2'],
    ['hysteria2://', 'hysteria2'],
    ['hysteria://', 'hysteria'],
    ['tuic://', 'tuic'],
    ['wg://', 'wireguard'],
    ['wireguard://', 'wireguard'],
    ['amneziawg://', 'amneziawg'],
    ['naive+https://', 'naive'],
    ['naive://', 'naive'],
    ['brook://', 'brook'],
    ['snowflake://', 'snowflake'],
];

/** What may follow a comma or semicolon for it to separate two items:
 *  every link scheme above, the messenger forms, a web address, and the
 *  base64 spelling of a Daal container's magic. "http/1.1" in an ALPN
 *  list is not "http://", so it does not split. */
const SPLIT_AFTER =
    /[,;](?=(?:vless|vmess|trojan|ss|hy2|hysteria2?|tuic|wg|wireguard|amneziawg|naive\+https|naive|brook|snowflake|tg|sgnl|https?):\/\/|(?:t|telegram)\.me\/|UEsDB|RFNCUAAB)/i;

/** Quotes, brackets and sentence punctuation around an item. `=` is not
 *  here: it is base64 padding at the end of an ss:// or vmess:// link. */
const EDGE = `"'\`«»“”„‘’‹›()[]{}<>,;.:!?،؛؟…`;

export function trimEdges(s: string): string {
    let a = 0;
    let b = s.length;
    while (a < b && EDGE.includes(s[a])) a++;
    while (b > a && EDGE.includes(s[b - 1])) {
        // A link keeps a closing bracket whose opener is inside it
        // ("…#Server(2)"), as a chat app's own link finder does.
        const close = s[b - 1];
        const open = close === ')' ? '(' : close === ']' ? '[' : '';
        if (open) {
            const body = s.slice(a, b);
            if (body.split(open).length > body.split(close).length - 1) break;
        }
        b--;
    }
    return s.slice(a, b);
}

/** Zero-width and bidi marks a messenger sprinkles into Latin text in
 *  a Persian chat. Removed from a link (they are never part of one). */
const INVISIBLE = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
/** What is removed from words that are NOT a link: bidi marks and the
 *  BOM only. The zero-width non-joiner (U+200C, the Persian half-space)
 *  and joiner stay, so a sentence is shown as it was written. */
const BIDI_ONLY = /[\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

function routeKindOf(s: string): RouteKind | null {
    const low = s.toLowerCase();
    for (const [prefix, kind] of ROUTE_SCHEMES) if (low.startsWith(prefix)) return kind;
    return null;
}

/** Does this token start with something we treat as a link? */
function isLinkToken(s: string): boolean {
    return routeKindOf(s) !== null || /^(?:tg|sgnl|https?):\/\//i.test(s) || /^(?:t|telegram)\.me\//i.test(s);
}

// ---- messenger proxies -------------------------------------------------

const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$|^\d{1,3}(?:\.\d{1,3}){3}$|^\[[0-9A-Fa-f:.]+\]$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+$/;
const PORT = /^\d{1,5}$/;
/** An MTProto secret: hex (plain, dd…, ee… with the fake-TLS domain in
 *  hex) or base64url. Nothing else may ride along into the link. */
const SECRET = /^[A-Za-z0-9_\-+/=]{1,512}$/;
/** SOCKS user and password: plain printable characters only. */
const CRED = /^[A-Za-z0-9._~\-]{1,128}$/;

function parseQuery(q: string): Map<string, string> | null {
    const out = new Map<string, string>();
    for (const part of q.split('&')) {
        if (!part) continue;
        const i = part.indexOf('=');
        const k = (i < 0 ? part : part.slice(0, i)).toLowerCase();
        let v = i < 0 ? '' : part.slice(i + 1);
        try {
            v = decodeURIComponent(v.replace(/\+/g, '%2B'));
        } catch {
            return null;
        }
        if (!out.has(k)) out.set(k, v);
    }
    return out;
}

/** Telegram's own proxy links: tg://proxy, tg://socks, t.me/proxy,
 *  t.me/socks (and telegram.me). The handed-over link is rebuilt from
 *  checked parts in the https form, which Telegram opens on every
 *  system and a browser turns into "open in Telegram". */
function telegramProxy(s: string): string | null {
    const m = /^(?:tg:\/\/|(?:https?:\/\/)?(?:www\.)?(?:t|telegram)\.me\/)(proxy|socks)\?([^#]*)$/i.exec(s);
    if (!m) return null;
    const type = m[1].toLowerCase();
    const q = parseQuery(m[2]);
    if (!q) return null;
    const server = q.get('server') ?? '';
    const port = q.get('port') ?? '';
    if (!HOST.test(server) || !PORT.test(port) || Number(port) < 1 || Number(port) > 65535) return null;
    const parts = [`server=${encodeURIComponent(server)}`, `port=${port}`];
    if (type === 'proxy') {
        const secret = q.get('secret') ?? '';
        if (!SECRET.test(secret)) return null;
        parts.push(`secret=${encodeURIComponent(secret)}`);
    } else {
        for (const k of ['user', 'pass']) {
            const v = q.get(k);
            if (v === undefined || v === '') continue;
            if (!CRED.test(v)) return null;
            parts.push(`${k}=${v}`);
        }
    }
    return `https://t.me/${type}?${parts.join('&')}`;
}

/** Signal's proxy links: https://signal.tube/#<host> (and the sgnl://
 *  form Signal also opens). Rebuilt as https with the checked host. */
function signalProxy(s: string): string | null {
    const m = /^(?:https?|sgnl):\/\/signal\.tube\/?#(.+)$/i.exec(s);
    if (!m) return null;
    const host = m[1].replace(/:443$/, '');
    if (!HOST.test(host)) return null;
    return `https://signal.tube/#${host}`;
}

/** What one trimmed token is, on its own. */
export function classifyItem(raw: string): PasteItem {
    const text = trimEdges(raw.replace(INVISIBLE, '').trim());
    if (!text) return { kind: 'unknown', text: raw };
    const route = routeKindOf(text);
    if (route) {
        // A scheme and nothing after it is not a link.
        return text.length > text.indexOf('://') + 3 ? routeItem(route, text) : { kind: 'unknown', text };
    }
    const tg = telegramProxy(text);
    if (tg) return { kind: 'messenger', app: 'telegram', text, open: tg };
    const sig = signalProxy(text);
    if (sig) return { kind: 'messenger', app: 'signal', text, open: sig };
    // Any other Telegram or Signal link (a channel, a group, a broken
    // proxy) is not a web address to check for updates.
    if (/^(?:(?:https?:\/\/)?(?:www\.)?(?:t|telegram)\.me\/|tg:\/\/|sgnl:\/\/|https?:\/\/signal\.(?:tube|me|group)\b)/i.test(text)) {
        return { kind: 'unknown', text };
    }
    if (/^https?:\/\/[^\s/?#]+\.[^\s/?#]+/i.test(text)) return { kind: 'web', text };
    const container = detectPastedContainer(text);
    if (container) return { kind: 'file', container, text };
    return { kind: 'unknown', text };
}

// ---- splitting ---------------------------------------------------------

/** `text` is what is shown; `bare` has every invisible mark removed,
 *  for the engine (a link, a Daal file's base64). */
type Piece = { text: string; bare: string; line: number; link: boolean; ord: number };

/** A WireGuard .conf line: a section header, a `Key = Value`, a comment. */
const CONF_LINE = /^\s*(?:\[(?:Interface|Peer)\]|[A-Za-z][A-Za-z0-9]*\s*=.*|[#;].*)\s*$/i;

/** Lines → .conf blocks (one item each) and the rest. */
function confBlocks(lines: string[]): { blocks: Array<{ at: number; text: string }>; rest: Array<{ at: number; text: string }> } {
    const blocks: Array<{ at: number; text: string }> = [];
    const rest: Array<{ at: number; text: string }> = [];
    let i = 0;
    while (i < lines.length) {
        if (/^\s*\[Interface\]\s*$/i.test(lines[i])) {
            const start = i;
            const body: string[] = [lines[i].trim()];
            i++;
            while (i < lines.length) {
                const l = lines[i];
                if (l.trim() === '') {
                    // A blank line stays inside when the block goes on.
                    let j = i + 1;
                    while (j < lines.length && lines[j].trim() === '') j++;
                    if (j < lines.length && CONF_LINE.test(lines[j]) && !/^\s*\[Interface\]\s*$/i.test(lines[j]) && !isLinkToken(lines[j].trim())) {
                        i = j;
                        continue;
                    }
                    break;
                }
                if (/^\s*\[Interface\]\s*$/i.test(l) || !CONF_LINE.test(l) || isLinkToken(l.trim())) break;
                body.push(l.trim());
                i++;
            }
            // A header alone is not a configuration.
            if (body.length > 1 && body.some((b) => /^PrivateKey\s*=/i.test(b))) blocks.push({ at: start, text: body.join('\n') });
            else body.forEach((b, k) => rest.push({ at: start + k, text: b }));
            continue;
        }
        rest.push({ at: i, text: lines[i] });
        i++;
    }
    return { blocks, rest };
}

/** Split a paste into items, in the order they were pasted. */
export function pasteItems(input: string): { items: PasteItem[]; truncated: boolean } {
    const lines = input.replace(/\r\n?/g, '\n').split('\n');
    const { blocks, rest } = confBlocks(lines);

    // Every whitespace-separated token, split again at a comma or
    // semicolon that a known scheme follows.
    const pieces: Piece[] = [];
    for (const { at, text } of rest) {
        for (const tok of text.split(/[ \t  - 　]+/)) {
            if (!tok) continue;
            for (const part of tok.split(SPLIT_AFTER)) {
                const stripped = trimEdges(part.replace(INVISIBLE, ''));
                if (!stripped) continue;
                const link = isLinkToken(stripped);
                const clean = link ? stripped : trimEdges(part.replace(BIDI_ONLY, ''));
                if (!clean) continue;
                pieces.push({ text: clean, bare: stripped, line: at, link, ord: pieces.length });
            }
        }
    }

    // The words that are not links: a Daal file when the container magic
    // is in them (they are handed over as one text, as the decoder
    // expects), otherwise one not-understood item per run on a line.
    const loose = pieces.filter((p) => !p.link);
    const looseText = loose.map((p) => p.bare).join(' ');
    const container = loose.length ? detectPastedContainer(looseText) : null;

    // In paste order: by line, then by position on the line.
    type Placed = { at: number; ord: number; item: PasteItem };
    const placed: Placed[] = [];
    for (const b of blocks) placed.push({ at: b.at, ord: -1, item: confItem(b.text) });
    if (container) placed.push({ at: loose[0].line, ord: loose[0].ord, item: { kind: 'file', container, text: looseText } });

    let run: Piece[] = [];
    const flush = () => {
        if (!run.length) return;
        placed.push({ at: run[0].line, ord: run[0].ord, item: { kind: 'unknown', text: run.map((p) => p.text).join(' ') } });
        run = [];
    };
    for (const p of pieces) {
        if (!p.link) {
            if (container) continue;
            if (run.length && run[run.length - 1].line !== p.line) flush();
            run.push(p);
            continue;
        }
        flush();
        placed.push({ at: p.line, ord: p.ord, item: classifyItem(p.text) });
    }
    flush();

    placed.sort((a, b) => a.at - b.at || a.ord - b.ord);
    const seen = new Set<string>();
    const items: PasteItem[] = [];
    let truncated = false;
    for (const { item } of placed) {
        const key = `${item.kind}\u0000${item.text}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (items.length >= MAX_ITEMS) {
            truncated = true;
            break;
        }
        items.push(item);
    }
    return { items, truncated };
}

/** Items Daal can add as routes: links and Daal files. A web address is
 *  added only when the person picks it (a link copied for another
 *  reason must not become a subscription). */
export function addable(items: PasteItem[]): PasteItem[] {
    return items.filter((i) => (i.kind === 'route' && i.importable) || i.kind === 'file');
}

/** How many route LINKS the paste holds: the bulk check and removal are
 *  offered only when this is two or more. A WireGuard conf is not
 *  counted: it is used only when picked, and never checked beside
 *  another connection. */
export function routeLinkCount(items: PasteItem[]): number {
    return items.filter((i) => i.kind === 'route' && i.importable && !i.manualOnly).length;
}

/** Whether text found on the clipboard is something Daal can add: a
 *  connection link it can import or a Daal file. Anything else (the
 *  phone's own Daal address, a sentence, a web page, a proxy for another
 *  app) is left where it is: the paste box opens empty and says nothing,
 *  because the person did not paste it. */
export function usableClipboard(text: string): boolean {
    if (!text || !text.trim()) return false;
    return addable(pasteItems(text).items).length > 0;
}

// ---- refusals ----------------------------------------------------------

/** The importer's refusal codes (bundle/go/uri/refuse.go RefusalCode),
 *  plus `no_match` for a link no parser took. Anything else is `other`. */
export const REFUSAL_CODES = [
    'transport_unsupported',
    'header_type_unsupported',
    'flow_unsupported',
    'encryption_unsupported',
    'plaintext_refused',
    'insecure_refused',
    'link_malformed',
    'manual_only',
    'no_match',
] as const;
export type RefusalCode = (typeof REFUSAL_CODES)[number] | 'other';

/** The stable token in an import error ("vless: … : uri: plaintext_refused"). */
export function refusalCode(raw: string): RefusalCode {
    if (/uri: no matching parser/.test(raw)) return 'no_match';
    const m = /\buri: ([a-z_]+)\b/.exec(raw);
    if (m && (REFUSAL_CODES as readonly string[]).includes(m[1])) return m[1] as RefusalCode;
    return 'other';
}
