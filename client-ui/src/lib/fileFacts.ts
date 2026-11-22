// What the Files tab says about one file and the ways inside it, from
// what the engine sent — pure functions, tested without a webview.
//
// The file card and its sheet used to name each way by the nickname the
// publisher's relay gave it ("r1", "r2"…) and put the same green tick on
// every one: nothing a person could use. They now say, per way, the
// KIND of connection (its protocol family: "VLESS Reality",
// "Hysteria 2" — names people in Iran know from V2Ray apps) and what
// Daal has seen of it on the network the phone is on now.
//
// Nothing here guesses:
//   * "here" is only ever said from a `measured` block, and the backends
//     drop that block when it is not about the network the device is on
//     now (lib/measured.ts rowForThisNetwork). No block: no claim.
//   * `healthPct` undefined is "not measured yet", never 0.
//   * `proven` says it carried at least once, somewhere: "Worked
//     before", not "works here".
import type { MeasuredGrade, PublisherTreeRow, RouteDisplayRow } from '../contract/D2Contract';
import type { RowState } from './networkRows';
import { restingNow } from './networkRows';
import { familyName, meaningfulNickname, type KindOf } from './familyName';

// Shared with Home and the way chooser: one name per kind everywhere.
export { familyName, meaningfulNickname };

type T = (k: string) => string;

/** The family token as i18n keys spell it ("vless-reality" → "vless_reality"). */
function famKey(family: string): string {
    return family.trim().toLowerCase().replace(/[-\s]/g, '_');
}

function lookup(t: T, key: string): string | undefined {
    const v = t(key);
    return v && v !== key ? v : undefined;
}

/** One plain paragraph about the kind: the dated Iran caveat where one
 *  is owed (family.*.about: Hysteria 2), else the long help line the
 *  Files tab already had for the less usual ones (network.family.*.help),
 *  else a short one of our own (files.fam.*.about). `undefined` when
 *  none. A route through Cloudflare says so first, in one line
 *  (route.label.ws_cdn.help); pass the route to get it. */
export function familyAbout(t: T, kind: KindOf): string | undefined {
    const family = typeof kind === 'string' ? kind : kind?.family;
    if (!family) return undefined;
    const k = famKey(family);
    const about = lookup(t, `family.${k}.about`) ?? lookup(t, `files.fam.${k}.about`) ?? lookup(t, `network.family.${k}.help`);
    const cdn = typeof kind === 'object' && kind.viaCdn === true && k === 'websocket_tls' ? lookup(t, 'route.label.ws_cdn.help') : undefined;
    return cdn ?? about;
}

/** Ways of one kind are counted together; a route through Cloudflare is
 *  its own kind for that ("WebSocket TLS · Cloudflare", not "· 2"). */
function kindGroup(r: RouteDisplayRow): string {
    return r.viaCdn ? `${famKey(r.family)}#cdn` : famKey(r.family);
}

export interface WayTitle {
    /** "VLESS Reality", or "VLESS Reality · 2" when the file holds two. */
    title: string;
    /** The file's own name for it, when meaningful. */
    nickname?: string;
}

/** The title of every way of a file, by route id. Two ways of one kind
 *  are told apart by their place among that kind: "· 1", "· 2". */
export function wayTitles(t: T, routes: readonly RouteDisplayRow[], locale = 'en'): Map<string, WayTitle> {
    const total = new Map<string, number>();
    for (const r of routes) total.set(kindGroup(r), (total.get(kindGroup(r)) ?? 0) + 1);
    const seen = new Map<string, number>();
    const out = new Map<string, WayTitle>();
    for (const r of routes) {
        const k = kindGroup(r);
        const name = familyName(t, r);
        const n = (seen.get(k) ?? 0) + 1;
        seen.set(k, n);
        const title = (total.get(k) ?? 1) > 1 ? `${name} · ${digits(n, locale)}` : name;
        const nickname = meaningfulNickname(r, name);
        out.set(r.routeId, nickname ? { title, nickname } : { title });
    }
    return out;
}

const FA = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
function digits(n: number | string, locale: string): string {
    const s = String(n);
    return locale === 'fa' ? s.replace(/[0-9]/g, (d) => FA[Number(d)]).replace(/\./g, '٫') : s;
}

// ---- one way ------------------------------------------------------------

/** What one way's row says, first match wins:
 *    in_use      the engine has it up and proved
 *    checking    the engine is proving it, or lost it and is retrying
 *    unsupported this build cannot dial the kind
 *    resting     in its cooldown now
 *    good/ok/slow/failing/untried   the engine's grade on THIS network
 *    proven      no word about this network, but it carried before
 *    unknown     nothing known: the row claims nothing */
export type WayState =
    | 'in_use'
    | 'checking'
    | 'unsupported'
    | 'resting'
    | MeasuredGrade
    | 'untried'
    | 'proven'
    | 'none';

export function wayState(r: RouteDisplayRow, st: RowState, nowMs: number): WayState {
    if (st === 'connected') return 'in_use';
    if (st === 'checking' || st === 'lost') return 'checking';
    if (r.familyMaturity === 'unsupported') return 'unsupported';
    if (restingNow(r, nowMs)) return 'resting';
    const g = r.measured?.grade;
    if (g === 'unknown') return 'untried';
    if (g) return g;
    return r.proven ? 'proven' : 'none';
}

export type Glyph = 'ok' | 'warn' | 'bad' | 'busy' | 'off' | 'none';

export function wayGlyph(s: WayState): Glyph {
    switch (s) {
        case 'in_use':
        case 'good':
        case 'ok':
            return 'ok';
        case 'checking':
            return 'busy';
        case 'slow':
        case 'resting':
            return 'warn';
        case 'failing':
            return 'bad';
        case 'unsupported':
            return 'off';
        default:
            return 'none';
    }
}

/** The short words under a way's title, or `undefined` for none. A
 *  resting way's time is added by the caller (it needs the clock). */
export function wayStateKey(s: WayState): string | undefined {
    switch (s) {
        case 'in_use':
            return 'network.in_use';
        case 'checking':
            return 'conn.headline_connecting';
        case 'unsupported':
            return 'files.way.unsupported';
        case 'resting':
            return 'files.way.resting_until';
        case 'good':
        case 'ok':
        case 'slow':
        case 'failing':
            return `measure.grade.${s}`;
        case 'untried':
            return 'measure.grade.unknown';
        case 'proven':
            return 'files.state.proven';
        default:
            return undefined;
    }
}

/** Seconds with one decimal: "0.4 s" / «۰٫۴ ثانیه». Under 0.1 s it is
 *  "0.1 s" — a time was measured, and "0.0" would read as none. */
export function setupText(t: T, locale: string, ms: number | undefined): string | undefined {
    if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return undefined;
    const s = Math.max(0.1, Math.round(ms / 100) / 10);
    const n = s >= 10 ? String(Math.round(s)) : s.toFixed(1);
    return t('files.way.setup').replace('{n}', digits(n, locale));
}

/** The health meter's colour, or `undefined` when there is no score. */
export function healthTone(pct: number | undefined): 'good' | 'warn' | 'bad' | undefined {
    if (typeof pct !== 'number' || !Number.isFinite(pct)) return undefined;
    return pct >= 70 ? 'good' : pct >= 40 ? 'warn' : 'bad';
}

/** The badge for the kind's maturity: experimental, or not dialable by
 *  this build. Stable and unknown grades get none. */
export function maturityBadgeKey(r: Pick<RouteDisplayRow, 'familyMaturity'>): string | undefined {
    if (r.familyMaturity === 'experimental') return 'files.way.experimental';
    if (r.familyMaturity === 'unsupported') return 'files.way.unsupported_short';
    return undefined;
}

// ---- one file -----------------------------------------------------------

export type FileState =
    | 'revoked'
    | 'checking'
    | 'in_use'
    | 'works'
    | 'resting'
    | 'failing'
    | 'some_failed'
    | 'untried'
    | 'unsupported'
    | 'proven'
    | 'none';

/** The one state of a file, as its card shows it:
 *    revoked      the sender took it back
 *    in_use       one of its ways is up (checking: being proved)
 *    works        one of its ways carried on THIS network
 *    resting      every way it could use is resting
 *    failing      every way tried here failed, and none is left untried
 *    some_failed  some failed here, none worked, others not tried yet
 *    untried      the engine knows this network and tried none of them
 *    unsupported  this build can dial none of its ways
 *    proven       no word about this network, but a way carried before
 *    none         nothing known */
export function fileState(
    p: Pick<PublisherTreeRow, 'cells' | 'revoked'>,
    activeRouteId: string | null,
    stateOf: (routeId: string) => RowState,
    nowMs: number,
): FileState {
    if (p.revoked) return 'revoked';
    const routes = p.cells.flatMap((c) => c.routes);
    const mine = routes.find((r) => r.routeId === activeRouteId);
    if (mine) {
        const st = stateOf(mine.routeId);
        return st === 'checking' || st === 'lost' ? 'checking' : 'in_use';
    }
    if (routes.length === 0) return 'none';
    const usable = routes.filter((r) => r.familyMaturity !== 'unsupported');
    if (usable.length === 0) return 'unsupported';
    const grades = usable.map((r) => r.measured?.grade);
    if (grades.some((g) => g === 'good' || g === 'ok' || g === 'slow')) return 'works';
    const free = usable.filter((r) => !restingNow(r, nowMs));
    if (free.length === 0) return 'resting';
    const withBlock = usable.filter((r) => r.measured !== undefined);
    if (withBlock.length > 0) {
        const failed = withBlock.filter((r) => r.measured!.grade === 'failing').length;
        const untried = usable.length - failed;
        if (failed > 0 && untried === 0) return 'failing';
        if (failed > 0) return 'some_failed';
        return 'untried';
    }
    return usable.some((r) => r.proven) ? 'proven' : 'none';
}

/** Where a file stands in the list: the one carrying traffic first,
 *  then the ones that work here, resting, untried, the rest. */
export function fileOrder(s: FileState): number {
    const order: FileState[] = ['in_use', 'checking', 'works', 'proven', 'resting', 'some_failed', 'untried', 'none', 'failing', 'unsupported', 'revoked'];
    const i = order.indexOf(s);
    return i < 0 ? order.length : i;
}

/** The disc is filled only for the file in use: "works here" is the
 *  same tick as an outline, so the one carrying traffic stands out. */
export function fileGlyphVariant(s: FileState): 'filled' | 'outline' {
    return s === 'works' ? 'outline' : 'filled';
}

export function fileGlyph(s: FileState): Glyph {
    switch (s) {
        case 'in_use':
        case 'works':
            return 'ok';
        case 'checking':
            return 'busy';
        case 'resting':
        case 'some_failed':
            return 'warn';
        case 'failing':
        case 'revoked':
            return 'bad';
        case 'unsupported':
            return 'off';
        default:
            return 'none';
    }
}

export type Tone = 'good' | 'warn' | 'bad' | 'neutral';

/** The card's badge: its words and colour, or `undefined` for none. */
export function fileBadge(s: FileState): { key: string; tone: Tone } | undefined {
    switch (s) {
        case 'revoked':
            return { key: 'files.state.revoked', tone: 'bad' };
        case 'checking':
            return { key: 'files.state.checking', tone: 'neutral' };
        case 'in_use':
            return { key: 'network.in_use', tone: 'good' };
        case 'works':
            return { key: 'files.state.works', tone: 'good' };
        case 'resting':
            return { key: 'network.resting', tone: 'warn' };
        case 'failing':
            return { key: 'files.state.failing', tone: 'bad' };
        case 'some_failed':
            return { key: 'files.state.some_failed', tone: 'warn' };
        case 'untried':
            return { key: 'measure.grade.unknown', tone: 'neutral' };
        case 'unsupported':
            return { key: 'files.state.unsupported', tone: 'neutral' };
        case 'proven':
            return { key: 'files.state.proven', tone: 'neutral' };
        default:
            return undefined;
    }
}

export type FamilyMark = 'good' | 'warn' | 'bad' | 'off' | 'none';

export interface FamilyTagRow {
    family: string;
    name: string;
    count: number;
    /** What Daal has seen of this kind here: some carried (good), all
     *  tried failed (bad), all resting (warn), not dialable (off), or
     *  nothing known (none). */
    mark: FamilyMark;
}

/** The kinds of connection in a file, once each, in the file's order,
 *  with how many ways of each and one mark for how the kind does here. */
export function familyTags(
    t: T,
    routes: readonly RouteDisplayRow[],
    activeRouteId: string | null,
    nowMs: number,
): FamilyTagRow[] {
    const order: string[] = [];
    const by = new Map<string, RouteDisplayRow[]>();
    for (const r of routes) {
        const k = kindGroup(r);
        if (!by.has(k)) {
            by.set(k, []);
            order.push(k);
        }
        by.get(k)!.push(r);
    }
    return order.map((k) => {
        const list = by.get(k)!;
        let mark: FamilyMark = 'none';
        const g = list.map((r) => r.measured?.grade);
        if (list.some((r) => r.routeId === activeRouteId) || g.some((x) => x === 'good' || x === 'ok' || x === 'slow')) {
            mark = 'good';
        } else if (list.every((r) => r.familyMaturity === 'unsupported')) {
            mark = 'off';
        } else if (list.every((r) => restingNow(r, nowMs))) {
            mark = 'warn';
        } else if (list.every((r) => r.measured?.grade === 'failing')) {
            mark = 'bad';
        }
        return { family: list[0].family, name: familyName(t, list[0]), count: list.length, mark };
    });
}

/** The earliest time a resting way of these comes back, or `undefined`. */
export function restingUntilMs(routes: readonly RouteDisplayRow[], nowMs: number): number | undefined {
    let best: number | undefined;
    for (const r of routes) {
        if (!restingNow(r, nowMs) || r.cooldownUntilUnixMs === undefined) continue;
        if (best === undefined || r.cooldownUntilUnixMs < best) best = r.cooldownUntilUnixMs;
    }
    return best;
}

/** "4 ways" / "1 way", in the page's digits. */
export function waysCountText(t: T, locale: string, n: number): string {
    return t(n === 1 ? 'files.card.ways_one' : 'files.card.ways').replace('{n}', digits(n, locale));
}

export { digits as localNumber };
