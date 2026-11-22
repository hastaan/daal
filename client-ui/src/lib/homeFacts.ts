// What Home says about the connection, beyond its one headline.
//
// The engine knows a good deal about the way it is using: which kind of
// connection it is, why it ended up on it, the network the phone is on,
// how fast traffic is moving, how the way did when it was checked, how
// every way on the device has done. Home used to keep all of that
// in the developer fold. Here each fact becomes ONE short line, drawn
// as an icon row (components/connection/HomeFacts.tsx).
//
// The rules of lib/measured.ts and lib/autoConnect.ts hold:
//   * a fact the engine did not send is `undefined`, and its row is not
//     drawn — never a default, never "0";
//   * no line claims a comparison that did not run ("worked best" is
//     never said: the selector compares nothing today, see
//     WhyThisRouteSummary.skipped);
//   * no engine token reaches a sentence: families become their
//     readable names (lib/familyName.ts), categories our own words.
//
// Pure functions, tested in lib/homeFacts.test.ts.
import type {
    AutoStatus,
    AutoTried,
    ConnectionSummary,
    FamilyMaturity,
    RouteDisplayRow,
    SkippedFamilyRow,
    ThroughputSnapshot,
    WhyThisRouteSummary,
} from '../contract/D2Contract';
import { familyLabel, familyName, meaningfulNickname, type KindOf } from './familyName';
import { autoResultKey } from './autoConnect';
import { gradeText, localDigits } from './measured';
import { isolate } from './format';
import { restingNow } from './networkRows';

type T = (k: string) => string;

const fill = (s: string, vars: Record<string, string>) =>
    Object.keys(vars).reduce((acc, k) => acc.split(`{${k}}`).join(vars[k]), s);

// ---- numbers -----------------------------------------------------------

/** A rate as people read it: "318 KB/s", "1.2 MB/s" (Persian digits in
 *  Persian; the unit stays Latin, as phones print it there too). */
export function rateText(bps: number, locale: string): string {
    const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
    let v = Number.isFinite(bps) && bps > 0 ? bps : 0;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i++;
    }
    // One decimal only where it says something: "2.4 MB/s", "46 KB/s".
    const n = v.toFixed(v >= 10 || i === 0 ? 0 : 1);
    const shown = locale === 'fa' ? n.replace(/[0-9]/g, (d) => localDigits(Number(d), 'fa')).replace('.', '٫') : n;
    return `${shown} ${units[i]}`;
}

/** Seconds from milliseconds, one decimal under ten ("0.3", "5.2"). */
export function secondsText(ms: number, locale: string): string {
    const s = ms / 1000;
    const n = s < 10 ? s.toFixed(1) : String(Math.round(s));
    return locale === 'fa' ? n.replace(/[0-9]/g, (d) => localDigits(Number(d), 'fa')).replace('.', '٫') : n;
}

// ---- the way ------------------------------------------------------------

/** The way in use, when connected: its kind, its name in the file, who
 *  made the file. */
export interface WayFact {
    family?: string;
    maturity?: FamilyMaturity;
    routeName?: string;
    publisher?: string;
}

export function wayFact(t: T, conn: ConnectionSummary | null): WayFact | undefined {
    if (!conn || conn.state !== 'connected' || !conn.activeRoute) return undefined;
    const r = conn.activeRoute;
    const out: WayFact = {
        family: familyLabel(t, r),
        maturity: r.familyMaturity,
        routeName: meaningfulNickname(r),
        publisher: r.publisherName || undefined,
    };
    return out.family || out.routeName || out.publisher ? out : undefined;
}

// ---- why this way -------------------------------------------------------

/** Why the connection is on this way, as the engine's own record shows
 *  it:
 *    picked        the person chose it (a pin, or a connect by hand)
 *    faster        automatic moved here because it was faster
 *    won_race      two were tried at once and this one answered first
 *    switched      the way that was up stopped carrying, and the
 *                  engine moved to this one (`why` 'was_connected' on
 *                  the entry it left)
 *    after_failed  others were tried first and did not get through
 *                  (dialled and failed: not_carrying / start_failed —
 *                  a route the engine REFUSED was never dialled, and
 *                  says nothing about this network)
 *    worked_here   the engine put it first because it carried on this
 *                  network the last time (`why` 'carried_here')
 *    first_try     the first one tried, and it carried */
export type WhyToken = 'picked' | 'faster' | 'won_race' | 'switched' | 'after_failed' | 'worked_here' | 'first_try';

export interface WhyFact {
    token: WhyToken;
    text: string;
}

/** Dialled, and did not carry. `refused` (never dialled: experimental
 *  kinds switched off, the mode, an old file), `cancelled` and
 *  `stopped` (another answered first) teach nothing about the network. */
const FAILED_RESULTS = new Set(['not_carrying', 'start_failed']);

export function whyFact(
    t: T,
    locale: string,
    conn: ConnectionSummary | null,
    pinnedId: string | null,
): WhyFact | undefined {
    if (!conn || conn.state !== 'connected') return undefined;
    const active = conn.activeRoute;
    const auto = conn.auto;
    const engineAuto = auto?.mode === true && auto.state === 'connected';
    if (!engineAuto) {
        // Not the engine's choice: the person's — said only when we know
        // it was (a pin on this very way).
        return pinnedId && active && pinnedId === active.routeId
            ? { token: 'picked', text: t('home.why.picked') }
            : undefined;
    }
    const activeId = auto.routeId || active?.routeId || '';
    if (auto.verdict === 'moved_faster') return { token: 'faster', text: t('home.why.faster') };
    const mine = auto.tried.find((x) => x.routeId === activeId && x.result === 'carried');
    const partner = mine?.racedWith ? auto.tried.find((x) => x.routeId === mine.racedWith) : undefined;
    if (partner && partner.result === 'stopped') return { token: 'won_race', text: t('home.why.won_race') };
    const failed = auto.tried.filter((x) => x.routeId !== activeId && FAILED_RESULTS.has(x.result));
    // The way that was up stopped carrying, and the engine moved on.
    const left = failed.find((x) => x.why === 'was_connected');
    if (left) {
        const from = familyLabel(t, left.family);
        const to = familyLabel(t, active ?? mine?.family);
        if (from && to && from !== to) {
            return { token: 'switched', text: fill(t('home.why.switched'), { from, to }) };
        }
        return { token: 'switched', text: t('home.why.switched_plain') };
    }
    if (failed.length === 1) {
        const fam = familyLabel(t, failed[0].family);
        return {
            token: 'after_failed',
            text: fam ? t('home.why.after_one').replace('{family}', fam) : t('home.why.after_other'),
        };
    }
    if (failed.length > 1) {
        return { token: 'after_failed', text: t('home.why.after_n').replace('{n}', localDigits(failed.length, locale)) };
    }
    // Nothing failed before it. Why it stood first is the engine's own
    // word on the entry: 'carried_here' = it carried on this network the
    // last time, and the engine puts those first. Anything else ('ranked'
    // …) is no claim about this network.
    if (mine?.why === 'carried_here') return { token: 'worked_here', text: t('home.why.worked_here') };
    if (mine) return { token: 'first_try', text: t('home.why.first_try') };
    return undefined;
}

// ---- the network ---------------------------------------------------------

export type NetKind = 'wifi' | 'cellular' | 'ethernet' | 'other';
export interface NetworkFact {
    kind: NetKind;
    text: string;
    metered: boolean;
}

/** The network the phone is on, as the HOST told the engine. Nothing
 *  when nobody told it (desktop without a report, Android before the
 *  service ran) or it says there is none. */
export function networkFact(t: T, conn: ConnectionSummary | null): NetworkFact | undefined {
    const n = conn?.network;
    if (!n || !n.fromHost) return undefined;
    const kind: NetKind | undefined =
        n.kind === 'wifi' ? 'wifi' : n.kind === 'cellular' ? 'cellular' : n.kind === 'ethernet' ? 'ethernet' : n.kind === 'other' || n.kind === 'vpn' ? 'other' : undefined;
    if (!kind) return undefined;
    const metered = n.metered === 1;
    const name = t(`home.net.${kind}`);
    return { kind, metered, text: metered ? `${name} · ${t('home.net.metered')}` : name };
}

// ---- speed -------------------------------------------------------------

export interface SpeedFact {
    down: string;
    up: string;
}

/** Live traffic, when this build counts it (`null` = nobody counts:
 *  no row, never "0 B/s"). Nothing either while no byte has moved yet:
 *  "0 B/s ↑ 0 B/s" on a connection that has just come up reads as
 *  "broken". */
export function speedFact(
    locale: string,
    conn: ConnectionSummary | null,
    tp: ThroughputSnapshot | null,
): SpeedFact | undefined {
    if (!conn || conn.state !== 'connected' || !tp) return undefined;
    if (tp.downBytesPerSec === null || tp.upBytesPerSec === null) return undefined;
    if (!(tp.downBytesPerSec > 0) && !(tp.upBytesPerSec > 0)) return undefined;
    return { down: rateText(tp.downBytesPerSec, locale), up: rateText(tp.upBytesPerSec, locale) };
}

// ---- quality -----------------------------------------------------------

export interface QualityFact {
    tone: 'good' | 'warn';
    label: string;
    /** "connected in 0.3 s" (this connect) or "usually 0.3 s" (the
     *  engine's smoothed time on this network). */
    setup?: string;
}

/** How the way does. The engine's live check, when it has one, is the
 *  answer about NOW ("Good" / "Slow"), and an older grade never
 *  overrules it. Without a live check the grade on this network speaks,
 *  in its own words, which say "here" ("Works well here", "Slow here").
 *  Nothing while it is still checking, or when it has said nothing. */
export function qualityFact(t: T, locale: string, conn: ConnectionSummary | null): QualityFact | undefined {
    if (!conn || conn.state !== 'connected') return undefined;
    const r = conn.activeRoute;
    const grade = r?.measured?.grade;
    let tone: 'good' | 'warn' | undefined;
    let label: string | undefined;
    if (conn.routeCheck === 'degraded') {
        tone = 'warn';
        label = t('conn.badge.slow');
    } else if (conn.routeCheck === 'ok') {
        tone = 'good';
        label = t('conn.quality.good');
    } else if (conn.routeCheck === undefined && (grade === 'good' || grade === 'ok' || grade === 'slow')) {
        tone = grade === 'slow' ? 'warn' : 'good';
        label = t(`measure.grade.${grade}`);
    }
    if (!tone || !label) return undefined;
    // This connect's own time only from the engine's automatic pass that
    // is up now: after a connect by hand an older pass may still be in
    // the block.
    const auto = conn.auto;
    const passUp = auto?.mode === true && auto.state === 'connected';
    const thisTry = passUp ? auto.tried.find((x) => x.routeId === r?.routeId && x.result === 'carried')?.setupMs : undefined;
    const usual = r?.measured?.setupMs;
    const setup =
        thisTry !== undefined
            ? t('home.fact.setup_now').replace('{s}', secondsText(thisTry, locale))
            : usual !== undefined
            ? t('home.fact.setup_usual').replace('{s}', secondsText(usual, locale))
            : undefined;
    return { tone, label, ...(setup ? { setup } : {}) };
}

// ---- everything shown while connected ----------------------------------

export interface ConnectedFacts {
    way?: WayFact;
    why?: WhyFact;
    network?: NetworkFact;
    speed?: SpeedFact;
    quality?: QualityFact;
}

export function connectedFacts(input: {
    t: T;
    locale: string;
    conn: ConnectionSummary | null;
    throughput: ThroughputSnapshot | null;
    pinnedId: string | null;
}): ConnectedFacts {
    const { t, locale, conn } = input;
    if (!conn || conn.state !== 'connected') return {};
    const out: ConnectedFacts = {};
    const way = wayFact(t, conn);
    if (way) out.way = way;
    const why = whyFact(t, locale, conn, input.pinnedId);
    if (why) out.why = why;
    const net = networkFact(t, conn);
    if (net) out.network = net;
    const speed = speedFact(locale, conn, input.throughput);
    if (speed) out.speed = speed;
    const q = qualityFact(t, locale, conn);
    if (q) out.quality = q;
    return out;
}

/** "Using Pars Relays · VLESS Reality": the line under "Connected". */
export function usingLine(t: T, name: string | undefined, conn: ConnectionSummary | null): string | undefined {
    // Names are isolated: a Latin name inside a Persian sentence keeps
    // its own direction and does not drag the "·" along with it.
    const fam = conn?.state === 'connected' ? familyLabel(t, conn.activeRoute) : undefined;
    if (!name) return fam ? t('conn.using').replace('{name}', isolate(fam)) : undefined;
    const using = t('conn.using').replace('{name}', isolate(name));
    return fam ? `${using} · ${isolate(fam)}` : using;
}

// ---- ready -----------------------------------------------------------------

/** A way automatic connect will not dial while the experimental kinds
 *  are off — the default, and this app cannot read the setting: the
 *  engine refuses them ('experimental_off'). Never counted as "ready". */
function counted(r: RouteDisplayRow): boolean {
    return r.familyMaturity !== 'unsupported' && r.familyMaturity !== 'experimental';
}

const GRADE_RANK: Record<string, number> = { good: 3, ok: 2, slow: 1 };

/** The way that carried best on this network, by the engine's grade. */
function bestHere(routes: readonly RouteDisplayRow[]): RouteDisplayRow | undefined {
    let best: RouteDisplayRow | undefined;
    for (const r of routes) {
        const m = r.measured;
        if (!m || !GRADE_RANK[m.grade] || m.carried < 1) continue;
        const b = best?.measured;
        if (!b || GRADE_RANK[m.grade] > GRADE_RANK[b.grade] || (GRADE_RANK[m.grade] === GRADE_RANK[b.grade] && m.carried > b.carried)) best = r;
    }
    return best;
}

/** The one line under "Tap to connect": how many ways automatic connect
 *  will try, and which kind carried on this network before — only when
 *  the engine measured one here (the route list carries `measured` only
 *  for the network the phone is on). */
export function readyLine(t: T, locale: string, routes: readonly RouteDisplayRow[] | undefined): string | undefined {
    if (!routes || routes.length === 0) return undefined;
    const usable = routes.filter(counted);
    if (usable.length === 0) return undefined;
    const count = t(usable.length === 1 ? 'home.ready.one' : 'home.ready.n').replace('{n}', localDigits(usable.length, locale));
    const best = bestHere(usable);
    const fam = best ? familyLabel(t, best) : undefined;
    return fam ? `${count} · ${t('home.ready.worked').replace('{family}', fam)}` : count;
}

/** How a kind did on this network, for its chip's dot: some carried
 *  here (good), every one tried here failed (bad), all resting (warn),
 *  nothing known (none). */
export type ReadyMark = 'good' | 'warn' | 'bad' | 'none';

export interface ReadyKind {
    name: string;
    mark: ReadyMark;
    /** Automatic connect leaves it out while the experimental kinds are
     *  off: the chip says "Experimental", the count leaves it out. */
    experimental: boolean;
    /** The engine's time to connect here, for the first chip's line. */
    setupMs?: number;
}

/** The kinds of connection on this device, each once: the chips under
 *  "Tap to connect". In the order the engine will try them — the kinds
 *  that carried here first, the ones that failed here last (the
 *  engine's own order: core/abi/connect_auto.go), experimental after
 *  them. At most `max`; `more` counts the rest. A kind this app cannot
 *  name is left out of the chips (the count in the line still has it). */
export function readyKinds(
    t: T,
    routes: readonly RouteDisplayRow[] | undefined,
    max = 4,
    nowMs = Date.now(),
): { names: string[]; more: number; tags: ReadyKind[] } {
    const by = new Map<string, RouteDisplayRow[]>();
    const order: string[] = [];
    for (const r of routes ?? []) {
        if (r.familyMaturity === 'unsupported') continue;
        const n = familyLabel(t, r);
        if (!n) continue;
        if (!by.has(n)) {
            by.set(n, []);
            order.push(n);
        }
        by.get(n)!.push(r);
    }
    const tags: ReadyKind[] = order.map((name) => {
        const list = by.get(name)!;
        const grades = list.map((r) => r.measured?.grade);
        const best = bestHere(list);
        const resting = list.every((r) => restingNow(r, nowMs));
        const mark: ReadyMark = best
            ? 'good'
            : resting
            ? 'warn'
            : grades.every((g) => g === 'failing')
            ? 'bad'
            : 'none';
        return {
            name,
            mark,
            experimental: list.every((r) => r.familyMaturity === 'experimental'),
            ...(best?.measured?.setupMs ? { setupMs: best.measured.setupMs } : {}),
        };
    });
    const rank = (k: ReadyKind) => (k.experimental ? 4 : k.mark === 'good' ? 0 : k.mark === 'none' ? 1 : k.mark === 'warn' ? 2 : 3);
    const sorted = tags
        .map((k, i) => ({ k, i }))
        .sort((a, b) => rank(a.k) - rank(b.k) || a.i - b.i)
        .map((x) => x.k);
    const shown = sorted.slice(0, max);
    return { names: shown.map((k) => k.name), more: Math.max(0, sorted.length - max), tags: shown };
}

// ---- trying ------------------------------------------------------------

export interface TryingFact {
    /** "Trying VLESS Reality · 2 of 4" */
    text: string;
    /** For the step dots: 1-based position and total, when the engine
     *  said them (2..8 candidates; more is no picture). */
    index?: number;
    total?: number;
    /** Two at once: the second dot lit as well. */
    racing?: boolean;
}

function familyOf(id: string, auto: AutoStatus, conn: ConnectionSummary | null, routes: readonly RouteDisplayRow[] | undefined): KindOf {
    const r = routes?.find((x) => x.routeId === id) ?? (conn?.activeRoute?.routeId === id ? conn.activeRoute : undefined);
    return r ?? auto.tried.find((x) => x.routeId === id)?.family;
}

/** What automatic connect is trying right now, by kind of connection.
 *  `undefined` when the engine did not name a way this app can name
 *  (the page then keeps its plain "Connecting…"). */
export function tryingFact(
    t: T,
    locale: string,
    conn: ConnectionSummary | null,
    routes: readonly RouteDisplayRow[] | undefined,
): TryingFact | undefined {
    const auto = conn?.auto;
    if (!auto || auto.state !== 'trying') return undefined;
    const steps =
        auto.total >= 2 && auto.total <= 8 && auto.index >= 1 && auto.index <= auto.total
            ? { index: auto.index, total: auto.total }
            : {};
    const racing = (auto.racing ?? []).filter(Boolean);
    if (racing.length === 2) {
        const a = familyLabel(t, familyOf(racing[0], auto, conn, routes));
        const b = familyLabel(t, familyOf(racing[1], auto, conn, routes));
        if (a && b && a !== b) {
            return { text: t('home.trying.two').replace('{a}', a).replace('{b}', b), ...steps, racing: true };
        }
        if (a && b) return { text: t('home.trying.two_same').replace('{family}', a), ...steps, racing: true };
        return undefined;
    }
    const fam = auto.trying ? familyLabel(t, familyOf(auto.trying, auto, conn, routes)) : undefined;
    if (!fam) return undefined;
    const base = t('home.trying.one').replace('{family}', fam);
    const of =
        steps.total !== undefined
            ? ` · ${fill(t('home.trying.of'), { i: localDigits(steps.index!, locale), n: localDigits(steps.total, locale) })}`
            : '';
    return { text: base + of, ...steps };
}

// ---- what was tried ----------------------------------------------------

/** One try, for a person: the kind, who made it, how it went in our
 *  words. */
export interface TriedRow {
    key: string;
    family: string;
    /** The route's name in its file, when the list has it. */
    name?: string;
    /** The state disc: 'ok' carried, 'bad' dialled and did not carry
     *  (not_carrying / start_failed), 'off' never dialled (refused:
     *  experimental kinds off, the mode, an old file), 'none' nothing
     *  learned (stopped: another answered first; cancelled). A red cross
     *  only for a way that really failed on this network. */
    glyph: 'ok' | 'bad' | 'off' | 'none';
    reason: string;
}

/** Engine categories, by what they mean to a person. A category this
 *  app does not know falls back to the plain result. */
const CATEGORY_GROUP: Record<string, string> = {
    tcp_connect_timeout: 'no_answer',
    udp_no_reply: 'no_answer',
    dns_timeout: 'no_answer',
    origin_unhealthy: 'no_answer',
    tcp_reset: 'blocked',
    sni_rst: 'blocked',
    tls_sni_or_cert_block_suspected: 'blocked',
    udp_port_blocked: 'blocked',
    udp_address_blocked: 'blocked',
    udp_unavailable: 'blocked',
    quic_unavailable: 'blocked',
    udp_collapsed: 'blocked',
    quic_collapsed: 'blocked',
    dns_poisoned: 'blocked',
    dns_bogon: 'blocked',
    auth_failed: 'refused',
    route_expired: 'expired',
    publisher_revoked: 'expired',
    network_offline: 'offline',
    path_too_slow: 'slow',
    relay_no_egress: 'no_egress',
};

/** What another try of the same pass adds (`refined`). */
const REFINED = new Set(['udp_blocked_here', 'relay_unreachable', 'name_blocked', 'address_blocked']);

/** The reason for one try, in our words. */
export function triedReason(t: T, x: AutoTried): string {
    if (x.result === 'carried') return t('home.tried.carried');
    if (!FAILED_RESULTS.has(x.result)) return t(autoResultKey(x.result));
    if (x.refined && REFINED.has(x.refined)) return t(`home.tried.refined.${x.refined}`);
    const g = CATEGORY_GROUP[x.category];
    return g ? t(`home.tried.${g}`) : t(autoResultKey(x.result));
}

export function triedGlyph(result: string): TriedRow['glyph'] {
    if (result === 'carried') return 'ok';
    if (FAILED_RESULTS.has(result)) return 'bad';
    if (result === 'refused') return 'off';
    return 'none';
}

export function triedRows(
    t: T,
    tried: readonly AutoTried[],
    routes: readonly RouteDisplayRow[] | undefined,
): TriedRow[] {
    return tried.map((x, i) => {
        const r = routes?.find((y) => y.routeId === x.routeId);
        return {
            key: `${x.routeId}-${i}`,
            family: familyName(t, x.family ? { family: x.family, viaCdn: r?.family === x.family && r.viaCdn === true } : r),
            ...(r && meaningfulNickname(r) ? { name: meaningfulNickname(r) } : {}),
            glyph: triedGlyph(x.result),
            reason: triedReason(t, x),
        };
    });
}

// ---- every way on this device, for the Details fold -------------------

/** One way, one row: its kind, the one state disc, and ONE line saying
 *  where it stands — in use, resting, failed just now, or the engine's
 *  grade here. Its score (last hour) at the end when the engine has one.
 *  The old fold listed a way up to three times (ways / resting / tried)
 *  with three different discs. */
export interface WayRow {
    routeId: string;
    family: string;
    name?: string;
    /** The one status line; `undefined` = the engine said nothing. */
    status?: string;
    state: 'ok' | 'warn' | 'bad' | 'off' | 'none';
    active: boolean;
    /** The engine's score, 0..100, last hour; `undefined` = no score yet
     *  (no bar: never a 0). */
    scorePct?: number;
    /** No score, and none will come by itself: the engine can check
     *  this kind of way only while it is connected on it. The card says
     *  "Checked when used" in the score's place. */
    whenUsed?: boolean;
}

/** "Tries again in about 9 min" for a way the engine is resting, by its
 *  own cooldown or its kind's. `undefined` when it is not resting. */
function restText(t: T, locale: string, untilMs: number | undefined, nowMs: number): string {
    return typeof untilMs === 'number' && untilMs > nowMs
        ? t('home.resting.for').replace('{n}', localDigits(Math.max(1, Math.ceil((untilMs - nowMs) / 60_000)), locale))
        : t('home.resting.plain');
}

/** Selector reasons the engine names (`skipped[].reasonToken`). */
const SKIP_KEYS: Record<string, string> = {
    rate_limited: 'home.skip.rate_limited',
    recent_failure: 'home.skip.recent_failure',
    last_resort_tier: 'home.skip.last_resort',
};

export function wayRows(input: {
    t: T;
    locale: string;
    routes: readonly RouteDisplayRow[] | undefined;
    activeId: string | undefined;
    why?: WhyThisRouteSummary | null;
    /** This automatic pass's tries (only while it is the pass that is up). */
    tried?: readonly AutoTried[];
    /** Scores by route id, from the engine's route health. */
    scores?: ReadonlyMap<string, number>;
    /** Route ids the engine's check of every way is on right now
     *  (lib/routeSurvey.ts). */
    checking?: ReadonlySet<string>;
    nowMs: number;
}): WayRow[] {
    const { t, locale, routes, activeId, why, tried, scores, checking, nowMs } = input;
    const restingFam = new Map<string, SkippedFamilyRow>();
    for (const f of why?.skippedFamilies ?? []) restingFam.set(f.family.trim().toLowerCase(), f);
    const skipped = new Map<string, string>();
    for (const s of why?.skipped ?? []) {
        const k = s.reasonToken ? SKIP_KEYS[s.reasonToken] : undefined;
        if (k) skipped.set(s.route.routeId, t(k));
    }
    return (routes ?? []).map((r) => {
        const g = r.measured?.grade;
        const fam = restingFam.get(r.family.trim().toLowerCase());
        const mine = tried?.filter((x) => x.routeId === r.routeId).pop();
        let state: WayRow['state'];
        let status: string | undefined;
        if (r.routeId === activeId) {
            state = 'ok';
            status = t('home.details.in_use');
        } else if (r.familyMaturity === 'unsupported') {
            state = 'off';
            status = t('files.way.unsupported_short');
        } else if (checking?.has(r.routeId)) {
            state = 'none';
            status = t('home.survey.checking_one');
        } else if (restingNow(r, nowMs)) {
            state = 'warn';
            status = restText(t, locale, r.cooldownUntilUnixMs ?? fam?.untilUnixMs, nowMs);
        } else if (fam && (fam.untilUnixMs === undefined || fam.untilUnixMs > nowMs)) {
            state = 'warn';
            status = restText(t, locale, fam.untilUnixMs, nowMs);
        } else if (mine && FAILED_RESULTS.has(mine.result)) {
            state = 'bad';
            status = triedReason(t, mine);
        } else if (skipped.has(r.routeId)) {
            state = g === 'failing' ? 'bad' : 'none';
            status = skipped.get(r.routeId);
        } else {
            state = g === 'good' || g === 'ok' ? 'ok' : g === 'slow' ? 'warn' : g === 'failing' ? 'bad' : 'none';
            status = r.measured ? gradeText(t, r.measured) : r.familyMaturity === 'experimental' ? t('files.way.experimental') : undefined;
        }
        const pct = typeof r.healthPct === 'number' && Number.isFinite(r.healthPct) ? r.healthPct : scores?.get(r.routeId);
        const scored = typeof pct === 'number' && Number.isFinite(pct);
        const nick = meaningfulNickname(r);
        return {
            routeId: r.routeId,
            family: familyName(t, r),
            ...(nick ? { name: nick } : {}),
            ...(status ? { status } : {}),
            state,
            active: r.routeId === activeId,
            ...(scored ? { scorePct: Math.max(0, Math.min(100, Math.round(pct))) } : {}),
            ...(!scored && r.checkedWhenUsed && r.routeId !== activeId && r.familyMaturity !== 'unsupported' ? { whenUsed: true } : {}),
        };
    });
}
