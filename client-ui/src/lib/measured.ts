// What the engine has measured about each route on this network, as the
// pages say it.
//
// The engine keeps, per network and per route, how long the route took
// to prove it carries, how often it carried and failed, and one closed
// grade it derives itself. This file is the reading of that block
// (`measured` in the route listing) and the few decisions the pages make
// with it — pure functions, tested without a webview.
//
// The rules of lib/autoConnect.ts hold here too:
//   * a sentence carries no number, no code and no engine word. The
//     grade becomes one of five plain phrases; milliseconds and counts
//     appear only inside a Details fold, for the person helping;
//   * a grade this app does not know is "the engine said nothing": the
//     row then claims nothing, rather than printing a raw code or
//     guessing "not tried".
import { sep } from './format';
import type {
    ConnectionSummary,
    Measured,
    MeasuredGrade,
    RouteDisplayRow,
} from '../contract/D2Contract';

const GRADES: readonly MeasuredGrade[] = ['unknown', 'good', 'ok', 'slow', 'failing'];

function count(v: unknown): number {
    return typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

/** `last` is shown under Details. The engine sends the start of a
 *  one-hour bucket as Unix seconds; printed raw that is a ten-digit
 *  number with no label, read out over the phone to somebody who cannot
 *  use it. It becomes the UTC date and hour ("2026-11-19 10h UTC" —
 *  Western digits on purpose: the line it goes in is left-to-right
 *  engine vocabulary). A string is taken as a bucket already written
 *  out, and only the characters one is made of get through; anything
 *  else is dropped whole. */
function bucket(v: unknown): string | undefined {
    if (typeof v === 'number' && Number.isFinite(v) && v > 0) return lastBucketText(v);
    if (typeof v !== 'string' || v === '' || v.length > 40) return undefined;
    return /^[0-9A-Za-z:+.\- ]+$/.test(v) ? v : undefined;
}

/** The engine's `last` (Unix seconds, the start of an hour) as it is
 *  shown: "2026-11-19 10h UTC". `undefined` for a number that is not a
 *  time this app can have seen (before 2000, after 2100). */
export function lastBucketText(unixSeconds: number): string | undefined {
    if (!Number.isFinite(unixSeconds) || unixSeconds < 946684800 || unixSeconds > 4102444800) return undefined;
    const iso = new Date(Math.floor(unixSeconds) * 1000).toISOString();
    return `${iso.slice(0, 10)} ${iso.slice(11, 13)}h UTC`;
}

/** The `measured` block of one route. `undefined` when there is no
 *  block or its grade is not one this app knows. */
export function parseMeasured(v: unknown): Measured | undefined {
    if (!v || typeof v !== 'object') return undefined;
    const m = v as Record<string, unknown>;
    const grade = m.grade;
    if (typeof grade !== 'string' || !(GRADES as readonly string[]).includes(grade)) return undefined;
    const setup = count(m.setup_ms);
    const last = bucket(m.last);
    const lastUnix = typeof m.last === 'number' && last ? Math.floor(m.last) : undefined;
    return {
        grade: grade as MeasuredGrade,
        ...(setup > 0 ? { setupMs: setup } : {}),
        samples: count(m.samples),
        carried: count(m.carried),
        failed: count(m.failed),
        ...(last ? { last } : {}),
        ...(lastUnix ? { lastUnix } : {}),
    };
}

/** i18n key of the plain phrase for a route's grade on this network, or
 *  `undefined` when the engine said nothing about it. */
export function gradeKey(m: Measured | undefined): string | undefined {
    return m ? `measure.grade.${m.grade}` : undefined;
}

/** The phrase itself, or `undefined`. */
export function gradeText(t: (k: string) => string, m: Measured | undefined): string | undefined {
    const k = gradeKey(m);
    return k ? t(k) : undefined;
}

/** i18n key of the ONE calm line about quality under "You're
 *  connected.", or `undefined` for none.
 *
 *  It is said only when it helps:
 *    - the connection is slow (the engine's own check says so, or the
 *      route is graded slow here): "Slow here."
 *    - …with "Daal will switch if it finds a faster way" ONLY where the
 *      engine can: its check says slow NOW (a grade from old samples
 *      starts nothing), it is in charge (automatic), there is another
 *      way to move to, and the network is not one the host calls
 *      metered — there the engine starts no probe by itself. A promise
 *      it will not keep leaves the person waiting for a switch instead
 *      of trying another network or asking for a file. (It can still
 *      decline for reasons this page cannot see — a kind of connection
 *      it cannot check beside the running one, a recent move — which is
 *      why the sentence says "if it finds".)
 *    - on a way the person picked it will not move, and the line says
 *      that instead of promising;
 *    - the route is graded good: "Works well here."
 *  "Works here", "not tried yet" and a route that failed here before
 *  and now carries add nothing to "You're connected."
 *
 *  `otherWays`: the person holds more than one way (`undefined` = not
 *  known: no promise). */
export function connectedQualityKey(
    s: ConnectionSummary | null | undefined,
    otherWays?: boolean,
): string | undefined {
    if (!s || s.state !== 'connected') return undefined;
    const grade = s.activeRoute?.measured?.grade;
    const slowNow = s.routeCheck === 'degraded';
    if (slowNow || grade === 'slow') {
        if (s.auto?.mode !== true) return 'measure.connected.slow_own';
        const engineMayMove = slowNow && otherWays === true && s.network?.metered !== 1;
        return engineMayMove ? 'measure.connected.slow_auto' : 'measure.connected.slow';
    }
    return grade === 'good' ? 'measure.connected.good' : undefined;
}

/** The words after a row's name about how the way does here: " · Works
 *  well here", or '' when the engine said nothing (then the row claims
 *  nothing). */
export function rowGradeSuffix(t: (k: string) => string, m: Measured | undefined): string {
    const k = gradeKey(m);
    return k ? ` · ${t(k)}` : '';
}

/** A route row as the pages get it: with its `measured` block only when
 *  that block is about the network the device is on now
 *  (lib/networkFacts.ts gradesAreForThisNetwork). Without it every page
 *  claims nothing about "here" — no phrase, no chip text, no fold. */
export function rowForThisNetwork<T extends { measured?: Measured }>(row: T, here: boolean): T {
    if (here || row.measured === undefined) return row;
    const { measured: _dropped, ...rest } = row;
    return rest as T;
}

/** For a family chip: of these routes, how many were tried on this
 *  network and how many of those carried. `undefined` when none of them
 *  has a `measured` block — then nothing is known and nothing is said. */
export function familyHere(
    routes: readonly RouteDisplayRow[],
): { worked: number; tried: number } | undefined {
    const withBlock = routes.filter((r) => r.measured !== undefined);
    if (withBlock.length === 0) return undefined;
    let worked = 0;
    let tried = 0;
    for (const r of withBlock) {
        const g = r.measured!.grade;
        if (g === 'unknown') continue;
        tried++;
        if (g !== 'failing') worked++;
    }
    return { worked, tried };
}

const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
export function localDigits(n: number, locale: string): string {
    const s = String(n);
    return locale === 'fa' ? s.replace(/[0-9]/g, (d) => FA_DIGITS[Number(d)]) : s;
}

/** The words on a family chip about this network: "2 of 3 worked
 *  here", "Not tried here yet", or `undefined` (say nothing). A count
 *  of routes — not a percentage, and not a success rate. */
export function chipHereText(
    t: (k: string) => string,
    locale: string,
    here: { worked: number; tried: number } | undefined,
): string | undefined {
    if (!here) return undefined;
    if (here.tried === 0) return t('measure.grade.unknown');
    return t('network.chip.worked_here')
        .replace('{a}', localDigits(here.worked, locale))
        .replace('{n}', localDigits(here.tried, locale));
}

/** What the old percentage on a chip is, in words — shown only in the
 *  chip's tap-to-open text. The number is a score the engine lowers
 *  after failures in a row and while a route rests; it was printed as
 *  "87%", which reads as "works 87% of the time" and is not that. */
export function chipScoreText(
    t: (k: string) => string,
    locale: string,
    healthPct: number | undefined,
): string | undefined {
    if (typeof healthPct !== 'number' || !Number.isFinite(healthPct)) return undefined;
    return t('network.chip.score').replace('{n}', localDigits(Math.round(healthPct), locale));
}

/** Details only: one route's numbers in our words. '' when there are
 *  none (never tried here). */
export function measuredWords(t: (k: string) => string, locale: string, m: Measured): string {
    const parts: string[] = [];
    if (m.setupMs !== undefined) {
        parts.push(t('measure.details.setup').replace('{n}', localDigits(m.setupMs, locale)));
    }
    if (m.samples > 0 || m.carried > 0 || m.failed > 0) {
        parts.push(
            t('measure.details.counts')
                .replace('{n}', localDigits(Math.max(m.samples, m.carried + m.failed), locale))
                .replace('{a}', localDigits(m.carried, locale))
                .replace('{b}', localDigits(m.failed, locale)),
        );
    }
    return parts.join(sep());
}

/** Details only: the same facts as the engine names them, to be read
 *  out or photographed for the person helping. Left-to-right, fixed
 *  width; ids, closed codes and rounded numbers only. */
export function measuredCode(routeId: string, family: string, m: Measured | undefined): string {
    const parts: string[] = [routeId, family];
    if (m) {
        parts.push(m.grade);
        if (m.setupMs !== undefined) parts.push(`${m.setupMs} ms`);
        parts.push(`n=${m.samples}`, `ok=${m.carried}`, `fail=${m.failed}`);
        if (m.last) parts.push(m.last);
    }
    return parts.filter(Boolean).join(sep());
}

/** Does any route carry a measured block? The Details fold is offered
 *  only then: an engine that measures nothing gets no empty box. */
export function anyMeasured(routes: readonly RouteDisplayRow[] | undefined): boolean {
    return !!routes && routes.some((r) => r.measured !== undefined);
}
