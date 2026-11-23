// backupCheck — "Check the backup update routes" (round 3a): the person
// asks the engine to try ONLY the backup routes of one file's relay, so
// they (and we) can see whether each works on this network. It rides
// engine_relaypack_refresh with a JSON request instead of a pack id
// (core/abi/relaypack_drill.go; build/ux/notes/wave3-engine-api.md).
//
// The engine's answer is closed words; this file turns them into the
// plain lines the sheet shows (one per route family: GitHub, Google,
// Other mirrors, DNS) and one sentence for how it went. Nothing in the
// answer, and nothing here, names a host, repository, zone or address.

import type { BackupRoute, ConnectionSummary, PublisherTreeRow } from '../contract/D2Contract';
import { autoTrying } from './autoConnect';

export type DrillClass = 'github' | 'google' | 'goproxy' | 'jsdelivr' | 'dns';
export type DrillResult = 'reached' | 'verified' | 'nothing_new' | 'failed' | 'skipped';
export type DrillReason = 'not_in_file' | 'no_resolver' | 'budget' | 'route_up' | 'not_held' | '';

export type DrillOutcome =
    | 'updated'
    | 'unchanged'
    | 'unreachable'
    | 'no_endpoints'
    | 'rejected'
    | 'tunnel_required'
    | 'rate_limited'
    | 'in_progress'
    | 'not_available'
    | 'unknown_pack'
    | 'cancelled'
    /** The call failed, or an engine that predates the check. */
    | 'unavailable';

export interface DrillClassResult {
    result: DrillResult;
    reason: DrillReason;
}

export interface DrillAnswer {
    outcome: DrillOutcome;
    /** Seconds until the check may run again (`rate_limited`); 0 otherwise. */
    retryAfterS: number;
    /** Per class; absent when the engine sent no `drill` block. */
    classes?: Partial<Record<DrillClass, DrillClassResult>>;
}

const OUTCOMES: ReadonlySet<string> = new Set([
    'updated',
    'unchanged',
    'unreachable',
    'no_endpoints',
    'rejected',
    'tunnel_required',
    'rate_limited',
    'in_progress',
    'not_available',
    'unknown_pack',
    'cancelled',
]);
const CLASSES: readonly DrillClass[] = ['github', 'google', 'goproxy', 'jsdelivr', 'dns'];
const RESULTS: ReadonlySet<string> = new Set(['reached', 'verified', 'nothing_new', 'failed', 'skipped']);
const REASONS: ReadonlySet<string> = new Set(['not_in_file', 'no_resolver', 'budget', 'route_up', 'not_held']);

/** The request the engine reads instead of a pack id. */
export function drillRequest(routeId: string): string {
    return JSON.stringify({ drill: true, route_id: routeId });
}

export function parseDrill(body: string): DrillAnswer {
    let v: { outcome?: unknown; retry_after_s?: unknown; drill?: unknown };
    try {
        v = JSON.parse(body) as typeof v;
    } catch {
        return { outcome: 'unavailable', retryAfterS: 0 };
    }
    if (!v || typeof v !== 'object') return { outcome: 'unavailable', retryAfterS: 0 };
    const outcome =
        typeof v.outcome === 'string' && OUTCOMES.has(v.outcome) ? (v.outcome as DrillOutcome) : 'unavailable';
    const retryAfterS =
        typeof v.retry_after_s === 'number' && v.retry_after_s > 0 ? Math.ceil(v.retry_after_s) : 0;
    const answer: DrillAnswer = { outcome, retryAfterS };
    if (v.drill && typeof v.drill === 'object') {
        const classes: Partial<Record<DrillClass, DrillClassResult>> = {};
        for (const c of CLASSES) {
            const raw = (v.drill as Record<string, unknown>)[c] as { result?: unknown; reason?: unknown } | undefined;
            if (!raw || typeof raw !== 'object') continue;
            if (typeof raw.result !== 'string' || !RESULTS.has(raw.result)) continue;
            const reason =
                typeof raw.reason === 'string' && REASONS.has(raw.reason) ? (raw.reason as DrillReason) : '';
            classes[c] = { result: raw.result as DrillResult, reason };
        }
        answer.classes = classes;
    }
    return answer;
}

// ---- what the sheet shows ------------------------------------------

export type DrillFamily = 'github' | 'google' | 'mirrors' | 'dns';
/** works = reached / verified; nothing_new = answered, nothing new;
 *  no_answer = failed; not_here = not asked on this network. */
export type DrillWord = 'works' | 'nothing_new' | 'no_answer' | 'not_here';

const FAMILIES: readonly { family: DrillFamily; classes: readonly DrillClass[] }[] = [
    { family: 'github', classes: ['github'] },
    { family: 'google', classes: ['google'] },
    // ONE of the two is asked per walk; the other says skipped/budget.
    { family: 'mirrors', classes: ['goproxy', 'jsdelivr'] },
    { family: 'dns', classes: ['dns'] },
];

const RANK: Record<DrillResult, number> = { reached: 0, verified: 1, nothing_new: 2, failed: 3, skipped: 4 };

function wordOf(r: DrillResult): DrillWord {
    switch (r) {
        case 'reached':
        case 'verified':
            return 'works';
        case 'nothing_new':
            return 'nothing_new';
        case 'failed':
            return 'no_answer';
        default:
            return 'not_here';
    }
}

/** One line per route family the file holds, in a fixed order. A family
 *  whose classes are all missing, `skipped`/`not_in_file` (not in the
 *  file) or `skipped`/`route_up` (not asked: a route was up) has no
 *  line. */
export function drillLines(a: DrillAnswer): { family: DrillFamily; word: DrillWord }[] {
    if (!a.classes) return [];
    const out: { family: DrillFamily; word: DrillWord }[] = [];
    for (const f of FAMILIES) {
        const got = f.classes
            .map((c) => a.classes![c])
            .filter((x): x is DrillClassResult => x !== undefined);
        // A class the file does not name, or one that was not asked
        // because a route was (or came) up, says nothing about this
        // network: no line for it.
        const said = got.filter((x) => !(x.result === 'skipped' && (x.reason === 'not_in_file' || x.reason === 'route_up')));
        if (said.length === 0) continue;
        const best = said.reduce((b, x) => (RANK[x.result] < RANK[b.result] ? x : b));
        out.push({ family: f.family, word: wordOf(best.result) });
    }
    return out;
}

/** The one sentence under the lines: its i18n key and tone. `{time}`
 *  in the rate-limit sentence is when it may run again. */
export function drillMessage(a: DrillAnswer): { key: string; tone: 'good' | 'neutral' | 'bad' } {
    switch (a.outcome) {
        case 'updated':
            return { key: 'files.check.updated', tone: 'good' };
        case 'unchanged':
            return { key: 'files.check.unchanged', tone: 'good' };
        case 'unreachable':
            // The engine's `unreachable` is "none brought a note that
            // verified": a family that answered with nothing new did
            // answer, and the headline must not say none did.
            if (drillLines(a).some((l) => l.word === 'nothing_new')) return { key: 'files.check.answered', tone: 'neutral' };
            return { key: 'files.check.unreachable', tone: 'bad' };
        case 'no_endpoints':
            return { key: 'files.check.no_endpoints', tone: 'neutral' };
        case 'rejected':
            return { key: 'files.check.rejected', tone: 'bad' };
        case 'tunnel_required':
            return { key: 'files.check.connected', tone: 'neutral' };
        case 'rate_limited':
            return { key: a.retryAfterS > 0 ? 'files.check.wait_until' : 'files.check.wait', tone: 'neutral' };
        case 'in_progress':
            return { key: 'files.check.busy', tone: 'neutral' };
        case 'cancelled':
            return { key: 'files.check.cancelled', tone: 'neutral' };
        case 'not_available':
        case 'unknown_pack':
            return { key: 'files.check.not_available', tone: 'neutral' };
        default:
            return { key: 'files.check.unavailable', tone: 'bad' };
    }
}

// ---- the file's backup routes --------------------------------------

/** The backup update routes the file holds (`backup_routes` on its
 *  routes; every route of one file carries the same list), in the
 *  engine's fixed order. Empty when it holds none or the engine says
 *  nothing. */
export function backupRoutesOf(p: PublisherTreeRow): BackupRoute[] {
    const seen = new Set<BackupRoute>();
    for (const c of p.cells) for (const r of c.routes) for (const b of r.backupRoutes ?? []) seen.add(b);
    return (['gittag', 'dns'] as const).filter((b) => seen.has(b));
}

/** "GitHub, DNS": what the muted line in the file's sheet lists. */
export function backupNames(t: (k: string) => string, list: readonly BackupRoute[]): string {
    return list.map((b) => t(b === 'gittag' ? 'files.backup.github' : 'files.backup.dns')).join(t('files.backup.sep'));
}

/** The route the check is asked about: any route of the file that names
 *  backup routes. The engine checks that route's relay. A file (one
 *  publisher row) can hold the routes of more than one relay; the row
 *  model carries no relay id, so such a file has its first relay with
 *  backup routes checked, while the muted line (backupRoutesOf) speaks
 *  for all of them. Telling relays apart needs the engine to name a
 *  route's relay pack in the summary, which it does not yet. */
export function drillRouteOf(p: PublisherTreeRow): string | undefined {
    for (const c of p.cells) for (const r of c.routes) if ((r.backupRoutes ?? []).length > 0) return r.routeId;
    return undefined;
}

/** The check is offered only for a file with backup routes, and only
 *  while nothing is up: no route running, none being checked, no
 *  automatic connect trying, no connect of this page waiting. */
export function canOfferCheck(
    p: PublisherTreeRow,
    s: ConnectionSummary | null,
    activeRouteId: string | null,
    pendingId: string | null,
): boolean {
    if (backupRoutesOf(p).length === 0) return false;
    if (activeRouteId !== null || pendingId !== null) return false;
    if (!s) return false;
    if (s.routeRunning === true || s.state === 'connected' || s.state === 'connecting') return false;
    if (autoTrying(s.auto)) return false;
    return true;
}

// ---- the last check, kept beyond the page ---------------------------

/** How long the engine refuses a second check of one file. */
export const CHECK_AGAIN_MS = 10 * 60_000;

/** The running check and the last answer, kept outside the page: the
 *  Files tab unmounts when the person leaves it, and the per-route lines
 *  are the point of the check. Memory only (never stored). */
export interface KeptCheck {
    fileName: string;
    running: boolean;
    /** When the check was started (ms): the engine's 10-minute stamp. */
    startedAt: number;
    answer?: DrillAnswer;
    /** When the answer came (ms). */
    at?: number;
}

let kept: KeptCheck | null = null;
const listeners = new Set<() => void>();

export function keptCheck(): KeptCheck | null {
    return kept;
}

export function setKeptCheck(k: KeptCheck | null): void {
    kept = k;
    for (const f of [...listeners]) f();
}

export function subscribeKeptCheck(f: () => void): () => void {
    listeners.add(f);
    return () => {
        listeners.delete(f);
    };
}

/** Outcomes after which the engine has kept its stamp for certain: a
 *  check that asked something. */
const ASKED: ReadonlySet<DrillOutcome> = new Set(['updated', 'unchanged', 'unreachable', 'rejected']);

/** The kept answer of `fileName` that still has lines, younger than the
 *  engine's 10 minutes; null otherwise. `askedOnly`: only one after
 *  which the engine surely refuses a new check (so it need not be asked). */
export function keptAnswerFor(fileName: string, nowMs: number, askedOnly: boolean): KeptCheck | null {
    const k = kept;
    if (!k || k.running || !k.answer || k.fileName !== fileName) return null;
    if (nowMs - k.startedAt >= CHECK_AGAIN_MS || nowMs < k.startedAt) return null;
    if (drillLines(k.answer).length === 0) return null;
    if (askedOnly && !ASKED.has(k.answer.outcome)) return null;
    return k;
}
