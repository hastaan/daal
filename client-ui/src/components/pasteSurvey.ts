// pasteSurvey — what the route survey found for the routes a paste added
// (wave 1, lane B): "Check them now", then "Remove the ones that did not
// answer", and the Files page's "Remove the ways that don't work".
//
// The survey is the engine's own check (core/abi/survey.go, started by
// lib/routeSurvey.ts checkAllRoutes). Its block carries one result per
// route checked: carried, not_carrying (it was tried and did not carry),
// when_used (it cannot be checked beside a tunnel: wireguard, tor, …),
// skipped, start_failed (nothing was learned about the network) and
// cancelled. Only `not_carrying` is "checked and failed". A route that
// was not checked, is "checked when used", or is used only when the
// person picks it (a pasted WireGuard conf, `manual_only`) is never
// removed.
//
// A check the person starts covers more than the background one: it
// goes past the 12-an-hour side-check allowance and takes the newly
// pasted routes first (core/abi/survey.go). It still has a ceiling, so
// "could not be checked" stays a possible answer.

import { invoke } from '@tauri-apps/api/core';
import type { RouteDisplayRow } from '../contract/D2Contract';
import { parseSurvey, type SurveyReport } from '../lib/routeSurvey';

export type RouteCheck = 'works' | 'failed' | 'when_used' | 'unchecked';

export interface SurveyRead {
    report: SurveyReport;
    /** route id → what the survey found of it. */
    results: Map<string, RouteCheck>;
}

/** One survey block → its report and a verdict per route. A route can
 *  appear more than once (one result per variant): it worked if any one
 *  carried, failed only if one was answered and none carried. */
export function readSurveyBlock(raw: unknown): SurveyRead | null {
    const report = parseSurvey(raw);
    if (!report) return null;
    const results = new Map<string, RouteCheck>();
    const list = Array.isArray((raw as { results?: unknown }).results) ? ((raw as { results: unknown[] }).results) : [];
    for (const r of list) {
        if (!r || typeof r !== 'object') continue;
        const id = (r as { route_id?: unknown }).route_id;
        const res = (r as { result?: unknown }).result;
        if (typeof id !== 'string' || typeof res !== 'string') continue;
        const now = results.get(id);
        if (res === 'carried') results.set(id, 'works');
        else if (res === 'when_used') {
            if (now !== 'works') results.set(id, 'when_used');
        } else if (res === 'not_carrying') {
            if (now === undefined || now === 'unchecked') results.set(id, 'failed');
        } else if (now === undefined) results.set(id, 'unchecked');
    }
    return { report, results };
}

/** The survey block now, without starting one. Null when the engine has
 *  none (older engine, harness, a failed call). Never throws. */
export async function readSurvey(): Promise<SurveyRead | null> {
    try {
        return readSurveyBlock(JSON.parse(await invoke<string>('survey_routes', { start: false })));
    } catch {
        return null;
    }
}

/** A survey that has ended (done, or stopped part way). */
export function surveyEnded(r: SurveyReport | null | undefined): boolean {
    return !!r && (r.state === 'done' || r.state === 'stopped');
}

/** Used only when picked: the engine's `manual_only` when the row has it,
 *  else (a mapping that predates it) a pasted WireGuard route, which is
 *  only ever a conf and manual-only by construction. */
function manualOnlyRow(r: RouteDisplayRow): boolean {
    const m = r.manualOnly;
    if (typeof m === 'boolean') return m;
    return (r.family ?? '').trim().toLowerCase() === 'wireguard' && isPastedRoute(r.routeId);
}

/** What is known of each of `ids`: the survey's result, with a route the
 *  route list calls "checked when used", or one used only when picked,
 *  kept out of `failed`. */
export function checksFor(ids: string[], read: SurveyRead | null, routes?: RouteDisplayRow[]): Map<string, RouteCheck> {
    const whenUsed = new Set((routes ?? []).filter((r) => r.checkedWhenUsed || manualOnlyRow(r)).map((r) => r.routeId));
    const out = new Map<string, RouteCheck>();
    for (const id of ids) {
        let c = read?.results.get(id) ?? 'unchecked';
        if (whenUsed.has(id) && c !== 'works') c = 'when_used';
        out.set(id, c);
    }
    return out;
}

/** Ids whose check failed: the only ones a bulk removal may take. */
export function failedIds(checks: Map<string, RouteCheck>): string[] {
    return [...checks].filter(([, c]) => c === 'failed').map(([id]) => id);
}

/** Routes added by pasting a link carry this id prefix (core/abi/share.go
 *  URIImport: "pasted-<time>"). */
export function isPastedRoute(routeId: string): boolean {
    return routeId.startsWith('pasted-');
}

/** The Files page: of a file's routes, the ones that were checked here
 *  and did not answer, by the last survey or by what this network
 *  remembers of them (tried, failed, never carried). Never the route in
 *  use, never one checked only when used, never one that ever carried
 *  here or that the survey found working. */
export function failingHere(routes: RouteDisplayRow[], read: SurveyRead | null, activeRouteId: string | null): string[] {
    const out: string[] = [];
    for (const r of routes) {
        if (r.routeId === activeRouteId || r.checkedWhenUsed || manualOnlyRow(r)) continue;
        const s = read?.results.get(r.routeId);
        if (s === 'works' || s === 'when_used') continue;
        const m = r.measured;
        const memoryFailed = !!m && m.grade === 'failing' && m.failed > 0 && m.carried === 0;
        if (s === 'failed' || memoryFailed) {
            if (m && m.carried > 0) continue;
            out.push(r.routeId);
        }
    }
    return out;
}
