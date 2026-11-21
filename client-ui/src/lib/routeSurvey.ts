// routeSurvey — "Check all ways": the engine checks the other routes of
// the file beside the tunnel, or with nothing connected
// (core/abi/survey.go, engine_survey_routes). Without the button it
// does the same by itself, slowly, after every connect.
//
// The report is the `survey` block of the diagnostics blob (and the body
// of the command): how far the check is, and what each route did. The
// scores themselves are not here — each result lands where a connect's
// does, and the route list carries them; `seq` moves whenever one did,
// which is the page's cue to read the list again.

import { invoke } from '@tauri-apps/api/core';

export type SurveyState = 'idle' | 'waiting' | 'checking' | 'done' | 'stopped';
export type SurveyRefused = 'running' | 'busy' | 'unsupported' | 'unavailable';

export interface SurveyReport {
    state: SurveyState;
    /** 'user' when the person asked for it. */
    trigger: 'auto' | 'user' | '';
    /** Route ids being checked right now. */
    checking: string[];
    total: number;
    done: number;
    /** Counts results that changed what the engine remembers. */
    seq: number;
    stopReason: string;
    /** How many routes carried in this check. */
    carried: number;
}

export interface SurveyStart {
    started: boolean;
    refused?: SurveyRefused;
    report: SurveyReport | null;
}

const STATES: ReadonlySet<string> = new Set(['idle', 'waiting', 'checking', 'done', 'stopped']);

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);

/** The `survey` block, or null when it is missing or not one (an engine
 *  that predates the survey). Never throws. */
export function parseSurvey(raw: unknown): SurveyReport | null {
    if (!raw || typeof raw !== 'object') return null;
    const v = raw as Record<string, unknown>;
    if (typeof v.state !== 'string' || !STATES.has(v.state)) return null;
    const results = Array.isArray(v.results) ? v.results : [];
    return {
        state: v.state as SurveyState,
        trigger: v.trigger === 'auto' || v.trigger === 'user' ? v.trigger : '',
        checking: Array.isArray(v.checking) ? v.checking.filter((x): x is string => typeof x === 'string') : [],
        total: num(v.total),
        done: num(v.done),
        seq: num(v.seq),
        stopReason: typeof v.stop_reason === 'string' ? v.stop_reason : '',
        carried: results.filter((r) => r && typeof r === 'object' && (r as { result?: unknown }).result === 'carried').length,
    };
}

export function parseSurveyStart(body: string): SurveyStart {
    try {
        const v = JSON.parse(body) as Record<string, unknown>;
        const refused = v.refused === 'running' || v.refused === 'busy' || v.refused === 'unsupported' ? v.refused : undefined;
        return { started: v.started === true, ...(refused ? { refused } : {}), report: parseSurvey(v) };
    } catch {
        return { started: false, refused: 'unavailable', report: null };
    }
}

/** Starts the check. Never throws: an old engine or a failed call is
 *  'unavailable'. */
export async function checkAllRoutes(): Promise<SurveyStart> {
    try {
        return parseSurveyStart(await invoke<string>('survey_routes', { start: true }));
    } catch {
        return { started: false, refused: 'unavailable', report: null };
    }
}

/** A check the person asked for, still going. */
export function surveyRunning(r: SurveyReport | null | undefined): boolean {
    return !!r && r.trigger === 'user' && (r.state === 'waiting' || r.state === 'checking');
}

/** The line under the button: progress while the person's check runs,
 *  then how it ended. `undefined` when there is nothing to say. */
export function surveyLine(t: (k: string) => string, r: SurveyReport | null | undefined, digits: (n: number) => string): string | undefined {
    if (!r || r.trigger !== 'user') return undefined;
    if (surveyRunning(r)) {
        if (r.total === 0) return t('home.survey.checking_one');
        return t('home.survey.checking')
            .replace('{done}', digits(Math.min(r.done, r.total)))
            .replace('{total}', digits(r.total));
    }
    if (r.state === 'stopped') return t('home.survey.stopped');
    if (r.state === 'done') return r.total === 0 ? t('home.survey.nothing') : t('home.survey.done');
    return undefined;
}

/** The toast for a press the engine did not take. */
export function surveyRefusedKey(refused: SurveyRefused): string | undefined {
    switch (refused) {
        case 'running':
            return undefined; // already going: the line says so
        case 'busy':
            return 'home.survey.busy';
        default:
            return 'home.survey.failed';
    }
}
