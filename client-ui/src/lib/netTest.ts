// netTest — the network test's state, read from the engine's answers
// (specs/field-probe-v2.md, core/abi/fieldprobe.go), and the words for
// every closed code it can give. Pure: no calls, no React.
//
// The engine decides everything (who may run, what is kept, what goes
// in the report); this file only turns its JSON into what the page
// shows. A code this app does not know gets a general line, never the
// code itself.

/** What `field_probe_status` said. */
export type NetStatus =
    | { kind: 'unavailable' }
    | { kind: 'idle'; plan: NetPlan; offered: boolean; publisherId: string }
    | { kind: 'running'; step: number; of: number }
    | {
          kind: 'result';
          complete: boolean;
          abortReason: string;
          /** i18n keys (`netTest.summary.*`) in the engine's order, known ones only. */
          summary: string[];
          netKind: string;
          offered: boolean;
          publisherId: string;
          /** What a new run tests (for "Run again"); null from an older engine. */
          plan: NetPlan | null;
          /** The full report as the engine keeps it ("Show everything"), pretty JSON; '' if none. */
          reportJson: string;
      };

export interface NetPlan {
    steps: number;
    minutes: number;
    consentVersion: number;
    /** The names the test connects to (from the signed list). */
    names: string[];
    /** The public resolver it asks ("1.1.1.1"); "" when not said. */
    publicResolver: string;
}

/** The summary keys this app has words for. */
export const SUMMARY_KEYS = [
    'netTest.summary.relayConnects',
    'netTest.summary.relayCutAtStart',
    'netTest.summary.relayNoAnswer',
    'netTest.summary.relayNotTested',
    'netTest.summary.splitHelloHelps',
    'netTest.summary.whiteNameHelps',
    'netTest.summary.googleGithubOpen',
    'netTest.summary.someForeignOpen',
    'netTest.summary.googleGithubClosed',
    'netTest.summary.dnsWrongAddresses',
    'netTest.summary.cloudflareClosed',
    'netTest.summary.cdnSlowsAfterStart',
    'netTest.summary.quicClosed',
    'netTest.summary.blackout',
    'netTest.summary.localBlocked',
    'netTest.summary.incomplete',
    'netTest.summary.privacy',
] as const;

const SUMMARY_SET = new Set<string>(SUMMARY_KEYS);

/** Start refusals (`{"started":false,"refused":code}`). */
export const REFUSAL_CODES = [
    'running',
    'connected',
    'vpn_active',
    'no_network',
    'local_blocked',
    'consent_required',
    'no_report_key',
    'no_test_relay',
    'test_relay_shared',
    'rate_limited',
] as const;

/** Why a run stopped early (`report.run.abort_reason`). */
export const ABORT_REASONS = [
    'cancelled',
    'backgrounded',
    'time_limit',
    'budget',
    'network_changed',
    'shutdown',
    'error',
    'local_blocked',
    'vpn_active',
    'connected',
] as const;

/** Seal refusals (`{"sealed":false,"refused":code}`). */
export const SEAL_REFUSALS = ['no_result', 'notes_too_long', 'running'] as const;

/** The labels a person may give the network (`network_label`). */
export const NETWORK_LABELS = [
    'not_said',
    'home_internet',
    'mci',
    'irancell',
    'rightel',
    'other_mobile',
    'work_or_public',
] as const;
export type NetworkLabel = (typeof NETWORK_LABELS)[number];

function obj(v: unknown): Record<string, unknown> | null {
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function num(v: unknown, d = 0): number {
    return typeof v === 'number' && Number.isFinite(v) ? v : d;
}
function str(v: unknown): string {
    return typeof v === 'string' ? v : '';
}

/** Parse `field_probe_status`. Anything that is not one of its three
 *  shapes is `unavailable` (the page then offers nothing). */
export function parseStatus(raw: unknown): NetStatus {
    let v: unknown = raw;
    if (typeof raw === 'string') {
        try {
            v = JSON.parse(raw);
        } catch {
            return { kind: 'unavailable' };
        }
    }
    const o = obj(v);
    if (!o) return { kind: 'unavailable' };
    const offered = o.has_test_relay === true;
    const readPlan = (p: Record<string, unknown>): NetPlan => {
        const names = Array.isArray(p.names)
            ? (p.names as unknown[]).filter((n): n is string => typeof n === 'string' && n.trim() !== '')
            : [];
        return {
            steps: Math.max(1, num(p.steps, 1)),
            minutes: Math.max(1, num(p.minutes, 4)),
            consentVersion: num(p.consent_version, 1),
            names,
            publicResolver: str(p.public_resolver),
        };
    };
    const publisherId = str(o.publisher_id);
    switch (o.state) {
        case 'running': {
            const of = Math.max(1, num(o.of, 1));
            return { kind: 'running', step: Math.min(of, Math.max(0, num(o.step))), of };
        }
        case 'done':
        case 'aborted': {
            const summary = Array.isArray(o.summary)
                ? (o.summary as unknown[]).filter((k): k is string => typeof k === 'string' && SUMMARY_SET.has(k))
                : [];
            return {
                kind: 'result',
                complete: o.state === 'done' && o.complete !== false,
                abortReason: str(o.abort_reason),
                summary,
                netKind: str(o.net_kind),
                offered,
                publisherId,
                plan: obj(o.plan) ? readPlan(obj(o.plan) ?? {}) : null,
                reportJson: obj(o.report) ? JSON.stringify(o.report, null, 2) : '',
            };
        }
        case 'idle':
            return {
                kind: 'idle',
                plan: readPlan(obj(o.plan) ?? {}),
                offered,
                publisherId,
            };
        default:
            return { kind: 'unavailable' };
    }
}

/** Is the network test row shown at all: a test relay is held, or a
 *  result is kept (it can still be sent or deleted). */
export function rowShown(s: NetStatus): boolean {
    if (s.kind === 'idle') return s.offered;
    return s.kind === 'running' || s.kind === 'result';
}

/** What `field_probe_start` answered. */
export type StartAnswer = { started: true } | { started: false; refused: string; retryAfterMin?: number };

export function parseStart(raw: unknown): StartAnswer {
    let v: unknown = raw;
    if (typeof raw === 'string') {
        try {
            v = JSON.parse(raw);
        } catch {
            return { started: false, refused: '' };
        }
    }
    const o = obj(v);
    if (!o) return { started: false, refused: '' };
    if (o.started === true) return { started: true };
    const retry = num(o.retry_after_min, -1);
    return { started: false, refused: str(o.refused), ...(retry >= 0 ? { retryAfterMin: retry } : {}) };
}

/** What `field_probe_share` / `field_probe_seal` answered. */
export type SealAnswer = { sealed: true; fileName: string } | { sealed: false; refused: string };

export function parseSeal(raw: unknown): SealAnswer {
    let v: unknown = raw;
    if (typeof raw === 'string') {
        try {
            v = JSON.parse(raw);
        } catch {
            return { sealed: false, refused: '' };
        }
    }
    const o = obj(v);
    if (!o) return { sealed: false, refused: '' };
    if (o.sealed === true) return { sealed: true, fileName: str(o.file_name) };
    return { sealed: false, refused: str(o.refused) };
}

/** The line for a start refusal. `{n}` (minutes) and `{name}` are
 *  filled by the caller. */
export function refusalKey(code: string): string {
    return (REFUSAL_CODES as readonly string[]).includes(code) ? `netTest.refused.${code}` : 'netTest.refused.other';
}

/** The line for a run that stopped early; '' for a complete run. */
export function abortKey(reason: string, complete: boolean): string {
    // No reason given: a run that ended on its own terms (a blackout cut
    // short, say). The summary says what happened.
    if (reason === '' || complete) return '';
    return (ABORT_REASONS as readonly string[]).includes(reason) ? `netTest.aborted.${reason}` : 'netTest.aborted.other';
}

export function sealRefusalKey(code: string): string {
    return (SEAL_REFUSALS as readonly string[]).includes(code) ? `netTest.sealRefused.${code}` : 'netTest.send.failed';
}

/** What the page shows now. */
export type NetView =
    | 'loading'
    | 'unavailable'
    | 'consent'
    | 'running'
    | 'result';

/** `again`: the person asked to run the test again over a kept result. */
export function viewOf(s: NetStatus | null, again = false): NetView {
    if (!s) return 'loading';
    switch (s.kind) {
        case 'unavailable':
            return 'unavailable';
        case 'idle':
            return s.offered ? 'consent' : 'unavailable';
        case 'running':
            return 'running';
        case 'result':
            return again && canRunAgain(s) ? 'consent' : 'result';
    }
}

/** Can a new run start over this kept result: a test relay is still
 *  held and the engine said what a run tests. */
export function canRunAgain(s: NetStatus | null): boolean {
    return s?.kind === 'result' && s.offered && s.plan !== null;
}

/** What a new run would test, from either state that can start one. */
export function planOf(s: NetStatus | null): NetPlan | null {
    if (s?.kind === 'idle') return s.plan;
    if (s?.kind === 'result') return s.plan;
    return null;
}

/** The summary lines to show: the engine's keys, without the privacy
 *  line (the page shows that one beside Send) and without "incomplete"
 *  when the page already says why the run stopped. */
export function resultLines(s: Extract<NetStatus, { kind: 'result' }>): string[] {
    const why = abortKey(s.abortReason, s.complete);
    return s.summary.filter(
        (k) => k !== 'netTest.summary.privacy' && !(why !== '' && k === 'netTest.summary.incomplete'),
    );
}

/** The share's progress fraction, 0..1. */
export function progress(s: Extract<NetStatus, { kind: 'running' }>): number {
    return Math.min(1, Math.max(0, s.step / s.of));
}

/** Put `{name}`, `{n}`, `{of}`… into a translated line. */
export function fill(text: string, values: Record<string, string | number>): string {
    return text.replace(/\{(\w+)\}/g, (m, k: string) => (k in values ? String(values[k]) : m));
}
