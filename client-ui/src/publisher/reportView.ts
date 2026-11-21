// reportView — a received network-test report (schema v2,
// test-rigs/field-probe/schema/probe-report-v2.json), turned into plain
// lines for the publisher, and into text to copy.
//
// The report is UNTRUSTED: anyone who holds the report address can make
// one. The opener (`daal-deploy report-open`) has already validated it
// strictly; this file still reads only the closed fields it knows, by
// whitelist, and treats the one free-text field (`notes`) as text.

import { abortKey } from '../lib/netTest';

export interface ReportProbe {
    id: string;
    name: string;
    role: string;
    variant: string;
    result: string;
    phase: string;
}

export interface ReportFinding {
    question: string;
    answer: 'yes' | 'no' | 'unclear';
    basis: string[];
}

export interface ReportView {
    reportId: string;
    hour: string;
    platform: string;
    networkLabel: string;
    netKind: string;
    complete: boolean;
    abortReason: string;
    durationMin: number;
    stepsRun: number;
    shortCircuit: boolean;
    probes: ReportProbe[];
    findings: ReportFinding[];
    notes: string;
}

export const PROBE_NAMES = [
    'dns_link_allowed',
    'dns_https_record',
    'dns_white_name',
    'dns_known_zone',
    'dns_calibration',
    'dns_public_resolver',
    'tls_baseline',
    'google_front',
    'google_front_redirect',
    'github_feed',
    'white_name_cdn',
    'cdn_neutral_carry',
    'ech',
    'ech_control',
    'quic_443',
    'relay_http_80',
    'relay_reality',
    'relay_reality_split',
    'relay_plain_white_sni',
    'relay_plain_cover_sni',
    'relay_plain_neutral_sni',
    'relay_alt_port',
    'relay_quic',
    'relay_reality_again',
] as const;

export const RESULTS = [
    'ok',
    'ok_carried',
    'reset_injected_likely',
    'reset',
    'silent_drop_forward',
    'silent_no_reply',
    'flow_capped_suspected',
    'refused',
    'closed',
    'tls_alert',
    'timeout',
    'auth_failed',
    'skipped',
    'bogon',
    'nxdomain',
    'servfail',
    'dns_timeout',
    'type_dropped',
    'answer_altered',
    'local_error',
    'unreachable',
    'dns_wrong_public',
    'cert_invalid',
    'dns_unlisted',
] as const;

export const QUESTIONS = [
    'reality_443_works',
    'split_hello_helps',
    'white_name_helps_on_relay_ip',
    'white_name_uncapped_on_cdn_ip',
    'grey_cap_seen_on_cdn_ip',
    'reset_looks_injected',
    'cloudflare_edge_reachable',
    'ech_passes',
    'google_front_passes',
    'github_feed_fetchable',
    'resolver_recurses_foreign_zone',
    'dns_injection_on_path',
    'quic_443_alive',
    'relay_alt_ports_open',
    'test_changed_outcome',
] as const;

const NAME_SET = new Set<string>(PROBE_NAMES);
const RESULT_SET = new Set<string>(RESULTS);
const QUESTION_SET = new Set<string>(QUESTIONS);
const LABELS = new Set(['home_internet', 'mci', 'irancell', 'rightel', 'other_mobile', 'work_or_public', 'not_said']);
const KINDS = new Set(['wifi', 'cellular', 'ethernet', 'other', 'none', 'vpn']);
/** A closed token: letters, digits, `_`, `-`, `.`; short. */
const TOKEN = /^[A-Za-z0-9_.-]{0,40}$/;
/** A variant or phase: the schema's lower-case codes only. No dot, so
 *  nothing shaped like an address can reach "Copy as text". */
const CODE = /^[a-z0-9_+-]{0,40}$/;

function obj(v: unknown): Record<string, unknown> | null {
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}
function tok(v: unknown): string {
    return typeof v === 'string' && TOKEN.test(v) ? v : '';
}
function code(v: unknown): string {
    return typeof v === 'string' && CODE.test(v) ? v : '';
}

/** Read a report, or null for anything that is not a v2 report. */
export function parseReport(raw: string): ReportView | null {
    let v: unknown;
    try {
        v = JSON.parse(raw);
    } catch {
        return null;
    }
    const o = obj(v);
    if (!o || o.schema_version !== 2) return null;
    const run = obj(o.run) ?? {};
    const net = obj(o.net) ?? {};
    const probes: ReportProbe[] = [];
    for (const p of Array.isArray(o.probes) ? (o.probes as unknown[]) : []) {
        const q = obj(p);
        if (!q) continue;
        const id = tok(q.id);
        if (!/^[ABC]\d{1,2}$/.test(id)) continue;
        probes.push({
            id,
            name: tok(q.name),
            role: tok(q.target_role),
            variant: code(q.variant),
            result: tok(q.result),
            phase: code(q.phase),
        });
    }
    const findings: ReportFinding[] = [];
    for (const f of Array.isArray(o.findings) ? (o.findings as unknown[]) : []) {
        const q = obj(f);
        if (!q) continue;
        const question = tok(q.question);
        const answer = q.answer === 'yes' || q.answer === 'no' ? q.answer : 'unclear';
        if (!QUESTION_SET.has(question)) continue;
        const basis = Array.isArray(q.basis) ? (q.basis as unknown[]).map(tok).filter((b) => b !== '') : [];
        findings.push({ question, answer, basis });
    }
    const label = tok(o.network_label);
    const kind = tok(net.kind);
    const dur = typeof run.duration_bucket_s === 'number' ? run.duration_bucket_s : 0;
    return {
        reportId: tok(o.report_id),
        hour: typeof o.generated_hour_bucket === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:00Z$/.test(o.generated_hour_bucket)
            ? o.generated_hour_bucket
            : '',
        platform: tok(o.platform),
        networkLabel: LABELS.has(label) ? label : 'not_said',
        netKind: KINDS.has(kind) ? kind : '',
        complete: run.complete === true,
        abortReason: tok(run.abort_reason),
        durationMin: Math.round(dur / 60),
        stepsRun: typeof run.steps_run === 'number' ? run.steps_run : 0,
        shortCircuit: run.short_circuit === true,
        probes,
        findings,
        notes: typeof o.notes === 'string' ? o.notes.slice(0, 500) : '',
    };
}

export type Stage = 'A' | 'B' | 'C';
export const STAGES: Stage[] = ['A', 'B', 'C'];

export function stageOf(p: ReportProbe): Stage {
    return p.id.charAt(0) as Stage;
}

export function probeKey(name: string): string {
    return NAME_SET.has(name) ? `netTest.probe.${name}` : 'netTest.probe.other';
}

export function resultKey(result: string): string {
    return RESULT_SET.has(result) ? `netTest.res.${result}` : 'netTest.res.other';
}

/** good: it went through. bad: something on the path stopped it.
 *  none: not tested, this phone's own problem, or the answer a
 *  comparison probe expects (the blocked name answered with a fake
 *  address is the calibration working, not news). */
export function resultTone(result: string, name = ''): 'good' | 'bad' | 'none' {
    if (name === 'dns_calibration' && result === 'bogon') return 'none';
    if (result === 'ok' || result === 'ok_carried') return 'good';
    if (result === 'skipped' || result === 'local_error' || result === '') return 'none';
    return 'bad';
}

/** Questions where "yes" is the bad news. */
const BAD_WHEN_YES = new Set([
    'grey_cap_seen_on_cdn_ip',
    'reset_looks_injected',
    'dns_injection_on_path',
    'test_changed_outcome',
]);

/** good / bad / none for a finding: "yes" is good news except for the
 *  questions that ask about interference. */
export function findingTone(f: ReportFinding): 'good' | 'bad' | 'none' {
    if (f.answer === 'unclear') return 'none';
    const yesIsGood = !BAD_WHEN_YES.has(f.question);
    return (f.answer === 'yes') === yesIsGood ? 'good' : 'bad';
}

export function questionKey(q: string): string {
    return `netTest.q.${q}`;
}

export function answerKey(a: ReportFinding['answer']): string {
    return `netTest.answer.${a}`;
}

/** The report as plain text, in the page's language, with the closed
 *  codes beside each line (so it can be sent on to someone helping). */
export function reportText(t: (k: string) => string, r: ReportView): string {
    const lines: string[] = [];
    lines.push(`${t('netTest.report.title')} (${r.reportId || '-'})`);
    const where = [t(`netTest.label.${r.networkLabel}`), r.netKind ? t(`netTest.kind.${r.netKind}`) : '']
        .filter((x) => x !== '')
        .join(' · ');
    lines.push(`${t('netTest.report.network')}: ${where}`);
    if (r.hour) lines.push(`${t('netTest.report.when')}: ${r.hour.replace('T', ' ').replace(':00Z', ':00 UTC')}`);
    const why = abortKey(r.abortReason, r.complete);
    lines.push(
        `${t('netTest.report.run')}: ${t(r.complete ? 'netTest.report.complete' : 'netTest.report.incomplete')}` +
            (why ? ` — ${t(why)} [${r.abortReason}]` : ''),
    );
    if (r.findings.length > 0) {
        lines.push('');
        lines.push(t('netTest.report.findings'));
        for (const f of r.findings) {
            lines.push(`- ${t(questionKey(f.question))}: ${t(answerKey(f.answer))} [${f.question}=${f.answer}; ${f.basis.join(',')}]`);
        }
    }
    for (const st of STAGES) {
        const ps = r.probes.filter((p) => stageOf(p) === st);
        if (ps.length === 0) continue;
        lines.push('');
        lines.push(t(`netTest.stage.${st}`));
        for (const p of ps) {
            const v = p.variant ? ` (${p.variant})` : '';
            lines.push(`- ${p.id} ${t(probeKey(p.name))}${v}: ${t(resultKey(p.result))} [${p.name}=${p.result}${p.phase ? `/${p.phase}` : ''}]`);
        }
    }
    if (r.notes.trim() !== '') {
        lines.push('');
        lines.push(`${t('netTest.report.notes')}: ${r.notes.trim()}`);
    }
    return lines.join('\n');
}

/** The variant worth showing beside a probe's name: a DNS record type
 *  (two A1 rows differ only by it). Other variants are codes for the
 *  copied text only. */
export function shownVariant(v: string): string {
    return /^(a|aaaa|https|txt|cname)$/i.test(v) ? v.toUpperCase() : '';
}

/** What a failed open means, as a key. */
export function openFailureKey(e: unknown): string {
    const msg = typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
    if (msg.startsWith('E_REPORT_NOT_A_REPORT')) return 'netTest.open.notReport';
    if (msg.startsWith('E_REPORT_NOT_OURS')) return 'netTest.open.notOurs';
    if (msg.startsWith('E_REPORT_NO_KEY')) return 'netTest.open.noKey';
    if (msg.startsWith('E_REPORT_READ_FAILED')) return 'netTest.open.readFailed';
    if (msg.startsWith('E_DEPLOY_TOO_OLD')) return 'pub.fail.deploy_too_old';
    if (msg.startsWith('E_CUSTODY_LOCKED') || msg.startsWith('E_CUSTODY_WRONG_PASS')) return 'pub.fail.locked';
    return 'netTest.open.failed';
}
