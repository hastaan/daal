// A received network-test report, read for the publisher (reportView.ts).
import { describe, expect, it } from 'vitest';
import en from '../i18n/d2/d2-extra.en.json';
import fa from '../i18n/d2/d2-extra.fa.json';
import { SAMPLE_REPORT } from '../harness/netTestFake';
import {
    PROBE_NAMES,
    QUESTIONS,
    RESULTS,
    STAGES,
    answerKey,
    findingTone,
    openFailureKey,
    parseReport,
    probeKey,
    questionKey,
    reportText,
    resultKey,
    resultTone,
    shownVariant,
    stageOf,
} from './reportView';

const EN = en as Record<string, string>;
const FA = fa as Record<string, string>;
const t = (k: string) => EN[k] ?? k;

describe('reading a report', () => {
    it('reads the closed fields of a v2 report', () => {
        const r = parseReport(JSON.stringify(SAMPLE_REPORT))!;
        expect(r).not.toBeNull();
        expect(r.networkLabel).toBe('mci');
        expect(r.netKind).toBe('cellular');
        expect(r.complete).toBe(true);
        expect(r.durationMin).toBe(3);
        expect(r.probes).toHaveLength(SAMPLE_REPORT.probes.length);
        expect(r.findings.map((f) => f.question)).toContain('reset_looks_injected');
        expect(r.probes.map(stageOf)).toEqual(expect.arrayContaining(['A', 'B', 'C']));
    });

    it('refuses what is not a v2 report, and drops what is not a closed token', () => {
        expect(parseReport('not json')).toBeNull();
        expect(parseReport('{"schema_version":1}')).toBeNull();
        const odd = {
            ...SAMPLE_REPORT,
            network_label: '<b>evil</b>',
            probes: [
                { id: 'Z9', name: 'x', result: 'ok' },
                { id: 'C2', name: 'relay_reality', target_role: 'relay', variant: 'a b <script>', result: 'reset', phase: 'handshake' },
            ],
            findings: [{ question: 'made_up', answer: 'yes', basis: [] }],
        };
        const r = parseReport(JSON.stringify(odd))!;
        expect(r.networkLabel).toBe('not_said');
        expect(r.probes).toEqual([
            { id: 'C2', name: 'relay_reality', role: 'relay', variant: '', result: 'reset', phase: 'handshake' },
        ]);
        expect(r.findings).toEqual([]);
    });

    it('a note is text, cut at 500', () => {
        const r = parseReport(JSON.stringify({ ...SAMPLE_REPORT, notes: 'x'.repeat(900) }))!;
        expect(r.notes).toHaveLength(500);
    });
});

describe('the words', () => {
    const keys = [
        ...PROBE_NAMES.map(probeKey),
        probeKey('from_the_future'),
        ...RESULTS.map(resultKey),
        resultKey('from_the_future'),
        ...QUESTIONS.map(questionKey),
        ...(['yes', 'no', 'unclear'] as const).map(answerKey),
        ...STAGES.map((s) => `netTest.stage.${s}`),
        ...['wifi', 'cellular', 'ethernet', 'other', 'none', 'vpn'].map((k) => `netTest.kind.${k}`),
        'netTest.open.notReport',
        'netTest.open.notOurs',
        'netTest.open.noKey',
        'netTest.open.readFailed',
        'netTest.open.failed',
    ];
    it.each(keys)('%s is in English and Persian', (k) => {
        expect(EN[k], `en ${k}`).toBeTruthy();
        expect(FA[k], `fa ${k}`).toBeTruthy();
    });

    it('good, bad and not-tested are told apart', () => {
        expect(resultTone('ok_carried')).toBe('good');
        expect(resultTone('reset_injected_likely')).toBe('bad');
        expect(resultTone('skipped')).toBe('none');
        expect(resultTone('local_error')).toBe('none');
        // The blocked name answered with a fake address is what the
        // comparison expects; through the public resolver it is news.
        expect(resultTone('bogon', 'dns_calibration')).toBe('none');
        expect(resultTone('bogon', 'dns_public_resolver')).toBe('bad');
        // "Yes" is bad news for the questions about interference.
        expect(findingTone({ question: 'reset_looks_injected', answer: 'yes', basis: [] })).toBe('bad');
        expect(findingTone({ question: 'reality_443_works', answer: 'yes', basis: [] })).toBe('good');
        expect(findingTone({ question: 'reality_443_works', answer: 'no', basis: [] })).toBe('bad');
        expect(findingTone({ question: 'quic_443_alive', answer: 'unclear', basis: [] })).toBe('none');
    });

    it('only a DNS record type is shown beside a name', () => {
        expect(shownVariant('aaaa')).toBe('AAAA');
        expect(shownVariant('desync_off')).toBe('');
    });

    it('a failed open is one plain line per code', () => {
        expect(openFailureKey('E_REPORT_NOT_OURS: no')).toBe('netTest.open.notOurs');
        expect(openFailureKey('E_REPORT_NOT_A_REPORT: no')).toBe('netTest.open.notReport');
        expect(openFailureKey('E_REPORT_NO_KEY: no')).toBe('netTest.open.noKey');
        expect(openFailureKey('E_DEPLOY_TOO_OLD: no')).toBe('pub.fail.deploy_too_old');
        expect(openFailureKey(new Error('boom'))).toBe('netTest.open.failed');
        expect(openFailureKey('E_CUSTODY_LOCKED: unlock')).toBe('pub.fail.locked');
        // A broken store is not "locked": unlocking would not help.
        expect(openFailureKey('E_CUSTODY_BACKEND: the stored report key is not valid')).toBe('netTest.open.failed');
    });
});

describe('variants and phases', () => {
    it('keep only the schema\'s lower-case codes: nothing dotted reaches the copied text', () => {
        const base = SAMPLE_REPORT.probes[0];
        const r = parseReport(
            JSON.stringify({
                ...SAMPLE_REPORT,
                probes: [
                    { ...base, variant: '203.0.113.9', phase: 'Reach' },
                    { ...base, variant: 'sni-cut+tls', phase: 'carry' },
                ],
            }),
        )!;
        expect(r.probes.map((p) => [p.variant, p.phase])).toEqual([
            ['', ''],
            ['sni-cut+tls', 'carry'],
        ]);
        expect(reportText(t, r)).not.toContain('203.0.113.9');
    });
});

describe('copy as text', () => {
    it('says each line in words, with the codes beside it for whoever helps', () => {
        const r = parseReport(JSON.stringify(SAMPLE_REPORT))!;
        const s = reportText(t, r);
        expect(s).toContain(EN['netTest.report.title']);
        expect(s).toContain(EN['netTest.label.mci']);
        expect(s).toContain(
            `C5 ${EN['netTest.probe.relay_plain_cover_sni']} (sni_cover): ${EN['netTest.res.reset_injected_likely']}`,
        );
        expect(s).toContain('[relay_plain_cover_sni=reset_injected_likely/handshake]');
        expect(s).toContain('[reset_looks_injected=yes; C5]');
        expect(s).toContain(EN['netTest.stage.C']);
        expect(s).toContain('Mobile data, at home.');
        // Stages in order.
        expect(s.indexOf(EN['netTest.stage.A'])).toBeLessThan(s.indexOf(EN['netTest.stage.C']));
    });
});
