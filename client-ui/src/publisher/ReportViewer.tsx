// ReportViewer — "Open a network test report" (network test,
// specs/field-probe-v2.md).
//
// Someone ran the network test and sent a `net-xxxxxxxx.dat`. This
// opens it with the report key on this phone and says, per stage, what
// went through and what was stopped, and how — in words, with the
// closed codes kept for "Copy as text".
//
// A report is UNTRUSTED (anyone with the address can make one): only
// closed fields are read (reportView.ts), the note is shown as text.

import { useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';
import { Button, Sheet, StateIcon, useToast } from '../design/primitives';
import { Wizard } from './wizardCommands';
import { PickedFile } from '../recipient/recipientCommands';
import { abortKey } from '../lib/netTest';
import {
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
import type { ReportView } from './reportView';

export interface ReportApi {
    /** A file the person picked, staged; null when they picked none. */
    pick(): Promise<string | null>;
    open(path: string): Promise<string>;
    copy(text: string): Promise<void>;
}

export const reportApi: ReportApi = {
    async pick() {
        // No extension filter: Android's picker cannot filter by an
        // extension it does not know.
        const picked = await openDialog({ multiple: false, directory: false });
        if (typeof picked !== 'string') return null;
        return PickedFile.stage(picked);
    },
    open: (path) => Wizard.reportOpen(path),
    copy: async (text) => {
        await navigator.clipboard.writeText(text);
    },
};

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    api?: ReportApi;
}

const SUB: React.CSSProperties = { fontSize: 13, lineHeight: 1.55, color: 'var(--muted)', margin: 0 };
const H3: React.CSSProperties = { margin: 0, fontSize: 14, fontWeight: 600, color: 'var(--fg)' };

export function ReportViewer({ t, onClose, api = reportApi }: Props) {
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<ReportView | null>(null);
    const [failure, setFailure] = useState<string | null>(null);
    const toast = useToast();

    const choose = async () => {
        setBusy(true);
        setFailure(null);
        try {
            const path = await api.pick();
            if (!path) return;
            const json = await api.open(path);
            const r = parseReport(json);
            if (!r) setFailure(t('netTest.open.notReport'));
            else setReport(r);
        } catch (e) {
            setFailure(t(openFailureKey(e)));
        } finally {
            setBusy(false);
        }
    };

    const copy = async () => {
        if (!report) return;
        try {
            await api.copy(reportText(t, report));
            toast.show('good', t('ui.copied'));
        } catch {
            toast.show('bad', t('netTest.report.copyFailed'));
        }
    };

    const why = report ? abortKey(report.abortReason, report.complete) : '';

    return (
        <Sheet title={t('pub.report.title')} width={560} onClose={() => !busy && onClose()}>
            <div style={{ display: 'grid', gap: 14 }} data-testid="report-viewer">
                {!report && (
                    <>
                        <p style={{ ...SUB, color: 'var(--fg)', fontSize: 14 }}>{t('pub.report.pick')}</p>
                        {failure && (
                            <p role="alert" data-testid="report-failure" style={{ ...SUB, color: 'var(--red)' }}>
                                {failure}
                            </p>
                        )}
                        <div>
                            <Button leading="file" dataButton="report-pick" disabled={busy} onClick={() => void choose()}>
                                {busy ? t('pub.report.opening') : t('pub.report.pick.go')}
                            </Button>
                        </div>
                        <p style={SUB}>{t('pub.testRelay.what.untrusted')}</p>
                    </>
                )}

                {report && (
                    <>
                        <div style={{ display: 'grid', gap: 4 }} data-testid="report-head">
                            <div style={{ fontSize: 14, color: 'var(--fg)', fontWeight: 600 }}>
                                {t(`netTest.label.${report.networkLabel}`)}
                                {report.netKind ? ` · ${t(`netTest.kind.${report.netKind}`)}` : ''}
                            </div>
                            {report.hour && (
                                <div style={SUB}>
                                    <bdi dir="ltr">{report.hour.replace('T', ' ').replace(':00Z', ':00 UTC')}</bdi>
                                </div>
                            )}
                            <div style={SUB}>
                                {t(report.complete ? 'netTest.report.complete' : 'netTest.report.incomplete')}
                                {why ? ` — ${t(why)}` : ''}
                            </div>
                        </div>

                        {report.findings.length > 0 && (
                            <section style={{ display: 'grid', gap: 6 }} data-testid="report-findings">
                                <h3 style={H3}>{t('netTest.report.findings')}</h3>
                                {report.findings.map((f) => (
                                    <div key={f.question} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                                        <span style={{ paddingBlockStart: 2, flexShrink: 0 }}>
                                            <StateIcon
                                                state={findingTone(f) === 'good' ? 'ok' : findingTone(f) === 'bad' ? 'bad' : 'none'}
                                                size={16}
                                            />
                                        </span>
                                        <span style={{ fontSize: 13, lineHeight: 1.5, color: 'var(--fg)' }}>
                                            {t(questionKey(f.question))}
                                            <span style={{ color: 'var(--muted)' }}> · {t(answerKey(f.answer))}</span>
                                        </span>
                                    </div>
                                ))}
                            </section>
                        )}

                        {STAGES.map((st) => {
                            const ps = report.probes.filter((p) => stageOf(p) === st);
                            if (ps.length === 0) return null;
                            return (
                                <section key={st} style={{ display: 'grid', gap: 6 }} data-testid={`report-stage-${st}`}>
                                    <h3 style={H3}>{t(`netTest.stage.${st}`)}</h3>
                                    {ps.map((p, i) => {
                                        const tone = resultTone(p.result, p.name);
                                        return (
                                            <div
                                                key={`${p.id}-${p.variant}-${i}`}
                                                style={{
                                                    display: 'flex',
                                                    gap: 8,
                                                    alignItems: 'flex-start',
                                                    paddingBlock: 4,
                                                    borderBlockEnd: '1px solid var(--line-soft)',
                                                }}
                                            >
                                                <span style={{ paddingBlockStart: 2, flexShrink: 0 }}>
                                                    <StateIcon state={tone === 'good' ? 'ok' : tone === 'bad' ? 'bad' : 'none'} size={16} />
                                                </span>
                                                <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                                                    <span style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.45 }}>
                                                        {t(probeKey(p.name))}
                                                        {shownVariant(p.variant) && (
                                                            <>
                                                                {' '}
                                                                <bdi
                                                                    dir="ltr"
                                                                    style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}
                                                                >
                                                                    {shownVariant(p.variant)}
                                                                </bdi>
                                                            </>
                                                        )}
                                                    </span>
                                                    <span style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.45 }}>
                                                        {t(resultKey(p.result))}
                                                    </span>
                                                </span>
                                            </div>
                                        );
                                    })}
                                </section>
                            );
                        })}

                        {report.notes.trim() !== '' && (
                            <section style={{ display: 'grid', gap: 6 }}>
                                <h3 style={H3}>{t('netTest.report.notes')}</h3>
                                <div
                                    dir="auto"
                                    style={{ ...SUB, color: 'var(--fg)', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}
                                >
                                    {report.notes.trim()}
                                </div>
                            </section>
                        )}

                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button leading="copy" dataButton="report-copy" onClick={() => void copy()}>
                                {t('netTest.report.copy')}
                            </Button>
                            <Button
                                variant="ghost"
                                dataButton="report-another"
                                onClick={() => {
                                    setReport(null);
                                    setFailure(null);
                                }}
                            >
                                {t('pub.report.another')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
            {toast.node}
        </Sheet>
    );
}
