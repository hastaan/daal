// RelayGonePanel — what the app says after a rebuild deleted the relay
// and could not build the replacement.
//
// WHY THIS IS A PANEL AND NOT AN ERROR TOAST
//
// The failure it reports outlives the sheet that caused it. L4/L5/L6
// delete the server before building the new one (`reprovision`
// deliberately does not re-create), so a failure in the second half
// leaves no relay — and the error string that reported it disappears
// the moment the operator closes the sheet. Everything after that
// point is a screen offering actions against a machine that no longer
// exists: swap the address, rotate credentials, change the disguise,
// delete the server. Each fails as a transport error, which reads as
// network trouble rather than "your relay was destroyed".
//
// So the state is persisted (operators.status = 'rebuild_failed') and
// rendered here, at the top of the danger zone, above every action it
// invalidates.
//
// WHY THE AUDIT IS ON THIS PANEL
//
// The worst part of this failure is not the lost relay, it is what may
// still be running. A failed provision can leave a half-built server
// billing and an SSH key that BLOCKS the next attempt — which has
// already happened to this project's own operator. The verb that finds
// those is `daal-deploy account-audit`, and until now the only thing
// pointing at it was an English sentence telling the operator to run a
// command with `--token-file <token>`: a shell they do not have, and a
// file that does not exist because the credential lives in device
// custody. Same verb, same report, reachable.
//
// It is READ-ONLY. `account-reclaim` deletes, and it is deliberately
// not wired to a button here — the read-only verb and the destructive
// one should not be one tap apart any more than they are one typo
// apart in the CLI.
import { useState } from 'react';
import { Wizard } from './wizardCommands';
import type { AccountAuditReport } from './wizardCommands';
import { Button, Card } from '../design/primitives';

const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 };
const MUTED: React.CSSProperties = { ...BODY, color: 'var(--muted)', fontSize: 12 };
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)', fontSize: 12 };

export function RelayGonePanel({
    t,
    operatorId,
}: {
    t: (k: string) => string;
    operatorId: number;
}) {
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<AccountAuditReport | null>(null);
    const [err, setErr] = useState<string | null>(null);

    const run = async () => {
        setBusy(true);
        setErr(null);
        try {
            setReport(await Wizard.accountAudit(operatorId));
        } catch (e) {
            setErr(String(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <Card>
            <div style={{ display: 'grid', gap: 10 }}>
                <div style={{ ...BODY, fontWeight: 600, color: 'var(--red)' }}>
                    {t('pub.danger.gone.title')}
                </div>
                <div style={BODY}>{t('pub.danger.gone.body')}</div>
                <div style={BODY}>{t('pub.danger.gone.next')}</div>
                <div style={MUTED}>{t('pub.danger.gone.audit_why')}</div>
                <span>
                    <Button variant="secondary" onClick={() => void run()} disabled={busy}>
                        {busy ? t('pub.danger.gone.checking') : t('pub.danger.gone.check')}
                    </Button>
                </span>
                {err && <div style={{ ...MUTED, color: 'var(--red)' }}>{err}</div>}

                {report && (
                    <div style={{ display: 'grid', gap: 6 }}>
                        {/* THE FIELD THAT DECIDES WHETHER ANY OF THIS
                            MEANS ANYTHING. A resource is an orphan
                            because no server stands behind it; if the
                            server list could not be read, that claim
                            cannot be made about anything, and an empty
                            list would otherwise read as a clean
                            account. */}
                        {!report.server_list_complete && (
                            <div style={{ ...BODY, color: 'var(--red)' }}>
                                {t('pub.danger.gone.incomplete')}
                            </div>
                        )}
                        {report.resources.length === 0 ? (
                            <div style={BODY}>
                                {report.server_list_complete
                                    ? t('pub.danger.gone.nothing')
                                    : t('pub.danger.gone.nothing_unproven')}
                            </div>
                        ) : (
                            <>
                                <div style={BODY}>{t('pub.danger.gone.found')}</div>
                                {report.resources.map((r, i) => (
                                    <div
                                        key={`${r.kind}:${r.id}:${i}`}
                                        style={{
                                            border: '1px solid var(--line)',
                                            borderRadius: 'var(--radius-md)',
                                            padding: '8px 10px',
                                            display: 'grid',
                                            gap: 4,
                                        }}
                                    >
                                        <div style={MONO}>
                                            {r.kind} {r.id}
                                            {r.name ? ` · ${r.name}` : ''}
                                        </div>
                                        {/* The fact this panel exists
                                            for: an operator with no
                                            shell needs to know which
                                            leftovers charge them, not
                                            just that leftovers exist.
                                            Translated, unlike the
                                            auditor's own evidence
                                            lines above. */}
                                        {r.billing && (
                                            <div
                                                style={{
                                                    ...BODY,
                                                    color: 'var(--red)',
                                                    fontWeight: 600,
                                                }}
                                            >
                                                {t('pub.danger.gone.billing')}
                                            </div>
                                        )}
                                        {/* Verdict and reason come from
                                            the auditor in English. They
                                            are evidence to cross-check
                                            against the provider
                                            console, not instructions —
                                            the instruction is the
                                            translated sentence above. */}
                                        {r.reason && <div style={MUTED}>{r.reason}</div>}
                                        {r.hint && <div style={MUTED}>{r.hint}</div>}
                                    </div>
                                ))}
                            </>
                        )}
                        {report.warnings.map((w, i) => (
                            <div key={i} style={{ ...MUTED, color: 'var(--red)' }}>
                                {w}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </Card>
    );
}
