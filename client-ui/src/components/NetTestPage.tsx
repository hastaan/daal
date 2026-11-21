// NetTestPage — Settings → Advanced → Network test (specs/field-probe-v2.md).
//
// Four states, each one card, read from the engine's status:
//
//   consent  what is tested, what the internet company sees, what
//            leaves the phone (nothing, unless Send), VPN off and Daal
//            disconnected, about four minutes; which internet this is
//            (optional); Start.
//   running  step n of N, a bar, Cancel. Leaving the app, or this page,
//            stops the test (the engine keeps what it found). The phone
//            keeps the screen on meanwhile (FieldProbeWatch.kt).
//   result   the engine's plain summary (never a name or an address),
//            "Show everything" (the report as it would be sent), then
//            Send report, Run again (first for a run that stopped
//            early) and Delete report. Sending is best done once Daal is
//            connected again, and allowed at once. Run again shows the
//            consent card over the kept result, which a new run replaces.
//   after a send: delete it from this phone? (Delete is the default.)
//
// Every refusal and every reason a run stopped is one plain line
// (lib/netTest.ts maps the engine's closed codes to keys).

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ConnState } from '../contract/D2Contract';
import { useContract } from '../contract/ContractProvider';
import { Button, Card, Disclosure, PageHeader, StateIcon } from '../design/primitives';
import {
    NETWORK_LABELS,
    abortKey,
    canRunAgain,
    fill,
    planOf,
    progress,
    refusalKey,
    resultLines,
    sealRefusalKey,
    viewOf,
} from '../lib/netTest';
import type { NetStatus, NetworkLabel } from '../lib/netTest';
import { NetTest } from '../lib/netTestCommands';
import { toFaDigits } from '../lib/i18n';
import { useDensity } from '../design/DensityProvider';
import type { NetTestApi } from '../lib/netTestCommands';

interface Props {
    t: (k: string) => string;
    /** Is Daal connected now (null = not known). */
    connState: ConnState | null;
    onBack: () => void;
    backLabel: string;
    api?: NetTestApi;
    /** How often the page asks while a test runs. */
    pollMs?: number;
}

const BODY: React.CSSProperties = { fontSize: 14, lineHeight: 1.6, color: 'var(--fg)', margin: 0 };
const MUTED: React.CSSProperties = { fontSize: 13, lineHeight: 1.55, color: 'var(--muted)', margin: 0 };
const H2: React.CSSProperties = {
    margin: 0,
    fontFamily: 'var(--font-display)',
    fontSize: 17,
    fontWeight: 500,
    color: 'var(--fg)',
};

/** A line that says no (red, with the icon). */
function NoLine({ text, testId }: { text: string; testId?: string }) {
    return (
        <div role="alert" data-testid={testId} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
            <span style={{ paddingBlockStart: 2, flexShrink: 0 }}>
                <StateIcon state="bad" size={16} />
            </span>
            <span style={{ ...MUTED, color: 'var(--red)' }}>{text}</span>
        </div>
    );
}

export default function NetTestPage({ t, connState, onBack, backLabel, api = NetTest, pollMs = 1000 }: Props) {
    const contract = useContract();
    const { isRTL } = useDensity();
    /** A number in the reader's digits. */
    const n = (v: number) => (isRTL ? toFaDigits(String(v)) : String(v));
    const [status, setStatus] = useState<NetStatus | null>(null);
    const [label, setLabel] = useState<NetworkLabel>('not_said');
    const [busy, setBusy] = useState<'start' | 'cancel' | 'send' | 'delete' | null>(null);
    const [refusal, setRefusal] = useState<string | null>(null);
    const [sendProblem, setSendProblem] = useState<string | null>(null);
    const [askDelete, setAskDelete] = useState(false);
    const [deleted, setDeleted] = useState(false);
    const [publisherName, setPublisherName] = useState('');
    /** "Run again" was pressed over a kept result: the consent card shows. */
    const [again, setAgain] = useState(false);
    const alive = useRef(true);

    const load = useCallback(async () => {
        const s = await api.status();
        if (alive.current) setStatus(s);
        return s;
    }, [api]);

    useEffect(() => {
        alive.current = true;
        void load();
        return () => {
            alive.current = false;
        };
    }, [load]);

    // Whose test relay: the publisher's name as the Files page shows it.
    const publisherId = status && (status.kind === 'idle' || status.kind === 'result') ? status.publisherId : '';
    useEffect(() => {
        if (!publisherId) return;
        let cancelled = false;
        contract
            .availableRoutes()
            .then((rows) => {
                const r = rows.find((x) => x.publisherId === publisherId && x.publisherName.trim() !== '');
                if (!cancelled && r) setPublisherName(r.publisherName.trim());
            })
            .catch(() => {
                /* the general words stand in */
            });
        return () => {
            cancelled = true;
        };
    }, [contract, publisherId]);

    const running = status?.kind === 'running';
    // Leaving this page while a test runs stops it too: the page that
    // listens for the app being left is gone then, and the text says
    // "if you leave it, the test stops". (On Android the shell also
    // stops it when Daal's screen goes away.)
    const runningRef = useRef(false);
    runningRef.current = running;
    useEffect(
        () => () => {
            if (runningRef.current) void api.cancel('').catch(() => undefined);
        },
        [api],
    );
    // While a test runs: ask often; leaving the app stops it.
    useEffect(() => {
        if (!running) return;
        const id = setInterval(() => void load(), pollMs);
        const onHide = () => {
            if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
                void api.cancel('backgrounded').catch(() => undefined);
            }
        };
        document.addEventListener('visibilitychange', onHide);
        return () => {
            clearInterval(id);
            document.removeEventListener('visibilitychange', onHide);
        };
    }, [running, load, api, pollMs]);

    const name = publisherName || t('netTest.yourPublisher');
    const connected = connState === 'connected';
    const view = viewOf(status, again);
    const plan = planOf(status);

    const start = async () => {
        if (!plan || (status?.kind !== 'idle' && !canRunAgain(status))) return;
        setBusy('start');
        setRefusal(null);
        setDeleted(false);
        setSendProblem(null);
        try {
            const a = await api.start(label, plan.consentVersion);
            if (!a.started) {
                setRefusal(fill(t(refusalKey(a.refused)), { n: n(a.retryAfterMin ?? 0), name }));
            } else {
                setAgain(false);
                setAskDelete(false);
            }
        } catch {
            setRefusal(t('netTest.refused.other'));
        } finally {
            setBusy(null);
            await load();
        }
    };

    const runAgain = () => {
        setAgain(true);
        setRefusal(null);
        setAskDelete(false);
        setSendProblem(null);
    };

    const cancel = async () => {
        setBusy('cancel');
        try {
            await api.cancel('');
        } catch {
            /* the status says what happened */
        } finally {
            setBusy(null);
            await load();
        }
    };

    const send = async () => {
        setBusy('send');
        setSendProblem(null);
        try {
            const a = await api.share(t('netTest.send.chooser'));
            if (a.sealed) setAskDelete(true);
            else setSendProblem(t(sealRefusalKey(a.refused)));
        } catch {
            setSendProblem(t('netTest.send.failed'));
        } finally {
            setBusy(null);
        }
    };

    const remove = async () => {
        setBusy('delete');
        try {
            await api.discard();
            setAskDelete(false);
            setDeleted(true);
        } catch {
            setSendProblem(t('netTest.delete.failed'));
        } finally {
            setBusy(null);
            await load();
        }
    };

    return (
        <div data-testid="nettest-page" data-view={view}>
            <PageHeader title={t('netTest.title')} back={{ label: backLabel, onClick: onBack }} />
            <div style={{ display: 'grid', gap: 16, marginBlockStart: 4 }}>
                {deleted && (
                    <div data-testid="nettest-deleted" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <StateIcon state="ok" size={18} />
                        <span style={MUTED}>{t('netTest.deleted')}</span>
                    </div>
                )}

                {view === 'loading' && <div style={MUTED}>{t('common.loading')}</div>}

                {view === 'unavailable' && (
                    <Card>
                        <p style={MUTED}>{t('netTest.unavailable')}</p>
                    </Card>
                )}

                {view === 'consent' && plan && (
                    <Card>
                        <div style={{ display: 'grid', gap: 14 }} data-testid="nettest-consent">
                            {again && (
                                <div data-testid="nettest-replaces" style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                                    <span style={{ paddingBlockStart: 2, flexShrink: 0 }}>
                                        <StateIcon state="warn" size={16} />
                                    </span>
                                    <span style={BODY}>{t('netTest.again.replaces')}</span>
                                </div>
                            )}
                            <p style={BODY}>{fill(t('netTest.consent.intro'), { name })}</p>
                            <ul style={{ margin: 0, paddingInlineStart: 20, display: 'grid', gap: 10, listStyle: 'disc' }}>
                                <li style={BODY}>{fill(t('netTest.consent.time'), { n: n(plan.minutes) })}</li>
                                <li style={BODY}>{t('netTest.consent.vpnOff')}</li>
                                <li style={BODY}>
                                    {fill(t('netTest.consent.connectsTo'), { name })}
                                    {plan.names.length > 0 && (
                                        <span
                                            dir="ltr"
                                            data-testid="nettest-names"
                                            style={{
                                                display: 'flex',
                                                flexWrap: 'wrap',
                                                gap: 6,
                                                marginBlock: '8px 2px',
                                            }}
                                        >
                                            {plan.names.map((n) => (
                                                <span
                                                    key={n}
                                                    style={{
                                                        fontFamily: 'var(--font-mono)',
                                                        fontSize: 12,
                                                        color: 'var(--fg)',
                                                        background: 'var(--surface-2)',
                                                        border: '1px solid var(--line-soft)',
                                                        borderRadius: 6,
                                                        padding: '2px 6px',
                                                    }}
                                                >
                                                    {n}
                                                </span>
                                            ))}
                                        </span>
                                    )}
                                </li>
                                <li style={BODY}>{t('netTest.consent.blockedName')}</li>
                                {plan.publicResolver !== '' && (
                                    <li style={BODY}>
                                        {(() => {
                                            const [before, after] = t('netTest.consent.resolver').split('{resolver}');
                                            return (
                                                <>
                                                    {before}
                                                    <bdi dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                                                        {plan.publicResolver}
                                                    </bdi>
                                                    {after ?? ''}
                                                </>
                                            );
                                        })()}
                                    </li>
                                )}
                                <li style={BODY}>{t('netTest.consent.seen')}</li>
                                <li style={BODY}>{fill(t('netTest.consent.leaves'), { name })}</li>
                            </ul>
                            <p style={MUTED}>{t('netTest.consent.notComfortable')}</p>

                            <label style={{ display: 'grid', gap: 6 }}>
                                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>
                                    {t('netTest.label.question')}
                                </span>
                                <select
                                    data-button="nettest-label"
                                    value={label}
                                    onChange={(e) => setLabel(e.target.value as NetworkLabel)}
                                    style={{
                                        minHeight: 44,
                                        paddingInline: 12,
                                        borderRadius: 'var(--radius-md)',
                                        border: '1px solid var(--line)',
                                        background: 'var(--surface-2)',
                                        color: 'var(--fg)',
                                        fontFamily: 'var(--font-body)',
                                        fontSize: 14,
                                        width: '100%',
                                    }}
                                >
                                    {NETWORK_LABELS.map((l) => (
                                        <option key={l} value={l}>
                                            {t(`netTest.label.${l}`)}
                                        </option>
                                    ))}
                                </select>
                            </label>

                            {connected && <NoLine text={t('netTest.refused.connected')} testId="nettest-connected" />}
                            {refusal && <NoLine text={refusal} testId="nettest-refused" />}

                            <div
                                data-testid="nettest-before"
                                style={{
                                    display: 'flex',
                                    gap: 8,
                                    alignItems: 'flex-start',
                                    padding: '10px 12px',
                                    borderRadius: 'var(--radius-md)',
                                    background: 'var(--surface-2)',
                                    border: '1px solid var(--line-soft)',
                                }}
                            >
                                <span style={{ paddingBlockStart: 2, flexShrink: 0 }}>
                                    <StateIcon state="warn" size={16} />
                                </span>
                                <span style={{ ...BODY, fontWeight: 500 }}>{t('netTest.consent.before')}</span>
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <Button
                                    dataButton="nettest-start"
                                    disabled={busy !== null || connected}
                                    onClick={() => void start()}
                                >
                                    {busy === 'start' ? t('netTest.starting') : t('netTest.start')}
                                </Button>
                                <Button
                                    variant="ghost"
                                    dataButton="nettest-later"
                                    disabled={busy !== null}
                                    onClick={() => {
                                        if (again) {
                                            setAgain(false);
                                            setRefusal(null);
                                        } else onBack();
                                    }}
                                >
                                    {t('netTest.later')}
                                </Button>
                            </div>
                        </div>
                    </Card>
                )}

                {view === 'running' && status?.kind === 'running' && (
                    <Card>
                        <div style={{ display: 'grid', gap: 12 }} data-testid="nettest-running">
                            <h2 style={H2}>{t('netTest.running.title')}</h2>
                            <div
                                role="progressbar"
                                aria-valuemin={0}
                                aria-valuemax={status.of}
                                aria-valuenow={status.step}
                                style={{
                                    height: 8,
                                    borderRadius: 4,
                                    background: 'var(--surface-2)',
                                    border: '1px solid var(--line-soft)',
                                    overflow: 'hidden',
                                }}
                            >
                                <div
                                    style={{
                                        height: '100%',
                                        width: `${Math.round(progress(status) * 100)}%`,
                                        background: 'var(--gold)',
                                        transition: 'width 400ms ease',
                                    }}
                                />
                            </div>
                            <p style={BODY}>{fill(t('netTest.running.step'), { n: n(status.step), of: n(status.of) })}</p>
                            <p style={MUTED}>{t('netTest.running.keepOpen')}</p>
                            <div>
                                <Button
                                    variant="secondary"
                                    dataButton="nettest-cancel"
                                    disabled={busy !== null}
                                    onClick={() => void cancel()}
                                >
                                    {t('common.cancel')}
                                </Button>
                            </div>
                        </div>
                    </Card>
                )}

                {view === 'result' && status?.kind === 'result' && (
                    <Card>
                        <div style={{ display: 'grid', gap: 12 }} data-testid="nettest-result">
                            <h2 style={H2}>{t(status.complete ? 'netTest.result.done' : 'netTest.result.stopped')}</h2>
                            {abortKey(status.abortReason, status.complete) !== '' && (
                                <p style={BODY} data-testid="nettest-abort">
                                    {t(abortKey(status.abortReason, status.complete))}
                                </p>
                            )}
                            {resultLines(status).length > 0 && (
                                <ul style={{ margin: 0, paddingInlineStart: 20, display: 'grid', gap: 8, listStyle: 'disc' }}>
                                    {resultLines(status).map((k) => (
                                        <li key={k} style={BODY}>
                                            {t(k)}
                                        </li>
                                    ))}
                                </ul>
                            )}
                            {status.reportJson !== '' && (
                                <Disclosure summary={t('netTest.showAll')} dataButton="nettest-show-all">
                                    <pre
                                        dir="ltr"
                                        data-testid="nettest-report-json"
                                        style={{
                                            margin: 0,
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 11,
                                            lineHeight: 1.5,
                                            color: 'var(--fg)',
                                            background: 'var(--surface-2)',
                                            border: '1px solid var(--line-soft)',
                                            borderRadius: 6,
                                            padding: 10,
                                            maxBlockSize: 320,
                                            overflow: 'auto',
                                            whiteSpace: 'pre-wrap',
                                            overflowWrap: 'anywhere',
                                            textAlign: 'left',
                                        }}
                                    >
                                        {status.reportJson}
                                    </pre>
                                </Disclosure>
                            )}
                            <p style={MUTED}>{fill(t('netTest.summary.privacy'), { name })}</p>

                            {askDelete ? (
                                <div style={{ display: 'grid', gap: 10 }} data-testid="nettest-ask-delete">
                                    <p style={BODY}>{t('netTest.afterSend.question')}</p>
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                        {/* Android cannot tell us whether the share went
                                            through, so keeping is the safe default: a
                                            person who backed out must not lose the report. */}
                                        <Button
                                            dataButton="nettest-keep"
                                            disabled={busy !== null}
                                            onClick={() => setAskDelete(false)}
                                        >
                                            {t('netTest.keep')}
                                        </Button>
                                        <Button
                                            variant="ghost"
                                            dataButton="nettest-delete-after"
                                            disabled={busy !== null}
                                            onClick={() => void remove()}
                                        >
                                            {t('netTest.delete')}
                                        </Button>
                                    </div>
                                </div>
                            ) : (
                                <>
                                    {!connected && (
                                        <p style={BODY} data-testid="nettest-connect-first">
                                            {fill(t('netTest.send.whenConnected'), { name })}
                                        </p>
                                    )}
                                    <p style={MUTED}>{t('netTest.send.copiesStay')}</p>
                                    {sendProblem && <NoLine text={sendProblem} testId="nettest-send-problem" />}
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                                        {/* A run that stopped early: trying again comes first. */}
                                        {canRunAgain(status) && !status.complete && (
                                            <Button leading="refresh" dataButton="nettest-again" disabled={busy !== null} onClick={runAgain}>
                                                {t('netTest.again')}
                                            </Button>
                                        )}
                                        <Button
                                            leading="share"
                                            variant={canRunAgain(status) && !status.complete ? 'secondary' : 'primary'}
                                            dataButton="nettest-send"
                                            disabled={busy !== null}
                                            onClick={() => void send()}
                                        >
                                            {busy === 'send' ? t('netTest.send.making') : t('netTest.send')}
                                        </Button>
                                        {canRunAgain(status) && status.complete && (
                                            <Button
                                                variant="secondary"
                                                leading="refresh"
                                                dataButton="nettest-again"
                                                disabled={busy !== null}
                                                onClick={runAgain}
                                            >
                                                {t('netTest.again')}
                                            </Button>
                                        )}
                                        <Button
                                            variant="ghost"
                                            dataButton="nettest-delete"
                                            disabled={busy !== null}
                                            onClick={() => void remove()}
                                        >
                                            {t('netTest.delete')}
                                        </Button>
                                    </div>
                                </>
                            )}
                        </div>
                    </Card>
                )}
            </div>
        </div>
    );
}
