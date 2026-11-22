// TestRelaySheet — relay page ⋯ → "Use as test relay" (network test,
// specs/field-probe-v2.md).
//
// A relay becomes the Test relay when its pack is signed with the
// publisher's report address: people who run the network test seal
// their report to it, and only this phone (and its backup) can open one.
// The key is made here, on this phone, the first time.
//
// The test makes unusual connections to the relay's address, so it must
// be a relay of its own. The sheet says so plainly, and for a relay
// people connect with it shows how many and asks a second time before
// anything runs (the wizard refuses otherwise, E_TEST_RELAY_IN_USE).
// Nothing on the relay changes: every file already handed out keeps
// working; afterwards the sheet says who needs a new file.

import { useEffect, useState } from 'react';
import { Badge, Button, Disclosure, Sheet, StateIcon } from '../design/primitives';
import { Wizard } from './wizardCommands';
import type { TestRelaySet, TestRelayStatus } from './wizardCommands';
import { explainFailure } from './failureText';
import type { Failure } from './failureText';
import { fill } from '../lib/netTest';
import { num, useLocale } from './ui';

export interface TestRelayApi {
    status(operatorId: number): Promise<TestRelayStatus>;
    set(operatorId: number, on: boolean, confirmInUse: boolean): Promise<TestRelaySet>;
}

export const testRelayApi: TestRelayApi = {
    status: (id) => Wizard.testRelayStatus(id),
    set: (id, on, confirmInUse) => Wizard.testRelaySet(id, on, confirmInUse),
};

interface Props {
    t: (k: string) => string;
    operatorId: number;
    onClose: () => void;
    /** Open a received report. */
    onOpenReport: () => void;
    /** After a change: the files on the page are new. */
    onChanged?: () => void;
    api?: TestRelayApi;
}

const BODY: React.CSSProperties = { fontSize: 14, lineHeight: 1.55, color: 'var(--fg)', margin: 0 };
const SUB: React.CSSProperties = { fontSize: 13, lineHeight: 1.55, color: 'var(--muted)', margin: 0 };

function errText(e: unknown): string {
    return typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
}

export function TestRelaySheet({ t, operatorId, onClose, onOpenReport, onChanged, api = testRelayApi }: Props) {
    const locale = useLocale();
    const [status, setStatus] = useState<TestRelayStatus | null>(null);
    const [busy, setBusy] = useState(false);
    const [done, setDone] = useState<TestRelaySet | null>(null);
    const [failure, setFailure] = useState<Failure | null>(null);
    /** The second question for a relay people connect with. */
    const [confirming, setConfirming] = useState(false);

    useEffect(() => {
        let cancelled = false;
        api.status(operatorId)
            .then((s) => {
                if (!cancelled) setStatus(s);
            })
            .catch((e) => {
                if (!cancelled) setFailure(explainFailure(t, e));
            });
        return () => {
            cancelled = true;
        };
    }, [api, operatorId, t]);

    const on = done ? done.is_test_relay : status?.is_test_relay === true;
    const people = status?.people_on_relay ?? 0;
    const inUse = people > 0 || status?.everyone_file === true;

    const change = async (next: boolean, confirmInUse: boolean) => {
        setBusy(true);
        setFailure(null);
        try {
            const r = await api.set(operatorId, next, confirmInUse);
            setDone(r);
            setConfirming(false);
            setStatus((s) => ({
                operator_id: operatorId,
                is_test_relay: r.is_test_relay,
                has_key: true,
                people_on_relay: s?.people_on_relay ?? r.people_to_send,
                everyone_file: s?.everyone_file ?? r.everyone_file_kept,
            }));
            onChanged?.();
        } catch (e) {
            if (errText(e).startsWith('E_TEST_RELAY_IN_USE')) {
                // People came onto the relay since the sheet looked.
                setConfirming(true);
                void api.status(operatorId).then(setStatus).catch(() => undefined);
            } else {
                setFailure(explainFailure(t, e));
            }
        } finally {
            setBusy(false);
        }
    };

    const use = () => {
        if (inUse) setConfirming(true);
        else void change(true, false);
    };

    /** "{n} people connect with this relay" / "… and it has a file for everyone". */
    const inUseLine = () => {
        const base =
            people > 0
                ? fill(t('pub.testRelay.inUse.people'), { n: num(locale, people) })
                : t('pub.testRelay.inUse.everyone');
        return people > 0 && status?.everyone_file ? `${base} ${t('pub.testRelay.inUse.andEveryone')}` : base;
    };

    return (
        <Sheet title={t('pub.testRelay.title')} width={480} onClose={() => !busy && onClose()}>
            <div style={{ display: 'grid', gap: 14 }} data-testid="test-relay-sheet" data-on={on ? '1' : '0'}>
                {on && (
                    <div>
                        <Badge tone="good" icon="check">
                            {t('pub.testRelay.on')}
                        </Badge>
                    </div>
                )}
                <p style={BODY}>{t('pub.testRelay.line')}</p>
                {!on && (
                    <div
                        data-testid="test-relay-separate"
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
                        <span style={{ display: 'grid', gap: 4 }}>
                            <span style={{ ...BODY, fontWeight: 500 }}>{t('pub.testRelay.cost')}</span>
                            {status && inUse && (
                                <span style={{ ...SUB, color: 'var(--amber)' }} data-testid="test-relay-in-use">
                                    {inUseLine()}
                                </span>
                            )}
                        </span>
                    </div>
                )}

                {done && (
                    <div data-testid="test-relay-done" style={{ display: 'grid', gap: 8 }}>
                        {done.is_test_relay ? (
                            <>
                                <p style={BODY}>
                                    {done.people_to_send > 0
                                        ? fill(t('pub.testRelay.done.people'), { n: num(locale, done.people_to_send) })
                                        : t('pub.testRelay.done.nobody')}
                                </p>
                                {done.everyone_file_kept && <p style={SUB}>{t('pub.testRelay.done.everyoneKept')}</p>}
                            </>
                        ) : (
                            <p style={BODY}>{t('pub.testRelay.done.off')}</p>
                        )}
                    </div>
                )}

                {failure && (
                    <div role="alert" style={{ display: 'grid', gap: 6 }}>
                        <p style={{ ...SUB, color: 'var(--red)' }}>{failure.message}</p>
                        {failure.detail && (
                            <Disclosure summary={t('pub.fb.details')}>
                                <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', overflowWrap: 'anywhere' }}>
                                    {failure.detail}
                                </div>
                            </Disclosure>
                        )}
                    </div>
                )}

                {confirming && !on ? (
                    <div data-testid="test-relay-confirm" style={{ display: 'grid', gap: 10 }}>
                        <p style={BODY}>{t('pub.testRelay.confirm')}</p>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button
                                variant="danger"
                                dataButton="test-relay-on-anyway"
                                disabled={busy}
                                onClick={() => void change(true, true)}
                            >
                                {busy ? t('pub.testRelay.working') : t('pub.testRelay.useAnyway')}
                            </Button>
                            <Button variant="ghost" dataButton="test-relay-confirm-cancel" disabled={busy} onClick={() => setConfirming(false)}>
                                {t('common.cancel')}
                            </Button>
                        </div>
                    </div>
                ) : (
                    <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
                        {!on ? (
                            <Button
                                variant={inUse ? 'secondary' : 'primary'}
                                dataButton="test-relay-on"
                                disabled={busy || status === null}
                                onClick={use}
                            >
                                {busy ? t('pub.testRelay.working') : t('pub.testRelay.use')}
                            </Button>
                        ) : (
                            <>
                                <Button leading="file" dataButton="test-relay-open-report" disabled={busy} onClick={onOpenReport}>
                                    {t('pub.report.open')}
                                </Button>
                                <Button
                                    variant="link"
                                    dataButton="test-relay-off"
                                    disabled={busy}
                                    onClick={() => void change(false, false)}
                                >
                                    {busy ? t('pub.testRelay.working') : t('pub.testRelay.stop')}
                                </Button>
                            </>
                        )}
                    </div>
                )}
                <Disclosure summary={t('pub.what')} icon="help" dataButton="test-relay-what">
                    <div style={{ display: 'grid', gap: 8 }}>
                        <p style={SUB}>{t('pub.testRelay.what.key')}</p>
                        <p style={SUB}>{t('pub.testRelay.what.files')}</p>
                        <p style={SUB}>{t('pub.testRelay.what.untrusted')}</p>
                    </div>
                </Disclosure>
            </div>
        </Sheet>
    );
}
