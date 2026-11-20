// GoogleCard — the update channel through Google
// (docs/optional-addons-plan.md §3.3, item G6).
//
// Off: the offer, the suspension warning (a dedicated account, never
// your own; Google can close it without warning), then two paths that
// end in the same state:
//   A. Sign in with Google — make a dedicated account, turn on the Apps
//      Script API once, sign in (the unverified-app warning is
//      explained first); Daal deploys and throws the token away.
//   B. By hand (more private) — show and copy the script (its write key
//      is already in it), deploy it in the editor, paste the web-app
//      address back.
// Both end in a fetch-back check. On: the last check, Check now, and,
// when this is the relay's only refresh address, the D-3 warning.

import { useEffect, useState } from 'react';
import { Button, Input, Sheet, Textarea } from '../../design/primitives';
import { WhatIsThis } from '../Disclosure';
import { useSecureScreen } from '../useSecureScreen';
import { Addons, Wizard } from '../wizardCommands';
import type { AddonRemoveReport, GoogleCheck } from './addonTypes';
import type { AddonSheetProps } from './StandbyCard';
import {
    BODY,
    ErrorNote,
    HowTo,
    MONO,
    MUTED,
    RemoveReportLines,
    StatusLine,
    Steps,
    copyText,
    useAddonSteps,
    useRun,
    whenText,
} from './addonUi';
import { sep } from '../../lib/format';

export const GOOGLE_SIGNUP_URL = 'https://accounts.google.com/signup';
export const APPS_SCRIPT_SETTINGS_URL = 'https://script.google.com/home/usersettings';
export const APPS_SCRIPT_NEW_URL = 'https://script.google.com/home/projects/create';

type View = { at: 'main' } | { at: 'remove' } | { at: 'removed'; report: AddonRemoveReport };

export function GoogleSheet({ t, operatorId, rows, onClose, onChanged }: AddonSheetProps) {
    const live = rows.find((r) => r.kind === 'google' && r.state !== 'promoted') ?? null;
    const [view, setView] = useState<View>({ at: 'main' });
    const [script, setScript] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [url, setUrl] = useState('');
    const [check, setCheck] = useState<GoogleCheck | null>(null);
    const [justReady, setJustReady] = useState(false);
    const [googleOnly, setGoogleOnly] = useState(false);
    const { steps, reset } = useAddonSteps(operatorId, 'google');
    const { busy, error, setError, run } = useRun();
    // The script carries the write key: no screenshots while it shows.
    useSecureScreen(script != null);

    const ready = live?.state === 'ready';
    useEffect(() => {
        let gone = false;
        Wizard.freshnessStatus(operatorId)
            .then((s) => {
                if (!gone) setGoogleOnly(!!s?.google_only);
            })
            .catch(() => {});
        return () => {
            gone = true;
        };
    }, [operatorId, ready]);

    const signIn = async () => {
        reset();
        const r = await run(() => Addons.googleSignIn({ operator_id: operatorId }));
        onChanged();
        if (r) setJustReady(true);
    };
    const showScript = async () => {
        const s = await run(() => Addons.googleScript({ operator_id: operatorId }));
        if (s) setScript(s.code_gs);
        onChanged();
    };
    const copyScript = async () => {
        let s = script;
        if (s == null) {
            const got = await run(() => Addons.googleScript({ operator_id: operatorId }));
            if (!got) return;
            s = got.code_gs;
            onChanged();
        }
        setCopied(await copyText(s));
    };
    const attach = async () => {
        reset();
        const r = await run(() => Addons.googleAttach({ operator_id: operatorId, url: url.trim() }));
        onChanged();
        if (r) {
            setJustReady(true);
            setScript(null);
        }
    };
    const checkNow = async () => {
        reset();
        const c = await run(() => Addons.googleCheck({ operator_id: operatorId }));
        if (c) setCheck(c);
        onChanged();
    };
    const remove = async () => {
        if (!live) return;
        reset();
        const r = await run(() => Addons.remove(live.id));
        onChanged();
        if (r) setView({ at: 'removed', report: r });
    };

    const d = (live?.detail ?? {}) as Record<string, unknown>;
    const lastAt = check ? check.checked_at_unix : Number(d.last_check_at_unix ?? 0);
    const lastOk = check ? check.ok : lastAt ? Boolean(d.last_check_ok) : null;
    const lastFront = check ? check.via_front : Boolean(d.last_check_via_front);
    const lastReason = check ? check.reason : String(d.last_check_reason ?? '');
    const checkText =
        lastOk == null
            ? t('pub.addons.never')
            : `${t(lastOk ? (lastFront ? 'pub.addons.google.check.front' : 'pub.addons.google.check.plain') : 'pub.addons.google.check.failed')}${sep()}${whenText(t, lastAt)}`;
    const reasonKey = lastReason ? `pub.addons.google.reason.${lastReason}` : '';
    const reasonText = reasonKey && t(reasonKey) !== reasonKey ? t(reasonKey) : '';
    const settingUp = !live || live.state === 'building';

    return (
        <Sheet title={t('pub.addons.google.title')} onClose={onClose} width={520}>
            <div data-testid="google-sheet" data-view={view.at} style={{ display: 'grid', gap: 14 }}>
                {view.at === 'main' && (
                    <>
                        {settingUp && <p style={BODY}>{t('pub.addons.google.offer')}</p>}
                        <p data-testid="google-warn" style={{ ...BODY, color: 'var(--amber)' }}>
                            {t('pub.addons.google.warn')}
                        </p>
                        {googleOnly && (
                            <p data-testid="google-only" style={{ ...BODY, color: 'var(--amber)' }}>
                                {t('pub.addons.google.only')}
                            </p>
                        )}
                    </>
                )}

                {view.at === 'main' && live?.state === 'building' && !!d.url && (
                    <>
                        <p style={BODY}>{t('pub.addons.google.building_line')}</p>
                        {reasonText && <p style={MUTED}>{reasonText}</p>}
                        <div>
                            <Button onClick={() => void checkNow()} disabled={busy} dataButton="google-check">
                                {busy ? t('pub.addons.working') : t('pub.addons.google.check')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && settingUp && (
                    <>
                        <section data-testid="google-path-a" style={{ display: 'grid', gap: 8 }}>
                            <div style={{ fontSize: 14, fontWeight: 600 }}>{t('pub.addons.google.path_a.title')}</div>
                            <p style={MUTED}>{t('pub.addons.google.path_a.line')}</p>
                            <HowTo
                                t={t}
                                items={[
                                    {
                                        key: 'pub.addons.google.path_a.step.1',
                                        action: {
                                            key: 'pub.addons.google.path_a.step.1.action',
                                            url: GOOGLE_SIGNUP_URL,
                                            dataButton: 'google-open-signup',
                                        },
                                    },
                                    {
                                        key: 'pub.addons.google.path_a.step.2',
                                        action: {
                                            key: 'pub.addons.google.path_a.step.2.action',
                                            url: APPS_SCRIPT_SETTINGS_URL,
                                            dataButton: 'google-open-settings',
                                        },
                                    },
                                    { key: 'pub.addons.google.path_a.step.3' },
                                ]}
                            />
                            <p style={MUTED}>{t('pub.addons.google.path_a.after')}</p>
                            <div>
                                <Button onClick={() => void signIn()} disabled={busy} dataButton="google-sign-in">
                                    {busy ? t('pub.addons.working') : t('pub.addons.google.path_a.go')}
                                </Button>
                            </div>
                            <WhatIsThis label={t('pub.addons.google.builders.label')}>
                                <p style={MUTED}>{t('pub.addons.google.builders')}</p>
                            </WhatIsThis>
                        </section>

                        <section
                            data-testid="google-path-b"
                            style={{ display: 'grid', gap: 8, borderTop: '1px solid var(--line)', paddingTop: 12 }}
                        >
                            <div style={{ fontSize: 14, fontWeight: 600 }}>{t('pub.addons.google.path_b.title')}</div>
                            <p style={MUTED}>{t('pub.addons.google.path_b.line')}</p>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <Button variant="secondary" leading="copy" onClick={() => void copyScript()} disabled={busy} dataButton="google-copy-script">
                                    {copied ? t('pub.addons.copied') : t('pub.addons.google.path_b.copy')}
                                </Button>
                                {script == null && (
                                    <Button variant="ghost" onClick={() => void showScript()} disabled={busy} dataButton="google-show-script">
                                        {t('pub.addons.google.path_b.show')}
                                    </Button>
                                )}
                            </div>
                            {script != null && (
                                <>
                                    <p style={{ ...MUTED, color: 'var(--amber)' }}>{t('pub.addons.google.path_b.secret')}</p>
                                    <Textarea
                                        readOnly
                                        value={script}
                                        rows={6}
                                        dir="ltr"
                                        spellCheck={false}
                                        aria-label={t('pub.addons.google.path_b.copy')}
                                        data-testid="google-script"
                                        style={{ ...MONO, fontSize: 11 }}
                                    />
                                </>
                            )}
                            <HowTo
                                t={t}
                                items={[
                                    {
                                        key: 'pub.addons.google.path_b.step.1',
                                        action: {
                                            key: 'pub.addons.google.path_b.step.1.action',
                                            url: APPS_SCRIPT_NEW_URL,
                                            dataButton: 'google-open-editor',
                                        },
                                    },
                                    { key: 'pub.addons.google.path_b.step.2' },
                                    { key: 'pub.addons.google.path_b.step.3' },
                                    { key: 'pub.addons.google.path_b.step.4' },
                                    { key: 'pub.addons.google.path_b.step.5' },
                                ]}
                            />
                            <Input
                                dir="ltr"
                                inputMode="url"
                                autoComplete="off"
                                spellCheck={false}
                                value={url}
                                onChange={(e) => setUrl(e.target.value)}
                                placeholder="https://script.google.com/macros/s/…/exec"
                                aria-label={t('pub.addons.google.path_b.url.label')}
                                data-button="google-url"
                            />
                            <div>
                                <Button
                                    onClick={() => void attach()}
                                    disabled={busy || url.trim() === ''}
                                    dataButton="google-attach"
                                >
                                    {busy ? t('pub.addons.working') : t('pub.addons.google.path_b.url.go')}
                                </Button>
                            </div>
                        </section>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                    </>
                )}

                {view.at === 'main' && live && !settingUp && (
                    <>
                        {justReady && (
                            <p data-testid="google-ready" style={BODY}>
                                {t('pub.addons.google.ready')}
                            </p>
                        )}
                        <div data-testid="google-status" style={{ display: 'grid', gap: 6 }}>
                            <StatusLine
                                testId="google-last-check"
                                label={t('pub.addons.google.last_check')}
                                value={checkText}
                                tone={lastOk == null ? 'none' : lastOk ? 'good' : 'bad'}
                            />
                            {!lastOk && reasonText && <p style={MUTED}>{reasonText}</p>}
                            {!!d.url && (
                                <WhatIsThis label={t('pub.addons.details')}>
                                    <div style={MONO} dir="ltr">
                                        {String(d.url)}
                                    </div>
                                </WhatIsThis>
                            )}
                        </div>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button variant="secondary" onClick={() => void checkNow()} disabled={busy} dataButton="google-check">
                                {busy ? t('pub.addons.working') : t('pub.addons.google.check')}
                            </Button>
                            <Button
                                variant="ghost"
                                onClick={() => {
                                    setError(null);
                                    setView({ at: 'remove' });
                                }}
                                disabled={busy}
                                dataButton="google-remove"
                            >
                                {t('pub.addons.google.remove')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && live?.state === 'building' && (
                    <div>
                        <Button variant="ghost" onClick={() => setView({ at: 'remove' })} disabled={busy} dataButton="google-remove">
                            {t('pub.addons.google.remove')}
                        </Button>
                    </div>
                )}

                {view.at === 'remove' && (
                    <>
                        <p style={BODY}>{t('pub.addons.google.remove.body')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button variant="danger" onClick={() => void remove()} disabled={busy} dataButton="google-remove-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.google.remove')}
                            </Button>
                            <Button variant="secondary" onClick={() => setView({ at: 'main' })} disabled={busy} dataButton="google-back">
                                {t('pub.addons.cancel')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'removed' && (
                    <>
                        <RemoveReportLines t={t} report={view.report} />
                        <div>
                            <Button onClick={onClose} dataButton="google-done">
                                {t('pub.addons.close')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}
