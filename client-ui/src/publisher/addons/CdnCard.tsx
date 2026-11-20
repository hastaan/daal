// CdnCard — the way in through Cloudflare (docs/optional-addons-plan.md
// §2.3, item B-7).
//
// Off: the offer (what it rescues, the cost, what Cloudflare learns),
// the three things the owner makes by hand (account, domain bought in
// the dashboard, a key with exactly five permissions), then: paste the
// key → check → pick the domain → build (steps live) → posture.
// On: the posture — name hidden (ECH) yes/no, only Cloudflare reaches
// the relay this way yes/no, the last test — Check again, the plain
// fallback switch (off by default, D-2), Remove.

import { useCallback, useEffect, useState } from 'react';
import { Button, Input, Sheet, Toggle } from '../../design/primitives';
import { WhatIsThis } from '../Disclosure';
import { Addons } from '../wizardCommands';
import type { AddonRemoveReport, CdnPosture, CdnTokenCheck } from './addonTypes';
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
    useAddonSteps,
    useRun,
    whenText,
} from './addonUi';
import { sep } from '../../lib/format';

/** The five permissions, in Cloudflare's own names (plan §2.5). */
export const CDN_PERMISSIONS = [
    'Zone — Zone — Read',
    'Zone — DNS — Edit',
    'Zone — SSL and Certificates — Edit',
    'Zone — Zone Settings — Edit',
    'Zone — Origin Rules — Edit',
] as const;

export const CLOUDFLARE_SIGNUP_URL = 'https://dash.cloudflare.com/sign-up';
export const CLOUDFLARE_REGISTRAR_URL = 'https://dash.cloudflare.com/?to=/:account/domains/register';

/** The pre-filled token page (plan §2.5; GATE C-1 confirms the keys on
 *  the real dashboard). It cannot pre-pick one zone: the sheet says to. */
export function cloudflareTokenUrl(): string {
    const groups = JSON.stringify([
        { key: 'zone', type: 'read' },
        { key: 'dns', type: 'edit' },
        { key: 'ssl_and_certificates', type: 'edit' },
        { key: 'zone_settings', type: 'edit' },
        { key: 'origin_rules', type: 'edit' },
    ]);
    return (
        'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
        encodeURIComponent(groups) +
        '&accountId=*&zoneId=all&name=daal'
    );
}

type View = { at: 'main' } | { at: 'remove' } | { at: 'removed'; report: AddonRemoveReport };

export function CdnSheet({ t, operatorId, rows, onClose, onChanged }: AddonSheetProps) {
    const live = rows.find((r) => r.kind === 'cdn' && r.state !== 'promoted') ?? null;
    const [view, setView] = useState<View>({ at: 'main' });
    const [token, setToken] = useState('');
    const [check, setCheck] = useState<CdnTokenCheck | null>(null);
    const [zone, setZone] = useState('');
    const [posture, setPosture] = useState<CdnPosture | null>(null);
    const [built, setBuilt] = useState(false);
    const { steps, reset } = useAddonSteps(operatorId, 'cdn');
    const { busy, error, setError, run } = useRun();

    const readPosture = useCallback(
        async (test: boolean) => {
            const p = await run(() => Addons.cdnPosture({ operator_id: operatorId, test }));
            if (p) setPosture(p);
        },
        [operatorId, run],
    );

    // Refreshed on open (a read, no handshake); "Check again" tests.
    const ready = live?.state === 'ready';
    useEffect(() => {
        if (ready) void readPosture(false);
    }, [ready, readPosture]);

    const checkToken = async () => {
        const typed = token;
        reset();
        const c = await run(() => Addons.cdnSetToken({ operator_id: operatorId, token: typed }));
        // The key leaves the page once it is checked, kept or not.
        setToken('');
        if (c) {
            setCheck(c);
            setZone(c.zones.length > 0 ? c.zones[0] : '');
        }
    };
    const build = async () => {
        reset();
        const r = await run(() => Addons.cdnBuild({ operator_id: operatorId, zone }));
        onChanged();
        if (r) {
            setBuilt(true);
            setCheck(null);
        }
    };
    const setFallback = async (allow: boolean) => {
        const r = await run(() => Addons.cdnSetPlainFallback({ operator_id: operatorId, allow }));
        if (r) {
            setPosture((p) => (p ? { ...p, plain_fallback: allow } : p));
            onChanged();
        }
    };
    const remove = async () => {
        if (!live) return;
        reset();
        const r = await run(() => Addons.remove(live.id));
        onChanged();
        if (r) setView({ at: 'removed', report: r });
    };

    const yesNo = (v: boolean | null | undefined) =>
        v == null ? t('pub.addons.unknown') : v ? t('pub.addons.yes') : t('pub.addons.no');
    const tone = (v: boolean | null | undefined) => (v == null ? 'none' : v ? 'good' : 'bad') as 'none' | 'good' | 'bad';
    const testText =
        posture == null || posture.last_test_ok == null
            ? t('pub.addons.never')
            : `${t(posture.last_test_ok ? 'pub.addons.cdn.posture.test_ok' : 'pub.addons.cdn.posture.test_failed')}${sep()}${whenText(t, posture.last_test_at_unix)}`;

    return (
        <Sheet title={t('pub.addons.cdn.title')} onClose={onClose} width={520}>
            <div data-testid="cdn-sheet" data-view={view.at} style={{ display: 'grid', gap: 14 }}>
                {view.at === 'main' && !live && (
                    <>
                        <p style={BODY}>{t('pub.addons.cdn.offer')}</p>
                        <HowTo
                            t={t}
                            testId="cdn-need"
                            title={t('pub.addons.need_first')}
                            items={[
                                {
                                    key: 'pub.addons.cdn.need.1',
                                    action: { key: 'pub.addons.cdn.need.1.action', url: CLOUDFLARE_SIGNUP_URL, dataButton: 'cdn-open-signup' },
                                },
                                {
                                    key: 'pub.addons.cdn.need.2',
                                    action: { key: 'pub.addons.cdn.need.2.action', url: CLOUDFLARE_REGISTRAR_URL, dataButton: 'cdn-open-registrar' },
                                    extra: (
                                        <div style={{ marginTop: 4 }}>
                                            <WhatIsThis label={t('pub.addons.details')}>
                                                <p style={MUTED}>{t('pub.addons.cdn.need.2.elsewhere')}</p>
                                            </WhatIsThis>
                                        </div>
                                    ),
                                },
                                {
                                    key: 'pub.addons.cdn.need.3',
                                    action: { key: 'pub.addons.cdn.need.3.action', url: cloudflareTokenUrl(), dataButton: 'cdn-open-token' },
                                    extra: (
                                        <>
                                            <ul data-testid="cdn-permissions" dir="ltr" style={{ margin: '6px 0', paddingInlineStart: 18 }}>
                                                {CDN_PERMISSIONS.map((p) => (
                                                    <li key={p} style={MONO}>
                                                        {p}
                                                    </li>
                                                ))}
                                            </ul>
                                            <span style={MUTED}>{t('pub.addons.cdn.need.3.pick')}</span>
                                        </>
                                    ),
                                },
                            ]}
                        />

                        {!built && (
                            <div style={{ display: 'grid', gap: 8 }}>
                                <Input
                                    type="password"
                                    autoComplete="off"
                                    spellCheck={false}
                                    dir="ltr"
                                    value={token}
                                    onChange={(e) => setToken(e.target.value)}
                                    placeholder={t('pub.addons.cdn.token.placeholder')}
                                    aria-label={t('pub.addons.cdn.token.label')}
                                    data-button="cdn-token"
                                />
                                <div>
                                    <Button
                                        variant="secondary"
                                        onClick={() => void checkToken()}
                                        disabled={busy || token.trim() === ''}
                                        dataButton="cdn-token-check"
                                    >
                                        {t('pub.addons.cdn.token.check')}
                                    </Button>
                                </div>
                            </div>
                        )}

                        {check && (
                            <div data-testid="cdn-verdict" data-verdict={check.verdict} style={{ display: 'grid', gap: 4 }}>
                                <p style={{ ...BODY, color: check.verdict === 'ok' ? 'var(--fg)' : 'var(--red)' }}>
                                    {t(`pub.addons.cdn.verdict.${check.verdict}`).replace('{zones}', check.zones.join(', '))}
                                </p>
                                {!check.stored && <p style={MUTED}>{t('pub.addons.cdn.not_stored')}</p>}
                                {[...(check.missing ?? []), ...(check.extra ?? [])].length > 0 && (
                                    <WhatIsThis label={t('pub.addons.details')}>
                                        {[...(check.missing ?? []), ...(check.extra ?? [])].map((p) => (
                                            <div key={p} style={MONO} dir="ltr">
                                                {p}
                                            </div>
                                        ))}
                                    </WhatIsThis>
                                )}
                            </div>
                        )}

                        {check?.verdict === 'ok' && (
                            <div style={{ display: 'grid', gap: 8 }}>
                                <div style={{ fontSize: 13, fontWeight: 600 }}>{t('pub.addons.cdn.zone.title')}</div>
                                <div role="radiogroup" aria-label={t('pub.addons.cdn.zone.title')} style={{ display: 'grid', gap: 4 }}>
                                    {check.zones.map((z) => (
                                        <label key={z} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 14 }}>
                                            <input
                                                type="radio"
                                                name="cdn-zone"
                                                checked={zone === z}
                                                onChange={() => setZone(z)}
                                                data-button={`cdn-zone-${z}`}
                                            />
                                            <span dir="ltr" style={MONO}>
                                                {z}
                                            </span>
                                        </label>
                                    ))}
                                </div>
                                <p style={MUTED}>{t('pub.addons.cdn.build.note')}</p>
                                <div>
                                    <Button onClick={() => void build()} disabled={busy || zone === ''} dataButton="cdn-build">
                                        {busy ? t('pub.addons.working') : t('pub.addons.cdn.build')}
                                    </Button>
                                </div>
                            </div>
                        )}
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                    </>
                )}

                {view.at === 'main' && live && live.state !== 'ready' && (
                    <>
                        <p style={BODY}>{t('pub.addons.cdn.building_line')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div>
                            <Button variant="danger" onClick={() => void remove()} disabled={busy} dataButton="cdn-remove-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.cdn.remove')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && live?.state === 'ready' && (
                    <>
                        {built && (
                            <p data-testid="cdn-ready" style={BODY}>
                                {t('pub.addons.cdn.ready')}
                            </p>
                        )}
                        <div data-testid="cdn-posture" style={{ display: 'grid', gap: 6 }}>
                            <StatusLine
                                label={t('pub.addons.cdn.posture.name')}
                                value={
                                    <span dir="ltr" style={MONO}>
                                        {posture?.hostname || String(live.detail?.hostname ?? '')}
                                    </span>
                                }
                            />
                            <StatusLine
                                testId="cdn-name-hidden"
                                label={t('pub.addons.cdn.posture.name_hidden')}
                                value={yesNo(posture ? posture.name_hidden : (live.detail?.name_hidden as boolean | undefined))}
                                tone={tone(posture ? posture.name_hidden : (live.detail?.name_hidden as boolean | undefined))}
                            />
                            <StatusLine
                                testId="cdn-door"
                                label={t('pub.addons.cdn.posture.door')}
                                value={yesNo(posture?.door_closed_to_others)}
                                tone={tone(posture?.door_closed_to_others)}
                            />
                            <StatusLine testId="cdn-last-test" label={t('pub.addons.cdn.posture.last_test')} value={testText} />
                            <WhatIsThis label={t('pub.addons.details')}>
                                <p style={MUTED}>{t('pub.addons.cdn.posture.name_hidden.help')}</p>
                                {posture?.notes && (
                                    <div style={MONO} dir="ltr">
                                        {posture.notes}
                                    </div>
                                )}
                            </WhatIsThis>
                        </div>
                        {posture?.needs_rebuild && <p style={{ ...BODY, color: 'var(--amber)' }}>{t('pub.addons.cdn.rebuild')}</p>}
                        <Toggle
                            checked={!!(posture ? posture.plain_fallback : live.detail?.plain_fallback)}
                            onChange={(v) => void setFallback(v)}
                            disabled={busy}
                            label={t('pub.addons.cdn.fallback.label')}
                            subtitle={t('pub.addons.cdn.fallback.help')}
                            dataButton="cdn-fallback"
                        />
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button variant="secondary" onClick={() => void readPosture(true)} disabled={busy} dataButton="cdn-check">
                                {busy ? t('pub.addons.working') : t('pub.addons.cdn.check_again')}
                            </Button>
                            <Button
                                variant="ghost"
                                onClick={() => {
                                    setError(null);
                                    setView({ at: 'remove' });
                                }}
                                disabled={busy}
                                dataButton="cdn-remove"
                            >
                                {t('pub.addons.cdn.remove')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'remove' && (
                    <>
                        <p style={BODY}>{t('pub.addons.cdn.remove.body')}</p>
                        <p style={MUTED}>{t('pub.addons.by_hand.cancel_domain')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button variant="danger" onClick={() => void remove()} disabled={busy} dataButton="cdn-remove-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.cdn.remove')}
                            </Button>
                            <Button variant="secondary" onClick={() => setView({ at: 'main' })} disabled={busy} dataButton="cdn-back">
                                {t('pub.addons.cancel')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'removed' && (
                    <>
                        <RemoveReportLines t={t} report={view.report} />
                        <div>
                            <Button onClick={onClose} dataButton="cdn-done">
                                {t('pub.addons.close')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}
