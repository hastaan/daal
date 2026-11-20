// StandbyCard — the standby address sheet (docs/optional-addons-plan.md
// §1.3, item S8).
//
// Off: what it is, today's price from Hetzner, "stops when you remove it
// or delete the relay", sealed by default (open only as a choice, and
// the shell refuses it while an Everyone file exists), Rent.
// On: kept back and ready; Switch to standby (confirm, then the
// 26-character code to send by any means); Show the code; Remove.
// Promoted: the relay uses it now; the code again; rent a new one.

import { useEffect, useState } from 'react';
import { Button, Sheet, Toggle } from '../../design/primitives';
import { Addons } from '../wizardCommands';
import type { AddonRemoveReport, AddonRow, StandbyPrice, StandbyPromoteResult } from './addonTypes';
import { money } from './addonErrors';
import { BODY, ErrorNote, MONO, MUTED, RemoveReportLines, Steps, copyText, useAddonSteps, useRun } from './addonUi';

export interface AddonSheetProps {
    t: (k: string) => string;
    operatorId: number;
    /** Every ledger row of this relay. */
    rows: AddonRow[];
    onClose: () => void;
    /** Something changed: read the ledger again. */
    onChanged: () => void;
}

type View =
    | { at: 'main' }
    | { at: 'ready' }
    | { at: 'switch' }
    | { at: 'key'; key: string; published?: boolean }
    | { at: 'remove' }
    | { at: 'removed'; report: AddonRemoveReport };

export function StandbySheet({ t, operatorId, rows, onClose, onChanged }: AddonSheetProps) {
    const live = rows.find((r) => r.kind === 'standby' && r.state !== 'promoted') ?? null;
    const promoted = rows.some((r) => r.kind === 'standby' && r.state === 'promoted');
    const [view, setView] = useState<View>({ at: 'main' });
    const [price, setPrice] = useState<StandbyPrice | null>(null);
    const [priceFailed, setPriceFailed] = useState(false);
    const [open, setOpen] = useState(false);
    const [copied, setCopied] = useState(false);
    const { steps, reset } = useAddonSteps(operatorId, 'standby');
    const { busy, error, setError, run } = useRun();

    const needPrice = !live || live.state === 'building';
    useEffect(() => {
        if (!needPrice) return;
        let gone = false;
        Addons.standbyPrice({ operator_id: operatorId })
            .then((p) => {
                if (!gone) setPrice(p);
            })
            .catch(() => {
                if (!gone) setPriceFailed(true);
            });
        return () => {
            gone = true;
        };
    }, [operatorId, needPrice]);

    const priceText = price ? money(t, price.monthly_cents, price.currency) : null;
    const priceLine = price
        ? t(price.vat_included ? 'pub.addons.standby.price_incl' : 'pub.addons.standby.price').replace('{price}', priceText!)
        : priceFailed
          ? t('pub.addons.standby.price_unknown')
          : null;

    const rent = async () => {
        reset();
        const r = await run(() => Addons.standbyAdd({ operator_id: operatorId, mode: open ? 'open' : 'sealed' }));
        onChanged();
        if (r) setView({ at: 'ready' });
    };
    const doSwitch = async () => {
        reset();
        const r: StandbyPromoteResult | undefined = await run(() => Addons.standbyPromote({ operator_id: operatorId }));
        onChanged();
        if (r) setView({ at: 'key', key: r.key, published: r.refresh_note_published });
    };
    const showKey = async () => {
        const r = await run(() => Addons.standbyKey({ operator_id: operatorId }));
        if (r) setView({ at: 'key', key: r.key });
    };
    const remove = async () => {
        if (!live) return;
        reset();
        const r = await run(() => Addons.remove(live.id));
        onChanged();
        if (r) setView({ at: 'removed', report: r });
    };
    const copy = async (key: string) => setCopied(await copyText(key));
    const share = async (key: string) => {
        const nav = navigator as Navigator & { share?: (d: { text: string }) => Promise<void> };
        if (typeof nav.share === 'function') {
            try {
                await nav.share({ text: key });
                return;
            } catch {
                /* closed, or not allowed: copy instead */
            }
        }
        await copy(key);
    };

    const back = () => {
        setError(null);
        setView({ at: 'main' });
    };
    const mode = live?.detail?.mode === 'open' ? 'open' : 'sealed';

    return (
        <Sheet title={t('pub.addons.standby.title')} onClose={onClose} width={480}>
            <div data-testid="standby-sheet" data-view={view.at} style={{ display: 'grid', gap: 12 }}>
                {view.at === 'main' && !live && (
                    <>
                        <p style={BODY}>{t('pub.addons.standby.offer')}</p>
                        {promoted && <p style={MUTED}>{t('pub.addons.standby.promoted_line')}</p>}
                        {priceLine && (
                            <p data-testid="standby-price" style={{ ...BODY, fontWeight: 600 }}>
                                {priceLine}
                            </p>
                        )}
                        <p style={MUTED}>{t('pub.addons.standby.stops')}</p>
                        <p style={MUTED}>{t('pub.addons.standby.ties')}</p>
                        <Toggle
                            checked={open}
                            onChange={setOpen}
                            disabled={busy}
                            label={t('pub.addons.standby.open.label')}
                            subtitle={t('pub.addons.standby.open.help')}
                            dataButton="standby-open"
                        />
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div>
                            <Button onClick={() => void rent()} disabled={busy} dataButton="standby-rent">
                                {busy
                                    ? t('pub.addons.working')
                                    : promoted && priceText
                                      ? t('pub.addons.standby.rent_new').replace('{price}', priceText)
                                      : t('pub.addons.standby.rent')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && live?.state === 'building' && (
                    <>
                        <p style={BODY}>{t('pub.addons.standby.building_line')}</p>
                        {priceLine && <p style={MUTED}>{priceLine}</p>}
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button onClick={() => void rent()} disabled={busy} dataButton="standby-rent">
                                {busy ? t('pub.addons.working') : t('pub.addons.try_again')}
                            </Button>
                            <Button variant="secondary" onClick={() => setView({ at: 'remove' })} disabled={busy} dataButton="standby-remove">
                                {t('pub.addons.standby.remove')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && live?.state === 'ready' && (
                    <>
                        <p style={BODY}>{t('pub.addons.standby.on_line')}</p>
                        <p data-testid="standby-mode" style={MUTED}>
                            {t(`pub.addons.standby.mode.${mode}`)}
                        </p>
                        {live.monthly_cost_cents > 0 && (
                            <p style={MUTED}>
                                {t('pub.addons.standby.price').replace('{price}', money(t, live.monthly_cost_cents, live.cost_currency))}
                            </p>
                        )}
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button onClick={() => setView({ at: 'switch' })} disabled={busy} dataButton="standby-switch">
                                {t('pub.addons.standby.switch')}
                            </Button>
                            <Button variant="secondary" onClick={() => void showKey()} disabled={busy} dataButton="standby-show-key">
                                {t('pub.addons.standby.key.show')}
                            </Button>
                            <Button variant="ghost" onClick={() => setView({ at: 'remove' })} disabled={busy} dataButton="standby-remove">
                                {t('pub.addons.standby.remove')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'main' && live?.state === 'removing' && (
                    <>
                        <p style={BODY}>{t('pub.addons.standby.removing_line')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div>
                            <Button onClick={() => void remove()} disabled={busy} dataButton="standby-remove-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.try_again')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'ready' && (
                    <>
                        <p data-testid="standby-ready" style={BODY}>
                            {t('pub.addons.standby.ready')}
                        </p>
                        <Steps t={t} steps={steps} />
                        <div>
                            <Button onClick={onClose} dataButton="standby-done">
                                {t('pub.addons.close')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'switch' && (
                    <>
                        <div style={{ fontSize: 15, fontWeight: 600 }}>{t('pub.addons.standby.switch.title')}</div>
                        <p style={BODY}>{t('pub.addons.standby.switch.body')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button onClick={() => void doSwitch()} disabled={busy} dataButton="standby-switch-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.standby.switch.go')}
                            </Button>
                            <Button variant="secondary" onClick={back} disabled={busy} dataButton="standby-back">
                                {t('pub.addons.cancel')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'key' && (
                    <>
                        <div style={{ fontSize: 15, fontWeight: 600 }}>{t('pub.addons.standby.key.title')}</div>
                        <div
                            data-testid="standby-key"
                            dir="ltr"
                            style={{ ...MONO, fontSize: 20, letterSpacing: 1, textAlign: 'center', padding: '12px 0', userSelect: 'all' }}
                        >
                            {view.key}
                        </div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                            <Button variant="secondary" leading="copy" onClick={() => void copy(view.key)} dataButton="standby-key-copy">
                                {copied ? t('pub.addons.copied') : t('pub.addons.copy')}
                            </Button>
                            <Button variant="secondary" leading="share" onClick={() => void share(view.key)} dataButton="standby-key-share">
                                {t('pub.addons.share')}
                            </Button>
                        </div>
                        <p style={BODY}>{t('pub.addons.standby.key.body')}</p>
                        {view.published != null && (
                            <p style={MUTED}>
                                {t(view.published ? 'pub.addons.standby.key.published' : 'pub.addons.standby.key.not_published')}
                            </p>
                        )}
                        <div>
                            <Button variant="secondary" onClick={back} dataButton="standby-back">
                                {t('pub.addons.back')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'remove' && (
                    <>
                        <p style={BODY}>{t('pub.addons.standby.remove.body')}</p>
                        <Steps t={t} steps={steps} />
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Button variant="danger" onClick={() => void remove()} disabled={busy} dataButton="standby-remove-go">
                                {busy ? t('pub.addons.working') : t('pub.addons.standby.remove')}
                            </Button>
                            <Button variant="secondary" onClick={back} disabled={busy} dataButton="standby-back">
                                {t('pub.addons.cancel')}
                            </Button>
                        </div>
                    </>
                )}

                {view.at === 'removed' && (
                    <>
                        <RemoveReportLines t={t} report={view.report} />
                        <div>
                            <Button onClick={onClose} dataButton="standby-done">
                                {t('pub.addons.close')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}
