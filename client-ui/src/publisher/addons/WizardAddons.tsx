// WizardAddons — «More protection (optional)» while building a relay.
//
//   WizardAddonsStep — the build wizard's step before «Create my relay»:
//     the relay page's three rows, each a title, one line, its cost and a
//     switch, all off. A switch whose account is not connected opens that
//     account's sheet (Cloudflare, Google) here, then comes back on.
//     Nothing is rented or set up here: it is only the choice.
//   WizardAddonsProgress — the finishing screen: each chosen extra as it
//     is turned on after the relay is built (wizardAddons.ts). A failure
//     is one line; the relay works and its page offers «Try again».

import { useState } from 'react';
import { Button, StateIcon, Toggle } from '../../design/primitives';
import { CloudflareSheet, GoogleByHandSheet, GoogleSheet } from './AccountSheets';
import { setGoogleChoice, useAccounts } from './accounts';
import type { AccountsState } from './accounts';
import { ADDON_COPY } from './addonText';
import type { AddonKind } from './addonTypes';
import { ErrorNote, MUTED } from './addonUi';
import { ADDON_ORDER, addonNeed } from './wizardAddons';
import type { ApplyState } from './wizardAddons';

const CARD: React.CSSProperties = {
    background: 'var(--surface)',
    border: '1px solid var(--line-soft)',
    borderRadius: 'var(--r-card)',
    padding: '0 16px',
};

/** The cost line in the wizard: the standby says it is extra. */
function costKey(kind: AddonKind, fallback: string): string {
    return kind === 'standby' ? 'pub.addons.wizard.standby.cost' : fallback;
}

export function WizardAddonsStep({
    t,
    chosen,
    onChange,
    accounts: given,
}: {
    t: (k: string) => string;
    chosen: readonly AddonKind[];
    onChange: (next: AddonKind[]) => void;
    /** The accounts, for tests; read from the shell otherwise. */
    accounts?: AccountsState;
}) {
    const read = useAccounts(given == null);
    const accounts = given ?? read.accounts;
    const [open, setOpen] = useState<'cloudflare' | 'google' | null>(null);

    const set = (kind: AddonKind, on: boolean) => {
        const next = ADDON_ORDER.filter((k) => (k === kind ? on : chosen.includes(k)));
        onChange(next);
    };
    const toggle = (kind: AddonKind, on: boolean) => {
        if (!on) return set(kind, false);
        const need = addonNeed(kind, accounts);
        if (need === 'cloudflare') return setOpen('cloudflare');
        if (need === 'google') return setOpen('google');
        set(kind, true);
    };

    return (
        <div data-testid="wizard-addons" style={{ display: 'grid', gap: 12 }}>
            <div style={CARD}>
                {ADDON_COPY.map((c, i) => {
                    const on = chosen.includes(c.kind);
                    const connected =
                        c.needs == null || (c.needs === 'cloudflare' ? accounts.cloudflare.connected : !!accounts.google);
                    const cost = t(costKey(c.kind, c.costKey));
                    const needs = !connected && c.needs ? t(`pub.addons.needs.${c.needs}`) : '';
                    const titleId = `wizard-addon-${c.kind}-title`;
                    return (
                        <div
                            key={c.kind}
                            data-testid={`wizard-addon-${c.kind}`}
                            data-chosen={String(on)}
                            role="group"
                            aria-labelledby={titleId}
                            style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 0', borderTop: i === 0 ? 'none' : '1px solid var(--line)' }}
                        >
                            <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2 }}>
                                <span id={titleId} style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>
                                    {t(c.titleKey)}
                                </span>
                                <span style={MUTED}>{t(c.lineKey)}</span>
                                <span data-testid={`wizard-addon-${c.kind}-cost`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
                                    {needs ? `${cost} · ${needs}` : cost}
                                </span>
                            </span>
                            <Toggle
                                checked={on}
                                onChange={(v) => toggle(c.kind, v)}
                                ariaLabel={t(c.titleKey)}
                                dataButton={`wizard-addon-${c.kind}-toggle`}
                            />
                        </div>
                    );
                })}
            </div>

            {open === 'cloudflare' && (
                <CloudflareSheet
                    t={t}
                    zone={null}
                    onClose={() => setOpen(null)}
                    onConnected={() => {
                        setOpen(null);
                        read.reload();
                        set('cdn', true);
                    }}
                />
            )}
            {open === 'google' && (
                <GoogleSheet
                    t={t}
                    choice={accounts.google}
                    onClose={() => setOpen(null)}
                    onChoose={(c) => {
                        setGoogleChoice(c);
                        setOpen(null);
                        read.reload();
                        if (c) set('google', true);
                    }}
                />
            )}
        </div>
    );
}

export function WizardAddonsProgress({
    t,
    operatorId,
    progress,
    onByHandDone,
}: {
    t: (k: string) => string;
    operatorId: number;
    progress: Partial<Record<AddonKind, ApplyState>>;
    /** The by-hand Google script was attached. */
    onByHandDone: () => void;
}) {
    const [hand, setHand] = useState(false);
    const kinds = ADDON_ORDER.filter((k) => progress[k] != null);
    if (kinds.length === 0) return null;
    return (
        <section data-testid="wizard-addons-progress" style={{ width: '100%', textAlign: 'start', display: 'grid', gap: 8 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>{t('pub.addons.title')}</div>
            <div style={CARD}>
                {kinds.map((kind, i) => {
                    const st = progress[kind]!;
                    const copy = ADDON_COPY.find((c) => c.kind === kind)!;
                    return (
                        <div
                            key={kind}
                            data-testid={`wizard-addon-${kind}-progress`}
                            data-state={st.k}
                            style={{ display: 'grid', gap: 4, padding: '12px 0', borderTop: i === 0 ? 'none' : '1px solid var(--line)' }}
                        >
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                                <StateIcon
                                    state={st.k === 'on' ? 'ok' : st.k === 'failed' ? 'bad' : st.k === 'running' ? 'busy' : 'none'}
                                    size={18}
                                />
                                <span style={{ flex: 1, minWidth: 0, fontSize: 14, fontWeight: 600, color: 'var(--fg)' }}>{t(copy.titleKey)}</span>
                                <span style={{ ...MUTED, color: st.k === 'on' ? 'var(--green)' : undefined }}>
                                    {st.k === 'on'
                                        ? t('pub.addons.state.on')
                                        : st.k === 'running'
                                          ? t('pub.addons.state.running')
                                          : st.k === 'waiting'
                                            ? t('pub.addons.wizard.waiting')
                                            : ''}
                                </span>
                            </div>
                            {st.k === 'failed' && (
                                <div data-testid={`wizard-addon-${kind}-failed`} style={{ display: 'grid', gap: 2 }}>
                                    <ErrorNote t={t} error={st.error} />
                                    <p style={MUTED}>{t('pub.addons.wizard.failed')}</p>
                                </div>
                            )}
                            {st.k === 'by_hand' && (
                                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                                    <p style={MUTED}>{t('pub.addons.wizard.by_hand')}</p>
                                    <Button size="sm" variant="secondary" onClick={() => setHand(true)} dataButton="wizard-google-by-hand">
                                        {t('pub.addons.google.hand.1.action')}
                                    </Button>
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
            {hand && (
                <GoogleByHandSheet
                    t={t}
                    operatorId={operatorId}
                    onClose={() => setHand(false)}
                    onDone={() => {
                        setHand(false);
                        onByHandDone();
                    }}
                />
            )}
        </section>
    );
}
