// AddonsSection — «More protection» on the relay page (the build wizard
// asks the same three on its own step: WizardAddons.tsx)
// (docs/optional-addons-plan.md, X3; owner review
// 2026-11-21: "Hetzner setup is very straightforward", make these so).
//
// Three rows: a title, ONE short line, the cost, a switch. Daal decides
// everything else (the standby is always sealed, no plain fallback, ECH
// as the zone allows); none of it is a choice here.
//
//   switch on, account missing → that account's sheet (Accounts); once
//                                connected, the switch carries on
//   switch on                  → «Setting up…», then «On», or one plain
//                                failure line with «Try again»
//   switch off                 → one sentence naming what is given back
//                                or keeps billing, then it runs
//
// The standby code shows only after a switch to the standby, or from
// «Details». The engine's choices (open standby, plain fallback) stay in
// the CLI and the Rust layer; this UI never asks for them.

import { useCallback, useEffect, useState } from 'react';
import { Button, Sheet, StateIcon, Toggle } from '../../design/primitives';
import { WhatIsThis } from '../Disclosure';
import { useConfirm } from '../ui';
import { Addons } from '../wizardCommands';
import type { AddonKind, AddonRemoveReport, AddonRow } from './addonTypes';
import { ADDON_COPY, liveRow } from './addonText';
import type { AddonCopy } from './addonText';
import { classifyAddonError } from './addonErrors';
import { CloudflareSheet, GoogleByHandSheet, GoogleSheet, APPS_SCRIPT_SETTINGS_URL } from './AccountSheets';
import { setGoogleChoice, useAccounts } from './accounts';
import type { AccountsState, GoogleChoice } from './accounts';
import { BODY, ErrorNote, MONO, MUTED, copyText, openExternal, useRun } from './addonUi';
import { addonNeed, clearAddonFailure, failedAddons, runAddon } from './wizardAddons';

export interface AddonsSectionProps {
    t: (key: string) => string;
    /** The relay; absent while it does not exist yet. */
    operatorId?: number | null;
    /** `relay`: the relay page (the only place it is shown). */
    variant?: 'relay';
    /** The accounts, for tests; read from the shell otherwise. */
    accounts?: AccountsState;
}

/** What a row is doing now, beyond what the ledger says. */
type Phase =
    | { k: 'idle' }
    | { k: 'running' }
    | { k: 'stopping' }
    | { k: 'failed'; op: 'on' | 'off'; error: unknown }
    | { k: 'billing'; what: string[] };

type Open =
    | { k: 'cloudflare'; then?: AddonKind }
    | { k: 'google'; then?: AddonKind }
    | { k: 'google-hand' }
    | { k: 'code'; code: string };

export function AddonsSection({ t, operatorId, variant = 'relay', accounts: given }: AddonsSectionProps) {
    const [rows, setRows] = useState<AddonRow[]>([]);
    const [generation, setGeneration] = useState(0);
    const reload = useCallback(() => setGeneration((g) => g + 1), []);
    const read = useAccounts(given == null);
    const accounts = given ?? read.accounts;
    const [phases, setPhases] = useState<Partial<Record<AddonKind, Phase>>>({});
    const [open, setOpen] = useState<Open | null>(null);
    const confirm = useConfirm();
    const code = useRun();

    // An extra chosen in the build wizard that did not turn on: one line
    // with «Try again» here, never a failed relay (wizardAddons.ts).
    useEffect(() => {
        if (operatorId == null) return;
        const failed = failedAddons(operatorId);
        const kinds = Object.keys(failed) as AddonKind[];
        if (kinds.length === 0) return;
        setPhases((all) => {
            const next = { ...all };
            for (const k of kinds) if (next[k] == null) next[k] = { k: 'failed', op: 'on', error: failed[k] };
            return next;
        });
    }, [operatorId]);

    useEffect(() => {
        let gone = false;
        if (operatorId == null) {
            setRows([]);
            return;
        }
        // A shell that predates the ledger, or a relay that went: all
        // off. Never an error on a section about extras.
        Addons.list(operatorId)
            .then((r) => {
                if (!gone) setRows(Array.isArray(r) ? r : []);
            })
            .catch(() => {
                if (!gone) setRows([]);
            });
        return () => {
            gone = true;
        };
    }, [operatorId, generation]);

    const setPhase = (kind: AddonKind, p: Phase) => setPhases((all) => ({ ...all, [kind]: p }));

    /** Turn one on with what is connected now (`acc`, since a sheet may
     *  have just connected the account). */
    const turnOn = async (kind: AddonKind, acc: AccountsState = accounts) => {
        if (operatorId == null) return;
        const need = addonNeed(kind, acc);
        if (need === 'cloudflare') {
            setOpen({ k: 'cloudflare', then: 'cdn' });
            return;
        }
        if (need === 'google') {
            setOpen({ k: 'google', then: 'google' });
            return;
        }
        if (need === 'by_hand') {
            setOpen({ k: 'google-hand' });
            return;
        }
        setPhase(kind, { k: 'running' });
        clearAddonFailure(operatorId, kind);
        try {
            await runAddon(kind, operatorId, acc);
            setPhase(kind, { k: 'idle' });
        } catch (e) {
            setPhase(kind, { k: 'failed', op: 'on', error: e });
            // The key went (a restore, another phone): connect again.
            if (classifyAddonError(e) === 'E_CDN_NO_TOKEN') {
                read.reload();
                setOpen({ k: 'cloudflare', then: 'cdn' });
            }
        }
        reload();
    };

    const turnOff = async (kind: AddonKind, ask: boolean) => {
        const row = liveRow(rows, kind);
        const copy = ADDON_COPY.find((c) => c.kind === kind)!;
        if (!row) return;
        if (ask) {
            const yes = await confirm.ask({
                title: t('pub.addons.off.title').replace('{name}', t(copy.titleKey)),
                body: t(copy.offKey),
                confirmLabel: t('pub.addons.off.go'),
                cancelLabel: t('pub.addons.cancel'),
                danger: true,
            });
            if (!yes) return;
        }
        setPhase(kind, { k: 'stopping' });
        try {
            const r: AddonRemoveReport = await Addons.remove(row.id);
            const billing = r.still_billing ?? [];
            if (!r.removed) setPhase(kind, { k: 'failed', op: 'off', error: '' });
            else setPhase(kind, billing.length > 0 ? { k: 'billing', what: billing } : { k: 'idle' });
        } catch (e) {
            setPhase(kind, { k: 'failed', op: 'off', error: e });
        }
        reload();
    };

    const retry = (kind: AddonKind) => {
        const p = phases[kind];
        const row = liveRow(rows, kind);
        if ((p?.k === 'failed' && p.op === 'off') || row?.state === 'removing') void turnOff(kind, false);
        else void turnOn(kind);
    };

    const showCode = async () => {
        if (operatorId == null) return;
        const r = await code.run(() => Addons.standbyKey({ operator_id: operatorId }));
        if (r) setOpen({ k: 'code', code: r.key });
    };
    const switchToStandby = async () => {
        if (operatorId == null) return;
        const yes = await confirm.ask({
            title: t('pub.addons.standby.switch.title'),
            body: t('pub.addons.standby.switch.body'),
            confirmLabel: t('pub.addons.standby.switch.go'),
            cancelLabel: t('pub.addons.cancel'),
        });
        if (!yes) return;
        const r = await code.run(() => Addons.standbyPromote({ operator_id: operatorId }));
        reload();
        if (r) setOpen({ k: 'code', code: r.key });
    };

    const standby = liveRow(rows, 'standby');
    const promoted = rows.some((r) => r.kind === 'standby' && r.state === 'promoted');
    const cdn = liveRow(rows, 'cdn');
    const nameHidden = cdn?.state === 'ready' && cdn.detail?.name_hidden === true;
    const details = standby?.state === 'ready' || promoted || nameHidden;

    const afterConnect = (kind: AddonKind | undefined, acc: AccountsState) => {
        setOpen(null);
        read.reload();
        if (kind) void turnOn(kind, acc);
    };

    return (
        <section data-testid={`addons-${variant}`} style={{ width: '100%', textAlign: 'start', display: 'grid', gap: 8 }}>
            <h2 style={H2}>{t('pub.addons.title')}</h2>
            <div
                style={{
                    background: 'var(--surface)',
                    border: '1px solid var(--line-soft)',
                    borderRadius: 'var(--r-card)',
                    padding: '0 16px',
                }}
            >
                {ADDON_COPY.map((c, i) => (
                    <ProtectRow
                        key={c.kind}
                        t={t}
                        copy={c}
                        row={liveRow(rows, c.kind)}
                        phase={phases[c.kind] ?? { k: 'idle' }}
                        connected={c.needs == null || (c.needs === 'cloudflare' ? accounts.cloudflare.connected : !!accounts.google)}
                        first={i === 0}
                        disabled={operatorId == null}
                        onToggle={(on) => void (on ? turnOn(c.kind) : turnOff(c.kind, true))}
                        onRetry={() => retry(c.kind)}
                        onByHand={c.kind === 'google' ? () => setOpen({ k: 'google-hand' }) : undefined}
                    />
                ))}
                {details && (
                    <div data-testid="addons-details" style={{ borderTop: '1px solid var(--line)', padding: '10px 0' }}>
                        <WhatIsThis label={t('pub.addons.details')} dataButton="addons-details">
                            <div style={{ display: 'grid', gap: 10, paddingTop: 6 }}>
                                {promoted && !standby && <p style={MUTED}>{t('pub.addons.standby.in_use')}</p>}
                                {(standby?.state === 'ready' || promoted) && (
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                        {standby?.state === 'ready' && (
                                            <Button size="sm" variant="secondary" onClick={() => void switchToStandby()} disabled={code.busy} dataButton="standby-switch">
                                                {t('pub.addons.standby.switch')}
                                            </Button>
                                        )}
                                        <Button size="sm" variant="ghost" onClick={() => void showCode()} disabled={code.busy} dataButton="standby-show-key">
                                            {t('pub.addons.standby.key.show')}
                                        </Button>
                                    </div>
                                )}
                                {code.error != null && <ErrorNote t={t} error={code.error} />}
                                {nameHidden && (
                                    <p data-testid="cdn-name-hidden" style={MUTED}>
                                        {t('pub.addons.cdn.name_hidden')}
                                    </p>
                                )}
                            </div>
                        </WhatIsThis>
                    </div>
                )}
            </div>

            {open?.k === 'cloudflare' && (
                <CloudflareSheet
                    t={t}
                    zone={accounts.cloudflare.connected ? accounts.cloudflare.zone : null}
                    onClose={() => setOpen(null)}
                    onConnected={(zone) => {
                        const acc = { ...accounts, cloudflare: { connected: true, zone } };
                        afterConnect(open.then, acc);
                    }}
                />
            )}
            {open?.k === 'google' && (
                <GoogleSheet
                    t={t}
                    choice={accounts.google}
                    onClose={() => setOpen(null)}
                    onChoose={(c: GoogleChoice | null) => {
                        setGoogleChoice(c);
                        if (c == null) {
                            setOpen(null);
                            read.reload();
                            return;
                        }
                        afterConnect(open.then, { ...accounts, google: c });
                    }}
                />
            )}
            {open?.k === 'google-hand' && operatorId != null && (
                <GoogleByHandSheet
                    t={t}
                    operatorId={operatorId}
                    onClose={() => setOpen(null)}
                    onDone={() => {
                        setOpen(null);
                        clearAddonFailure(operatorId, 'google');
                        setPhase('google', { k: 'idle' });
                        reload();
                    }}
                />
            )}
            {open?.k === 'code' && <CodeSheet t={t} code={open.code} onClose={() => setOpen(null)} />}
            {confirm.node}
        </section>
    );
}

function ProtectRow({
    t,
    copy,
    row,
    phase,
    connected,
    first,
    disabled,
    onToggle,
    onRetry,
    onByHand,
}: {
    t: (key: string) => string;
    copy: AddonCopy;
    row: AddonRow | null;
    phase: Phase;
    /** The account it needs is connected (or it needs none). */
    connected: boolean;
    first: boolean;
    disabled: boolean;
    onToggle: (on: boolean) => void;
    onRetry: () => void;
    onByHand?: () => void;
}) {
    const titleId = `addon-${copy.kind}-title`;
    const busy = phase.k === 'running' || phase.k === 'stopping';
    const checked = phase.k === 'running' || (phase.k !== 'stopping' && row != null);
    // The same words on or off: the cost never loses its "+ VAT".
    const cost = t(copy.costKey);
    const needs = !connected && copy.needs ? t(`pub.addons.needs.${copy.needs}`) : '';
    const code = phase.k === 'failed' ? classifyAddonError(phase.error) : null;
    const state =
        phase.k === 'idle' || phase.k === 'billing' ? (row ? row.state : 'off') : phase.k;

    return (
        <div
            data-testid={`addon-${copy.kind}`}
            data-state={state}
            role="group"
            aria-labelledby={titleId}
            style={{ display: 'grid', gap: 6, padding: '14px 0', borderTop: first ? 'none' : '1px solid var(--line)' }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2 }}>
                    <span id={titleId} style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>
                        {t(copy.titleKey)}
                    </span>
                    <span style={MUTED}>{t(copy.lineKey)}</span>
                    <span data-testid={`addon-${copy.kind}-cost`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
                        {needs ? `${cost} · ${needs}` : cost}
                    </span>
                </span>
                <Toggle
                    checked={checked}
                    onChange={onToggle}
                    disabled={disabled || busy}
                    ariaLabel={t(copy.titleKey)}
                    dataButton={`addon-${copy.kind}-toggle`}
                />
            </div>

            {busy && (
                <div data-testid={`addon-${copy.kind}-status`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <StateIcon state="busy" size={16} />
                    <span style={MUTED}>{t(phase.k === 'running' ? 'pub.addons.state.running' : 'pub.addons.state.stopping')}</span>
                </div>
            )}

            {!busy && phase.k !== 'failed' && row?.state === 'ready' && (
                <div data-testid={`addon-${copy.kind}-status`} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <StateIcon state="ok" size={16} />
                    <span style={{ ...MUTED, color: 'var(--green)', fontWeight: 600 }}>{t('pub.addons.state.on')}</span>
                </div>
            )}

            {!busy && phase.k !== 'failed' && (row?.state === 'building' || row?.state === 'removing') && (
                <Failed t={t} line={t(`pub.addons.state.${row.state}`)} onRetry={onRetry} kind={copy.kind} />
            )}

            {phase.k === 'failed' && (
                <Failed t={t} error={phase.error} line={phase.error ? undefined : t('pub.addons.state.removing')} onRetry={onRetry} kind={copy.kind}>
                    {code === 'E_GOOGLE_API_NOT_ENABLED' && (
                        <Button size="sm" variant="link" leading="external" onClick={() => void openExternal(APPS_SCRIPT_SETTINGS_URL)} dataButton="google-api-open">
                            {t('pub.addons.google.api.open')}
                        </Button>
                    )}
                    {code === 'E_GOOGLE_NOT_CONFIGURED' && onByHand && (
                        <Button size="sm" variant="link" onClick={onByHand} dataButton="google-by-hand">
                            {t('pub.accounts.google.by_hand')}
                        </Button>
                    )}
                </Failed>
            )}

            {phase.k === 'billing' &&
                phase.what.map((w) => (
                    <p key={w} data-testid={`addon-${copy.kind}-billing`} style={{ ...MUTED, color: 'var(--amber)' }}>
                        {t(w === 'domain' ? 'pub.addons.billing.domain' : 'pub.addons.billing.address')}
                    </p>
                ))}
        </div>
    );
}

function Failed({
    t,
    kind,
    error,
    line,
    onRetry,
    children,
}: {
    t: (k: string) => string;
    kind: AddonKind;
    error?: unknown;
    line?: string;
    onRetry: () => void;
    children?: React.ReactNode;
}) {
    return (
        <div data-testid={`addon-${kind}-failed`} style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
            {line ? <p style={{ ...MUTED, color: 'var(--red)' }}>{line}</p> : <ErrorNote t={t} error={error} />}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <Button size="sm" variant="secondary" onClick={onRetry} dataButton={`addon-${kind}-retry`}>
                    {t('pub.addons.try_again')}
                </Button>
                {children}
            </div>
        </div>
    );
}

/** The standby code: after a switch, or from Details. */
function CodeSheet({ t, code, onClose }: { t: (k: string) => string; code: string; onClose: () => void }) {
    const [copied, setCopied] = useState(false);
    const share = async () => {
        const nav = navigator as Navigator & { share?: (d: { text: string }) => Promise<void> };
        if (typeof nav.share === 'function') {
            try {
                await nav.share({ text: code });
                return;
            } catch {
                /* closed, or not allowed: copy instead */
            }
        }
        setCopied(await copyText(code));
    };
    return (
        <Sheet title={t('pub.addons.standby.key.title')} onClose={onClose} width={440}>
            <div data-testid="standby-code-sheet" style={{ display: 'grid', gap: 12 }}>
                <div
                    data-testid="standby-key"
                    dir="ltr"
                    style={{ ...MONO, fontSize: 20, letterSpacing: 1, textAlign: 'center', padding: '12px 0', userSelect: 'all' }}
                >
                    {code}
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                    <Button variant="secondary" leading="copy" onClick={async () => setCopied(await copyText(code))} dataButton="standby-key-copy">
                        {copied ? t('pub.addons.copied') : t('pub.addons.copy')}
                    </Button>
                    <Button variant="secondary" leading="share" onClick={() => void share()} dataButton="standby-key-share">
                        {t('pub.addons.share')}
                    </Button>
                </div>
                <p style={BODY}>{t('pub.addons.standby.key.body')}</p>
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button onClick={onClose} dataButton="standby-key-close">
                        {t('pub.addons.close')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}

const H2: React.CSSProperties = {
    fontFamily: 'var(--font-display)',
    fontSize: 20,
    fontWeight: 500,
    lineHeight: 1.2,
    margin: 0,
    color: 'var(--fg)',
};
