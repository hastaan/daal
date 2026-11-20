// addonUi — the small pieces the three add-on sheets share: the live
// step list, the owner's "what you need first" list, an error with its
// Details, and the two outside actions (open a page, copy a text).
//
// Calm on purpose: one sentence per state, the provider's own words
// only under Details.

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button, StateIcon } from '../../design/primitives';
import { WhatIsThis } from '../Disclosure';
import { onAddonProgress } from '../wizardCommands';
import type { AddonKind, AddonProgress } from './addonTypes';
import { STEP_WORDS, addonErrorText, warningLine } from './addonErrors';
import { formatDate } from '../../lib/format';

export const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.6, margin: 0 };
export const MUTED: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.6, margin: 0 };
export const MONO: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    color: 'var(--fg)',
    wordBreak: 'break-all',
};

/** Open a page in the system browser. */
export async function openExternal(url: string): Promise<void> {
    try {
        await invoke('open_external_url', { url });
        return;
    } catch {
        /* not in the app shell */
    }
    try {
        window.open(url, '_blank');
    } catch {
        /* nothing to open with */
    }
}

/** Copy a text. Never logs it (a script carries a write key). */
export async function copyText(text: string): Promise<boolean> {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

export interface StepState {
    step: string;
    state: AddonProgress['state'];
}

/** The steps of the add-on operation running now, in the order they
 *  first appeared. Only steps of this relay and kind, and only words
 *  the UI has a sentence for. */
export function useAddonSteps(operatorId: number, kind: AddonKind) {
    const [steps, setSteps] = useState<StepState[]>([]);
    useEffect(() => {
        let un: (() => void) | null = null;
        let gone = false;
        try {
            onAddonProgress((ev) => {
                if (ev.operator_id !== operatorId || ev.kind !== kind) return;
                if (!(STEP_WORDS as readonly string[]).includes(ev.step)) return;
                setSteps((prev) => {
                    const i = prev.findIndex((s) => s.step === ev.step);
                    if (i < 0) return [...prev, { step: ev.step, state: ev.state }];
                    const next = prev.slice();
                    next[i] = { step: ev.step, state: ev.state };
                    return next;
                });
            })
                .then((f) => {
                    if (gone) f();
                    else un = f;
                })
                .catch(() => {});
        } catch {
            /* no event bridge (tests, a browser): no live steps */
        }
        return () => {
            gone = true;
            if (un) un();
        };
    }, [operatorId, kind]);
    const reset = useCallback(() => setSteps([]), []);
    return { steps, reset };
}

export function Steps({ t, steps }: { t: (k: string) => string; steps: StepState[] }) {
    if (steps.length === 0) return null;
    return (
        <ol data-testid="addon-steps" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
            {steps.map((s) => (
                <li key={s.step} data-step={s.step} data-state={s.state} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <StateIcon state={s.state === 'running' ? 'busy' : s.state === 'ok' ? 'ok' : 'bad'} size={16} />
                    <span style={BODY}>{t(`pub.addons.step.${s.step}`)}</span>
                </li>
            ))}
        </ol>
    );
}

/** A short numbered list of what the owner does by hand, each with an
 *  optional button that opens the right page. */
export function HowTo({
    t,
    title,
    items,
    testId,
}: {
    t: (k: string) => string;
    title?: string;
    items: { key: string; action?: { key: string; url: string; dataButton: string }; extra?: ReactNode }[];
    testId?: string;
}) {
    return (
        <div data-testid={testId} style={{ display: 'grid', gap: 8 }}>
            {title && <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{title}</div>}
            <ol style={{ margin: 0, paddingInlineStart: 20, display: 'grid', gap: 10 }}>
                {items.map((it) => (
                    <li key={it.key} style={BODY}>
                        <span>{t(it.key)}</span>
                        {it.extra}
                        {it.action && (
                            <div style={{ marginTop: 6 }}>
                                <Button
                                    size="sm"
                                    variant="secondary"
                                    leading="external"
                                    dataButton={it.action.dataButton}
                                    onClick={() => void openExternal(it.action!.url)}
                                >
                                    {t(it.action.key)}
                                </Button>
                            </div>
                        )}
                    </li>
                ))}
            </ol>
        </div>
    );
}

export function ErrorNote({ t, error, testId }: { t: (k: string) => string; error: unknown; testId?: string }) {
    const e = addonErrorText(t, error);
    return (
        <div role="alert" data-testid={testId ?? 'addon-error'} data-code={e.code ?? ''} style={{ display: 'grid', gap: 4 }}>
            <p style={{ ...BODY, color: 'var(--red)' }}>{e.line}</p>
            {e.detail && (
                <WhatIsThis label={t('pub.addons.details')}>
                    <div style={MONO} dir="ltr">
                        {e.detail}
                    </div>
                </WhatIsThis>
            )}
        </div>
    );
}

/** What a removal left for the publisher: by-hand steps and warnings. */
export function RemoveReportLines({
    t,
    report,
}: {
    t: (k: string) => string;
    report: { removed: boolean; still_billing?: string[]; by_hand?: string[]; warnings?: string[] };
}) {
    const warnings = report.warnings ?? [];
    const lines = warnings.map((w) => warningLine(t, w)).filter((x): x is string => !!x);
    const raw = warnings.filter((w) => warningLine(t, w) == null);
    const byHand = report.by_hand ?? [];
    return (
        <div data-testid="addon-remove-report" style={{ display: 'grid', gap: 8 }}>
            <p style={BODY}>{t(report.removed ? 'pub.addons.remove.done' : 'pub.addons.remove.not_done')}</p>
            {(report.still_billing ?? []).length > 0 && (
                <p style={{ ...BODY, color: 'var(--red)' }}>
                    {t('pub.addons.still_billing').replace('{what}', (report.still_billing ?? []).join(', '))}
                </p>
            )}
            {byHand.length > 0 && (
                <div style={{ display: 'grid', gap: 4 }}>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{t('pub.addons.remove.by_hand')}</div>
                    <ul style={{ margin: 0, paddingInlineStart: 20 }}>
                        {byHand.map((w) => (
                            <li key={w} style={BODY}>
                                {t(`pub.addons.by_hand.${w}`)}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
            {lines.map((l, i) => (
                <p key={i} style={MUTED}>
                    {l}
                </p>
            ))}
            {raw.length > 0 && (
                <WhatIsThis label={t('pub.addons.details')}>
                    {raw.map((w, i) => (
                        <div key={i} style={MONO} dir="ltr">
                            {w}
                        </div>
                    ))}
                </WhatIsThis>
            )}
        </div>
    );
}

/** A label: value line of a status block. */
export function StatusLine({
    label,
    value,
    tone,
    testId,
}: {
    label: string;
    value: ReactNode;
    tone?: 'good' | 'bad' | 'none';
    testId?: string;
}) {
    return (
        <div data-testid={testId} style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, color: 'var(--muted)' }}>{label}</span>
            <span
                style={{
                    fontSize: 13,
                    fontWeight: 600,
                    color: tone === 'good' ? 'var(--green)' : tone === 'bad' ? 'var(--amber)' : 'var(--fg)',
                }}
            >
                {value}
            </span>
        </div>
    );
}

/** Run one async action at a time, with its error kept for the card. */
export function useRun() {
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<unknown>(null);
    const alive = useRef(true);
    // Set on every mount: StrictMode mounts, unmounts and mounts again,
    // and a ref left false would keep `busy` on for good.
    useEffect(() => {
        alive.current = true;
        return () => {
            alive.current = false;
        };
    }, []);
    const run = useCallback(async <T,>(f: () => Promise<T>): Promise<T | undefined> => {
        setBusy(true);
        setError(null);
        try {
            return await f();
        } catch (e) {
            if (alive.current) setError(e);
            return undefined;
        } finally {
            if (alive.current) setBusy(false);
        }
    }, []);
    return { busy, error, setError, run };
}

/** The date and time, as the rest of the app writes them (Persian
 *  calendar and digits for a Persian reader), isolated for RTL. */
export function whenText(t: (k: string) => string, unix: number): string {
    if (!unix) return t('pub.addons.never');
    return formatDate(/[؀-ۿ]/.test(t('pub.addons.title')) ? 'fa' : 'en', unix, 'dayTime');
}
