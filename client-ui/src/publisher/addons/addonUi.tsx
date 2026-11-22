// addonUi — the small pieces the protection rows and the account sheets
// share: numbered steps in the wizard's look, a one-line failure with
// its Details, and the two outside actions (open a page, copy a text).

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Button, Icon } from '../../design/primitives';
import { useDensity } from '../../design/DensityProvider';
import { toFaDigits } from '../../lib/i18n';
import { WhatIsThis } from '../Disclosure';
import { addonErrorText } from './addonErrors';
import { writeClipboardText } from '../../lib/clipboard';

export const BODY: React.CSSProperties = { fontSize: 14, color: 'var(--fg)', lineHeight: 1.55, margin: 0 };
export const MUTED: React.CSSProperties = { fontSize: 13, color: 'var(--muted)', lineHeight: 1.5, margin: 0 };
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
        await writeClipboardText(text);
        return true;
    } catch {
        return false;
    }
}

export interface StepItem {
    /** The step, already in words. */
    text: string;
    /** A button that opens the right page. */
    action?: { label: string; url: string; dataButton: string };
    extra?: ReactNode;
}

/** The wizard's numbered guide (PublisherWizard, H-47): a numbered
 *  circle, one short line, and the link that opens the page. */
export function NumberedSteps({ items, testId }: { items: StepItem[]; testId?: string }) {
    const { isRTL } = useDensity();
    return (
        <ol data-testid={testId} style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }}>
            {items.map((it, i) => (
                <li key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                    <span
                        aria-hidden
                        style={{
                            width: 24,
                            height: 24,
                            flexShrink: 0,
                            borderRadius: '50%',
                            background: 'var(--surface-3)',
                            color: 'var(--fg)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: 13,
                            fontWeight: 600,
                        }}
                    >
                        {isRTL ? toFaDigits(String(i + 1)) : i + 1}
                    </span>
                    <span style={{ ...BODY, minWidth: 0 }}>
                        {it.text}
                        {it.action && (
                            <>
                                {' '}
                                <Button
                                    variant="link"
                                    trailing={<Icon name="external" size={14} />}
                                    onClick={() => void openExternal(it.action!.url)}
                                    dataButton={it.action.dataButton}
                                    style={{ paddingBlock: 0, minHeight: 44, marginBlock: -6 }}
                                >
                                    {it.action.label}
                                </Button>
                            </>
                        )}
                        {it.extra}
                    </span>
                </li>
            ))}
        </ol>
    );
}

/** One plain line for a failure; the raw text only under Details. */
export function ErrorNote({ t, error, testId }: { t: (k: string) => string; error: unknown; testId?: string }) {
    const e = addonErrorText(t, error);
    return (
        <div role="alert" data-testid={testId ?? 'addon-error'} data-code={e.code ?? ''} style={{ display: 'grid', gap: 2 }}>
            <p style={{ ...MUTED, color: 'var(--red)' }}>{e.line}</p>
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

/** Run one async action at a time, with its error kept. */
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
