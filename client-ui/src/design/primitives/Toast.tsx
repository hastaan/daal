// Toast — a short answer to a tap ("Copied", "Couldn't copy the report"):
// an icon and at most two lines at the bottom of the screen, above the
// phone's tab bar. One at a time: a newer toast replaces the older one.
//
//   const toast = useToast();
//   toast.show('good', t('ui.copied'));
//   …
//   {toast.node}

import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { IconButton } from './IconButton';
import { Icon } from './icons';
import { StateIcon } from './StateIcon';
import { uiText } from './uiText';

export type ToastTone = 'good' | 'bad' | 'neutral';

interface ToastProps {
    tone?: ToastTone;
    children: ReactNode;
    onDismiss: () => void;
    /** 3500 by default; 0 = stays until closed. */
    autoHideMs?: number;
    /** The close button's name; defaults to ui.close. */
    closeLabel?: string;
}

// One toast at a time across the whole app: each one that appears tells
// the others to go.
let seq = 0;
const live = new Map<number, () => void>();

export function Toast({ tone = 'neutral', children, onDismiss, autoHideMs = 3500, closeLabel }: ToastProps) {
    const { density } = useDensity();
    const phone = density === 'phone';
    const dismissRef = useRef(onDismiss);
    dismissRef.current = onDismiss;

    useEffect(() => {
        const id = ++seq;
        for (const [other, go] of Array.from(live.entries())) {
            if (other !== id) {
                live.delete(other);
                go();
            }
        }
        live.set(id, () => dismissRef.current());
        return () => {
            live.delete(id);
        };
    }, []);

    useEffect(() => {
        if (!autoHideMs) return;
        const h = setTimeout(() => dismissRef.current(), autoHideMs);
        return () => clearTimeout(h);
        // Not keyed on `children`: a parent that re-renders every second
        // (a live clock) would otherwise keep the toast up for ever. A new
        // message is a new toast (useToast keys it).
    }, [autoHideMs]);

    return (
        <div
            role="status"
            aria-live="polite"
            data-toast={tone}
            style={{
                position: 'fixed',
                zIndex: 400,
                bottom: phone ? 'calc(72px + env(safe-area-inset-bottom, 0px))' : 24,
                insetInlineStart: phone ? 16 : undefined,
                insetInlineEnd: phone ? 16 : 24,
                maxWidth: phone ? undefined : 420,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                paddingBlock: 6,
                paddingInlineStart: 14,
                paddingInlineEnd: 4,
                background: 'var(--surface-2)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--r-tile)',
                boxShadow: '0 16px 40px rgba(0,0,0,0.4)',
                color: 'var(--fg)',
            }}
        >
            {tone === 'neutral' ? (
                <span style={{ color: 'var(--muted)', display: 'inline-flex' }}>
                    <Icon name="info" size={20} />
                </span>
            ) : (
                <StateIcon state={tone === 'good' ? 'ok' : 'bad'} size={20} />
            )}
            <div
                style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 14,
                    lineHeight: 1.4,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                }}
            >
                {children}
            </div>
            <IconButton label={closeLabel ?? uiText('ui.close')} dataButton="toast-close" onClick={() => dismissRef.current()}>
                <Icon name="close" size={18} />
            </IconButton>
        </div>
    );
}

interface ToastState {
    tone: ToastTone;
    text: ReactNode;
    key: number;
    autoHideMs?: number;
}

/** A page's toast: `show()` replaces whatever toast is up; render `node`. */
export function useToast(): {
    show: (tone: ToastTone, text: ReactNode, autoHideMs?: number) => void;
    hide: () => void;
    node: ReactNode;
} {
    const [state, setState] = useState<ToastState | null>(null);
    const hide = useCallback(() => setState(null), []);
    const show = useCallback((tone: ToastTone, text: ReactNode, autoHideMs?: number) => {
        setState((prev) => ({ tone, text, autoHideMs, key: (prev?.key ?? 0) + 1 }));
    }, []);
    const node = state ? (
        <Toast key={state.key} tone={state.tone} onDismiss={hide} autoHideMs={state.autoHideMs}>
            {state.text}
        </Toast>
    ) : null;
    return { show, hide, node };
}
