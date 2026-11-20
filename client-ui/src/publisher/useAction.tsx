// useAction — every publisher action answers the person who tapped it.
//
// WHY THIS EXISTS
//
// On the first real-phone pass the owner pressed Save on a person's
// file. The save worked. Nothing on screen said so (the only notice
// was a grey line at the very top of a long page, scrolled out of
// view), so they pressed it three more times. An action that ends
// silently is indistinguishable from one that never started.
//
// So there is ONE rule, implemented once:
//
//   * while an action runs, its button says so and no button on the
//     same controller can fire — a second tap is dropped, not queued;
//   * when it ends there is a visible result, pinned to the bottom of
//     the screen wherever the page happens to be scrolled: what
//     happened, or that it failed and why, in plain words.
//
// The lock is a plain field, not React state. State is only applied on
// the next render, so two taps in the same frame would both see
// "not busy"; a field is already set when the second tap arrives.

import { useEffect, useRef, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { Button, Icon, IconButton, StateIcon } from '../design/primitives';
import { WhatIsThis } from './Disclosure';
import type { Failure } from './failureText';

export interface ActionOutcome {
    /** Increments per outcome, so two identical results in a row are
     *  still two results (the toast re-announces). */
    seq: number;
    key: string;
    kind: 'ok' | 'fail';
    /** Plain words. Never a raw error. */
    message: string;
    /** The untranslated error, shown only behind "Details". */
    detail?: string;
}

export interface ActionState {
    /** Key of the action in flight, or null. */
    busy: string | null;
    outcome: ActionOutcome | null;
}

export interface RunOptions<T> {
    /** What to say when it worked. A function gets the result (to name
     *  a path, a count…). Return null to say nothing — only for actions
     *  whose success opens its own result screen. */
    ok?: string | null | ((value: T) => string | null);
    /** What did not happen, as a full sentence: "The file was not
     *  saved." The reason is appended by the explainer. */
    fail: string;
}

export type RunResult<T> =
    | { ran: true; ok: true; value: T }
    | { ran: true; ok: false }
    /** Dropped because another action was still running. */
    | { ran: false; ok: false };

export class ActionController {
    private state: ActionState = { busy: null, outcome: null };
    private listeners = new Set<() => void>();
    private seq = 0;

    /** `explain` turns a thrown value into plain words + raw detail. */
    constructor(private explain: (e: unknown) => Failure) {}

    getState = (): ActionState => this.state;

    subscribe = (l: () => void): (() => void) => {
        this.listeners.add(l);
        return () => {
            this.listeners.delete(l);
        };
    };

    private set(next: ActionState) {
        this.state = next;
        for (const l of this.listeners) l();
    }

    dismiss = (): void => {
        if (this.state.outcome) this.set({ ...this.state, outcome: null });
    };

    /** Report a result that did not come from `run` (a sheet that has
     *  its own busy state, say). */
    report = (key: string, kind: 'ok' | 'fail', message: string, detail?: string): void => {
        this.set({
            ...this.state,
            outcome: { seq: ++this.seq, key, kind, message, detail },
        });
    };

    run = async <T,>(
        key: string,
        fn: () => Promise<T>,
        opts: RunOptions<T>,
    ): Promise<RunResult<T>> => {
        // Synchronous check-and-set: the second tap of a double tap
        // lands here before any render and is dropped.
        if (this.state.busy !== null) return { ran: false, ok: false };
        this.set({ busy: key, outcome: null });
        try {
            const value = await fn();
            const said = typeof opts.ok === 'function' ? opts.ok(value) : opts.ok;
            this.set({
                busy: null,
                outcome: said
                    ? { seq: ++this.seq, key, kind: 'ok', message: said }
                    : null,
            });
            return { ran: true, ok: true, value };
        } catch (e) {
            const why = this.explain(e);
            this.set({
                busy: null,
                outcome: {
                    seq: ++this.seq,
                    key,
                    kind: 'fail',
                    message: `${opts.fail} ${why.message}`,
                    detail: why.detail,
                },
            });
            return { ran: true, ok: false };
        }
    };
}

/** How long a success stays up. Failures stay until dismissed: a person
 *  who looked away must still find out it did not work. */
const OK_VISIBLE_MS = 7000;

export interface Action extends ActionState {
    run: ActionController['run'];
    report: ActionController['report'];
    dismiss: () => void;
}

export function useAction(explain: (e: unknown) => Failure): Action {
    // The explainer closes over `t`, which changes identity with the
    // language; the controller must not be rebuilt (and lose its lock)
    // when it does.
    const explainRef = useRef(explain);
    explainRef.current = explain;
    const ref = useRef<ActionController | null>(null);
    if (!ref.current) {
        ref.current = new ActionController((e) => explainRef.current(e));
    }
    const c = ref.current;
    const state = useSyncExternalStore(c.subscribe, c.getState, c.getState);

    const outcome = state.outcome;
    useEffect(() => {
        if (!outcome || outcome.kind !== 'ok') return;
        const h = window.setTimeout(c.dismiss, OK_VISIBLE_MS);
        return () => window.clearTimeout(h);
    }, [c, outcome]);

    return { ...state, run: c.run, report: c.report, dismiss: c.dismiss };
}

type ButtonProps = Parameters<typeof Button>[0];

/** A button bound to one action key: shows progress while its own
 *  action runs, and is inert while ANY action on the controller runs. */
export function ActionButton({
    action,
    k,
    busyLabel,
    children,
    disabled,
    ...rest
}: Omit<ButtonProps, 'children'> & {
    action: ActionState;
    k: string;
    busyLabel: string;
    children: ReactNode;
}) {
    const mine = action.busy === k;
    return (
        <Button
            {...rest}
            disabled={disabled || action.busy !== null}
            aria-busy={mine || undefined}
        >
            {mine ? busyLabel : children}
        </Button>
    );
}

/** The result, pinned to the bottom of the screen above the tab bar and
 *  above any open sheet. `inset-inline` + inherited direction: it lays
 *  out the same in RTL. */
export function ActionToast({
    t,
    outcome,
    onDismiss,
}: {
    t: (k: string) => string;
    outcome: ActionOutcome | null;
    onDismiss: () => void;
}) {
    if (!outcome) return null;
    // Phone or not, without needing the density provider (a toast may be
    // drawn by a test or a sheet on its own).
    let phone = true;
    try {
        phone = typeof window === 'undefined' || typeof window.matchMedia !== 'function' || window.matchMedia('(max-width: 640px)').matches;
    } catch {
        phone = true;
    }
    const failed = outcome.kind === 'fail';
    return (
        <div
            // `alert` interrupts a screen reader, `status` waits its
            // turn — a failure is worth interrupting for.
            role={failed ? 'alert' : 'status'}
            data-kind={outcome.kind}
            data-toast={failed ? 'bad' : 'good'}
            key={outcome.seq}
            style={{
                position: 'fixed',
                zIndex: 400,
                bottom: phone ? 'calc(72px + env(safe-area-inset-bottom, 0px))' : 24,
                insetInlineStart: phone ? 16 : undefined,
                insetInlineEnd: phone ? 16 : 24,
                maxWidth: phone ? undefined : 420,
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                paddingBlock: 6,
                paddingInlineStart: 14,
                paddingInlineEnd: 4,
                background: 'var(--surface-2)',
                border: `1px solid ${failed ? 'var(--red)' : 'var(--line)'}`,
                borderRadius: 'var(--r-tile)',
                boxShadow: '0 16px 40px rgba(0,0,0,0.4)',
                color: 'var(--fg)',
                textAlign: 'start',
            }}
        >
            <span style={{ display: 'inline-flex', paddingBlockStart: 12 }}>
                <StateIcon state={failed ? 'bad' : 'ok'} size={20} />
            </span>
            <div style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2, paddingBlock: 10 }}>
                <div style={{ fontSize: 14, color: 'var(--fg)', lineHeight: 1.45 }}>{outcome.message}</div>
                {outcome.detail && (
                    <WhatIsThis label={t('pub.fb.details')}>
                        <div
                            dir="ltr"
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 11,
                                color: 'var(--muted)',
                                wordBreak: 'break-word',
                                whiteSpace: 'pre-wrap',
                                maxHeight: 120,
                                overflowY: 'auto',
                                textAlign: 'left',
                            }}
                        >
                            {outcome.detail}
                        </div>
                    </WhatIsThis>
                )}
            </div>
            <IconButton label={t('common.close')} dataButton="toast-close" onClick={onDismiss}>
                <Icon name="close" size={18} />
            </IconButton>
        </div>
    );
}
