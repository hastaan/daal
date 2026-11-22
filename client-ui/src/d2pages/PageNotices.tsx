// PageNotices.tsx — the notices the recipient pages share (spec C2: one
// notice at most, each one bordered row: a state icon, one line, its
// action; anything longer behind "Details").
//
//   FailureBox        a plain sentence of ours, an optional Try again,
//                     and the raw error text folded away under Details
//                     (never the sentence the person reads). Also used by
//                     the Publisher and Status pages: its props stay.
//   StoreResetNotice  said once: Daal had to reset its saved files.
//   EngineStartNotice Daal could not start: nothing on the page can work,
//                     and "Try again" would be a promise it cannot keep.
//   NoticeRow         the shape all of them share, for the page's own
//                     notices ("this build cannot carry traffic", a
//                     refused connect).
import type { CSSProperties, ReactNode } from 'react';
import { Button, Disclosure, StateIcon } from '../design/primitives';
import { mix } from '../design/mix';

type T = (k: string) => string;

const TONE: Record<'bad' | 'warn', string> = { bad: 'var(--red)', warn: 'var(--amber)' };

function boxStyle(tone: 'bad' | 'warn'): CSSProperties {
    return {
        inlineSize: '100%',
        maxWidth: 'var(--content-max)',
        background: mix(TONE[tone], 8, 'transparent'),
        border: `1px solid ${mix(TONE[tone], 40, 'transparent')}`,
        color: 'var(--fg)',
        padding: '10px 12px',
        borderRadius: 'var(--r-tile)',
        marginBlockEnd: 16,
        fontSize: 14,
        textAlign: 'start',
    };
}

/** One bordered row: icon, one line, its action; `more` folds away. */
export function NoticeRow({
    t,
    tone = 'bad',
    text,
    action,
    more,
    detail,
    dataTestId,
}: {
    t: T;
    tone?: 'bad' | 'warn';
    /** Already translated: the one line. */
    text: ReactNode;
    action?: ReactNode;
    /** More words, behind Details. */
    more?: ReactNode;
    /** Raw error text (left-to-right, mono), behind Details. */
    detail?: string;
    dataTestId?: string;
}) {
    return (
        <div role="alert" data-testid={dataTestId} style={boxStyle(tone)}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <StateIcon state={tone} size={20} />
                <span style={{ flex: 1, minWidth: 160 }}>{text}</span>
                {action}
            </div>
            {(more || detail) && (
                <div style={{ marginBlockStart: 2, marginInlineStart: 26 }}>
                    <Disclosure summary={t('ui.details')} dataButton="notice-details">
                        <div style={{ color: 'var(--muted)', fontSize: 13 }}>
                            {more && <div style={{ marginBlockEnd: detail ? 6 : 0 }}>{more}</div>}
                            {detail && (
                                <code
                                    dir="ltr"
                                    style={{
                                        display: 'block',
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 11,
                                        whiteSpace: 'pre-wrap',
                                        overflowWrap: 'anywhere',
                                        textAlign: 'start',
                                        unicodeBidi: 'isolate',
                                    }}
                                >
                                    {detail}
                                </code>
                            )}
                        </div>
                    </Disclosure>
                </div>
            )}
        </div>
    );
}

export function FailureBox({
    t,
    text,
    detail,
    onRetry,
}: {
    t: T;
    /** Already translated. */
    text: string;
    /** Raw error text (lib/errorText.ts), or nothing. */
    detail?: string;
    onRetry?: () => void;
}) {
    return (
        <NoticeRow
            t={t}
            text={text}
            detail={detail}
            action={
                onRetry && (
                    <Button size="sm" variant="secondary" onClick={onRetry} dataButton="notice-retry">
                        {t('network.try_again')}
                    </Button>
                )
            }
        />
    );
}

export function StoreResetNotice({ t, onDismiss }: { t: T; onDismiss: () => void }) {
    return (
        <NoticeRow
            t={t}
            tone="warn"
            text={t('store.reset.title')}
            more={t('store.reset.body')}
            action={
                <Button size="sm" variant="secondary" onClick={onDismiss} dataButton="store-reset-ok">
                    {t('store.reset.dismiss')}
                </Button>
            }
        />
    );
}

export function EngineStartNotice({ t, detail }: { t: T; detail?: string }) {
    // The what-to-do sentence is the notice's action (there is no button
    // that could help), so it stays on the surface; the reason folds away.
    return (
        <NoticeRow
            t={t}
            text={
                <>
                    <strong style={{ display: 'block', fontWeight: 600 }}>{t('engine.start_failed.title')}</strong>
                    <span style={{ display: 'block', color: 'var(--muted)', fontSize: 13 }}>
                        {t('engine.start_failed.body')}
                    </span>
                </>
            }
            detail={detail}
        />
    );
}
