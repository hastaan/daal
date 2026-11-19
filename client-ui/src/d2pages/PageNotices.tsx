// PageNotices.tsx — the two boxes the recipient pages share.
//
//   FailureBox       a plain sentence of ours, an optional Try again
//                    button, and the raw error text folded away under
//                    "Details" (never the sentence the person reads).
//   StoreResetNotice said once: Daal had to reset its saved connections.
//   EngineStartNotice Daal could not start: nothing on the page can work,
//                    and "Try again" would be a promise it cannot keep.
import type { CSSProperties } from 'react';
import { Button } from '../design/primitives';

type T = (k: string) => string;

const box: CSSProperties = {
    background: 'rgba(200,85,61,0.10)',
    border: '1px solid rgba(200,85,61,0.40)',
    color: 'var(--red)',
    padding: 12,
    borderRadius: 'var(--radius-md)',
    marginBottom: 16,
    fontSize: 13,
};

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
        <div role="alert" style={box}>
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    flexWrap: 'wrap',
                }}
            >
                <span style={{ flex: 1, minWidth: 180 }}>{text}</span>
                {onRetry && (
                    <Button size="sm" variant="secondary" onClick={onRetry}>
                        {t('network.try_again')}
                    </Button>
                )}
            </div>
            {detail && (
                <details style={{ marginTop: 8, color: 'var(--muted)', fontSize: 11 }}>
                    <summary style={{ cursor: 'pointer' }}>
                        {t('network.error_details')}
                    </summary>
                    <code
                        dir="ltr"
                        style={{
                            display: 'block',
                            marginTop: 4,
                            fontFamily: 'var(--font-mono)',
                            whiteSpace: 'pre-wrap',
                            overflowWrap: 'anywhere',
                            textAlign: 'left',
                        }}
                    >
                        {detail}
                    </code>
                </details>
            )}
        </div>
    );
}

export function StoreResetNotice({ t, onDismiss }: { t: T; onDismiss: () => void }) {
    return (
        <div
            role="alert"
            style={{
                background: 'rgba(193,158,80,0.10)',
                border: '1px solid rgba(193,158,80,0.40)',
                color: 'var(--fg)',
                padding: 12,
                borderRadius: 'var(--radius-md)',
                marginBottom: 16,
                fontSize: 13,
                maxWidth: 640,
                textAlign: 'start',
            }}
        >
            <strong style={{ display: 'block', marginBottom: 6 }}>
                {t('store.reset.title')}
            </strong>
            <span style={{ display: 'block', marginBottom: 10, opacity: 0.9 }}>
                {t('store.reset.body')}
            </span>
            <Button size="sm" variant="secondary" onClick={onDismiss}>
                {t('store.reset.dismiss')}
            </Button>
        </div>
    );
}

export function EngineStartNotice({ t, detail }: { t: T; detail?: string }) {
    return (
        <div role="alert" style={{ ...box, color: 'var(--fg)', textAlign: 'start' }}>
            <strong style={{ display: 'block', marginBottom: 6, color: 'var(--red)' }}>
                {t('engine.start_failed.title')}
            </strong>
            <span style={{ display: 'block', opacity: 0.9 }}>{t('engine.start_failed.body')}</span>
            {detail && (
                <details style={{ marginTop: 8, color: 'var(--muted)', fontSize: 11 }}>
                    <summary style={{ cursor: 'pointer' }}>{t('network.error_details')}</summary>
                    <code
                        dir="ltr"
                        style={{
                            display: 'block',
                            marginTop: 4,
                            fontFamily: 'var(--font-mono)',
                            whiteSpace: 'pre-wrap',
                            overflowWrap: 'anywhere',
                            textAlign: 'left',
                        }}
                    >
                        {detail}
                    </code>
                </details>
            )}
        </div>
    );
}
