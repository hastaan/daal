// BottomSheet — slide-up sheet for the phone form factor.

import type { ReactNode } from 'react';
import { useEffect } from 'react';

interface Props {
    title?: ReactNode;
    children: ReactNode;
    onClose: () => void;
    footer?: ReactNode;
}

export function BottomSheet({ title, children, onClose, footer }: Props) {
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose();
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [onClose]);

    return (
        <div
            role="dialog"
            aria-modal="true"
            onClick={onClose}
            style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0,0,0,0.55)',
                display: 'flex',
                alignItems: 'flex-end',
                justifyContent: 'center',
                zIndex: 200,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    width: '100%',
                    maxHeight: '92vh',
                    overflow: 'auto',
                    background: 'var(--surface)',
                    borderTop: '1px solid var(--line)',
                    borderTopLeftRadius: 'var(--r-card)',
                    borderTopRightRadius: 'var(--r-card)',
                    padding: '14px 16px max(16px, env(safe-area-inset-bottom))',
                    color: 'var(--fg)',
                }}
            >
                <div
                    aria-hidden
                    style={{
                        width: 36,
                        height: 4,
                        borderRadius: 2,
                        background: 'var(--line)',
                        margin: '0 auto 12px',
                    }}
                />
                {title && (
                    <h2
                        style={{
                            marginTop: 0,
                            fontFamily: 'var(--font-display)',
                            fontSize: 18,
                            fontWeight: 500,
                        }}
                    >
                        {title}
                    </h2>
                )}
                {children}
                {footer && (
                    <div
                        style={{
                            marginTop: 14,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 8,
                        }}
                    >
                        {footer}
                    </div>
                )}
            </div>
        </div>
    );
}
