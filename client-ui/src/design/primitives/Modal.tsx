// Modal — centered desktop-style modal. The Sheet primitive picks
// this on tablet/desktop and BottomSheet on phone.

import type { ReactNode } from 'react';
import { useEffect } from 'react';

interface Props {
    title?: ReactNode;
    children: ReactNode;
    onClose: () => void;
    width?: number;
    footer?: ReactNode;
}

export function Modal({ title, children, onClose, width = 540, footer }: Props) {
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
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 200,
                padding: 16,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    width: '100%',
                    maxWidth: width,
                    maxHeight: '90vh',
                    overflow: 'auto',
                    background: 'var(--surface)',
                    border: '1px solid var(--line)',
                    borderRadius: 'var(--r-card)',
                    padding: 22,
                    color: 'var(--fg)',
                    boxShadow: '0 30px 60px rgba(0,0,0,0.45)',
                }}
            >
                {title && (
                    <h2
                        style={{
                            marginTop: 0,
                            fontFamily: 'var(--font-display)',
                            fontSize: 20,
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
                            marginTop: 16,
                            display: 'flex',
                            justifyContent: 'flex-end',
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
