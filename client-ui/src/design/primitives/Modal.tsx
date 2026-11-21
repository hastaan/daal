// Modal — centered desktop-style modal. The Sheet primitive picks
// this on tablet/desktop and BottomSheet on phone.

import type { ReactNode } from 'react';
import { useEffect } from 'react';
import { useBack } from '../../lib/useBack';
import { effectiveLocale, translate } from '../../lib/i18n';
import { IconButton } from './IconButton';

interface Props {
    title?: ReactNode;
    children: ReactNode;
    onClose: () => void;
    width?: number;
    footer?: ReactNode;
}

export function Modal({ title, children, onClose, width = 540, footer }: Props) {
    // System Back (and Alt+Left) is the same close as Escape or a tap
    // outside: the cancel path. A sheet whose onClose refuses while busy
    // refuses Back the same way.
    useBack(true, onClose);
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
                background: 'var(--scrim)',
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
                    boxShadow: 'var(--shadow-lg)',
                }}
            >
                {title && (
                    // A visible way out on a computer, beside the title: a
                    // tap outside and Escape are not things everyone knows.
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBlockEnd: 16 }}>
                        <h2
                            style={{
                                margin: 0,
                                paddingBlockStart: 8,
                                flex: 1,
                                minWidth: 0,
                                fontFamily: 'var(--font-display)',
                                fontSize: 20,
                                fontWeight: 500,
                            }}
                        >
                            {title}
                        </h2>
                        <span style={{ marginBlockStart: -6, marginInlineEnd: -10, flexShrink: 0 }}>
                            <IconButton icon="close" label={translate(effectiveLocale(), 'ui.close')} onClick={onClose} dataButton="modal-close" />
                        </span>
                    </div>
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
