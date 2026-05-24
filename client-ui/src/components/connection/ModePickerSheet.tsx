// ModePickerSheet — modal sheet with the 4 connection modes,
// matching the dark-theme d2 design surface. Selecting a mode
// dispatches setMode() and closes the sheet.
import type { ConnMode } from '../../contract/D2Contract';

interface Props {
    t: (k: string) => string;
    current: ConnMode;
    onPick: (m: ConnMode) => void;
    onClose: () => void;
}

const ORDER: ConnMode[] = ['lifeline', 'lifeline-strict', 'normal', 'bulk'];

const LABEL_KEY: Record<ConnMode, string> = {
    'lifeline': 'mode_lifeline',
    'lifeline-strict': 'mode_lifeline_strict',
    'normal': 'mode_normal',
    'bulk': 'mode_bulk',
};

const DESC_KEY: Record<ConnMode, string> = {
    'lifeline': 'mode_picker_lifeline_desc',
    'lifeline-strict': 'mode_picker_lifeline_strict_desc',
    'normal': 'mode_picker_normal_desc',
    'bulk': 'mode_picker_bulk_desc',
};

export default function ModePickerSheet({
    t,
    current,
    onPick,
    onClose,
}: Props) {
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
                zIndex: 50,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: 'var(--teal-deep)',
                    border: '1px solid var(--teal-border)',
                    borderRadius: 14,
                    width: 480,
                    maxWidth: 'calc(100vw - 32px)',
                    maxHeight: 'calc(100vh - 64px)',
                    overflow: 'auto',
                    boxShadow: '0 24px 48px rgba(0,0,0,0.5)',
                }}
            >
                <div
                    style={{
                        padding: '18px 22px 6px',
                        borderBlockEnd: '1px solid var(--teal-hairline)',
                    }}
                >
                    <h3
                        style={{
                            fontFamily: 'var(--font-display)',
                            fontSize: 18,
                            color: 'var(--paper)',
                            margin: 0,
                        }}
                    >
                        {t('mode_picker_title')}
                    </h3>
                </div>
                <div style={{ padding: '8px 0' }}>
                    {ORDER.map((m) => {
                        const isActive = m === current;
                        return (
                            <button
                                key={m}
                                type="button"
                                onClick={() => {
                                    onPick(m);
                                    onClose();
                                }}
                                style={{
                                    width: '100%',
                                    background: isActive
                                        ? 'rgba(201,162,58,0.08)'
                                        : 'transparent',
                                    borderTop: 0,
                                    borderInlineEnd: 0,
                                    borderBottom: 0,
                                    borderInlineStart: `2px solid ${
                                        isActive ? 'var(--gold)' : 'transparent'
                                    }`,
                                    padding: '12px 22px',
                                    textAlign: 'start',
                                    color: 'var(--paper-dim)',
                                    cursor: 'pointer',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 4,
                                }}
                            >
                                <span
                                    style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 13,
                                        color: 'var(--paper)',
                                        letterSpacing: '0.04em',
                                    }}
                                >
                                    {t(LABEL_KEY[m])}
                                </span>
                                <span
                                    style={{
                                        fontFamily: 'var(--font-body)',
                                        fontSize: 12,
                                        color: 'var(--ink-soft)',
                                    }}
                                >
                                    {t(DESC_KEY[m])}
                                </span>
                            </button>
                        );
                    })}
                </div>
                <div
                    style={{
                        padding: '12px 22px 18px',
                        display: 'flex',
                        justifyContent: 'flex-end',
                        borderBlockStart: '1px solid var(--teal-hairline)',
                    }}
                >
                    <button
                        type="button"
                        onClick={onClose}
                        style={{
                            background: 'transparent',
                            border: '1px solid var(--teal-border)',
                            color: 'var(--paper-dim)',
                            padding: '8px 14px',
                            borderRadius: 8,
                            fontFamily: 'var(--font-body)',
                            fontSize: 12,
                            cursor: 'pointer',
                        }}
                    >
                        {t('common.cancel')}
                    </button>
                </div>
            </div>
        </div>
    );
}
