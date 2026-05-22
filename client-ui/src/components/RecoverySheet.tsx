// RecoverySheet.tsx — connection-failure recovery sheet (D-2 §5C).
// Centered modal on desktop with four explicit options.

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    onTryOther: () => void;
    onRefreshSources: () => void;
    onLifeline: () => void;
    onExportDiag: () => void;
}

export default function RecoverySheet({
    t,
    onClose,
    onTryOther,
    onRefreshSources,
    onLifeline,
    onExportDiag,
}: Props) {
    return (
        <div
            role="dialog"
            aria-modal="true"
            aria-label={t('conn.recovery.title')}
            style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0,0,0,0.6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 100,
            }}
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: 'var(--teal-surface)',
                    border: '1px solid var(--teal-border)',
                    borderRadius: 'var(--radius-lg)',
                    padding: 32,
                    minWidth: 480,
                    maxWidth: 560,
                    boxShadow: '0 30px 60px rgba(0,0,0,0.45)',
                }}
            >
                <h2
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 22,
                        color: 'var(--paper)',
                        margin: 0,
                        marginBottom: 8,
                    }}
                >
                    {t('conn.recovery.title')}
                </h2>
                <p
                    style={{
                        color: 'var(--paper-dim)',
                        fontSize: 14,
                        margin: 0,
                        marginBottom: 20,
                    }}
                >
                    {t('common.error.try_again')}
                </p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <RecoveryButton onClick={onTryOther}>
                        {t('conn.recovery.try_other')}
                    </RecoveryButton>
                    <RecoveryButton onClick={onRefreshSources}>
                        {t('conn.recovery.refresh_sources')}
                    </RecoveryButton>
                    <RecoveryButton onClick={onLifeline}>
                        {t('conn.recovery.lifeline')}
                    </RecoveryButton>
                    <RecoveryButton onClick={onExportDiag}>
                        {t('conn.recovery.export_diag')}
                    </RecoveryButton>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 18 }}>
                    <button
                        onClick={onClose}
                        style={{
                            background: 'transparent',
                            border: 0,
                            color: 'var(--ink-soft)',
                            cursor: 'pointer',
                            fontFamily: 'var(--font-body)',
                            fontSize: 13,
                        }}
                    >
                        {t('common.cancel')}
                    </button>
                </div>
            </div>
        </div>
    );
}

function RecoveryButton({
    onClick,
    children,
}: {
    onClick: () => void;
    children: React.ReactNode;
}) {
    return (
        <button
            onClick={onClick}
            style={{
                width: '100%',
                background: 'var(--teal-raised)',
                border: '1px solid var(--teal-border)',
                color: 'var(--paper)',
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                cursor: 'pointer',
                textAlign: 'start',
            }}
        >
            {children}
        </button>
    );
}
