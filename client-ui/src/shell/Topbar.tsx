// Topbar.tsx — breadcrumb + ⌘K search hint.
// Visual contract from client-shared/designs/daal-desktop.html .topbar.
// EN/FA toggle moved to Settings (locked spec); intentionally omitted here.

import type { SectionId } from './Sidebar';

interface Props {
    t: (k: string) => string;
    section: SectionId;
    engineHealthy: boolean;
    onSearchClick?: () => void;
}

const SECTION_KEY: Record<SectionId, string> = {
    connection: 'nav.connection',
    network: 'nav.network',
    status: 'nav.status',
    settings: 'nav.settings',
    publisher: 'nav.publisher',
};

export default function Topbar({
    t,
    section,
    engineHealthy,
    onSearchClick,
}: Props) {
    return (
        <div>
            <div
                style={{
                    height: 56,
                    flex: '0 0 56px',
                    borderBlockEnd: '1px solid var(--teal-hairline)',
                    padding: '0 28px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 14,
                }}
            >
                <span
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 18,
                        color: 'var(--paper)',
                        letterSpacing: '0.005em',
                    }}
                >
                    {t('app.title')}
                </span>
                <span
                    style={{
                        color: 'var(--ink-mute)',
                        margin: '0 8px',
                        fontSize: 14,
                    }}
                    aria-hidden
                >
                    /
                </span>
                <span
                    style={{
                        fontFamily: 'var(--font-body)',
                        color: 'var(--paper-dim)',
                        fontSize: 14,
                    }}
                >
                    {t(SECTION_KEY[section])}
                </span>
                <div style={{ flex: 1 }} />
                <button
                    type="button"
                    onClick={onSearchClick}
                    style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        background: 'rgba(255,255,255,0.04)',
                        border: '1px solid var(--teal-hairline)',
                        borderRadius: 'var(--radius-md)',
                        padding: '6px 12px',
                        color: 'var(--ink-soft)',
                        fontSize: 12,
                        width: 220,
                        cursor: 'pointer',
                        fontFamily: 'var(--font-body)',
                        textAlign: 'start',
                    }}
                    aria-label={t('search_placeholder')}
                >
                    <svg
                        width="13"
                        height="13"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden
                    >
                        <circle cx="11" cy="11" r="7" />
                        <path d="m21 21-4.3-4.3" />
                    </svg>
                    <span style={{ flex: 1, color: 'var(--ink-soft)' }}>
                        {t('search_placeholder')}
                    </span>
                    <span
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            background: 'rgba(255,255,255,0.06)',
                            color: 'var(--paper-dim)',
                            padding: '1px 5px',
                            borderRadius: 3,
                            border: '1px solid var(--teal-hairline)',
                        }}
                    >
                        ⌘K
                    </span>
                </button>
            </div>
            {!engineHealthy && (
                <div
                    style={{
                        background: 'rgba(224,169,59,0.10)',
                        borderBlockEnd: '1px solid var(--teal-hairline)',
                        color: 'var(--warn)',
                        padding: '6px 28px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 12,
                        letterSpacing: '0.04em',
                    }}
                    role="status"
                >
                    {t('engine.heartbeat_lost')}
                </div>
            )}
        </div>
    );
}
