// Sidebar.tsx — vertical navigation for the desktop D-2 shell.
// Layout matches client-shared/designs/daal-desktop.html: 240 px wide,
// brand block (Daal flat SVG + serif Daal + version),
// MAIN section (5 nav rows with icons + ⌘1-5 hints),
// ADVANCED section with Publisher (OFF badge),
// sidebar-footer panic-wipe button with shield icon.
// (Glyph removed from sidebar — the brand mark already lives on the
// Connection page and is redundant in a permanent rail on desktop.)

export type SectionId =
    | 'connection'
    | 'network'
    | 'status'
    | 'settings'
    | 'publisher';

interface Props {
    t: (k: string) => string;
    section: SectionId;
    onChange: (s: SectionId) => void;
    publisherEnabled: boolean;
    onPanic: () => void;
    appVersion: string;
}

interface RowSpec {
    id: SectionId;
    key: string;
    shortcut: string;
    icon: JSX.Element;
}

const ICON_PROPS = {
    viewBox: '0 0 24 24',
    fill: 'none' as const,
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
};

const ICON_CONNECTION = (
    <svg {...ICON_PROPS}>
        <path d="M5 12.55a11 11 0 0 1 14 0" />
        <path d="M8.5 16a6 6 0 0 1 7 0" />
        <path d="M2 8.82a15 15 0 0 1 20 0" />
        <circle cx="12" cy="20" r="0.5" fill="currentColor" />
    </svg>
);

const ICON_NETWORK = (
    <svg {...ICON_PROPS}>
        <circle cx="6" cy="6" r="2" />
        <circle cx="18" cy="6" r="2" />
        <circle cx="12" cy="18" r="2" />
        <path d="M8 6h8M7 8l4 8M17 8l-4 8" />
    </svg>
);

const ICON_STATUS = (
    <svg {...ICON_PROPS}>
        <path d="M3 12h4l3-7 4 14 3-7h4" />
    </svg>
);

const ICON_SETTINGS = (
    <svg {...ICON_PROPS}>
        <circle cx="12" cy="12" r="3" />
        <path d="M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4.9a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.5a7 7 0 0 0-2 1.2L5.1 5.8l-2 3.4 2 1.6A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-.9a7 7 0 0 0 2 1.2L10 21h4l.5-2.5a7 7 0 0 0 2-1.2l2.4.9 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z" />
    </svg>
);

const ICON_PUBLISHER = (
    <svg {...ICON_PROPS}>
        <path d="M12 2 4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6l-8-4z" />
        <path d="M9 12l2 2 4-4" />
    </svg>
);

const ICON_PANIC = (
    <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.8}
        strokeLinecap="round"
        strokeLinejoin="round"
        width={14}
        height={14}
        aria-hidden
    >
        <path d="M12 2 4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6l-8-4z" />
        <path d="M12 8v5" />
        <circle cx="12" cy="16" r="0.6" fill="currentColor" />
    </svg>
);

const MAIN_ROWS: RowSpec[] = [
    { id: 'connection', key: 'nav.connection', shortcut: '⌘1', icon: ICON_CONNECTION },
    { id: 'network', key: 'nav.network', shortcut: '⌘2', icon: ICON_NETWORK },
    { id: 'status', key: 'nav.status', shortcut: '⌘3', icon: ICON_STATUS },
    { id: 'settings', key: 'nav.settings', shortcut: '⌘4', icon: ICON_SETTINGS },
];

export function Sidebar({
    t,
    section,
    onChange,
    publisherEnabled,
    onPanic,
    appVersion,
}: Props) {
    return (
        <aside
            style={{
                background:
                    'linear-gradient(180deg, #042F3F 0%, #032834 100%)',
                borderInlineEnd: '1px solid var(--teal-hairline)',
                display: 'flex',
                flexDirection: 'column',
                padding: '20px 0',
                minHeight: 0,
            }}
        >
            <BrandBlock t={t} appVersion={appVersion} />

            <SectionLabel>{t('nav.section.main')}</SectionLabel>
            {MAIN_ROWS.map((r) => (
                <NavRow
                    key={r.id}
                    active={section === r.id}
                    onClick={() => onChange(r.id)}
                    label={t(r.key)}
                    shortcut={r.shortcut}
                    icon={r.icon}
                />
            ))}

            <SectionLabel>{t('nav.section.advanced')}</SectionLabel>
            <NavRow
                active={section === 'publisher'}
                dim={!publisherEnabled}
                onClick={() => publisherEnabled && onChange('publisher')}
                label={t('nav.publisher')}
                badge={!publisherEnabled ? t('badge_off') : undefined}
                icon={ICON_PUBLISHER}
            />

            <div
                style={{
                    marginTop: 'auto',
                    padding: '16px 20px',
                    borderBlockStart: '1px solid var(--teal-hairline)',
                }}
            >
                <button
                    onClick={onPanic}
                    aria-label={t('settings.panic_wipe')}
                    style={{
                        width: '100%',
                        background: 'transparent',
                        border: '1px solid rgba(200,85,61,0.4)',
                        color: '#E07A66',
                        borderRadius: 'var(--radius-md)',
                        padding: '10px 12px',
                        fontFamily: 'var(--font-body)',
                        fontSize: 12,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 8,
                        letterSpacing: '0.02em',
                    }}
                >
                    {ICON_PANIC}
                    {t('settings.panic_wipe')}
                </button>
            </div>
        </aside>
    );
}

function BrandBlock({
    t,
    appVersion,
}: {
    t: (k: string) => string;
    appVersion: string;
}) {
    // Sidebar header on desktop — pure text. The eagle glyph and the
    // separator/box framing were removed: the brand mark already lives
    // on the Connection page, and a bordered placeholder on every
    // desktop screen reads as a stray empty box.
    return (
        <div
            style={{
                display: 'flex',
                flexDirection: 'column',
                lineHeight: 1.2,
                padding: '0 20px 18px',
                minWidth: 0,
            }}
        >
            <span
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 17,
                    color: 'var(--paper)',
                    letterSpacing: '0.01em',
                }}
            >
                {t('app.title')}
            </span>
            <span
                style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    textTransform: 'uppercase',
                    letterSpacing: '0.16em',
                    color: 'var(--ink-mute)',
                }}
            >
                v{appVersion}
            </span>
        </div>
    );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                textTransform: 'uppercase',
                letterSpacing: '0.16em',
                color: 'var(--ink-mute)',
                padding: '14px 20px 8px',
            }}
        >
            {children}
        </div>
    );
}

function NavRow({
    active,
    dim,
    onClick,
    label,
    shortcut,
    badge,
    icon,
}: {
    active: boolean;
    dim?: boolean;
    onClick: () => void;
    label: string;
    shortcut?: string;
    badge?: string;
    icon: JSX.Element;
}) {
    return (
        <button
            onClick={onClick}
            disabled={dim}
            type="button"
            style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                padding: '10px 20px',
                color: dim
                    ? 'var(--ink-mute)'
                    : active
                        ? 'var(--paper)'
                        : 'var(--paper-dim)',
                fontSize: 14,
                background: active ? 'rgba(201,162,58,0.08)' : 'transparent',
                borderInlineStart: `2px solid ${
                    active ? 'var(--gold)' : 'transparent'
                }`,
                borderTop: 0,
                borderInlineEnd: 0,
                borderBottom: 0,
                cursor: dim ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-body)',
                textAlign: 'start',
                transition: 'background 120ms, color 120ms',
            }}
        >
            <span
                style={{
                    width: 18,
                    height: 18,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'currentColor',
                    flexShrink: 0,
                }}
                aria-hidden
            >
                {icon}
            </span>
            <span style={{ flex: 1 }}>{label}</span>
            {badge && (
                <span
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 9,
                        textTransform: 'uppercase',
                        letterSpacing: '0.14em',
                        background: 'var(--teal-border)',
                        color: 'var(--paper-dim)',
                        padding: '2px 6px',
                        borderRadius: 3,
                    }}
                >
                    {badge}
                </span>
            )}
            {shortcut && !badge && (
                <span
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        color: 'var(--ink-mute)',
                        letterSpacing: '0.06em',
                    }}
                    aria-hidden
                >
                    {shortcut}
                </span>
            )}
        </button>
    );
}
