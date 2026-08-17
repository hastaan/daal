// icons.tsx — shared icon set, used by TabBar / SidebarRail / SidebarFull
// so all three navigations stay visually consistent.

const ICON_PROPS = {
    viewBox: '0 0 24 24',
    fill: 'none' as const,
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
};

export const ConnectionIcon = (
    <svg {...ICON_PROPS}>
        <path d="M5 12.55a11 11 0 0 1 14 0" />
        <path d="M8.5 16a6 6 0 0 1 7 0" />
        <path d="M2 8.82a15 15 0 0 1 20 0" />
        <circle cx="12" cy="20" r="0.5" fill="currentColor" />
    </svg>
);

export const RoutesIcon = (
    <svg {...ICON_PROPS}>
        <circle cx="6" cy="6" r="2" />
        <circle cx="18" cy="6" r="2" />
        <circle cx="12" cy="18" r="2" />
        <path d="M8 6h8M7 8l4 8M17 8l-4 8" />
    </svg>
);

export const SourcesIcon = (
    <svg {...ICON_PROPS}>
        <path d="M4 5h12a4 4 0 0 1 0 8H8a4 4 0 0 0 0 8h12" />
    </svg>
);

export const StatusIcon = (
    <svg {...ICON_PROPS}>
        <path d="M3 12h4l3-7 4 14 3-7h4" />
    </svg>
);

export const NetworkIcon = (
    <svg {...ICON_PROPS}>
        <path d="M4 8h16M4 12h16M4 16h10" />
        <circle cx="18" cy="16" r="2" fill="currentColor" stroke="none" />
    </svg>
);

export const SettingsIcon = (
    <svg {...ICON_PROPS}>
        <circle cx="12" cy="12" r="3" />
        <path d="M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4.9a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.5a7 7 0 0 0-2 1.2L5.1 5.8l-2 3.4 2 1.6A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.6 2 3.4 2.4-.9a7 7 0 0 0 2 1.2L10 21h4l.5-2.5a7 7 0 0 0 2-1.2l2.4.9 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z" />
    </svg>
);

export const PublisherIcon = (
    <svg {...ICON_PROPS}>
        <path d="M12 2 4 6v6c0 5 3.5 9 8 10 4.5-1 8-5 8-10V6l-8-4z" />
        <path d="M9 12l2 2 4-4" />
    </svg>
);

export type SectionId =
    | 'connection'
    | 'network'
    | 'status'
    | 'settings'
    | 'publisher';

export const SECTION_ICONS: Record<SectionId, JSX.Element> = {
    connection: ConnectionIcon,
    network: NetworkIcon,
    status: StatusIcon,
    settings: SettingsIcon,
    publisher: PublisherIcon,
};
