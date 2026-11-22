// icons.tsx — shared icon set, used by TabBar / SidebarRail / SidebarFull
// so all three navigations stay visually consistent.

import type { CSSProperties } from 'react';

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

// ---- the general icon set --------------------------------------------
//
// Hand-drawn on the same 24-unit grid and stroke as the navigation icons
// above; no icon font, no dependency. `Icon` draws one by name.

const FILLED = { fill: 'currentColor', stroke: 'none' } as const;

const PATHS = {
    check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
    cross: <path d="M6 6l12 12M18 6L6 18" />,
    close: <path d="M7 7l10 10M17 7L7 17" />,
    alert: (
        <>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 7.5v5.5" />
            <circle cx="12" cy="16.6" r="0.6" {...FILLED} />
        </>
    ),
    info: (
        <>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 11v5.5" />
            <circle cx="12" cy="7.6" r="0.6" {...FILLED} />
        </>
    ),
    dot: <circle cx="12" cy="12" r="4" {...FILLED} />,
    more: (
        <>
            <circle cx="5" cy="12" r="1.7" {...FILLED} />
            <circle cx="12" cy="12" r="1.7" {...FILLED} />
            <circle cx="19" cy="12" r="1.7" {...FILLED} />
        </>
    ),
    chevron: <path d="M9.5 6l6 6-6 6" />,
    chevronDown: <path d="M6 9.5l6 6 6-6" />,
    back: <path d="M19 12H5M11 6l-6 6 6 6" />,
    plus: <path d="M12 5v14M5 12h14" />,
    share: (
        <>
            <circle cx="18" cy="5.5" r="2.5" />
            <circle cx="6" cy="12" r="2.5" />
            <circle cx="18" cy="18.5" r="2.5" />
            <path d="M8.3 10.8l7.4-4M8.3 13.2l7.4 4" />
        </>
    ),
    download: <path d="M12 4v11M7 10l5 5 5-5M5 20h14" />,
    qr: (
        <>
            <rect x="4" y="4" width="6" height="6" rx="1" />
            <rect x="14" y="4" width="6" height="6" rx="1" />
            <rect x="4" y="14" width="6" height="6" rx="1" />
            <path d="M14 14h2.5v2.5H14zM17.5 17.5H20V20h-2.5zM14 20h1M20 14v1" />
        </>
    ),
    copy: (
        <>
            <rect x="9" y="9" width="11" height="11" rx="2" />
            <path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3" />
        </>
    ),
    paste: (
        <>
            <rect x="9" y="3" width="6" height="3.5" rx="1" />
            <path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" />
        </>
    ),
    file: (
        <>
            <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
            <path d="M14 3v5h5" />
        </>
    ),
    files: (
        <>
            <path d="M4.5 9A1.5 1.5 0 0 1 6 7.5h6.5l4 4v8A1.5 1.5 0 0 1 15 21H6a1.5 1.5 0 0 1-1.5-1.5z" />
            <path d="M12.5 7.5v4h4" />
            <path d="M8 7.5v-3A1.5 1.5 0 0 1 9.5 3H16l4 4v9.5a1.5 1.5 0 0 1-1.5 1.5h-2" />
        </>
    ),
    camera: (
        <>
            <path d="M4 8.5a2 2 0 0 1 2-2h2L9.5 4h5L16 6.5h2a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z" />
            <circle cx="12" cy="13" r="3.5" />
        </>
    ),
    link: (
        <>
            <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1" />
            <path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />
        </>
    ),
    lock: (
        <>
            <rect x="5" y="11" width="14" height="10" rx="2" />
            <path d="M8 11V8a4 4 0 0 1 8 0v3" />
        </>
    ),
    shield: <path d="M12 3 5 6v5.5c0 4.5 3 8.2 7 9.5 4-1.3 7-5 7-9.5V6z" />,
    shieldAlert: (
        <>
            <path d="M12 3 5 6v5.5c0 4.5 3 8.2 7 9.5 4-1.3 7-5 7-9.5V6z" />
            <path d="M12 8.5v4" />
            <circle cx="12" cy="15.6" r="0.6" {...FILLED} />
        </>
    ),
    trash: <path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4h6v3" />,
    edit: <path d="M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4" />,
    refresh: <path d="M20 11a8 8 0 0 0-14.3-4.9L4 8M4 4v4h4M4 13a8 8 0 0 0 14.3 4.9L20 16M20 20v-4h-4" />,
    wifi: (
        <>
            <path d="M5 12.55a11 11 0 0 1 14 0" />
            <path d="M8.5 16a6 6 0 0 1 7 0" />
            <path d="M2 8.82a15 15 0 0 1 20 0" />
            <circle cx="12" cy="20" r="0.9" {...FILLED} />
        </>
    ),
    wifiOff: (
        <>
            <path d="M5 12.55a11 11 0 0 1 5.2-2.4M14 10.2a11 11 0 0 1 5 2.35" />
            <path d="M8.5 16a6 6 0 0 1 7 0" />
            <path d="M2 8.82a15 15 0 0 1 4.3-2.6M10.7 5.1A15 15 0 0 1 22 8.82" />
            <circle cx="12" cy="20" r="0.9" {...FILLED} />
            <path d="M3 3l18 18" />
        </>
    ),
    server: (
        <>
            <rect x="4" y="4" width="16" height="7" rx="2" />
            <rect x="4" y="13" width="16" height="7" rx="2" />
            <circle cx="8" cy="7.5" r="0.9" {...FILLED} />
            <circle cx="8" cy="16.5" r="0.9" {...FILLED} />
        </>
    ),
    person: (
        <>
            <circle cx="12" cy="8" r="4" />
            <path d="M4.5 21a7.5 7.5 0 0 1 15 0" />
        </>
    ),
    people: (
        <>
            <circle cx="9" cy="8" r="3.5" />
            <path d="M2.5 20a6.5 6.5 0 0 1 13 0" />
            <path d="M15.5 4.6a3.5 3.5 0 0 1 0 6.8" />
            <path d="M18 14.2a6.5 6.5 0 0 1 3.5 5.8" />
        </>
    ),
    key: (
        <>
            <circle cx="8" cy="15" r="4" />
            <path d="M10.9 12.1 20 3M16 7l3 3M18.5 4.5l2 2" />
        </>
    ),
    help: (
        <>
            <circle cx="12" cy="12" r="9" />
            <path d="M9.5 9.5a2.5 2.5 0 1 1 3.4 2.3c-.6.3-.9.8-.9 1.4v.6" />
            <circle cx="12" cy="16.8" r="0.6" {...FILLED} />
        </>
    ),
    sun: (
        <>
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" />
        </>
    ),
    moon: <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" />,
    auto: (
        <>
            <circle cx="12" cy="12" r="8" />
            <path d="M12 4a8 8 0 0 1 0 16z" {...FILLED} />
        </>
    ),
    globe: (
        <>
            <circle cx="12" cy="12" r="9" />
            <path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z" />
        </>
    ),
    clock: (
        <>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 7v5l3 2" />
        </>
    ),
    erase: (
        <>
            <path d="M12 3 5 6v5.5c0 4.5 3 8.2 7 9.5 4-1.3 7-5 7-9.5V6z" />
            <path d="M9.6 9.6l4.8 4.8M14.4 9.6l-4.8 4.8" />
        </>
    ),
    external: <path d="M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />,
    // Mobile data: four rising bars.
    signal: <path d="M5 19v-3M10 19v-6M15 19v-9M20 19V6" />,
    // Speed: a gauge with its needle.
    speed: (
        <>
            <path d="M4.5 17a8.5 8.5 0 1 1 15 0" />
            <path d="M12 13.5l4-4" />
            <circle cx="12" cy="13.5" r="1.2" {...FILLED} />
        </>
    ),
    // Traffic both ways: an arrow down beside an arrow up.
    updown: <path d="M8 4v15M4 15l4 4 4-4M16 20V5M12 9l4-4 4 4" />,
    // A reason: a light bulb (the "why this way" line on Home).
    bulb: (
        <>
            <path d="M9 18h6M10 21h4" />
            <path d="M12 3a6 6 0 0 0-3.6 10.8c.7.6 1.1 1.4 1.1 2.2h5c0-.8.4-1.6 1.1-2.2A6 6 0 0 0 12 3z" />
        </>
    ),
    // A way in: two arrows through a gap.
    route: (
        <>
            <circle cx="6" cy="18" r="2.2" />
            <circle cx="18" cy="6" r="2.2" />
            <path d="M8 18h6.5a3.5 3.5 0 0 0 0-7h-5a3.5 3.5 0 0 1 0-7H16" />
        </>
    ),
} satisfies Record<string, JSX.Element>;

export type IconName = keyof typeof PATHS;

/** Every icon name, in declaration order (tests, galleries). */
export const ICON_NAMES = Object.keys(PATHS) as IconName[];

export function isIconName(v: unknown): v is IconName {
    return typeof v === 'string' && Object.prototype.hasOwnProperty.call(PATHS, v);
}

/** Icons that point along the reading direction: mirrored under RTL. */
export const DIRECTIONAL_ICONS: ReadonlySet<IconName> = new Set<IconName>(['chevron', 'back', 'external']);

interface IconProps {
    name: IconName;
    size?: number;
    /** Gives the icon a name of its own (role="img"); without it the icon is hidden from screen readers. */
    title?: string;
    style?: CSSProperties;
}

/**
 * One icon by name. `chevron`, `back` and `external` come wrapped in
 * `<span class="daal-flip-rtl">`, so they mirror under dir="rtl".
 */
export function Icon({ name, size = 20, title, style }: IconProps): JSX.Element {
    const directional = DIRECTIONAL_ICONS.has(name);
    const svg = (
        <svg
            {...ICON_PROPS}
            width={size}
            height={size}
            aria-hidden={title ? undefined : true}
            role={title ? 'img' : undefined}
            focusable="false"
            style={{ display: 'block', flexShrink: 0, ...(directional ? null : style) }}
        >
            {title ? <title>{title}</title> : null}
            {PATHS[name]}
        </svg>
    );
    if (!directional) return svg;
    return (
        <span className="daal-flip-rtl" style={{ display: 'inline-flex', flexShrink: 0, ...style }}>
            {svg}
        </span>
    );
}

/** The Files tab glyph (two stacked sheets), sized by its container. */
export const FilesIcon = <svg {...ICON_PROPS}>{PATHS.files}</svg>;

export type SectionId =
    | 'connection'
    | 'network'
    | 'status'
    | 'settings'
    | 'publisher';

export const SECTION_ICONS: Record<SectionId, JSX.Element> = {
    connection: ConnectionIcon,
    // The Network tab is "Files" now (spec C3/C4): two stacked sheets.
    network: FilesIcon,
    status: StatusIcon,
    settings: SettingsIcon,
    publisher: PublisherIcon,
};
