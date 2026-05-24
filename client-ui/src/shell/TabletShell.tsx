// TabletShell.tsx — mid-size host (641–1023px).
//
// Phase 1 stub: icon-only side rail + main content. Phase 5 fleshes
// out the actual screens; for now it reuses the same legacy pages.

import { useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import ConnectionPage from '../d2pages/ConnectionPage';
import RoutesPage from '../d2pages/RoutesPage';
import SourcesPage from '../d2pages/SourcesPage';
import StatusPage from '../d2pages/StatusPage';
import SettingsPage from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';

type Section =
    | 'connection'
    | 'routes'
    | 'sources'
    | 'status'
    | 'publisher'
    | 'settings';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

// Static list of rail entries. Publisher gets injected at render time
// so the icon only appears once the user opts in via Settings.
const BASE_ITEMS: Array<{ id: Section; key: string; glyph: string }> = [
    { id: 'connection', key: 'nav.connection', glyph: '⟿' },
    { id: 'routes', key: 'nav.routes', glyph: '⌘' },
    { id: 'sources', key: 'nav.subs', glyph: '∾' },
    { id: 'status', key: 'nav.status', glyph: '∼' },
    { id: 'settings', key: 'nav.settings', glyph: '⚙' },
];

export default function TabletShell(props: Props) {
    const [section, setSection] = useState<Section>('connection');
    const [publisherEnabled, setPublisherEnabled] = useState(
        Prefs.publisherEnabled(),
    );
    const { t, locale, onLocaleChange, appVersion } = props;

    // Insert Publisher between Status and Settings so the tab order
    // matches the desktop sidebar (ADVANCED group). The glyph reuses
    // the "share" arrow used elsewhere in the design.
    const items = publisherEnabled
        ? [
              ...BASE_ITEMS.slice(0, 4),
              { id: 'publisher' as Section, key: 'nav.publisher', glyph: '⤴' },
              BASE_ITEMS[4],
          ]
        : BASE_ITEMS;

    return (
        <div
            style={{
                height: '100%',
                display: 'grid',
                gridTemplateColumns: '72px 1fr',
                background: 'var(--bg)',
                color: 'var(--fg)',
            }}
        >
            <aside
                style={{
                    background: 'var(--bg-deep)',
                    borderInlineEnd: '1px solid var(--line-soft)',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    padding: '14px 0',
                    gap: 4,
                }}
            >
                <div
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 22,
                        fontWeight: 600,
                        color: 'var(--gold-warm)',
                        marginBottom: 16,
                    }}
                >
                    د
                </div>
                {items.map((it) => {
                    const active = section === it.id;
                    return (
                        <button
                            key={it.id}
                            title={t(it.key)}
                            onClick={() => setSection(it.id)}
                            style={{
                                background: active
                                    ? 'rgba(201,162,58,0.10)'
                                    : 'transparent',
                                border: 0,
                                color: active
                                    ? 'var(--gold-warm)'
                                    : 'var(--dim)',
                                width: 48,
                                height: 48,
                                borderRadius: 12,
                                fontSize: 20,
                                cursor: 'pointer',
                            }}
                        >
                            {it.glyph}
                        </button>
                    );
                })}
            </aside>
            <main
                style={{
                    minWidth: 0,
                    minHeight: 0,
                    overflow: 'auto',
                    padding: 'var(--gutter)',
                }}
            >
                {section === 'connection' && (
                    <ConnectionPage t={t} onNavigate={() => {}} />
                )}
                {section === 'routes' && <RoutesPage t={t} />}
                {section === 'sources' && <SourcesPage t={t} />}
                {section === 'status' && <StatusPage t={t} />}
                {section === 'settings' && (
                    <SettingsPage
                        t={t}
                        locale={locale}
                        appVersion={appVersion}
                        onLocaleChange={onLocaleChange}
                        publisherEnabled={publisherEnabled}
                        onPublisherEnabledChange={(v) => {
                            Prefs.setPublisherEnabled(v);
                            setPublisherEnabled(v);
                            // Toggle only reachable from Settings; no
                            // section-bounce needed here.
                        }}
                    />
                )}
                {section === 'publisher' && publisherEnabled && (
                    <PublisherPage t={t} />
                )}
            </main>
        </div>
    );
}
