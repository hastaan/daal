// MobileShell.tsx — phone form-factor host (≤640px).
//
// Phase 1 stub: renders the legacy D2Shell content inside a phone-style
// frame with a bottom tab bar so a resized browser instantly shows
// "we know we're in mobile mode now". Phase 5 replaces the body with
// proper screens.

import { useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import ConnectionPage from '../d2pages/ConnectionPage';
import RoutesPage from '../d2pages/RoutesPage';
import SourcesPage from '../d2pages/SourcesPage';
import StatusPage from '../d2pages/StatusPage';
import SettingsPage from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';
import {
    Segmented,
    TabBar,
    ConnectionIcon,
    NetworkIcon,
    SettingsIcon,
    PublisherIcon,
} from '../design/primitives';

type Section = 'connection' | 'network' | 'publisher' | 'settings';
type NetworkTab = 'routes' | 'sources';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

export default function MobileShell(props: Props) {
    const [section, setSection] = useState<Section>('connection');
    const [networkTab, setNetworkTab] = useState<NetworkTab>('routes');
    const [showDiagnostics, setShowDiagnostics] = useState(false);
    // Publisher is hidden behind a Settings → "I am a publisher" toggle
    // (matches desktop), so the tab only appears once the user opts in.
    // Persisted in localStorage via Prefs so the choice survives
    // restarts (and matches what DesktopShell does).
    const [publisherEnabled, setPublisherEnabled] = useState(
        Prefs.publisherEnabled(),
    );
    const { t, locale, onLocaleChange, appVersion } = props;

    return (
        <div
            style={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                background: 'var(--bg)',
                color: 'var(--fg)',
            }}
        >
            <main
                style={{
                    flex: 1,
                    minHeight: 0,
                    overflow: 'auto',
                    // Respect the device's notch + status-bar inset at the
                    // top, and add bottom inset so a long scroll never
                    // hides its last row behind the TabBar (which already
                    // owns env(safe-area-inset-bottom) for the gesture
                    // indicator). The 12px base padding is preserved.
                    paddingInline: 'var(--gutter)',
                    paddingBlockStart:
                        'calc(env(safe-area-inset-top, 0px) + 12px)',
                    paddingBlockEnd: '12px',
                }}
            >
                {section === 'connection' && (
                    <ConnectionPage t={t} onNavigate={() => {}} />
                )}
                {section === 'network' && (
                    <div>
                        <div
                            style={{
                                display: 'flex',
                                justifyContent: 'center',
                                padding: '8px 0 4px',
                            }}
                        >
                            <Segmented
                                value={networkTab}
                                onChange={setNetworkTab}
                                items={[
                                    {
                                        value: 'routes',
                                        label: t('network.tab.routes'),
                                    },
                                    {
                                        value: 'sources',
                                        label: t('network.tab.sources'),
                                    },
                                ]}
                            />
                        </div>
                        {networkTab === 'routes' && <RoutesPage t={t} />}
                        {networkTab === 'sources' && <SourcesPage t={t} />}
                    </div>
                )}
                {section === 'settings' &&
                    (showDiagnostics ? (
                        <div>
                            <div
                                style={{
                                    padding: '8px var(--gutter)',
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: 10,
                                }}
                            >
                                <button
                                    onClick={() => setShowDiagnostics(false)}
                                    style={{
                                        background: 'transparent',
                                        border: 0,
                                        color: 'var(--gold-warm)',
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 12,
                                        cursor: 'pointer',
                                    }}
                                    aria-label="Back"
                                >
                                    ‹ {t('nav.settings')}
                                </button>
                            </div>
                            <StatusPage t={t} />
                        </div>
                    ) : (
                        <SettingsPage
                            t={t}
                            locale={locale}
                            appVersion={appVersion}
                            onLocaleChange={onLocaleChange}
                            publisherEnabled={publisherEnabled}
                            onPublisherEnabledChange={(v) => {
                                Prefs.setPublisherEnabled(v);
                                setPublisherEnabled(v);
                                // The toggle is only reachable from the
                                // Settings tab, so we don't need a
                                // section-bounce here — the desktop
                                // shell has the same observation.
                            }}
                            onOpenDiagnostics={() =>
                                setShowDiagnostics(true)
                            }
                        />
                    ))}
                {section === 'publisher' && publisherEnabled && (
                    <PublisherPage t={t} />
                )}
            </main>

            <TabBar<Section>
                active={section}
                onChange={setSection}
                items={[
                    {
                        id: 'connection',
                        label: t('nav.connection'),
                        icon: ConnectionIcon,
                    },
                    {
                        id: 'network',
                        label: t('nav.network'),
                        icon: NetworkIcon,
                    },
                    // Publisher tab only appears when the user has opted
                    // in via Settings → "I am a publisher". This keeps
                    // the default 3-tab layout clean for the >95% of
                    // users who are consumers, not publishers.
                    ...(publisherEnabled
                        ? [
                              {
                                  id: 'publisher' as Section,
                                  label: t('nav.publisher'),
                                  icon: PublisherIcon,
                              },
                          ]
                        : []),
                    {
                        id: 'settings',
                        label: t('nav.settings'),
                        icon: SettingsIcon,
                    },
                ]}
            />
        </div>
    );
}
