// MobileShell.tsx — the phone host (≤640 px), spec C8.
//
// A bottom tab bar: Connection, Files, Publisher (only when switched
// on), Settings. Status and Advanced are inner pages of Settings with a
// back control; system Back returns from them (SettingsPage registers
// it). Home's "Status" lands on Settings → Status.

import { useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import ConnectionPage from '../d2pages/ConnectionPage';
import NetworkPage from '../d2pages/NetworkPage';
import SettingsPage from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';
import PanicWipeDialog from '../components/PanicWipeDialog';
import OpenedFileToast from './OpenedFileToast';
import { TabBar, SECTION_ICONS } from '../design/primitives';
import { useShellNav, visibleSections, type ShellSection } from './useShellNav';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

const LABEL_KEY: Record<ShellSection, string> = {
    connection: 'nav.connection',
    network: 'nav.network',
    publisher: 'nav.publisher',
    settings: 'nav.settings',
};

export default function MobileShell(props: Props) {
    const { t, locale, onLocaleChange, appVersion } = props;
    // Publisher is hidden behind Settings → "Help family connect", so the
    // tab only appears once the person turns it on. Persisted by Prefs.
    const [publisherEnabled, setPublisherEnabled] = useState(Prefs.publisherEnabled());
    const nav = useShellNav(publisherEnabled);


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
                    // The notch + status-bar inset at the top; the TabBar
                    // owns the bottom inset.
                    paddingInline: 'var(--gutter)',
                    paddingBlockStart: 'calc(env(safe-area-inset-top, 0px) + 12px)',
                    paddingBlockEnd: '12px',
                }}
            >
                {nav.section === 'connection' && <ConnectionPage t={t} onNavigate={nav.navigate} />}
                {nav.section === 'network' && <NetworkPage t={t} onNavigate={nav.navigate} />}
                {nav.section === 'settings' && (
                    <SettingsPage
                        t={t}
                        locale={locale}
                        appVersion={appVersion}
                        onLocaleChange={onLocaleChange}
                        publisherEnabled={publisherEnabled}
                        onPublisherEnabledChange={(v) => {
                            Prefs.setPublisherEnabled(v);
                            setPublisherEnabled(v);
                        }}
                        subPage={nav.settingsPage}
                        onSubPageChange={nav.setSettingsPage}
                    />
                )}
                {nav.section === 'publisher' && publisherEnabled && <PublisherPage t={t} locale={locale} />}
            </main>

            <TabBar<ShellSection>
                active={nav.section}
                onChange={nav.pick}
                items={visibleSections(publisherEnabled).map((id) => ({
                    id,
                    label: t(LABEL_KEY[id]),
                    icon: SECTION_ICONS[id],
                }))}
            />

            {nav.eraseOpen && <PanicWipeDialog t={t} onClose={() => nav.setEraseOpen(false)} />}
            {nav.fileWaiting && (
                <OpenedFileToast t={t} onOpen={nav.openWaitingFile} onDismiss={nav.dismissFileWaiting} />
            )}
        </div>
    );
}
