// TabletShell.tsx — the mid-size host (641–1023 px). The desktop rules
// with an icon rail (spec C9): the same places and the same status
// strip; names are the icons' tooltips; erase is an icon at the foot.

import { useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import ConnectionPage from '../d2pages/ConnectionPage';
import NetworkPage from '../d2pages/NetworkPage';
import SettingsPage from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';
import PanicWipeDialog from '../components/PanicWipeDialog';
import OpenedFileToast from './OpenedFileToast';
import { IconButton, SidebarRail } from '../design/primitives';
import StatusStrip from './StatusStrip';
import { NAV_LABEL_KEY, useNavShortcuts } from './DesktopShell';
import { useShellNav, visibleSections, type ShellSection } from './useShellNav';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

export default function TabletShell({ locale, onLocaleChange, engineHealthy, appVersion, t }: Props) {
    const [publisherEnabled, setPublisherEnabled] = useState(Prefs.publisherEnabled());
    const nav = useShellNav(publisherEnabled);
    const order = visibleSections(publisherEnabled);
    useNavShortcuts(order, nav.pick);


    return (
        <div
            style={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                background: 'var(--bg)',
                color: 'var(--fg)',
                minHeight: 0,
            }}
        >
            <StatusStrip
                t={t}
                locale={locale}
                engineHealthy={engineHealthy}
                onOpenConnection={() => nav.pick('connection')}
                onOpenStatus={() => nav.navigate('status')}
            />
            <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '72px minmax(0, 1fr)' }}>
                <SidebarRail
                    active={nav.section}
                    onChange={(id) => nav.pick(id as ShellSection)}
                    items={order.map((id) => ({ id, label: t(NAV_LABEL_KEY[id]) }))}
                    footer={
                        <IconButton
                            icon="erase"
                            label={t('nav.erase')}
                            dataButton="erase"
                            onClick={() => nav.setEraseOpen(true)}
                            style={{ color: 'var(--muted)' }}
                        />
                    }
                />
                <main style={{ minWidth: 0, minHeight: 0, overflow: 'auto', padding: 'var(--gutter)' }}>
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
            </div>
            {nav.eraseOpen && <PanicWipeDialog t={t} onClose={() => nav.setEraseOpen(false)} />}
            {nav.fileWaiting && (
                <OpenedFileToast t={t} onOpen={nav.openWaitingFile} onDismiss={nav.dismissFileWaiting} />
            )}
        </div>
    );
}
