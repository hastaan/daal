// DesktopShell.tsx — the computer host (≥1024 px), spec C9.
//
// A calm desktop window, not a stretched phone or a cockpit:
//   - a thin status strip on top: one connection badge, and a warning
//     only when the engine stops answering (StatusStrip);
//   - a 220 px sidebar with the same places as the phone tabs and no
//     section labels; shortcut hints show on hover/focus only; at the
//     bottom a quiet "Erase Daal…" row and the version;
//   - the page. Status is an inner page of Settings, as on the phone.

import { useEffect, useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import { SidebarFull, Icon, shortcutLabel } from '../design/primitives';
import ConnectionPage from '../d2pages/ConnectionPage';
import NetworkPage from '../d2pages/NetworkPage';
import SettingsPage, { VersionText } from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';
import PanicWipeDialog from '../components/PanicWipeDialog';
import OpenedFileToast from './OpenedFileToast';
import StatusStrip from './StatusStrip';
import { useShellNav, visibleSections, type ShellSection } from './useShellNav';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

export const NAV_LABEL_KEY: Record<ShellSection, string> = {
    connection: 'nav.connection',
    network: 'nav.network',
    publisher: 'nav.publisher',
    settings: 'nav.settings',
};

/** Ctrl/⌘ + 1..n picks the n-th visible place. */
export function useNavShortcuts(order: ShellSection[], pick: (s: ShellSection) => void) {
    const key = order.join(',');
    useEffect(() => {
        const order = key.split(',') as ShellSection[];
        const onKey = (e: KeyboardEvent) => {
            if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return;
            const n = Number(e.key);
            if (!Number.isInteger(n) || n < 1 || n > order.length) return;
            e.preventDefault();
            pick(order[n - 1]);
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [key, pick]);
}

export default function DesktopShell({ locale, onLocaleChange, engineHealthy, appVersion, t }: Props) {
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
            <div
                style={{
                    flex: 1,
                    minHeight: 0,
                    display: 'grid',
                    gridTemplateColumns: '220px minmax(0, 1fr)',
                }}
            >
                <SidebarFull
                    width={220}
                    active={nav.section}
                    onChange={(id) => nav.pick(id as ShellSection)}
                    sections={[
                        {
                            label: '',
                            items: order.map((id, i) => ({
                                id,
                                label: t(NAV_LABEL_KEY[id]),
                                shortcut: shortcutLabel(i + 1),
                            })),
                        },
                    ]}
                    footer={<SidebarFooter t={t} appVersion={appVersion} onErase={() => nav.setEraseOpen(true)} />}
                />
                <main
                    style={{
                        minWidth: 0,
                        minHeight: 0,
                        overflow: 'auto',
                        background: 'var(--bg)',
                        display: 'flex',
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
            </div>

            {nav.eraseOpen && <PanicWipeDialog t={t} onClose={() => nav.setEraseOpen(false)} />}
            {nav.fileWaiting && (
                <OpenedFileToast t={t} onOpen={nav.openWaitingFile} onDismiss={nav.dismissFileWaiting} />
            )}
        </div>
    );
}

/** The sidebar's foot: a quiet erase row (red only on hover or focus,
 *  never a filled red button) and the version. */
export function SidebarFooter({ t, appVersion, onErase }: { t: (k: string) => string; appVersion: string; onErase: () => void }) {
    const [hot, setHot] = useState(false);
    return (
        <div style={{ display: 'grid', gap: 2, marginInline: -10 }}>
            <button
                type="button"
                data-button="erase"
                onClick={onErase}
                onMouseEnter={() => setHot(true)}
                onMouseLeave={() => setHot(false)}
                onFocus={() => setHot(true)}
                onBlur={() => setHot(false)}
                style={{
                    appearance: 'none',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    minHeight: 44,
                    width: '100%',
                    paddingInline: 10,
                    background: 'transparent',
                    border: 0,
                    borderRadius: 8,
                    color: hot ? 'var(--red)' : 'var(--muted)',
                    fontFamily: 'var(--font-body)',
                    fontSize: 13,
                    textAlign: 'start',
                    cursor: 'pointer',
                    transition: 'color var(--t-fast)',
                }}
            >
                <Icon name="erase" size={18} />
                <span>{t('nav.erase')}</span>
            </button>
            {appVersion && (
                <div style={{ fontSize: 11, color: 'var(--muted)', paddingInline: 10 }}>
                    <VersionText t={t} version={appVersion} />
                </div>
            )}
        </div>
    );
}
