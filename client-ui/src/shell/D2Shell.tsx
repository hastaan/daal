// D2Shell.tsx — titlebar + sidebar + topbar + main layout for D-2.
// Implements the IA from D-2 §4.2 and the visual structure from
// client-shared/designs/daal-desktop.html.

import { useEffect, useMemo, useState } from 'react';
import { applyDir, type Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import { useContract } from '../contract/ContractProvider';
import { Sidebar, type SectionId } from './Sidebar';
import Topbar from './Topbar';
import TitleBar from './TitleBar';
import ConnectionPage from '../d2pages/ConnectionPage';
import RoutesPage from '../d2pages/RoutesPage';
import SourcesPage from '../d2pages/SourcesPage';
import StatusPage from '../d2pages/StatusPage';
import SettingsPage from '../d2pages/SettingsPage';
import PublisherPage from '../d2pages/PublisherPage';
import PanicWipeDialog from '../components/PanicWipeDialog';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

export default function D2Shell({
    locale,
    onLocaleChange,
    engineHealthy,
    appVersion,
    t,
}: Props) {
    const contract = useContract();
    const [section, setSection] = useState<SectionId>('connection');
    const [publisherEnabled, setPublisherEnabled] = useState(
        Prefs.publisherEnabled(),
    );
    const [showPanic, setShowPanic] = useState(false);

    // Lifted connection state: the titlebar's "Connected · HH:MM:SS" pill
    // and the ConnectionPage hero both derive from this single source.
    const [isConnected, setIsConnected] = useState(false);
    const [connectedSinceUnixMs, setConnectedSinceUnixMs] = useState<
        number | null
    >(null);

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const c = await contract.connectionSummary();
                if (cancelled) return;
                const nowConnected = c.state === 'connected';
                setIsConnected(nowConnected);
                if (nowConnected && connectedSinceUnixMs == null) {
                    setConnectedSinceUnixMs(
                        c.connectedSinceUnixMs ?? Date.now(),
                    );
                } else if (!nowConnected && connectedSinceUnixMs != null) {
                    setConnectedSinceUnixMs(null);
                }
            } catch {
                /* ignore — ConnectionPage will surface details */
            }
        };
        tick();
        const id = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [connectedSinceUnixMs, contract]);

    // Keyboard shortcuts: Cmd/Ctrl+1..6 jump to sections.
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (!(e.ctrlKey || e.metaKey)) return;
            const map: Record<string, SectionId> = {
                '1': 'connection',
                '2': 'routes',
                '3': 'sources',
                '4': 'status',
                '5': 'settings',
                '6': 'publisher',
            };
            const next = map[e.key];
            if (next) {
                if (next === 'publisher' && !publisherEnabled) return;
                e.preventDefault();
                setSection(next);
            }
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [publisherEnabled]);

    const navigate = useMemo(
        () => (target: SectionId) => {
            if (target === 'publisher' && !publisherEnabled) return;
            setSection(target);
        },
        [publisherEnabled],
    );

    return (
        <div
            style={{
                height: '100%',
                background: 'var(--bg)',
                color: 'var(--paper)',
                display: 'flex',
                flexDirection: 'column',
                minHeight: 0,
            }}
        >
            <TitleBar
                t={t}
                isConnected={isConnected}
                connectedSinceUnixMs={connectedSinceUnixMs}
            />
            <div
                style={{
                    flex: 1,
                    minHeight: 0,
                    display: 'grid',
                    gridTemplateColumns: '240px 1fr',
                }}
            >
                <Sidebar
                    t={t}
                    section={section}
                    onChange={setSection}
                    publisherEnabled={publisherEnabled}
                    onPanic={() => setShowPanic(true)}
                    appVersion={appVersion}
                />
                <div
                    style={{
                        display: 'flex',
                        flexDirection: 'column',
                        minWidth: 0,
                        minHeight: 0,
                    }}
                >
                    <Topbar
                        t={t}
                        section={section}
                        engineHealthy={engineHealthy}
                    />
                    <main
                        style={{
                            flex: 1,
                            minHeight: 0,
                            overflow: 'auto',
                            background: 'var(--teal-deep)',
                            display: 'flex',
                        }}
                    >
                        {section === 'connection' && (
                            <ConnectionPage t={t} onNavigate={navigate} />
                        )}
                        {section === 'routes' && <RoutesPage t={t} />}
                        {section === 'sources' && <SourcesPage t={t} />}
                        {section === 'status' && <StatusPage t={t} />}
                        {section === 'settings' && (
                            <SettingsPage
                                t={t}
                                locale={locale}
                                onLocaleChange={(l) => {
                                    onLocaleChange(l);
                                    applyDir(l);
                                }}
                                publisherEnabled={publisherEnabled}
                                onPublisherEnabledChange={(v) => {
                                    Prefs.setPublisherEnabled(v);
                                    setPublisherEnabled(v);
                                    if (
                                        !v &&
                                        (section as SectionId) === 'publisher'
                                    ) {
                                        setSection('connection');
                                    }
                                }}
                            />
                        )}
                        {section === 'publisher' && publisherEnabled && (
                            <PublisherPage t={t} />
                        )}
                    </main>
                </div>
            </div>

            {showPanic && (
                <PanicWipeDialog
                    t={t}
                    onClose={() => setShowPanic(false)}
                />
            )}
        </div>
    );
}
