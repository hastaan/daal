// DesktopShell.tsx — large-viewport host (≥1024px) built from
// primitives in client-ui/src/design/primitives. Replaces the
// pre-v0.3 D2Shell (deleted once this shell superseded it).

import { useEffect, useMemo, useState } from 'react';
import { applyDir, type Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import { useContract } from '../contract/ContractProvider';
import {
    SidebarFull,
    TitleBar,
    Button,
    StatusPill,
    type SectionId,
} from '../design/primitives';
import ConnectionPage from '../d2pages/ConnectionPage';
import NetworkPage from '../d2pages/NetworkPage';
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

export default function DesktopShell({
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
                /* ignored */
            }
        };
        tick();
        const id = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract, connectedSinceUnixMs]);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (!(e.ctrlKey || e.metaKey)) return;
            const map: Record<string, SectionId> = {
                '1': 'connection',
                '2': 'network',
                '3': 'status',
                '4': 'settings',
                '5': 'publisher',
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
                display: 'flex',
                flexDirection: 'column',
                background: 'var(--bg)',
                color: 'var(--fg)',
                minHeight: 0,
            }}
        >
            <TitleBar
                left={
                    isConnected ? (
                        <StatusPill tone="good" glow>
                            {t('connection.connected')} ·{' '}
                            {formatElapsed(connectedSinceUnixMs)}
                        </StatusPill>
                    ) : (
                        <StatusPill tone="neutral" dotless>
                            {t('connection.disconnected')}
                        </StatusPill>
                    )
                }
                right={
                    <span>
                        {engineHealthy
                            ? t('engine.healthy')
                            : t('engine.degraded')}
                    </span>
                }
            />
            <div
                style={{
                    flex: 1,
                    minHeight: 0,
                    display: 'grid',
                    gridTemplateColumns: '240px 1fr',
                }}
            >
                <SidebarFull
                    active={section}
                    onChange={navigate}
                    sections={[
                        {
                            label: t('nav.section.main'),
                            items: [
                                {
                                    id: 'connection',
                                    label: t('nav.connection'),
                                    shortcut: '⌘1',
                                },
                                {
                                    id: 'network',
                                    label: t('nav.network'),
                                    shortcut: '⌘2',
                                },
                                {
                                    id: 'status',
                                    label: t('nav.status'),
                                    shortcut: '⌘3',
                                },
                                {
                                    id: 'settings',
                                    label: t('nav.settings'),
                                    shortcut: '⌘4',
                                },
                            ],
                        },
                        {
                            label: t('nav.section.advanced'),
                            items: [
                                {
                                    id: 'publisher',
                                    label: t('nav.publisher'),
                                    shortcut: '⌘5',
                                    badge: publisherEnabled
                                        ? undefined
                                        : t('badge_off'),
                                    disabled: !publisherEnabled,
                                },
                            ],
                        },
                    ]}
                    footer={
                        <Button
                            variant="danger"
                            block
                            onClick={() => setShowPanic(true)}
                        >
                            {t('settings.panic_wipe')}
                        </Button>
                    }
                />
                <div
                    style={{
                        display: 'flex',
                        flexDirection: 'column',
                        minWidth: 0,
                        minHeight: 0,
                    }}
                >
                    <main
                        style={{
                            flex: 1,
                            minHeight: 0,
                            overflow: 'auto',
                            background: 'var(--bg)',
                            display: 'flex',
                        }}
                    >
                        {section === 'connection' && (
                            <ConnectionPage t={t} onNavigate={navigate} />
                        )}
                        {section === 'network' && <NetworkPage t={t} />}
                        {section === 'status' && <StatusPage t={t} />}
                        {section === 'settings' && (
                            <SettingsPage
                                t={t}
                                locale={locale}
                                appVersion={appVersion}
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
                <PanicWipeDialog t={t} onClose={() => setShowPanic(false)} />
            )}
        </div>
    );
}

function formatElapsed(sinceUnixMs: number | null): string {
    if (sinceUnixMs == null) return '00:00:00';
    const sec = Math.max(0, Math.floor((Date.now() - sinceUnixMs) / 1000));
    const h = String(Math.floor(sec / 3600)).padStart(2, '0');
    const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
}
