// SettingsPage.tsx — one short list (spec C5).
//
//   main      Status · Language · Theme · Help family connect · Advanced,
//             then Erase on its own, then the version line.
//   advanced  Connection mode, My Daal address (CustodyPanel), Automatic
//             updates (only when there are any), Network test (only when a
//             held file carries a test relay, or a report is kept), and
//             [dev] Developer tools.
//   nettest   The network test (components/NetTestPage), back to Advanced.
//   status    The Status page (StatusPage), with a back control.
//
// The sub-page can be driven by the shell (`subPage` + `onSubPageChange`,
// so Home's "Status" lands here) or kept here when the shell passes
// nothing. Back returns from a sub-page to the main list.

import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import { useBack } from '../lib/useBack';
import { errorText } from '../lib/errorText';
import { isDeveloperMode, setDeveloperMode, useDeveloperMode } from '../lib/devMode';
import PanicWipeDialog, { useEraseWording } from '../components/PanicWipeDialog';
import CustodyPanel from '../components/CustodyPanel';
import SubscriptionsPanel from '../components/SubscriptionsPanel';
import StatusPage from './StatusPage';
import NetTestPage from '../components/NetTestPage';
import { NetTest } from '../lib/netTestCommands';
import { rowShown } from '../lib/netTest';
import type { NetStatus } from '../lib/netTest';
import { useContract } from '../contract/ContractProvider';
import type { ConnMode, ConnState, VersionInfo } from '../contract/D2Contract';
import {
    Badge,
    Button,
    Card,
    Icon,
    ListRow,
    PageHeader,
    Segmented,
    StateIcon,
    Toggle,
    useToast,
} from '../design/primitives';
import { useDensity } from '../design/DensityProvider';

export type SettingsSubPage = 'main' | 'advanced' | 'status' | 'nettest';

interface Props {
    t: (k: string) => string;
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    publisherEnabled: boolean;
    onPublisherEnabledChange: (v: boolean) => void;
    /** The version line at the bottom. Threaded from the shell that owns
     *  the authoritative app version string. */
    appVersion?: string;
    /** Kept for older callers: when given, the Status row calls it
     *  instead of opening the Status sub-page here. */
    onOpenDiagnostics?: () => void;
    /** The open sub-page, when the shell drives it. */
    subPage?: SettingsSubPage;
    onSubPageChange?: (p: SettingsSubPage) => void;
}

/** Seven taps on the version line within this window switch developer tools. */
export const DEV_TAPS = 7;
export const DEV_TAP_WINDOW_MS = 3000;

export default function SettingsPage({
    t,
    locale,
    onLocaleChange,
    publisherEnabled,
    onPublisherEnabledChange,
    appVersion,
    onOpenDiagnostics,
    subPage,
    onSubPageChange,
}: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const toast = useToast();

    const [ownPage, setOwnPage] = useState<SettingsSubPage>('main');
    const page = subPage ?? ownPage;
    const go = (p: SettingsSubPage) => {
        if (onSubPageChange) onSubPageChange(p);
        else setOwnPage(p);
    };
    useBack(page !== 'main', () => go(page === 'nettest' ? 'advanced' : 'main'), 'page');

    const [version, setVersion] = useState<VersionInfo | null>(null);
    const [connState, setConnState] = useState<ConnState | null>(null);
    const [mode, setMode] = useState<ConnMode>('normal');

    useEffect(() => {
        let cancelled = false;
        contract
            .versionInfo()
            .then((v) => {
                if (!cancelled) setVersion(v);
            })
            .catch(() => {
                /* the version line falls back to the shell's string */
            });
        const tick = async () => {
            try {
                const c = await contract.connectionSummary();
                if (cancelled) return;
                setConnState(c.state);
                setMode(c.mode);
            } catch {
                // No answer: the Status row shows no badge rather than a guess.
                if (!cancelled) setConnState(null);
            }
        };
        void tick();
        const id = setInterval(tick, 3000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    const versionText = appVersion ?? version?.guiVersion ?? '';

    // ---- the version line: 7 taps within 3 s switch developer tools ----
    const taps = useRef<number[]>([]);
    const onVersionTap = () => {
        const now = Date.now();
        taps.current = [...taps.current.filter((at) => now - at < DEV_TAP_WINDOW_MS), now];
        if (taps.current.length < DEV_TAPS) return;
        taps.current = [];
        const next = !isDeveloperMode();
        setDeveloperMode(next);
        toast.show('neutral', t(next ? 'ui.dev.on' : 'ui.dev.off'));
    };

    const wrap = (children: ReactNode) => (
        <div
            data-settings-page={page}
            style={{
                width: '100%',
                maxWidth: isPhone ? '100%' : 'calc(var(--content-max) + 64px)',
                // Phone and tablet shells already give the gutter.
                padding: isPhone ? '0 0 24px' : density === 'tablet' ? '0 0 24px' : '24px 32px 32px',
                color: 'var(--fg)',
            }}
        >
            {children}
            {toast.node}
        </div>
    );

    if (page === 'status') {
        return wrap(<StatusPage t={t} locale={locale} onBack={() => go('main')} />);
    }
    if (page === 'nettest') {
        return wrap(
            <NetTestPage
                t={t}
                connState={connState}
                backLabel={t('settings.advanced.title')}
                onBack={() => go('advanced')}
            />,
        );
    }
    if (page === 'advanced') {
        return wrap(
            <AdvancedPage
                t={t}
                locale={locale}
                mode={mode}
                onModeChanged={setMode}
                version={version}
                onOpenNetTest={() => go('nettest')}
                onBack={() => go('main')}
                onDevOff={() => {
                    setDeveloperMode(false);
                    toast.show('neutral', t('ui.dev.off'));
                }}
            />,
        );
    }

    return wrap(
        <MainList
            t={t}
            locale={locale}
            onLocaleChange={onLocaleChange}
            publisherEnabled={publisherEnabled}
            onPublisherEnabledChange={onPublisherEnabledChange}
            connState={connState}
            onOpenStatus={onOpenDiagnostics ?? (() => go('status'))}
            onOpenAdvanced={() => go('advanced')}
            versionText={versionText}
            onVersionTap={onVersionTap}
        />,
    );
}

// ---- main list -------------------------------------------------------

/** The Status row's leading icon for a connection state. */
export function connStateIcon(s: ConnState | null): 'ok' | 'busy' | 'none' | 'bad' {
    return s === 'connected' ? 'ok' : s === 'connecting' ? 'busy' : s === 'error' ? 'bad' : 'none';
}

/** The one Badge for a connection state, shared with StatusPage. */
export function ConnBadge({ t, state, size = 'sm' }: { t: (k: string) => string; state: ConnState; size?: 'sm' | 'md' }) {
    if (state === 'connected') return <Badge tone="good" size={size}>{t('connection.connected')}</Badge>;
    if (state === 'connecting') return <Badge tone="gold" size={size} pulse>{t('status.badge.connecting')}</Badge>;
    if (state === 'error') return <Badge tone="bad" size={size}>{t('status.badge.failed')}</Badge>;
    return <Badge tone="neutral" size={size}>{t('connection.disconnected')}</Badge>;
}

function MainList({
    t,
    locale,
    onLocaleChange,
    publisherEnabled,
    onPublisherEnabledChange,
    connState,
    onOpenStatus,
    onOpenAdvanced,
    versionText,
    onVersionTap,
}: {
    t: (k: string) => string;
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    publisherEnabled: boolean;
    onPublisherEnabledChange: (v: boolean) => void;
    connState: ConnState | null;
    onOpenStatus: () => void;
    onOpenAdvanced: () => void;
    versionText: string;
    onVersionTap: () => void;
}) {
    const { density } = useDensity();
    const onPhone = useEraseWording();
    const [theme, setThemeLocal] = useState<'system' | 'light' | 'dark'>(() => {
        try {
            return Prefs.theme();
        } catch {
            return 'system';
        }
    });
    const [showErase, setShowErase] = useState(false);

    const setTheme = (v: 'system' | 'light' | 'dark') => {
        try {
            Prefs.setTheme(v);
        } catch {
            /* storage refused: the theme still changes for this session */
        }
        setThemeLocal(v);
        document.documentElement.setAttribute('data-theme', v === 'system' ? '' : v);
    };

    return (
        <>
            <PageHeader title={t('settings.title')} />

            <Card style={{ padding: '0 16px', marginBlockStart: 4 }}>
                <ListRow
                    dataButton="status-row"
                    leading={<StateIcon state={connStateIcon(connState)} size={22} />}
                    title={t('page.status.title')}
                    badge={connState ? <ConnBadge t={t} state={connState} /> : undefined}
                    chevron
                    onClick={onOpenStatus}
                />
                <ListRow
                    title={t('settings.language.label')}
                    stack={false}
                    trailing={
                        <Segmented<Locale>
                            dataButton="language"
                            value={locale}
                            items={[
                                { value: 'en', label: t('settings.language_en') },
                                { value: 'fa', label: t('settings.language_fa') },
                            ]}
                            onChange={(v) => onLocaleChange(v)}
                        />
                    }
                />
                <ListRow
                    title={t('settings.theme.label')}
                    stack={false}
                    trailing={
                        <Segmented<'system' | 'light' | 'dark'>
                            dataButton="theme"
                            iconOnly
                            value={theme}
                            items={[
                                {
                                    value: 'system',
                                    icon: 'auto',
                                    label: t(density === 'phone' ? 'settings.theme.system_phone' : 'settings.theme.system'),
                                },
                                { value: 'light', icon: 'sun', label: t('settings.theme.light') },
                                { value: 'dark', icon: 'moon', label: t('settings.theme.dark') },
                            ]}
                            onChange={setTheme}
                        />
                    }
                />
                <ListRow
                    title={t('settings.publisher.toggle')}
                    stack={false}
                    onClick={() => onPublisherEnabledChange(!publisherEnabled)}
                    trailing={
                        <Toggle
                            checked={publisherEnabled}
                            onChange={onPublisherEnabledChange}
                            ariaLabel={t('settings.publisher.toggle')}
                            dataButton="publisher-toggle"
                        />
                    }
                />
                <ListRow
                    dataButton="advanced-row"
                    title={t('settings.advanced.title')}
                    chevron
                    onClick={onOpenAdvanced}
                    last
                />
            </Card>

            <Card style={{ padding: '0 16px', marginBlockStart: 16 }}>
                <ListRow
                    dataButton="erase"
                    leading={
                        <span style={{ color: 'var(--red)', display: 'inline-flex' }}>
                            <Icon name="erase" size={22} />
                        </span>
                    }
                    title={t(onPhone ? 'settings.erase.row' : 'settings.erase.row_desktop')}
                    danger
                    chevron
                    onClick={() => setShowErase(true)}
                    last
                />
            </Card>

            {versionText && (
                <div style={{ display: 'flex', justifyContent: 'center', marginBlockStart: 12 }}>
                    <button
                        type="button"
                        data-button="version"
                        onClick={onVersionTap}
                        style={{
                            appearance: 'none',
                            minHeight: 44,
                            minWidth: 44,
                            paddingInline: 12,
                            background: 'transparent',
                            border: 0,
                            color: 'var(--muted)',
                            fontFamily: 'var(--font-body)',
                            fontSize: 12,
                            cursor: 'default',
                            // No text selection or tap flash on the hidden switch.
                            userSelect: 'none',
                        }}
                    >
                        <VersionText t={t} version={versionText} />
                    </button>
                </div>
            )}

            {showErase && <PanicWipeDialog t={t} onClose={() => setShowErase(false)} />}
        </>
    );
}

/** "Daal 0.9.0", with the version kept left-to-right inside Persian. */
export function VersionText({ t, version }: { t: (k: string) => string; version: string }) {
    const [before, after] = t('settings.version').split('{version}');
    // dir=auto: the first word ("Daal" / «دال») sets the order, even
    // inside a button that an old WebView lays out left to right.
    return (
        <span dir="auto">
            {before}
            <bdi dir="ltr">{version}</bdi>
            {after ?? ''}
        </span>
    );
}

// ---- advanced --------------------------------------------------------

function AdvancedPage({
    t,
    locale,
    mode,
    onModeChanged,
    version,
    onOpenNetTest,
    onBack,
    onDevOff,
}: {
    t: (k: string) => string;
    locale: Locale;
    mode: ConnMode;
    onModeChanged: (m: ConnMode) => void;
    version: VersionInfo | null;
    onOpenNetTest: () => void;
    onBack: () => void;
    onDevOff: () => void;
}) {
    const contract = useContract();
    const dev = useDeveloperMode();
    const [modeFailed, setModeFailed] = useState(false);
    // The network test row: asked once; hidden until the engine says a
    // held file carries a test relay (or a report is kept).
    const [netTest, setNetTest] = useState<NetStatus | null>(null);
    useEffect(() => {
        let cancelled = false;
        void NetTest.status().then((s) => {
            if (!cancelled) setNetTest(s);
        });
        return () => {
            cancelled = true;
        };
    }, []);

    const changeMode = async (next: ConnMode) => {
        const before = mode;
        onModeChanged(next);
        setModeFailed(false);
        try {
            await contract.setMode(next);
        } catch {
            // The engine refused: put the old value back and say so.
            onModeChanged(before);
            setModeFailed(true);
        }
    };

    return (
        <>
            <PageHeader
                title={t('settings.advanced.title')}
                back={{ label: t('settings.title'), onClick: onBack }}
            />
            <div style={{ display: 'grid', gap: 16, marginBlockStart: 4 }}>
                <Card>
                    <CardTitle>{t('settings.network.mode')}</CardTitle>
                    <div style={{ marginBlockStart: 10 }}>
                        <Segmented<ConnMode>
                            dataButton="mode"
                            value={mode}
                            items={[
                                { value: 'normal', label: t('settings.mode.normal') },
                                { value: 'lifeline', label: t('settings.mode.lifeline') },
                                { value: 'lifeline-strict', label: t('settings.mode.lifeline_strict') },
                                { value: 'bulk', label: t('settings.mode.bulk') },
                            ]}
                            onChange={(v) => void changeMode(v)}
                        />
                    </div>
                    <div style={{ fontSize: 13, color: 'var(--muted)', marginBlockStart: 8, lineHeight: 1.45 }}>
                        {t('settings.network.mode.help')}
                    </div>
                    {modeFailed && <FailLine text={t('settings.failed')} />}
                </Card>

                <CustodyPanel t={t} locale={locale} />

                <SubscriptionsPanel t={t} locale={locale} />

                {netTest && rowShown(netTest) && (
                    <Card style={{ padding: '0 16px' }}>
                        <ListRow
                            dataButton="nettest-row"
                            leading={
                                <span style={{ color: 'var(--muted)', display: 'inline-flex' }}>
                                    <Icon name="signal" size={22} />
                                </span>
                            }
                            title={t('netTest.title')}
                            subtitle={t(
                                netTest.kind === 'result'
                                    ? 'netTest.row.ready'
                                    : netTest.kind === 'running'
                                      ? 'netTest.row.running'
                                      : 'netTest.row.sub',
                            )}
                            wrapSubtitle
                            badge={
                                netTest.kind === 'result' ? (
                                    <Badge tone="gold" size="sm">
                                        {t('netTest.row.badge')}
                                    </Badge>
                                ) : undefined
                            }
                            chevron
                            onClick={onOpenNetTest}
                            last
                        />
                    </Card>
                )}

                {dev && <DevTools t={t} version={version} onDevOff={onDevOff} />}
            </div>
        </>
    );
}

export function CardTitle({ children, trailing }: { children: ReactNode; trailing?: ReactNode }) {
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minHeight: 28, flexWrap: 'wrap' }}>
            <h2
                style={{
                    margin: 0,
                    flex: '1 1 auto',
                    minWidth: 0,
                    fontFamily: 'var(--font-display)',
                    fontSize: 17,
                    fontWeight: 500,
                    color: 'var(--fg)',
                }}
            >
                {children}
            </h2>
            {trailing}
        </div>
    );
}

export function FailLine({ text, detail, t }: { text: string; detail?: string; t?: (k: string) => string }) {
    return (
        <div role="alert" style={{ marginBlockStart: 8 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', color: 'var(--red)', fontSize: 13, lineHeight: 1.45 }}>
                <span style={{ paddingBlockStart: 1 }}>
                    <StateIcon state="bad" size={16} />
                </span>
                <span>{text}</span>
            </div>
            {detail && t && <DetailFold t={t} detail={detail} />}
        </div>
    );
}

function DetailFold({ t, detail }: { t: (k: string) => string; detail: string }) {
    const [open, setOpen] = useState(false);
    return (
        <div>
            <button
                type="button"
                aria-expanded={open}
                onClick={() => setOpen((v) => !v)}
                style={{
                    appearance: 'none',
                    minHeight: 44,
                    background: 'transparent',
                    border: 0,
                    padding: 0,
                    color: 'var(--gold-warm)',
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: 'pointer',
                }}
            >
                {t('ui.details')}
            </button>
            {open && (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', overflowWrap: 'anywhere' }}>
                    {detail}
                </div>
            )}
        </div>
    );
}

// ---- [dev] developer tools ------------------------------------------

type DevKey = 'bulk' | 'autopromote' | 'push' | 'experimental' | 'masque';

function DevTools({
    t,
    version,
    onDevOff,
}: {
    t: (k: string) => string;
    version: VersionInfo | null;
    onDevOff: () => void;
}) {
    const contract = useContract();
    // No engine getter exists for these (spec 0.2): they start from the
    // defaults this page always assumed and show a line when refused.
    const [allowBulk, setAllowBulk] = useState(false);
    const [autoPromote, setAutoPromote] = useState(true);
    const [pushRendez, setPushRendez] = useState(true);
    const [expFamilies, setExpFamilies] = useState(false);
    const [detailedNotif, setDetailedNotif] = useState(true);
    const [masque, setMasque] = useState<'' | 'h3' | 'h2' | 'h1'>('');
    const [failed, setFailed] = useState<Partial<Record<DevKey, string>>>({});
    const [wasm, setWasm] = useState<{ modules: string[]; killPub: string } | null>(null);

    useEffect(() => {
        let cancelled = false;
        Promise.all([
            contract.loadedWasmModules().catch(() => [] as string[]),
            contract.wasmKillSwitchPubkey().catch(() => ''),
        ]).then(([modules, killPub]) => {
            if (!cancelled) setWasm({ modules, killPub });
        });
        return () => {
            cancelled = true;
        };
    }, [contract]);

    const apply = async <V,>(key: DevKey, next: V, prev: V, set: (v: V) => void, call: (v: V) => Promise<void>) => {
        set(next);
        setFailed((f) => ({ ...f, [key]: undefined }));
        try {
            await call(next);
        } catch (e) {
            set(prev);
            setFailed((f) => ({ ...f, [key]: errorText(e) }));
        }
    };

    const fail = (k: DevKey) =>
        failed[k] !== undefined ? <FailLine t={t} text={t('settings.failed')} detail={failed[k] || undefined} /> : null;

    const toggleRow = (
        key: DevKey | 'notif',
        title: string,
        help: string,
        checked: boolean,
        onChange: (v: boolean) => void,
        last?: boolean,
    ) => (
        <div key={key} style={{ borderBottom: last ? 'none' : '1px solid var(--line-soft)', paddingBlockEnd: key !== 'notif' && failed[key as DevKey] !== undefined ? 8 : 0 }}>
            <ListRow
                title={title}
                subtitle={help}
                wrapSubtitle
                stack={false}
                last
                trailing={<Toggle checked={checked} onChange={onChange} ariaLabel={title} dataButton={`dev-${key}`} />}
            />
            {key !== 'notif' && fail(key as DevKey)}
        </div>
    );

    const mono = { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)', overflowWrap: 'anywhere' as const };

    return (
        <Card>
            <CardTitle>{t('settings.dev.title')}</CardTitle>
            <div style={{ marginBlockStart: 4 }}>
                {toggleRow('bulk', t('settings.network.bulk'), t('settings.network.bulk.help'), allowBulk, (v) =>
                    void apply('bulk', v, allowBulk, setAllowBulk, (x) => contract.setAllowBulkCapable(x)),
                )}
                {toggleRow('autopromote', t('settings.advanced.autopromote'), t('settings.advanced.autopromote.help'), autoPromote, (v) =>
                    void apply('autopromote', v, autoPromote, setAutoPromote, (x) => contract.setAutoPromotion(x)),
                )}
                {toggleRow('push', t('settings.advanced.push'), t('settings.advanced.push.help'), pushRendez, (v) =>
                    void apply('push', v, pushRendez, setPushRendez, (x) => contract.setPushRendezvousEnabled(x)),
                )}
                {/* Records a preference and nothing else: the 3A gate it was
                    written for is unwired (see core/abi/abi.go's note on
                    experimentalFamiliesEnabled); the help text says so. */}
                {toggleRow('experimental', t('settings.advanced.experimental'), t('settings.advanced.experimental.help'), expFamilies, (v) =>
                    void apply('experimental', v, expFamilies, setExpFamilies, (x) => contract.setExperimentalFamiliesEnabled(x)),
                )}
                <div style={{ borderBottom: '1px solid var(--line-soft)', paddingBlock: '11px' }}>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{t('settings.advanced.masque')}</div>
                    <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.4, marginBlock: '2px 8px' }}>
                        {t('settings.advanced.masque.help')}
                    </div>
                    <Segmented<'' | 'h3' | 'h2' | 'h1'>
                        dataButton="dev-masque"
                        value={masque}
                        items={[
                            { value: '', label: t('settings.masque.auto') },
                            { value: 'h3', label: 'h3' },
                            { value: 'h2', label: 'h2' },
                            { value: 'h1', label: 'h1' },
                        ]}
                        onChange={(v) => void apply('masque', v, masque, setMasque, (x) => contract.setMasqueSubmodeOverride(x))}
                    />
                    {fail('masque')}
                </div>
                {toggleRow('notif', t('settings.notifications.detailed'), t('settings.notifications.detailed.help'), detailedNotif, setDetailedNotif)}
                <ListRow title={t('settings.engine_version')} subtitle={<span style={mono}>{version?.engineVersion || '—'}</span>} />
                <ListRow
                    title={t('settings.about.wasm')}
                    subtitle={<span style={mono}>{wasm?.modules.length ? wasm.modules.join(', ') : '—'}</span>}
                    wrapSubtitle
                />
                <ListRow
                    title={t('settings.about.killswitch')}
                    subtitle={<span style={mono}>{wasm?.killPub || '—'}</span>}
                    wrapSubtitle
                    last
                />
            </div>
            <div style={{ marginBlockStart: 12 }}>
                <Button variant="secondary" dataButton="dev-off" onClick={onDevOff}>
                    {t('settings.dev.off')}
                </Button>
            </div>
        </Card>
    );
}
