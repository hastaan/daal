// SettingsPage.tsx — v0.3 refresh. Eight groups per D-2 §7.6, rebuilt
// on the v0.3 primitives (Card, ListRow, Segmented, Toggle, GroupLabel)
// with oklch tokens. The legacy table-row aesthetic is gone — every
// section reads like the rest of the app.
//
// Layout: one centered column. A sticky chip rail at the top jumps to
// any group. Each group is a `GroupLabel` + a `Card` of `ListRow`s.
// Enums are `Segmented`; booleans are inline `Toggle`s; readouts use
// mono meta on the row's right side.

import { useEffect, useMemo, useRef, useState } from 'react';
import type { Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import PanicWipeDialog from '../components/PanicWipeDialog';
import CustodyPanel from '../components/CustodyPanel';
import SubscriptionsPanel from '../components/SubscriptionsPanel';
import { useContract } from '../contract/ContractProvider';
import type { ConnMode, VersionInfo } from '../contract/D2Contract';
import {
    Card,
    GroupLabel,
    ListRow,
    Segmented,
    StatusPill,
    DaalGlyph,
} from '../design/primitives';
import { useDensity } from '../design/DensityProvider';

interface Props {
    t: (k: string) => string;
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    publisherEnabled: boolean;
    onPublisherEnabledChange: (v: boolean) => void;
    /** Shown in the About card. Threaded from the shell that owns the
     *  authoritative app version string. */
    appVersion?: string;
    /** Phone-only: when present, settings shows a "Diagnostics" row
     *  at the top that the host shell uses to swap in the diagnostics
     *  view. Desktop/Tablet keep Diagnostics in the side nav so they
     *  never pass this. */
    onOpenDiagnostics?: () => void;
}

interface GroupDef {
    id: string;
    label: string;
}

export default function SettingsPage({
    t,
    locale,
    onLocaleChange,
    publisherEnabled,
    onPublisherEnabledChange,
    appVersion,
    onOpenDiagnostics,
}: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const isPhone = density === 'phone';

    const [theme, setThemeLocal] = useState(Prefs.theme());
    const [detailedNotif, setDetailedNotif] = useState(true);
    const [showPanic, setShowPanic] = useState(false);
    const [mode, setMode] = useState<ConnMode>('normal');
    const [version, setVersion] = useState<VersionInfo | null>(null);
    const [wasm, setWasm] = useState<{
        modules: string[];
        killPub: string;
    } | null>(null);
    const [allowBulk, setAllowBulk] = useState(false);
    const [autoPromote, setAutoPromote] = useState(true);
    const [pushRendez, setPushRendez] = useState(true);
    const [expFamilies, setExpFamilies] = useState(false);
    const [masqueOverride, setMasqueOverride] = useState<'' | 'h3' | 'h2' | 'h1'>(
        '',
    );

    useEffect(() => {
        (async () => {
            try {
                const [c, v, modules, killPub] = await Promise.all([
                    contract.connectionSummary(),
                    contract.versionInfo(),
                    contract.loadedWasmModules().catch(() => [] as string[]),
                    contract.wasmKillSwitchPubkey().catch(() => ''),
                ]);
                setMode(c.mode);
                setVersion(v);
                setWasm({ modules, killPub });
            } catch {
                /* ignore */
            }
        })();
    }, [contract]);

    // Group definitions used for the sticky chip rail.
    const groups: GroupDef[] = useMemo(() => {
        const base: GroupDef[] = [
            { id: 'general', label: t('settings.group.general') },
            { id: 'appearance', label: t('settings.group.appearance') },
            { id: 'network', label: t('settings.group.network') },
            { id: 'notifications', label: t('settings.group.notifications') },
            { id: 'privacy', label: t('settings.group.privacy') },
            { id: 'advanced', label: t('settings.group.advanced') },
            { id: 'about', label: t('settings.group.about') },
            { id: 'emergency', label: t('settings.group.emergency') },
        ];
        if (onOpenDiagnostics) {
            base.unshift({
                id: 'diagnostics',
                label: t('settings.diagnostics'),
            });
        }
        return base;
    }, [onOpenDiagnostics, t]);

    // Track active group while scrolling. Updates the chip rail
    // highlight so the user always knows where they are.
    const [activeGroup, setActiveGroup] = useState<string>(
        groups[0]?.id ?? 'general',
    );
    const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});
    useEffect(() => {
        const observer = new IntersectionObserver(
            (entries) => {
                const visible = entries
                    .filter((e) => e.isIntersecting)
                    .sort(
                        (a, b) =>
                            b.intersectionRatio - a.intersectionRatio ||
                            a.boundingClientRect.top - b.boundingClientRect.top,
                    );
                if (visible[0]) {
                    setActiveGroup(visible[0].target.id);
                }
            },
            { rootMargin: '-30% 0px -50% 0px', threshold: [0, 0.25, 0.5] },
        );
        for (const g of groups) {
            const el = sectionRefs.current[g.id];
            if (el) observer.observe(el);
        }
        return () => observer.disconnect();
    }, [groups]);

    const jumpTo = (id: string) => {
        const el = sectionRefs.current[id];
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
            setActiveGroup(id);
        }
    };

    const themeOptions = [
        { value: 'system', label: t('settings.theme.system') },
        { value: 'light', label: t('settings.theme.light') },
        { value: 'dark', label: t('settings.theme.dark') },
    ] as const;

    const modeOptions = [
        { value: 'normal', label: t('settings.mode.normal') },
        { value: 'lifeline', label: t('settings.mode.lifeline') },
        { value: 'lifeline-strict', label: t('settings.mode.lifeline_strict') },
        { value: 'bulk', label: t('settings.mode.bulk') },
    ] as const;

    const localeOptions = [
        { value: 'en', label: t('lang.en') },
        { value: 'fa', label: t('lang.fa') },
    ] as const;

    const masqueOptions = [
        { value: '', label: t('settings.masque.auto') },
        { value: 'h3', label: 'h3' },
        { value: 'h2', label: 'h2' },
        { value: 'h1', label: 'h1' },
    ] as const;

    const pageMaxWidth = isPhone ? '100%' : 720;

    return (
        <div
            style={{
                width: '100%',
                maxWidth: pageMaxWidth,
                margin: '0 auto',
                // On phones the outer shell (MobileShell <main>) already
                // owns the horizontal gutter + safe-area-inset-top. We
                // only add vertical breathing room here.
                padding: isPhone
                    ? '4px 0 16px'
                    : 'calc(var(--gutter) * 1.5)',
                color: 'var(--fg)',
            }}
        >
            {/* Page head */}
            <header style={{ marginBottom: 16 }}>
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        letterSpacing: '0.18em',
                        textTransform: 'uppercase',
                        color: 'var(--dim)',
                    }}
                >
                    Settings
                </div>
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: isPhone ? 22 : 28,
                        margin: '4px 0 0',
                    }}
                >
                    {t('settings.title')}
                </h1>
            </header>

            {/* Sticky chip rail */}
            <div
                style={{
                    position: 'sticky',
                    top: 0,
                    zIndex: 5,
                    margin: '0 calc(var(--gutter) * -0.5) 14px',
                    padding: '6px calc(var(--gutter) * 0.5)',
                    background:
                        'linear-gradient(var(--bg) 70%, transparent)',
                    overflowX: 'auto',
                    WebkitOverflowScrolling: 'touch',
                    scrollbarWidth: 'none',
                }}
            >
                <div
                    style={{
                        display: 'flex',
                        gap: 6,
                        whiteSpace: 'nowrap',
                        paddingBlock: 4,
                    }}
                >
                    {groups.map((g) => {
                        const on = activeGroup === g.id;
                        return (
                            <button
                                key={g.id}
                                onClick={() => jumpTo(g.id)}
                                style={{
                                    appearance: 'none',
                                    background: on
                                        ? 'rgba(201,162,58,0.14)'
                                        : 'var(--surface-2)',
                                    color: on ? 'var(--fg)' : 'var(--muted)',
                                    border: `1px solid ${
                                        on
                                            ? 'var(--gold)'
                                            : 'var(--line-soft)'
                                    }`,
                                    padding: '5px 12px',
                                    borderRadius: 'var(--r-pill)',
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 10,
                                    letterSpacing: '0.10em',
                                    textTransform: 'uppercase',
                                    cursor: 'pointer',
                                }}
                            >
                                {g.label}
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* Diagnostics shortcut (phone-only host injects) */}
            {onOpenDiagnostics && (
                <Section
                    id="diagnostics"
                    label={t('settings.diagnostics')}
                    refMap={sectionRefs.current}
                >
                    <Card style={{ padding: 0 }}>
                        <div style={{ padding: '0 16px' }}>
                            <ListRow
                                leading={<Dot tone="good" />}
                                title={t('settings.diagnostics')}
                                subtitle={t('settings.diagnostics.subtitle')}
                                trailing={<Chevron />}
                                onClick={onOpenDiagnostics}
                                last
                            />
                        </div>
                    </Card>
                </Section>
            )}

            {/* General */}
            <Section
                id="general"
                label={t('settings.group.general')}
                refMap={sectionRefs.current}
            >
                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ListRow
                            title={t('settings.language.label')}
                            subtitle={t('settings.language.help')}
                            trailing={
                                <Segmented
                                    value={locale}
                                    items={[...localeOptions]}
                                    onChange={(v) =>
                                        onLocaleChange(v as Locale)
                                    }
                                />
                            }
                            last
                        />
                    </div>
                </Card>
            </Section>

            {/* Appearance */}
            <Section
                id="appearance"
                label={t('settings.group.appearance')}
                refMap={sectionRefs.current}
            >
                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ListRow
                            title={t('settings.theme.label')}
                            subtitle={t('settings.theme.help')}
                            trailing={
                                <Segmented
                                    value={theme}
                                    items={[...themeOptions]}
                                    onChange={(v) => {
                                        Prefs.setTheme(v);
                                        setThemeLocal(v);
                                        document.documentElement.setAttribute(
                                            'data-theme',
                                            v === 'system' ? '' : v,
                                        );
                                    }}
                                />
                            }
                            last
                        />
                    </div>
                </Card>
            </Section>

            {/* Network */}
            <Section
                id="network"
                label={t('settings.group.network')}
                refMap={sectionRefs.current}
                rightAdornment={
                    <StatusPill tone="gold" dotless>
                        {t('settings.network.modepill').replace(
                            '{mode}',
                            t(modeI18nKey(mode)),
                        )}
                    </StatusPill>
                }
            >
                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ListRow
                            title={t('settings.network.mode')}
                            subtitle={t('settings.network.mode.help')}
                            trailing={
                                <Segmented
                                    value={mode}
                                    items={[...modeOptions]}
                                    onChange={async (v) => {
                                        setMode(v as ConnMode);
                                        try {
                                            await contract.setMode(
                                                v as ConnMode,
                                            );
                                        } catch {
                                            /* ignore */
                                        }
                                    }}
                                />
                            }
                        />
                        <ToggleRow
                            title={t('settings.network.bulk')}
                            subtitle={t('settings.network.bulk.help')}
                            checked={allowBulk}
                            onChange={async (v) => {
                                setAllowBulk(v);
                                try {
                                    await contract.setAllowBulkCapable(v);
                                } catch {
                                    /* ignore */
                                }
                            }}
                            last
                        />
                    </div>
                </Card>

                {/* Subscriptions (Gap 4-recipient). The engine's
                    scheduler.Plan governs the actual refresh cadence;
                    this card shows the current state and exposes
                    manual ↻/remove. */}
                <div style={{ marginTop: 12 }}>
                    <div
                        style={{
                            fontSize: 12,
                            color: 'var(--muted)',
                            letterSpacing: '0.04em',
                            textTransform: 'uppercase',
                            padding: '0 4px 6px 4px',
                        }}
                    >
                        {t('subs.section_title')}
                    </div>
                    <SubscriptionsPanel t={t} />
                </div>
            </Section>

            {/* Notifications */}
            <Section
                id="notifications"
                label={t('settings.group.notifications')}
                refMap={sectionRefs.current}
            >
                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ToggleRow
                            title={t('settings.notifications.detailed')}
                            subtitle={t('settings.notifications.detailed.help')}
                            checked={detailedNotif}
                            onChange={setDetailedNotif}
                            last
                        />
                    </div>
                </Card>
            </Section>

            {/* Privacy — Device Custody + Panic wipe */}
            <Section
                id="privacy"
                label={t('settings.group.privacy')}
                refMap={sectionRefs.current}
            >
                <div style={{ display: 'grid', gap: 10 }}>
                    <CustodyPanel t={t} />
                    <Card
                        style={{
                            padding: 0,
                            borderColor:
                                'color-mix(in oklab, var(--red) 35%, var(--line-soft))',
                        }}
                    >
                        <div style={{ padding: '0 16px' }}>
                            <ListRow
                                leading={<Dot tone="bad" />}
                                title={t('settings.panic_wipe')}
                                subtitle={t('settings.privacy.panic.help')}
                                trailing={
                                    <button
                                        onClick={() => setShowPanic(true)}
                                        style={{
                                            background: 'transparent',
                                            border:
                                                '1px solid color-mix(in oklab, var(--red) 60%, transparent)',
                                            color: 'var(--red)',
                                            padding: '6px 14px',
                                            borderRadius: 'var(--r-pill)',
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 11,
                                            letterSpacing: '0.06em',
                                            textTransform: 'uppercase',
                                            cursor: 'pointer',
                                        }}
                                    >
                                        {t('settings.panic_wipe.erase')}
                                    </button>
                                }
                                last
                            />
                        </div>
                    </Card>
                </div>
            </Section>

            {/* Advanced */}
            <Section
                id="advanced"
                label={t('settings.group.advanced')}
                refMap={sectionRefs.current}
            >
                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ToggleRow
                            title={t('settings.publisher.toggle')}
                            subtitle={t('settings.publisher.help')}
                            checked={publisherEnabled}
                            onChange={onPublisherEnabledChange}
                        />
                        <ToggleRow
                            title={t('settings.advanced.autopromote')}
                            subtitle={t('settings.advanced.autopromote.help')}
                            checked={autoPromote}
                            onChange={async (v) => {
                                setAutoPromote(v);
                                try {
                                    await contract.setAutoPromotion(v);
                                } catch {
                                    /* ignore */
                                }
                            }}
                        />
                        <ToggleRow
                            title={t('settings.advanced.push')}
                            subtitle={t('settings.advanced.push.help')}
                            checked={pushRendez}
                            onChange={async (v) => {
                                setPushRendez(v);
                                try {
                                    await contract.setPushRendezvousEnabled(v);
                                } catch {
                                    /* ignore */
                                }
                            }}
                        />
                        <ToggleRow
                            title={t('settings.advanced.experimental')}
                            subtitle={t('settings.advanced.experimental.help')}
                            checked={expFamilies}
                            onChange={async (v) => {
                                setExpFamilies(v);
                                try {
                                    await contract.setExperimentalFamiliesEnabled(
                                        v,
                                    );
                                } catch {
                                    /* ignore */
                                }
                            }}
                        />
                        <ListRow
                            title={t('settings.advanced.masque')}
                            subtitle={t('settings.advanced.masque.help')}
                            trailing={
                                <Segmented
                                    value={masqueOverride}
                                    items={[...masqueOptions]}
                                    onChange={async (v) => {
                                        setMasqueOverride(
                                            v as typeof masqueOverride,
                                        );
                                        try {
                                            await contract.setMasqueSubmodeOverride(
                                                v,
                                            );
                                        } catch {
                                            /* ignore */
                                        }
                                    }}
                                />
                            }
                            last
                        />
                    </div>
                </Card>
            </Section>

            {/* About */}
            <Section
                id="about"
                label={t('settings.group.about')}
                refMap={sectionRefs.current}
            >
                {/* Brand card — the app's identity now lives here,
                 * not in the chrome. */}
                <Card style={{ marginBottom: 10 }}>
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: 14,
                        }}
                    >
                        <DaalGlyph size={44} />
                        <div style={{ minWidth: 0 }}>
                            <div
                                style={{
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 22,
                                    color: 'var(--fg)',
                                    lineHeight: 1.1,
                                }}
                            >
                                {locale === 'fa' ? 'دال' : 'Daal'}
                            </div>
                            <div
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 10,
                                    color: 'var(--dim)',
                                    letterSpacing: '0.18em',
                                    textTransform: 'uppercase',
                                    marginTop: 4,
                                }}
                            >
                                v{appVersion ?? version?.guiVersion ?? '—'}
                                {version?.engineVersion
                                    ? ` · engine ${version.engineVersion}`
                                    : ''}
                            </div>
                        </div>
                    </div>
                </Card>

                <Card style={{ padding: 0 }}>
                    <div style={{ padding: '0 16px' }}>
                        <ListRow
                            title={t('settings.about.wasm')}
                            meta={
                                wasm?.modules.length
                                    ? wasm.modules.join(', ')
                                    : '—'
                            }
                        />
                        <ListRow
                            title={t('settings.about.killswitch')}
                            subtitle={
                                wasm?.killPub ? (
                                    <span
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            wordBreak: 'break-all',
                                        }}
                                    >
                                        {wasm.killPub}
                                    </span>
                                ) : (
                                    '—'
                                )
                            }
                            last
                        />
                    </div>
                </Card>
            </Section>

            {/* Emergency */}
            <Section
                id="emergency"
                label={t('settings.group.emergency')}
                refMap={sectionRefs.current}
            >
                <Card>
                    <div
                        style={{
                            color: 'var(--muted)',
                            fontSize: 13,
                            lineHeight: 1.45,
                        }}
                    >
                        {t('settings.emergency.body')}
                    </div>
                </Card>
            </Section>

            {showPanic && (
                <PanicWipeDialog t={t} onClose={() => setShowPanic(false)} />
            )}
        </div>
    );
}

// ---- Local helpers ----

function Section({
    id,
    label,
    refMap,
    rightAdornment,
    children,
}: {
    id: string;
    label: string;
    refMap: Record<string, HTMLDivElement | null>;
    rightAdornment?: React.ReactNode;
    children: React.ReactNode;
}) {
    return (
        <div
            ref={(el) => {
                refMap[id] = el;
            }}
            id={id}
            style={{ scrollMarginTop: 80, marginBottom: 16 }}
        >
            <div
                style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                }}
            >
                <GroupLabel>{label}</GroupLabel>
                {rightAdornment}
            </div>
            {children}
        </div>
    );
}

function ToggleRow({
    title,
    subtitle,
    checked,
    onChange,
    last,
}: {
    title: string;
    subtitle?: string;
    checked: boolean;
    onChange: (v: boolean) => void;
    last?: boolean;
}) {
    return (
        <ListRow
            title={title}
            subtitle={subtitle}
            trailing={
                <SwitchInline checked={checked} onChange={onChange} />
            }
            last={last}
        />
    );
}

function SwitchInline({
    checked,
    onChange,
}: {
    checked: boolean;
    onChange: (v: boolean) => void;
}) {
    return (
        <button
            role="switch"
            aria-checked={checked}
            type="button"
            onClick={() => onChange(!checked)}
            style={{
                flexShrink: 0,
                width: 36,
                height: 20,
                borderRadius: 10,
                background: checked ? 'var(--gold)' : 'var(--surface-3)',
                border: 0,
                position: 'relative',
                cursor: 'pointer',
                transition: 'background var(--t-fast)',
            }}
        >
            <span
                aria-hidden
                style={{
                    position: 'absolute',
                    top: 2,
                    left: checked ? 18 : 2,
                    width: 16,
                    height: 16,
                    background: checked ? 'oklch(20% 0.04 80)' : 'var(--fg)',
                    borderRadius: '50%',
                    transition: 'left var(--t-fast)',
                }}
            />
        </button>
    );
}

function Dot({ tone }: { tone: 'good' | 'warn' | 'bad' | 'neutral' }) {
    const color =
        tone === 'good'
            ? 'var(--green)'
            : tone === 'warn'
                ? 'var(--amber)'
                : tone === 'bad'
                    ? 'var(--red)'
                    : 'var(--muted)';
    return (
        <span
            aria-hidden
            style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: color,
                display: 'inline-block',
                boxShadow: `0 0 6px color-mix(in oklab, ${color} 60%, transparent)`,
            }}
        />
    );
}

function Chevron() {
    return (
        <span
            aria-hidden
            style={{
                color: 'var(--dim)',
                fontFamily: 'var(--font-mono)',
                fontSize: 14,
            }}
        >
            ›
        </span>
    );
}

function modeI18nKey(mode: ConnMode): string {
    switch (mode) {
        case 'normal':
            return 'settings.mode.normal';
        case 'lifeline':
            return 'settings.mode.lifeline';
        case 'lifeline-strict':
            return 'settings.mode.lifeline_strict';
        case 'bulk':
            return 'settings.mode.bulk';
        default:
            return 'settings.mode.normal';
    }
}
