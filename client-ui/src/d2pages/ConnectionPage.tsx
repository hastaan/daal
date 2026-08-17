// ConnectionPage.tsx — D-2.1 Connection screen.
//
// Visual contract: client-shared/designs/daal-desktop.html (.work + .work-main + .rail).
// Data contract: client-ui/src/contract/d2-contract.ts
//   - connectionSummary()  : state, mode, activeRoute, networkLabel, pointerValidDays
//   - whyThisRoute()       : active + reasonText + skipped[]
//   - pointerRotation()    : lastRotated, validForDays, rotatedSuccessfully
//   - routeHealth()        : RouteHealthDisplayRow[]
//   - connect/disconnect/setMode/exportDiagnostics
//
// No legacy `bridge.diagnostics()` usage. The titlebar + connection-duration
// ticker live in D2Shell (lifted state); this page only renders the
// center hero + right rail and dispatches actions.

import { useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type {
    ConnectionSummary,
    WhyThisRouteSummary,
    PointerRotationSummary,
    RouteHealthDisplayRow,
    ThroughputSnapshot,
    ConnState,
    ConnMode,
} from '../contract/D2Contract';
import { effectiveLocale } from '../lib/i18n';
import { useDensity } from '../design/DensityProvider';
import DaalButton, { type DaalConnectState } from '../components/DaalButton';
import RouteChip from '../components/connection/RouteChip';
import StatusLine from '../components/connection/StatusLine';
import ModeChip from '../components/connection/ModeChip';
import WhyThisRoute from '../components/connection/WhyThisRoute';
import RouteHealthBars from '../components/connection/RouteHealthBars';
import PointerBanner from '../components/connection/PointerBanner';
import ModePickerSheet from '../components/connection/ModePickerSheet';
import RecoverySheet from '../components/RecoverySheet';
import type { SectionId } from '../shell/Sidebar';

interface Props {
    t: (k: string) => string;
    onNavigate: (s: SectionId) => void;
}

const HEADLINE_KEY: Record<ConnState, string> = {
    disconnected: 'conn.headline_disconnected',
    connecting: 'conn.headline_connecting',
    connected: 'conn.headline_connected',
    error: 'conn.headline_error',
};

const STATE_LABEL_KEY: Record<ConnState, string> = {
    disconnected: 'conn.disconnected',
    connecting: 'conn.connecting',
    connected: 'conn.state.routing', // "Connected · Routing" per design
    error: 'conn.error',
};

function toDaalConnectState(s: ConnState): DaalConnectState {
    return s;
}

function formatBps(bps: number): string {
    if (!Number.isFinite(bps) || bps <= 0) return '0 B/s';
    const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s'];
    let v = bps;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
        v /= 1024;
        i++;
    }
    return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export default function ConnectionPage({ t, onNavigate }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const [conn, setConn] = useState<ConnectionSummary | null>(null);
    const [why, setWhy] = useState<WhyThisRouteSummary | null>(null);
    const [pointer, setPointer] = useState<PointerRotationSummary | null>(null);
    const [health, setHealth] = useState<RouteHealthDisplayRow[]>([]);
    const [throughput, setThroughput] = useState<ThroughputSnapshot | null>(null);
    const [showMode, setShowMode] = useState(false);
    const [showRecovery, setShowRecovery] = useState(false);
    const [busy, setBusy] = useState(false);
    // Phone-only: the right rail (why-this-route + health + pointer
    // banner) collapses behind a single disclosure header so the first
    // paint is the Daal mark and route chip only.
    const [diagOpen, setDiagOpen] = useState(false);
    // Optimistic-UI flag: while a user-initiated connect/disconnect is
    // in flight, override the FSM-derived state so the eagle and
    // headline reflect the user's intent instantly instead of waiting
    // for the next 2 s diagnostics poll. Cleared whenever the polled
    // state matches the optimistic target, OR after a 6 s safety
    // timeout so a stuck backend can never freeze the UI.
    const [optimistic, setOptimistic] = useState<ConnState | null>(null);
    // Transient user-facing notice (export result, failed mode change, …).
    const [notice, setNotice] = useState<string | null>(null);
    useEffect(() => {
        if (!notice) return;
        const id = setTimeout(() => setNotice(null), 4000);
        return () => clearTimeout(id);
    }, [notice]);
    const locale = effectiveLocale();

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const [c, w, p, h] = await Promise.all([
                    contract.connectionSummary(),
                    contract.whyThisRoute(),
                    contract.pointerRotation(),
                    contract.routeHealth(),
                ]);
                if (cancelled) return;
                setConn(c);
                setWhy(w);
                setPointer(p);
                setHealth(h);
                // Clear optimistic flag as soon as the polled state
                // agrees with what the user asked for, so the UI
                // converges to the truth.
                setOptimistic((prev) => {
                    if (!prev) return prev;
                    if (prev === c.state) return null;
                    return prev;
                });
            } catch {
                if (!cancelled) {
                    setConn((prev) =>
                        prev
                            ? { ...prev, state: 'error' as ConnState }
                            : null,
                    );
                }
            }
        };
        tick();
        const id = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    // Throughput poll — only when state=connected, 1 s cadence.
    useEffect(() => {
        if (conn?.state !== 'connected') {
            setThroughput(null);
            return;
        }
        let cancelled = false;
        const tick = async () => {
            try {
                const tp = await contract.throughputSnapshot();
                if (!cancelled) setThroughput(tp);
            } catch { /* ignore */ }
        };
        tick();
        const id = setInterval(tick, 1000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [conn?.state, contract]);

    // The state shown to the user. Optimistic overrides win until the
    // next poll lands a matching ground-truth state.
    const state: ConnState = optimistic ?? conn?.state ?? 'disconnected';
    const mode: ConnMode = conn?.mode ?? 'normal';

    // Safety net: never let an optimistic state linger longer than
    // 6 s. If the backend never converged we drop the override and
    // fall back to whatever the diagnostics blob says.
    useEffect(() => {
        if (!optimistic) return;
        const id = setTimeout(() => setOptimistic(null), 6000);
        return () => clearTimeout(id);
    }, [optimistic]);

    const onDaalClick = async () => {
        if (busy) return;
        if (state === 'connected') {
            // Optimistic: immediately render disconnected so the eagle
            // greys out the moment the user taps; the next poll
            // confirms.
            setOptimistic('disconnected');
            setBusy(true);
            try { await contract.disconnect(); }
            finally { setBusy(false); }
            return;
        }
        if (state === 'error') {
            setShowRecovery(true);
            return;
        }
        // disconnected/connecting → if no active route, navigate to Routes;
        // otherwise reconnect to the active one.
        if (!conn?.activeRoute) {
            onNavigate('network');
            return;
        }
        // Optimistic: flip to 'connecting' the instant the tap fires.
        // The eagle pulses, the headline reads "Connecting…", and the
        // tap registers as "something happened" even if the engine
        // resolves in <50 ms (Stub) or several seconds (real driver).
        setOptimistic('connecting');
        setBusy(true);
        try {
            await contract.connect(conn.activeRoute.routeId);
        } catch {
            setOptimistic(null);
            setShowRecovery(true);
        } finally {
            setBusy(false);
        }
    };

    const onPickMode = async (m: ConnMode) => {
        try {
            await contract.setMode(m);
        } catch {
            // Don't fail silently — tell the user the change didn't take.
            setNotice(t('conn.mode_failed'));
        }
    };

    // Diagnostics export: the Tauri fs plugin isn't wired, so we can't
    // write a file. Rather than show a save dialog that silently does
    // nothing, copy the JSON to the clipboard and say so plainly.
    const onExport = async () => {
        try {
            const json = await contract.exportDiagnostics();
            try {
                await navigator.clipboard.writeText(json);
                setNotice(t('conn.export_copied'));
            } catch {
                setNotice(t('conn.export_failed'));
            }
        } catch {
            setNotice(t('conn.export_failed'));
        }
    };

    const daalLabel =
        state === 'connected'
            ? t('conn.disconnect_action')
            : t('conn.connect_action');

    // Layout: phone → single column, rail stacks under hero.
    // tablet  → single column with wider hero, rail collapses to
    //           cards below.
    // desktop → 1fr / 320px grid (the original layout).
    const isPhone = density === 'phone';
    const isDesktop = density === 'desktop';

    return (
        <div
            style={{
                flex: 1,
                display: isDesktop ? 'grid' : 'flex',
                flexDirection: isDesktop ? undefined : 'column',
                gridTemplateColumns: isDesktop ? '1fr 320px' : undefined,
                minHeight: 0,
                overflow: 'auto',
            }}
        >
            {/* Transient status line (export result, failed mode change). */}
            <div
                aria-live="polite"
                style={{
                    position: 'absolute',
                    insetInlineStart: 0,
                    insetInlineEnd: 0,
                    top: 8,
                    textAlign: 'center',
                    pointerEvents: 'none',
                    zIndex: 10,
                }}
            >
                {notice && (
                    <span
                        style={{
                            display: 'inline-block',
                            padding: '6px 14px',
                            borderRadius: 999,
                            background: 'var(--teal-hairline)',
                            color: 'var(--fg)',
                            fontSize: 13,
                        }}
                    >
                        {notice}
                    </span>
                )}
            </div>

            {/* CENTER: hero */}
            <section
                style={{
                    padding: isPhone ? '20px 4px' : '36px 48px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    overflow: 'auto',
                    borderInlineEnd: isDesktop
                        ? '1px solid var(--teal-hairline)'
                        : undefined,
                }}
            >
                <div className={`d2-conn-state-label ${state}`}>
                    {t(STATE_LABEL_KEY[state])}
                </div>

                <DaalButton
                    state={toDaalConnectState(state)}
                    onClick={onDaalClick}
                    label={daalLabel}
                />

                <h1
                    className="d2-conn-headline"
                    style={{ marginBlockStart: 24, marginBlockEnd: 10 }}
                >
                    {t(HEADLINE_KEY[state])}
                </h1>

                <RouteChip
                    row={conn?.activeRoute}
                    locale={locale}
                    t={t}
                    onClick={() => onNavigate('network')}
                    disabled={busy}
                />

                <StatusLine
                    locale={locale}
                    t={t}
                    networkLabel={
                        conn?.networkLabel
                            ? t('conn.network.wifi')
                            : undefined
                    }
                    pointerSource={conn?.pointerSource}
                    pointerValidDays={conn?.pointerValidDays}
                />

                {state === 'connected' && (
                    <ModeChip
                        mode={mode}
                        t={t}
                        onClick={() => setShowMode(true)}
                    />
                )}

                {state === 'connected' && throughput && (
                    <div
                        className="d2-throughput"
                        style={{
                            marginTop: 14,
                            display: 'flex',
                            gap: 18,
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            color: 'var(--paper-dim)',
                            letterSpacing: '0.08em',
                        }}
                    >
                        <span aria-label={t('conn.throughput.up')}>
                            ↑ {formatBps(throughput.upBytesPerSec)}
                        </span>
                        <span aria-label={t('conn.throughput.down')}>
                            ↓ {formatBps(throughput.downBytesPerSec)}
                        </span>
                    </div>
                )}
            </section>

            {/* RIGHT RAIL
             * On desktop this is a stacked column of sections that sit
             * directly on the page background — no card wrapping. On
             * phone we mirror that exactly: same typography, same
             * sections; we just make the heading row tappable so the
             * body collapses by default. No outer card, so the gold
             * pointer banner doesn't look nested. */}
            {isPhone ? (
                <aside
                    className="d2-rail"
                    style={{ padding: '8px var(--gutter) 24px' }}
                >
                    <button
                        type="button"
                        aria-expanded={diagOpen}
                        onClick={() => setDiagOpen((v) => !v)}
                        style={{
                            appearance: 'none',
                            inlineSize: '100%',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: 12,
                            background: 'transparent',
                            border: 0,
                            padding: '6px 0 10px',
                            color: 'var(--fg)',
                            cursor: 'pointer',
                            textAlign: 'start',
                            borderBlockEnd: '1px solid var(--line-soft)',
                        }}
                    >
                        <span>
                            <span
                                className="d2-rail-title"
                                style={{ marginBlockEnd: 4 }}
                            >
                                {t('rail_diagnostic')}
                            </span>
                            <span
                                style={{
                                    display: 'block',
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 14,
                                    fontWeight: 600,
                                    color: 'var(--paper)',
                                }}
                            >
                                {t('why_this_route')}
                            </span>
                        </span>
                        <span
                            aria-hidden
                            style={{
                                color: 'var(--muted)',
                                fontFamily: 'var(--font-mono)',
                                fontSize: 14,
                                transform: diagOpen
                                    ? 'rotate(180deg)'
                                    : 'rotate(0)',
                                transition: 'transform var(--t-fast)',
                            }}
                        >
                            ⌄
                        </span>
                    </button>
                    {diagOpen && (
                        <>
                            <WhyThisRoute data={why} t={t} headless />
                            <RouteHealthBars
                                rows={health}
                                locale={locale}
                                t={t}
                            />
                            <PointerBanner
                                data={pointer}
                                locale={locale}
                                t={t}
                            />
                        </>
                    )}
                </aside>
            ) : (
                <aside className="d2-rail">
                    <WhyThisRoute data={why} t={t} />
                    <RouteHealthBars rows={health} locale={locale} t={t} />
                    <PointerBanner data={pointer} locale={locale} t={t} />
                </aside>
            )}

            {showMode && (
                <ModePickerSheet
                    t={t}
                    current={mode}
                    onPick={onPickMode}
                    onClose={() => setShowMode(false)}
                />
            )}

            {showRecovery && (
                <RecoverySheet
                    t={t}
                    onClose={() => setShowRecovery(false)}
                    onTryOther={() => {
                        setShowRecovery(false);
                        onNavigate('network');
                    }}
                    onRefreshSources={() => {
                        setShowRecovery(false);
                        onNavigate('network');
                    }}
                    onLifeline={() => {
                        setShowRecovery(false);
                        onPickMode('lifeline');
                    }}
                    onExportDiag={() => {
                        setShowRecovery(false);
                        void onExport();
                    }}
                />
            )}
        </div>
    );
}
