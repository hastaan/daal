// StatusPage.tsx — health card on top + 3 accordions.

import { useEffect, useRef, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type {
    BootstrapStatus,
    ProbeResult,
    SchedulerStatus,
    StatsRedacted,
    StatusPagePayload,
} from '../contract/D2Contract';
import {
    MetricTile,
    HealthBar,
    Sparkline,
    StatusLight,
} from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

export default function StatusPage({ t }: Props) {
    const contract = useContract();
    const [payload, setPayload] = useState<StatusPagePayload | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [open, setOpen] = useState<{
        b: boolean; r: boolean; d: boolean;
        sched: boolean; stats: boolean; boot: boolean; net: boolean;
    }>({
        b: true, r: false, d: false,
        sched: false, stats: false, boot: false, net: false,
    });
    const [sched, setSched] = useState<SchedulerStatus | null>(null);
    const [stats, setStats] = useState<StatsRedacted | null>(null);
    const [bootSt, setBootSt] = useState<BootstrapStatus | null>(null);
    const [probes, setProbes] = useState<{ udp?: ProbeResult; dns?: ProbeResult; tcp?: ProbeResult }>({});
    const [probing, setProbing] = useState(false);

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const [p, s, st, bs] = await Promise.all([
                    contract.statusPagePayload(),
                    contract.schedulerStatus().catch(() => ({ json: '' })),
                    contract.statsRedacted().catch(() => ({ json: '' })),
                    contract.bootstrapStatus().catch(() => ({ json: '' })),
                ]);
                if (!cancelled) {
                    setPayload(p);
                    setSched(s);
                    setStats(st);
                    setBootSt(bs);
                    setError(null);
                }
            } catch (e) {
                if (!cancelled) setError((e as Error).message || 'unknown');
            }
        };
        tick();
        const id = setInterval(tick, 3000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    const runProbes = async () => {
        setProbing(true);
        try {
            const [udp, dns, tcp] = await Promise.all([
                contract.probeUdp(2000),
                contract.probeDns(2000),
                contract.probeTcp443(2000),
            ]);
            setProbes({ udp, dns, tcp });
        } finally {
            setProbing(false);
        }
    };

    const routeCount = payload?.routeHealth.length ?? 0;
    const bucket = new Date().toISOString().slice(0, 13);
    const posture = payload?.connection.mode ?? '—';
    const connState = payload?.connection.state ?? 'disconnected';

    // Throughput history for the sparkline, capped at 60 samples.
    const upHistory = useRef<number[]>([]);
    const downHistory = useRef<number[]>([]);
    const [, forceTick] = useState(0);
    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const tp = await contract.throughputSnapshot();
                if (cancelled) return;
                // null = this build counts no bytes. Pushing it as 0
                // would draw a confident flat line through a sparkline
                // that has measured nothing; drop the sample instead
                // and let the tile say so.
                if (tp.upBytesPerSec !== null) {
                    upHistory.current = [
                        ...upHistory.current.slice(-59),
                        tp.upBytesPerSec,
                    ];
                }
                if (tp.downBytesPerSec !== null) {
                    downHistory.current = [
                        ...downHistory.current.slice(-59),
                        tp.downBytesPerSec,
                    ];
                }
                forceTick((n) => (n + 1) % 1024);
            } catch {
                /* ignore */
            }
        };
        tick();
        const id = setInterval(tick, 1000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    // Roll-up health metrics from per-route status.
    //
    // Only routes with a MEASURED percentage take part. A route the
    // engine has never observed carries no severity and no pct, and
    // averaging it in (or counting it as 'bad') would turn silence into
    // a verdict — which is what this tile did before: every fresh
    // install read "0% AVG HEALTH" on a red bar.
    const measuredHealth = payload?.routeHealth.filter(
        (r) => typeof r.pct === 'number',
    ) ?? [];
    const unmeasuredRoutes =
        (payload?.routeHealth.length ?? 0) - measuredHealth.length;
    const healthyRoutes = measuredHealth.filter((r) => r.severity === 'ok').length;
    const warnRoutes = measuredHealth.filter((r) => r.severity === 'warn').length;
    const badRoutes = measuredHealth.filter((r) => r.severity === 'bad').length;
    // null, not 0 — "no route has ever been measured" is not a score.
    const avgHealthPct =
        measuredHealth.length > 0
            ? Math.round(
                  measuredHealth.reduce((s, r) => s + (r.pct ?? 0), 0) /
                      measuredHealth.length,
              )
            : null;
    const overallTone: 'good' | 'warn' | 'bad' | 'neutral' =
        connState === 'connected' && badRoutes === 0 && warnRoutes === 0
            ? 'good'
            : connState === 'connected' && badRoutes === 0
                ? 'warn'
                : badRoutes > 0
                    ? 'bad'
                    : 'neutral';
    // `null`, not 0, when no sample has ever landed — the history is
    // empty exactly when the engine reported "unmeasured".
    const lastUp = upHistory.current[upHistory.current.length - 1] ?? null;
    const lastDown = downHistory.current[downHistory.current.length - 1] ?? null;

    const onExport = async () => {
        try {
            const json = await contract.exportDiagnostics();
            try {
                await navigator.clipboard.writeText(json);
            } catch {
                /* ignore */
            }
        } catch {
            /* ignore */
        }
    };

    return (
        <div
            style={{
                padding: 'var(--gutter)',
                width: '100%',
                maxWidth: 980,
                margin: '0 auto',
            }}
        >
            <header
                style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    marginBottom: 8,
                    flexWrap: 'wrap',
                }}
            >
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 24,
                        color: 'var(--fg)',
                        margin: 0,
                    }}
                >
                    {t('page.status.title')}
                </h1>
                <button
                    onClick={onExport}
                    style={{
                        background: 'var(--gold)',
                        color: '#1A1208',
                        border: 0,
                        padding: '8px 14px',
                        borderRadius: 'var(--radius-md)',
                        fontWeight: 600,
                        fontFamily: 'var(--font-body)',
                        fontSize: 13,
                        cursor: 'pointer',
                    }}
                >
                    {t('page.status.export')}
                </button>
            </header>
            <p
                style={{
                    color: 'var(--muted)',
                    fontSize: 13,
                    margin: '0 0 18px',
                    maxInlineSize: '64ch',
                }}
            >
                {t('page.status.lede')}
            </p>

            {error && (
                <div style={errorBox()}>
                    {t('common.error')}: {error}
                </div>
            )}

            {/* DASHBOARD GRID */}
            <div
                style={{
                    display: 'grid',
                    gridTemplateColumns:
                        'repeat(auto-fit, minmax(160px, 1fr))',
                    gap: 12,
                    marginBottom: 16,
                }}
            >
                <MetricTile
                    label={t('status.tile.overall')}
                    tone={overallTone}
                    pulse={connState === 'connecting'}
                    value={connState.toUpperCase()}
                    sub={posture}
                />
                <MetricTile
                    label={t('status.tile.routes')}
                    value={String(routeCount)}
                    sub={
                        <span
                            style={{
                                display: 'inline-flex',
                                gap: 10,
                                alignItems: 'center',
                            }}
                        >
                            <span>
                                <StatusLight tone="good" size={6} />{' '}
                                {t('status.routes.ok').replace(
                                    '{n}',
                                    String(healthyRoutes),
                                )}
                            </span>
                            <span>
                                <StatusLight tone="warn" size={6} /> {warnRoutes}
                            </span>
                            <span>
                                <StatusLight tone="bad" size={6} /> {badRoutes}
                            </span>
                            {unmeasuredRoutes > 0 && (
                                <span style={{ color: 'var(--dim)' }}>
                                    {t('status.routes.unmeasured').replace(
                                        '{n}',
                                        String(unmeasuredRoutes),
                                    )}
                                </span>
                            )}
                        </span>
                    }
                />
                <div
                    style={{
                        background: 'var(--surface)',
                        border: '1px solid var(--line-soft)',
                        borderRadius: 'var(--r-card)',
                        padding: '14px 16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                    }}
                >
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            letterSpacing: '0.18em',
                            textTransform: 'uppercase',
                            color: 'var(--dim)',
                        }}
                    >
                        {t('status.tile.avg_health')}
                    </div>
                    {avgHealthPct === null ? (
                        // No bar at all: a 0-width bar is still a bar,
                        // and reads as a measured floor.
                        <div
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 13,
                                color: 'var(--muted)',
                                lineHeight: 1.4,
                            }}
                        >
                            {t('status.tile.avg_health.unmeasured')}
                        </div>
                    ) : (
                        <>
                            <div
                                style={{
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 26,
                                    color: 'var(--fg)',
                                    lineHeight: 1.1,
                                }}
                            >
                                {avgHealthPct}
                                <span
                                    style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 13,
                                        color: 'var(--muted)',
                                        marginInlineStart: 4,
                                    }}
                                >
                                    %
                                </span>
                            </div>
                            <HealthBar
                                pct={avgHealthPct}
                                tone={
                                    avgHealthPct >= 70
                                        ? 'good'
                                        : avgHealthPct >= 40
                                            ? 'warn'
                                            : 'bad'
                                }
                            />
                        </>
                    )}
                </div>
                <div
                    style={{
                        background: 'var(--surface)',
                        border: '1px solid var(--line-soft)',
                        borderRadius: 'var(--r-card)',
                        padding: '14px 16px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6,
                    }}
                >
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 10,
                            letterSpacing: '0.18em',
                            textTransform: 'uppercase',
                            color: 'var(--dim)',
                        }}
                    >
                        {t('status.tile.throughput')}
                    </div>
                    <div
                        style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            gap: 12,
                        }}
                    >
                        <div
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 12,
                                color: 'var(--paper)',
                            }}
                        >
                            {lastUp === null || lastDown === null ? (
                                t('network.unmeasured')
                            ) : (
                                <>
                                    ↑ {fmtBps(lastUp)}
                                    <br />↓ {fmtBps(lastDown)}
                                </>
                            )}
                        </div>
                        <Sparkline
                            values={downHistory.current}
                            tone="gold"
                            width={120}
                            height={36}
                        />
                    </div>
                </div>
                <MetricTile
                    label={t('status.tile.bucket')}
                    value={bucket.slice(-2)}
                    unit="h"
                    sub={bucket.slice(0, 10)}
                />
                <MetricTile
                    label={t('status.tile.bootstrap')}
                    tone={bootSt?.json ? 'good' : 'neutral'}
                    value={
                        bootSt?.json
                            ? t('status.tile.bootstrap.ok')
                            : t('status.tile.bootstrap.none')
                    }
                    sub={t('status.tile.bootstrap.sub')}
                />
            </div>

            <Accordion
                title={t('status.acc.routes')}
                open={open.r}
                onToggle={() => setOpen({ ...open, r: !open.r })}
            >
                {!payload?.routeHealth || payload.routeHealth.length === 0 ? (
                    <div style={{ color: 'var(--paper-dim)' }}>
                        {t('common.empty')}
                    </div>
                ) : (
                    <ul
                        style={{
                            listStyle: 'none',
                            padding: 0,
                            margin: 0,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 8,
                        }}
                    >
                        {payload.routeHealth.map((r) => {
                            // 'neutral' for an unmeasured route — a green
                            // light next to a route nobody has tried is
                            // the same fabrication as a 0% bar.
                            const tone =
                                r.severity === undefined
                                    ? 'neutral'
                                    : r.severity === 'bad'
                                        ? 'bad'
                                        : r.severity === 'warn'
                                            ? 'warn'
                                            : 'good';
                            return (
                                <li
                                    key={r.routeId}
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns:
                                            'auto 1fr auto',
                                        alignItems: 'center',
                                        gap: 10,
                                        padding: '8px 10px',
                                        background: 'var(--surface-2)',
                                        borderRadius: 'var(--r-tile)',
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 11,
                                        color: 'var(--paper)',
                                    }}
                                >
                                    <StatusLight tone={tone} size={8} />
                                    <div
                                        style={{
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: 4,
                                            minWidth: 0,
                                        }}
                                    >
                                        <span
                                            style={{
                                                overflow: 'hidden',
                                                textOverflow: 'ellipsis',
                                                whiteSpace: 'nowrap',
                                            }}
                                        >
                                            {r.routeId}
                                        </span>
                                        {r.pct !== undefined && (
                                            <HealthBar pct={r.pct} tone={tone} />
                                        )}
                                    </div>
                                    <span style={{ color: 'var(--muted)' }}>
                                        {r.pct === undefined
                                            ? t('network.unmeasured')
                                            : `${r.pct}%`}
                                    </span>
                                </li>
                            );
                        })}
                    </ul>
                )}
            </Accordion>

            <Accordion
                title={t('status.acc.budgets')}
                open={open.b}
                onToggle={() => setOpen({ ...open, b: !open.b })}
            >
                <div style={{ color: 'var(--paper-dim)', fontFamily: 'var(--font-mono)', fontSize: 12, whiteSpace: 'pre-wrap' }}>
                    {payload?.rawDiagnosticsJson?.slice(0, 600) || t('common.empty')}
                </div>
            </Accordion>

            <Accordion
                title={t('status.acc.network')}
                open={open.net}
                onToggle={() => setOpen({ ...open, net: !open.net })}
            >
                <button
                    disabled={probing}
                    onClick={runProbes}
                    style={smallBtn()}
                >
                    {probing ? t('status.probes.running') : t('status.probes.run')}
                </button>
                <div
                    style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(3, 1fr)',
                        gap: 8,
                        marginTop: 10,
                    }}
                >
                    <ProbeTile label={t('status.probes.udp')} probe={probes.udp} t={t} />
                    <ProbeTile label={t('status.probes.dns')} probe={probes.dns} t={t} />
                    <ProbeTile label={t('status.probes.tcp443')} probe={probes.tcp} t={t} />
                </div>
            </Accordion>

            <Accordion
                title={t('status.acc.scheduler')}
                open={open.sched}
                onToggle={() => setOpen({ ...open, sched: !open.sched })}
            >
                <pre style={preStyle()}>{prettyJson(sched?.json)}</pre>
            </Accordion>

            <Accordion
                title={t('status.acc.stats')}
                open={open.stats}
                onToggle={() => setOpen({ ...open, stats: !open.stats })}
            >
                <pre style={preStyle()}>{prettyJson(stats?.json)}</pre>
            </Accordion>

            <Accordion
                title={t('status.acc.bootstrap')}
                open={open.boot}
                onToggle={() => setOpen({ ...open, boot: !open.boot })}
            >
                <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                    <button
                        onClick={async () => {
                            try { await contract.bootstrapInstallSeeds(); }
                            catch { /* ignore */ }
                        }}
                        style={smallBtn()}
                    >
                        {t('status.bootstrap.install')}
                    </button>
                    <button
                        onClick={async () => {
                            try { await contract.bootstrapRefresh(8000); }
                            catch { /* ignore */ }
                        }}
                        style={smallBtn()}
                    >
                        {t('status.bootstrap.refresh')}
                    </button>
                </div>
                <pre style={preStyle()}>{prettyJson(bootSt?.json)}</pre>
            </Accordion>

        </div>
    );
}

function Accordion({
    title,
    open,
    onToggle,
    children,
}: {
    title: string;
    open: boolean;
    onToggle: () => void;
    children: React.ReactNode;
}) {
    return (
        <div style={{ ...card(), marginTop: 12 }}>
            <button
                onClick={onToggle}
                style={{
                    width: '100%',
                    background: 'transparent',
                    border: 0,
                    color: 'var(--paper)',
                    fontFamily: 'var(--font-display)',
                    fontSize: 16,
                    textAlign: 'start',
                    cursor: 'pointer',
                    padding: 0,
                    marginBottom: open ? 12 : 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                }}
                aria-expanded={open}
            >
                <span>{title}</span>
                <span style={{ color: 'var(--ink-mute)' }} aria-hidden>
                    {open ? '−' : '+'}
                </span>
            </button>
            {open && children}
        </div>
    );
}

function card() {
    return {
        background: 'var(--teal-surface)',
        border: '1px solid var(--teal-hairline)',
        borderRadius: 'var(--radius-lg)',
        padding: 18,
    } as const;
}
function errorBox() {
    return {
        background: 'rgba(200,85,61,0.10)',
        border: '1px solid rgba(200,85,61,0.40)',
        color: 'var(--danger)',
        padding: 12,
        borderRadius: 'var(--radius-md)',
        marginBottom: 20,
        fontSize: 13,
    } as const;
}
function smallBtn() {
    return {
        background: 'var(--teal-raised)',
        border: '1px solid var(--teal-border)',
        color: 'var(--paper)',
        padding: '6px 10px',
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 12,
        cursor: 'pointer',
    } as const;
}
function preStyle() {
    return {
        background: 'var(--teal-deep)',
        color: 'var(--paper-dim)',
        padding: 10,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        margin: 0,
        whiteSpace: 'pre-wrap' as const,
        wordBreak: 'break-all' as const,
        maxHeight: 240,
        overflow: 'auto' as const,
    };
}
function prettyJson(s: string | undefined): string {
    if (!s) return '—';
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; }
}
function fmtBps(bps: number): string {
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

function ProbeTile({
    label,
    probe,
    t,
}: {
    label: string;
    probe: import('../contract/D2Contract').ProbeResult | undefined;
    t: (k: string) => string;
}) {
    const tone: 'good' | 'bad' | 'neutral' =
        !probe || probe.unavailable ? 'neutral' : probe.ok ? 'good' : 'bad';
    return (
        <div
            style={{
                background: 'var(--surface-2)',
                borderRadius: 'var(--r-tile)',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
            }}
        >
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    letterSpacing: '0.16em',
                    textTransform: 'uppercase',
                    color: 'var(--dim)',
                }}
            >
                <StatusLight tone={tone} size={7} />
                {label}
            </div>
            <div
                style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    color: 'var(--paper)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }}
            >
                {!probe
                    ? '—'
                    : probe.unavailable
                        ? t('status.probes.unavailable')
                        : probe.ok
                            ? 'ok'
                            : 'fail'}
            </div>
            {!probe?.unavailable && probe?.raw ? (
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        color: 'var(--muted)',
                    }}
                >
                    {probe.raw}
                </div>
            ) : null}
        </div>
    );
}
