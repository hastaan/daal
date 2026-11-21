// StatusPage.tsx — "Status" (spec C6), an inner page of Settings.
//
// What a person sees: a short summary (connection, the way in use, how
// many ways work, no internet when that is so), one button that copies
// a report for whoever helps them, and a closed fold "For someone
// helping you" with the numbers that mean something. Everything raw
// (bucket, throughput, network test, scheduler/stats/bootstrap JSON,
// the whole diagnostics blob) is in a Developer tools card that renders
// only in developer mode.
//
// A row whose value is unknown is not drawn. Nothing reads "not
// measured yet", and no tile text can break inside a word.

import { sep } from '../lib/format';
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useContract } from '../contract/ContractProvider';
import type {
    BootstrapStatus,
    ProbeResult,
    RouteDisplayRow,
    SchedulerStatus,
    StatsRedacted,
    StatusPagePayload,
} from '../contract/D2Contract';
import type { Locale } from '../lib/i18n';
import { toFaDigits } from '../lib/i18n';
import { errorText } from '../lib/errorText';
import { gradeText } from '../lib/measured';
import { routeForDisplay } from '../lib/activeRoute';
import { autoFailure, autoVerdictKey } from '../lib/autoConnect';
import { useDeveloperMode } from '../lib/devMode';
import {
    Badge,
    Button,
    Card,
    Disclosure,
    HealthBar,
    PageHeader,
    Sparkline,
    StateIcon,
    useToast,
} from '../design/primitives';

interface Props {
    t: (k: string) => string;
    locale?: Locale;
    /** Back to Settings. Without it the page has no back control. */
    onBack?: () => void;
}

type Tone = 'good' | 'warn' | 'bad' | 'neutral';

/** "Pars Relays · Rescue 03" — the way's name as a person reads it. */
export function wayName(t: (k: string) => string, r: RouteDisplayRow | undefined): string | undefined {
    const d = routeForDisplay(r, t);
    if (!d) return undefined;
    const parts = [d.publisherName, d.routeNickname].filter((s) => !!s && s.trim() !== '');
    return parts.length ? parts.join(sep()) : undefined;
}

/** The summary's rollup of per-way health. Only MEASURED ways count:
 *  a way nobody has tried is not a failure, and averaging it in would
 *  turn silence into a verdict. */
export function healthRollup(rows: StatusPagePayload['routeHealth'] | undefined) {
    const all = rows ?? [];
    const measured = all.filter((r) => typeof r.pct === 'number');
    const ok = measured.filter((r) => r.severity === 'ok').length;
    const warn = measured.filter((r) => r.severity === 'warn').length;
    const bad = measured.filter((r) => r.severity === 'bad').length;
    const avg =
        measured.length > 0
            ? Math.round(measured.reduce((s, r) => s + (r.pct ?? 0), 0) / measured.length)
            : null;
    return { total: all.length, measured: measured.length, ok, warn, bad, avg };
}

export default function StatusPage({ t, locale = 'en', onBack }: Props) {
    const contract = useContract();
    const dev = useDeveloperMode();
    const toast = useToast();
    const [payload, setPayload] = useState<StatusPagePayload | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [online, setOnline] = useState<boolean>(() => {
        try {
            return navigator.onLine !== false;
        } catch {
            return true;
        }
    });

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const p = await contract.statusPagePayload();
                if (!cancelled) {
                    setPayload(p);
                    setError(null);
                }
            } catch (e) {
                // A rejected Tauri command is a plain string; reading
                // `.message` off it gave the single word "unknown".
                if (!cancelled) setError(errorText(e));
            }
        };
        void tick();
        const id = setInterval(tick, 3000);
        const on = () => setOnline(true);
        const off = () => setOnline(false);
        window.addEventListener('online', on);
        window.addEventListener('offline', off);
        return () => {
            cancelled = true;
            clearInterval(id);
            window.removeEventListener('online', on);
            window.removeEventListener('offline', off);
        };
    }, [contract]);

    const conn = payload?.connection;
    const connState = conn?.state;
    const using = connState === 'connected' ? wayName(t, conn?.activeRoute) : undefined;
    const h = healthRollup(payload?.routeHealth);
    const failure = autoFailure(conn);
    const noInternet = !online || failure?.verdict === 'network_down';
    const num = (n: number) => (locale === 'fa' ? toFaDigits(String(n)) : String(n));
    // Persian writes the percent sign after the digits as ٪.
    const pct = (n: number) => (locale === 'fa' ? `${toFaDigits(String(n))}٪` : `${n}%`);

    const onReport = async () => {
        try {
            const json = await contract.exportDiagnostics();
            await navigator.clipboard.writeText(json);
            toast.show('good', t('status.report.done'), 6000);
        } catch {
            toast.show('bad', t('status.report.failed'));
        }
    };

    // While connected, a weak way elsewhere is a warning, not trouble.
    const overall: Tone =
        connState === 'connected'
            ? h.bad === 0 && h.warn === 0
                ? 'good'
                : 'warn'
            : h.bad > 0
                ? 'bad'
                : 'neutral';

    const validDays = payload?.pointer?.validForDays ?? conn?.pointerValidDays;
    // An empty fold is not drawn (nothing measured, no list, no failure).
    const foldHasContent =
        overall !== 'neutral' ||
        h.avg !== null ||
        typeof validDays === 'number' ||
        !!failure ||
        (payload?.routeHealth.length ?? 0) > 0;

    return (
        <div data-status-page style={{ width: '100%' }}>
            <PageHeader
                title={t('page.status.title')}
                back={onBack ? { label: t('settings.title'), onClick: onBack } : undefined}
            />

            {error && (
                <div role="alert" style={{ display: 'flex', gap: 8, color: 'var(--red)', fontSize: 13, lineHeight: 1.45, marginBlockEnd: 10 }}>
                    <StateIcon state="bad" size={16} />
                    <span>{t('status.load_failed')}</span>
                </div>
            )}

            {/* Summary: at most four rows, none with an unknown value. */}
            {/* The card clips the last row's line (overflow + -1 px). */}
            <Card style={{ padding: '0 16px', marginBlockStart: 4, overflow: 'hidden' }}>
                <div style={{ marginBlockEnd: -1 }}>
                {connState && (
                    <SumRow
                        id="connection"
                        icon={connState === 'connected' ? 'ok' : connState === 'connecting' ? 'busy' : connState === 'error' ? 'bad' : 'none'}
                        label={t('status.sum.connection')}
                        value={
                            connState === 'connected' ? (
                                <Badge tone="good" size="sm">{t('connection.connected')}</Badge>
                            ) : connState === 'connecting' ? (
                                <Badge tone="gold" size="sm" pulse>{t('status.badge.connecting')}</Badge>
                            ) : connState === 'error' ? (
                                <Badge tone="bad" size="sm">{t('status.badge.failed')}</Badge>
                            ) : (
                                <Badge tone="neutral" size="sm">{t('connection.disconnected')}</Badge>
                            )
                        }
                    />
                )}
                {using && (
                    <SumRow id="using" icon="ok" label={t('status.sum.using')} value={<bdi>{using}</bdi>} />
                )}
                {h.measured > 0 && (
                    <SumRow
                        id="ways"
                        icon={h.ok === h.total ? 'ok' : h.ok > 0 ? 'warn' : 'bad'}
                        label={t('status.sum.ways')}
                        value={t('status.sum.ways.value').replace('{ok}', num(h.ok)).replace('{total}', num(h.total))}
                    />
                )}
                {noInternet && (
                    <SumRow
                        id="internet"
                        icon="bad"
                        label={t('status.sum.internet')}
                        value={<Badge tone="bad" size="sm">{t('status.sum.no_internet')}</Badge>}
                    />
                )}
                </div>
            </Card>

            <div style={{ marginBlock: '16px' }}>
                <Button variant="primary" dataButton="export" leading="copy" onClick={() => void onReport()}>
                    {t('status.report')}
                </Button>
            </div>

            {foldHasContent && (
            <Disclosure variant="card" icon="help" summary={t('ui.helper_fold')} dataButton="helper-fold">
                <div style={{ display: 'grid', gap: 0 }}>
                    {overall !== 'neutral' && (
                        <InfoRow
                            label={t('status.tile.overall')}
                            value={
                                <Badge tone={overall} size="sm">
                                    {t(overall === 'good' ? 'status.overall.good' : overall === 'warn' ? 'status.overall.mixed' : 'status.overall.bad')}
                                </Badge>
                            }
                        />
                    )}
                    {h.avg !== null && (
                        <InfoRow
                            label={t('status.tile.avg_health')}
                            value={
                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
                                    <span style={{ width: 80 }}>
                                        <HealthBar pct={h.avg} tone={h.avg >= 70 ? 'good' : h.avg >= 40 ? 'warn' : 'bad'} />
                                    </span>
                                    <bdi>{pct(h.avg)}</bdi>
                                </span>
                            }
                        />
                    )}
                    {typeof validDays === 'number' && (
                        <InfoRow
                            label={t('status.tile.pointers')}
                            value={
                                validDays < 0 ? (
                                    <Badge tone="bad" size="sm">{t('status.tile.pointers.expired')}</Badge>
                                ) : (
                                    t('status.tile.pointers.valid').replace('{n}', num(validDays))
                                )
                            }
                        />
                    )}
                    {failure && (
                        <InfoRow label={t('status.last_failure')} value={null} below={t(autoVerdictKey(failure.verdict))} />
                    )}
                    {(payload?.routeHealth.length ?? 0) > 0 && (
                        <div style={{ marginBlockStart: 12 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--muted)', marginBlockEnd: 4 }}>
                                {t('status.acc.routes')}
                            </div>
                            {payload!.routeHealth.map((r) => {
                                const st = r.severity === 'ok' ? 'ok' : r.severity === 'warn' ? 'warn' : r.severity === 'bad' ? 'bad' : 'none';
                                const right =
                                    typeof r.pct === 'number' ? pct(r.pct) : gradeText(t, r.measured);
                                return (
                                    <div
                                        key={r.routeId}
                                        data-way-row
                                        style={{ display: 'flex', alignItems: 'center', gap: 10, minHeight: 40, fontSize: 14 }}
                                    >
                                        <StateIcon state={st} size={18} />
                                        <bdi style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                            {r.label || r.routeId}
                                        </bdi>
                                        {right && <span style={{ color: 'var(--muted)', fontSize: 13, flexShrink: 0 }}>{right}</span>}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </Disclosure>
            )}

            {dev && (
                <div style={{ marginBlockStart: 16 }}>
                    <DevStatus t={t} payload={payload} />
                </div>
            )}
            {toast.node}
        </div>
    );
}

function SumRow({ id, icon, label, value }: { id: string; icon: 'ok' | 'warn' | 'bad' | 'busy' | 'none'; label: string; value: ReactNode }) {
    return (
        <div
            data-sum-row={id}
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                minHeight: 52,
                borderBottom: '1px solid var(--line-soft)',
            }}
        >
            <StateIcon state={icon} size={20} />
            <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)', flexShrink: 0 }}>{label}</span>
            <span
                style={{
                    flex: 1,
                    minWidth: 0,
                    display: 'flex',
                    justifyContent: 'flex-end',
                    fontSize: 14,
                    color: 'var(--muted)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                }}
            >
                {value}
            </span>
        </div>
    );
}

function InfoRow({ label, value, below }: { label: string; value: ReactNode; below?: string }) {
    return (
        <div style={{ paddingBlock: 8, borderBottom: '1px solid var(--line-soft)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, minHeight: 28 }}>
                <span style={{ flex: 1, fontSize: 14, color: 'var(--fg)' }}>{label}</span>
                {value !== null && <span style={{ fontSize: 14, color: 'var(--muted)', whiteSpace: 'nowrap' }}>{value}</span>}
            </div>
            {below && <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.45 }}>{below}</div>}
        </div>
    );
}

// ---- [dev] developer tools ------------------------------------------

function DevStatus({ t, payload }: { t: (k: string) => string; payload: StatusPagePayload | null }) {
    const contract = useContract();
    const [sched, setSched] = useState<SchedulerStatus | null>(null);
    const [stats, setStats] = useState<StatsRedacted | null>(null);
    const [bootSt, setBootSt] = useState<BootstrapStatus | null>(null);
    const [probes, setProbes] = useState<{ udp?: ProbeResult; dns?: ProbeResult; tcp?: ProbeResult }>({});
    const [probing, setProbing] = useState(false);
    const [probeErr, setProbeErr] = useState<string | null>(null);
    const [bootResult, setBootResult] = useState<{ ok: boolean; text: string } | null>(null);

    useEffect(() => {
        let cancelled = false;
        const load = async () => {
            const [s, st, bs] = await Promise.all([
                contract.schedulerStatus().catch(() => ({ json: '' })),
                contract.statsRedacted().catch(() => ({ json: '' })),
                contract.bootstrapStatus().catch(() => ({ json: '' })),
            ]);
            if (cancelled) return;
            setSched(s);
            setStats(st);
            setBootSt(bs);
        };
        void load();
        const id = setInterval(load, 3000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    // Throughput: only while a number exists. null = this build counts
    // no bytes, and a flat line would claim it measured nothing moving.
    const upHistory = useRef<number[]>([]);
    const downHistory = useRef<number[]>([]);
    const [, forceTick] = useState(0);
    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const tp = await contract.throughputSnapshot();
                if (cancelled) return;
                if (tp.upBytesPerSec !== null) upHistory.current = [...upHistory.current.slice(-59), tp.upBytesPerSec];
                if (tp.downBytesPerSec !== null) downHistory.current = [...downHistory.current.slice(-59), tp.downBytesPerSec];
                forceTick((n) => (n + 1) % 1024);
            } catch {
                /* no sample: the row stays hidden */
            }
        };
        void tick();
        const id = setInterval(tick, 1000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);
    const lastUp = upHistory.current[upHistory.current.length - 1] ?? null;
    const lastDown = downHistory.current[downHistory.current.length - 1] ?? null;

    const runProbes = async () => {
        setProbing(true);
        setProbeErr(null);
        try {
            const [udp, dns, tcp] = await Promise.all([
                contract.probeUdp(2000),
                contract.probeDns(2000),
                contract.probeTcp443(2000),
            ]);
            setProbes({ udp, dns, tcp });
        } catch (e) {
            setProbeErr(errorText(e));
        } finally {
            setProbing(false);
        }
    };

    const boot = async (which: 'install' | 'refresh') => {
        setBootResult(null);
        try {
            const out = which === 'install' ? await contract.bootstrapInstallSeeds() : await contract.bootstrapRefresh(8000);
            setBootResult({ ok: true, text: out ? `${t('status.bootstrap.ok')} · ${out}` : t('status.bootstrap.ok') });
        } catch (e) {
            setBootResult({ ok: false, text: t('status.bootstrap.failed').replace('{error}', errorText(e)) });
        }
    };

    const bucket = new Date().toISOString().slice(0, 13).replace('T', ' ') + 'h';
    const rowStyle = { display: 'flex', alignItems: 'center', gap: 12, minHeight: 40, borderBottom: '1px solid var(--line-soft)' } as const;
    const mono = { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' } as const;

    return (
        <Card>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, minHeight: 28 }}>
                <h2 style={{ margin: 0, flex: 1, fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 500 }}>
                    {t('settings.dev.title')}
                </h2>
            </div>
            <div style={rowStyle}>
                <span style={{ flex: 1, fontSize: 14 }}>{t('status.tile.bucket')}</span>
                <span dir="ltr" style={mono}>{bucket}</span>
            </div>
            {lastUp !== null && lastDown !== null && (
                <div style={rowStyle}>
                    <span style={{ flex: 1, fontSize: 14 }}>{t('status.tile.throughput')}</span>
                    <span dir="ltr" style={mono}>↑ {fmtBps(lastUp)} · ↓ {fmtBps(lastDown)}</span>
                    <Sparkline values={downHistory.current} tone="gold" width={80} height={24} />
                </div>
            )}

            <DevFold title={t('status.acc.network')} id="dev-network">
                <Button variant="secondary" size="sm" dataButton="run-probes" disabled={probing} onClick={() => void runProbes()}>
                    {probing ? t('status.probes.running') : `${t('status.probes.run')} ${t('status.probes.stub')}`}
                </Button>
                {probeErr && <div style={{ color: 'var(--red)', fontSize: 13, marginBlockStart: 6 }}>{probeErr}</div>}
                {(probes.udp || probes.dns || probes.tcp) && (
                    <div style={{ display: 'grid', gap: 4, marginBlockStart: 8 }}>
                        <ProbeLine label={t('status.probes.udp')} probe={probes.udp} t={t} />
                        <ProbeLine label={t('status.probes.dns')} probe={probes.dns} t={t} />
                        <ProbeLine label={t('status.probes.tcp443')} probe={probes.tcp} t={t} />
                    </div>
                )}
            </DevFold>
            <DevFold title={t('status.acc.scheduler')} id="dev-scheduler">
                <pre style={preStyle}>{prettyJson(sched?.json)}</pre>
            </DevFold>
            <DevFold title={t('status.acc.stats')} id="dev-stats">
                <pre style={preStyle}>{prettyJson(stats?.json)}</pre>
            </DevFold>
            <DevFold title={t('status.acc.bootstrap')} id="dev-bootstrap">
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBlockEnd: 8 }}>
                    <Button variant="secondary" size="sm" dataButton="install-seeds" onClick={() => void boot('install')}>
                        {t('status.bootstrap.install')}
                    </Button>
                    <Button variant="secondary" size="sm" dataButton="bootstrap-refresh" onClick={() => void boot('refresh')}>
                        {t('status.bootstrap.refresh')}
                    </Button>
                </div>
                {bootResult && (
                    <div role="status" style={{ fontSize: 13, color: bootResult.ok ? 'var(--green)' : 'var(--red)', marginBlockEnd: 8, overflowWrap: 'anywhere' }}>
                        {bootResult.text}
                    </div>
                )}
                <pre style={preStyle}>{prettyJson(bootSt?.json)}</pre>
            </DevFold>
            <DevFold title={t('status.acc.raw')} id="dev-raw">
                <pre style={preStyle}>{prettyJson(payload?.rawDiagnosticsJson)}</pre>
            </DevFold>
        </Card>
    );
}

function DevFold({ title, id, children }: { title: string; id: string; children: ReactNode }) {
    return (
        <div style={{ borderBottom: '1px solid var(--line-soft)' }}>
            <Disclosure summary={title} dataButton={id}>
                {children}
            </Disclosure>
        </div>
    );
}

function ProbeLine({ label, probe, t }: { label: string; probe: ProbeResult | undefined; t: (k: string) => string }) {
    const st = !probe || probe.unavailable ? 'off' : probe.ok ? 'ok' : 'bad';
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
            <StateIcon state={st} size={16} />
            <span style={{ flex: 1 }}>{label}</span>
            <span dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' }}>
                {!probe ? '—' : probe.unavailable ? t('status.probes.unavailable') : `${probe.ok ? 'ok' : 'fail'} (${probe.raw})`}
            </span>
        </div>
    );
}

const preStyle = {
    background: 'var(--bg-deep)',
    color: 'var(--muted)',
    padding: 10,
    borderRadius: 'var(--r-tile)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    margin: 0,
    whiteSpace: 'pre-wrap' as const,
    overflowWrap: 'anywhere' as const,
    maxHeight: 320,
    overflow: 'auto' as const,
    direction: 'ltr' as const,
    textAlign: 'start' as const,
};

function prettyJson(s: string | undefined): string {
    if (!s) return '—';
    try {
        return JSON.stringify(JSON.parse(s), null, 2);
    } catch {
        return s;
    }
}

export function fmtBps(bps: number): string {
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
