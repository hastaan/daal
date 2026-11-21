// HealthPanel — "is my relay working?", answered as far as this phone
// can answer it (D3). Logic and wording rules live in relayHealth.ts.
//
// One row (spec C7.2 §3): a badge, the time of the check and a "check
// now" icon. Under it, always, the hedge (MUST KEEP 7): this phone
// cannot see blocking inside Iran. Only the checks that FAILED are
// listed on the card; the full checklist is behind "What was checked"
// (not "Details": the relay page has a Details card of its own).

import { Badge, Card, Disclosure, IconButton, Icon, StateIcon } from '../design/primitives';
import type { BadgeTone } from '../design/primitives';
import { formatTime } from '../lib/format';
import type { RelayHealth } from './wizardCommands';
import type { Failure } from './failureText';
import { healthIsFresh, healthLines, renderLine } from './relayHealth';
import type { HealthLine } from './relayHealth';
import { useDeviceT, useLocale } from './ui';

const SUB: React.CSSProperties = { fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 };

const BADGE: Record<RelayHealth['overall'], { tone: BadgeTone; key: string }> = {
    working: { tone: 'good', key: 'pub.relays.status.working' },
    partly: { tone: 'warn', key: 'pub.relays.status.partly' },
    not_working: { tone: 'bad', key: 'pub.relays.status.not_working' },
    unknown: { tone: 'neutral', key: 'pub.relays.status.not_checked' },
};

/** At most this many failing lines on the card; the rest are in Details. */
export const HEALTH_FAILING_MAX = 5;

/** The lines a person must see without opening anything: only failures. */
export function failingLines(lines: HealthLine[]): HealthLine[] {
    return lines.filter((l) => l.tone === 'bad').slice(0, HEALTH_FAILING_MAX);
}

function LineRow({ t, l }: { t: (k: string) => string; l: HealthLine }) {
    return (
        <li style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 13, lineHeight: 1.5 }}>
            <span style={{ display: 'inline-flex', paddingBlockStart: 1, flexShrink: 0 }}>
                <StateIcon state={l.tone === 'good' ? 'ok' : l.tone === 'bad' ? 'bad' : 'off'} size={16} />
            </span>
            <span style={{ color: l.tone === 'neutral' ? 'var(--muted)' : 'var(--fg)', fontWeight: l.serious ? 600 : 400 }}>
                {renderLine(t, l)}
            </span>
        </li>
    );
}

const LIST: React.CSSProperties = { listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 };

export function HealthPanel({
    t,
    health,
    busy,
    failed,
    now,
    onCheck,
    onRenew,
}: {
    t: (k: string) => string;
    health: RelayHealth | null;
    busy: boolean;
    /** The check itself could not run: a plain sentence, and the raw
     *  text for Details (see `healthFailure`). */
    failed: Failure | null;
    now: number;
    onCheck: () => void;
    /** Present when people are missing on the server: go to D2. */
    onRenew?: () => void;
}) {
    const locale = useLocale();
    const dt = useDeviceT(t);
    const lines = health ? healthLines(t, health) : [];
    const failing = health && health.overall !== 'working' ? failingLines(lines) : [];
    const stale = health ? !healthIsFresh(health, now) : false;
    const b = health ? BADGE[health.overall] : BADGE.unknown;
    const showRenew = !!onRenew && !!health && ((health.people_missing ?? 0) > 0 || health.everyone_missing === true);
    return (
        <Card>
            <div style={{ display: 'grid', gap: 8 }} data-testid="health-panel">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: 44 }}>
                    <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        {busy ? (
                            <Badge tone="neutral" pulse>
                                {t('pub.health.checking')}
                            </Badge>
                        ) : (
                            <Badge tone={b.tone}>{t(b.key)}</Badge>
                        )}
                        {health && health.checked_at_unix > 0 && (
                            <span style={{ ...SUB, color: stale ? 'var(--amber)' : 'var(--muted)' }} data-testid="health-time">
                                {'· '}
                                {formatTime(locale, health.checked_at_unix)}
                            </span>
                        )}
                    </div>
                    <IconButton
                        label={busy ? t('pub.health.checking') : t('pub.health.check_now')}
                        dataButton="check-now"
                        disabled={busy}
                        onClick={onCheck}
                    >
                        <Icon name="refresh" size={20} />
                    </IconButton>
                </div>

                {/* MUST KEEP 7, always, under the badge. */}
                <div style={SUB} data-testid="health-hedge">
                    {dt('pub.health.hedge')}
                </div>

                {failed && <div style={{ ...SUB, color: 'var(--red)' }}>{failed.message}</div>}

                {failing.length > 0 && (
                    <ul style={LIST} data-testid="health-failing">
                        {failing.map((l, i) => (
                            <LineRow key={i} t={t} l={l} />
                        ))}
                    </ul>
                )}

                {showRenew && (
                    <div>
                        <button
                            type="button"
                            onClick={onRenew}
                            data-button="renew"
                            style={{
                                appearance: 'none',
                                background: 'transparent',
                                border: 0,
                                padding: '10px 4px',
                                minHeight: 44,
                                color: 'var(--gold-warm)',
                                font: 'inherit',
                                fontSize: 14,
                                fontWeight: 600,
                                cursor: 'pointer',
                            }}
                        >
                            {t('pub.renew.action')}
                        </button>
                    </div>
                )}

                <div style={{ display: 'flex', flexWrap: 'wrap', columnGap: 16 }}>
                    <Disclosure summary={t('pub.health.why')} icon="help" dataButton="health-why">
                        <div style={SUB}>{t('pub.health.limits')}</div>
                    </Disclosure>
                    {(lines.length > 0 || (failed && failed.detail)) && (
                        <Disclosure summary={t('pub.health.checked')} dataButton="health-details">
                            <div style={{ display: 'grid', gap: 8 }}>
                                {health && <div style={SUB}>{dt(`pub.health.overall.${health.overall}`)}</div>}
                                {lines.length > 0 && (
                                    <ul style={LIST}>
                                        {lines.map((l, i) => (
                                            <LineRow key={i} t={t} l={l} />
                                        ))}
                                    </ul>
                                )}
                                {failed && failed.detail && (
                                    <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                                        {failed.detail}
                                    </div>
                                )}
                                {(health?.details ?? []).map((d, i) => (
                                    <div
                                        key={i}
                                        dir="ltr"
                                        style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)', wordBreak: 'break-word' }}
                                    >
                                        {d}
                                    </div>
                                ))}
                            </div>
                        </Disclosure>
                    )}
                </div>
            </div>
        </Card>
    );
}
