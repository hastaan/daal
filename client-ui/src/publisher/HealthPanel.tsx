// HealthPanel — "is my relay working?", answered as far as this phone
// can answer it (D3). Logic and wording rules live in relayHealth.ts.

import { Button, Card } from '../design/primitives';
import type { RelayHealth } from './wizardCommands';
import type { Failure } from './failureText';
import { WhatIsThis } from './Disclosure';
import { healthIsFresh, healthLines, overallKey, renderLine } from './relayHealth';

const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.55 };

function timeLabel(unix: number): string {
    if (!unix) return '';
    try {
        // The phone's own time zone: a UTC time reads as hours off.
        return new Date(unix * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    } catch {
        return '';
    }
}

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
    const stale = health ? !healthIsFresh(health, now) : false;
    const lines = health ? healthLines(t, health) : [];
    const overallColor =
        health?.overall === 'working'
            ? 'var(--green)'
            : health?.overall === 'not_working'
              ? 'var(--red)'
              : 'var(--gold)';
    return (
        <Card>
            <div style={{ display: 'grid', gap: 8 }} data-testid="health-panel">
                <div
                    style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        gap: 10,
                        flexWrap: 'wrap',
                    }}
                >
                    <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>
                        {t('pub.health.title')}
                    </div>
                    <Button variant="secondary" size="sm" disabled={busy} onClick={onCheck}>
                        {busy ? t('pub.health.checking') : t('pub.health.check_now')}
                    </Button>
                </div>

                {!health && !busy && !failed && <div style={SUB}>{t('pub.health.never')}</div>}
                {!health && busy && <div style={SUB}>{t('pub.health.checking')}</div>}
                {failed && (
                    <div style={{ ...SUB, color: 'var(--red)' }}>{failed.message}</div>
                )}

                {health && (
                    <>
                        <div style={{ fontSize: 14, color: overallColor, fontWeight: 600, lineHeight: 1.45 }}>
                            {t(overallKey(health.overall))}
                        </div>
                        <div style={SUB}>
                            {(stale ? t('pub.health.checked_stale') : t('pub.health.checked_at')).replace(
                                '{time}',
                                timeLabel(health.checked_at_unix),
                            )}
                        </div>
                        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 }}>
                            {lines.map((l, i) => (
                                <li
                                    key={i}
                                    style={{
                                        fontSize: 13,
                                        lineHeight: 1.5,
                                        fontWeight: l.serious ? 600 : 400,
                                        color:
                                            l.tone === 'bad'
                                                ? 'var(--red)'
                                                : l.tone === 'good'
                                                  ? 'var(--fg)'
                                                  : 'var(--muted)',
                                    }}
                                >
                                    <span aria-hidden style={{ marginInlineEnd: 6 }}>
                                        {l.tone === 'good' ? '✓' : l.tone === 'bad' ? '✗' : '·'}
                                    </span>
                                    {renderLine(t, l)}
                                </li>
                            ))}
                        </ul>
                        {onRenew && ((health.people_missing ?? 0) > 0 || health.everyone_missing === true) && (
                            <div>
                                <Button size="sm" onClick={onRenew}>
                                    {t('pub.renew.action')}
                                </Button>
                            </div>
                        )}
                    </>
                )}

                {/* Said once, here, and nowhere else on the page. */}
                <div style={{ ...SUB, fontStyle: 'italic' }}>{t('pub.health.limits')}</div>

                {((failed && failed.detail) || (health?.details ?? []).length > 0) && (
                    <WhatIsThis label={t('pub.fb.details')}>
                        {failed && failed.detail && <div dir="ltr">{failed.detail}</div>}
                        {(health?.details ?? []).map((d, i) => (
                            <div key={i} dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                {d}
                            </div>
                        ))}
                    </WhatIsThis>
                )}
            </div>
        </Card>
    );
}
