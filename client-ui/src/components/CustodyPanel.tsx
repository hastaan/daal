// CustodyPanel.tsx — Device Custody B4 panel for Settings.
//
// Renders inside the Settings → Privacy section. Shows:
//   - the honest custody level (hardware / OS keystore / session
//     passphrase) with a status pill,
//   - a Lock-now button (only meaningful on session-passphrase
//     devices, hidden on hardware/OS-keystore since lock() is a
//     no-op there),
//   - a Rotate-identity button that pops a confirm dialog before
//     calling DeviceCustody.rotate(),
//   - an expandable History view listing retired addresses + an
//     audit log of custody-level events.
//
// All copy is i18n-keyed (`settings.custody.*`) and falls back to
// English when the catalog is missing the key.

import { useCallback, useEffect, useState } from 'react';
import {
    DeviceCustody,
    type CustodyEventRow,
    type CustodyLevel,
    type RecipientIdentityHistoryRow,
    type RecipientIdentitySummary,
    RecipientIdentity,
} from '../recipient/recipientCommands';
import { Card, ListRow } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

export default function CustodyPanel({ t }: Props) {
    const [level, setLevel] = useState<CustodyLevel | null>(null);
    const [unlocked, setUnlocked] = useState<boolean>(true);
    const [identity, setIdentity] = useState<RecipientIdentitySummary | null>(null);
    const [history, setHistory] = useState<RecipientIdentityHistoryRow[]>([]);
    const [events, setEvents] = useState<CustodyEventRow[]>([]);
    const [showHistory, setShowHistory] = useState(false);
    const [showRotate, setShowRotate] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [toast, setToast] = useState<string | null>(null);

    const reload = useCallback(async () => {
        try {
            const [lvl, u, id, h, ev] = await Promise.all([
                DeviceCustody.level().catch(() => null),
                DeviceCustody.isUnlocked().catch(() => true),
                RecipientIdentity.get().catch(() => null),
                DeviceCustody.history().catch(() => [] as RecipientIdentityHistoryRow[]),
                DeviceCustody.events(50).catch(() => [] as CustodyEventRow[]),
            ]);
            setLevel(lvl);
            setUnlocked(u);
            setIdentity(id);
            setHistory(h);
            setEvents(ev);
        } catch (e) {
            setError(String(e));
        }
    }, []);

    useEffect(() => {
        reload();
    }, [reload]);

    const onLockNow = async () => {
        setBusy(true);
        setError(null);
        try {
            await DeviceCustody.lock();
            setUnlocked(false);
            setToast(t('settings.custody.locked_toast'));
            setTimeout(() => setToast(null), 1500);
            await reload();
        } catch (e) {
            setError(String(e));
        } finally {
            setBusy(false);
        }
    };

    const onRotateConfirm = async () => {
        setBusy(true);
        setError(null);
        try {
            const next = await DeviceCustody.rotate();
            setIdentity(next);
            setShowRotate(false);
            setToast(t('settings.custody.rotated_toast'));
            setTimeout(() => setToast(null), 2500);
            await reload();
        } catch (e) {
            setError(String(e));
        } finally {
            setBusy(false);
        }
    };

    const levelLabel = (l: CustodyLevel | null): string => {
        if (!l) return '—';
        return t(`recipient.address.custody.${l}`);
    };
    const fmtTs = (n: number) => {
        if (!n) return '—';
        try {
            return new Date(n * 1000).toLocaleString();
        } catch {
            return String(n);
        }
    };
    const shortAddr = (addr: string) => {
        if (addr.length < 16) return addr;
        return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
    };

    return (
        <Card style={{ padding: 0 }}>
            <div style={{ padding: '0 16px' }}>
                <ListRow
                    title={t('settings.custody.level_title')}
                    subtitle={levelLabel(level)}
                    trailing={
                        <span
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 10,
                                letterSpacing: '0.08em',
                                textTransform: 'uppercase',
                                color: unlocked ? 'var(--green)' : 'var(--amber)',
                            }}
                        >
                            {unlocked
                                ? t('settings.custody.unlocked')
                                : t('settings.custody.locked')}
                        </span>
                    }
                />
                {identity && (
                    <ListRow
                        title={t('settings.custody.current_address')}
                        subtitle={
                            <span
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 12,
                                    color: 'var(--muted)',
                                    wordBreak: 'break-all',
                                }}
                            >
                                {identity.address}
                            </span>
                        }
                    />
                )}
                {level === 'session_passphrase' && (
                    <ListRow
                        title={t('settings.custody.lock_now')}
                        subtitle={t('settings.custody.lock_now.help')}
                        trailing={
                            <button
                                disabled={busy || !unlocked}
                                onClick={onLockNow}
                                style={smallBtn(false)}
                            >
                                {t('settings.custody.lock_now.button')}
                            </button>
                        }
                    />
                )}
                <ListRow
                    title={t('settings.custody.rotate')}
                    subtitle={t('settings.custody.rotate.help')}
                    trailing={
                        <button
                            disabled={busy || !identity}
                            onClick={() => setShowRotate(true)}
                            style={smallBtn(false)}
                        >
                            {t('settings.custody.rotate.button')}
                        </button>
                    }
                />
                <ListRow
                    title={t('settings.custody.history')}
                    subtitle={
                        history.length === 0
                            ? t('settings.custody.history.empty')
                            : t('settings.custody.history.count').replace(
                                  '{n}',
                                  String(history.length),
                              )
                    }
                    trailing={
                        <button
                            onClick={() => setShowHistory((v) => !v)}
                            style={smallBtn(true)}
                        >
                            {showHistory
                                ? t('settings.custody.history.hide')
                                : t('settings.custody.history.show')}
                        </button>
                    }
                    last={!showHistory}
                />
                {showHistory && (
                    <div
                        style={{
                            padding: '8px 0 14px',
                            borderTop: '1px solid var(--line-soft)',
                        }}
                    >
                        {/* Retired addresses */}
                        {history.length === 0 ? (
                            <div
                                style={{
                                    color: 'var(--muted)',
                                    fontSize: 12,
                                    padding: '6px 0',
                                }}
                            >
                                {t('settings.custody.history.empty')}
                            </div>
                        ) : (
                            <div style={{ display: 'grid', gap: 6 }}>
                                {history.map((h) => (
                                    <div
                                        key={h.id}
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 11,
                                            color: 'var(--muted)',
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            gap: 8,
                                        }}
                                    >
                                        <span>
                                            v{h.version}{' '}
                                            <span style={{ color: 'var(--fg)' }}>
                                                {shortAddr(h.address_str)}
                                            </span>
                                        </span>
                                        <span>{fmtTs(h.retired_at_unix)}</span>
                                    </div>
                                ))}
                            </div>
                        )}

                        {/* Audit events */}
                        <div
                            style={{
                                marginTop: 14,
                                fontFamily: 'var(--font-mono)',
                                fontSize: 10,
                                letterSpacing: '0.16em',
                                textTransform: 'uppercase',
                                color: 'var(--dim)',
                            }}
                        >
                            {t('settings.custody.events')}
                        </div>
                        {events.length === 0 ? (
                            <div
                                style={{
                                    color: 'var(--muted)',
                                    fontSize: 12,
                                    padding: '6px 0',
                                }}
                            >
                                —
                            </div>
                        ) : (
                            <div style={{ display: 'grid', gap: 4, marginTop: 6 }}>
                                {events.slice(0, 20).map((e) => (
                                    <div
                                        key={e.id}
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 11,
                                            color: 'var(--muted)',
                                            display: 'flex',
                                            justifyContent: 'space-between',
                                            gap: 8,
                                        }}
                                    >
                                        <span style={{ color: 'var(--fg)' }}>
                                            {t(`settings.custody.event.${e.kind}`)}
                                        </span>
                                        <span>{fmtTs(e.at_unix)}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                )}
                {error && (
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            color: 'var(--red)',
                            padding: '0 0 12px',
                        }}
                    >
                        {error}
                    </div>
                )}
            </div>
            {toast && (
                <div
                    role="status"
                    style={{
                        textAlign: 'center',
                        padding: '6px 0 10px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: 'var(--green)',
                    }}
                >
                    {toast}
                </div>
            )}

            {showRotate && (
                <RotateDialog
                    t={t}
                    busy={busy}
                    onCancel={() => setShowRotate(false)}
                    onConfirm={onRotateConfirm}
                />
            )}
        </Card>
    );
}

function smallBtn(ghost: boolean) {
    return {
        background: ghost ? 'transparent' : 'var(--surface-2)',
        border: ghost
            ? '1px solid var(--line-soft)'
            : '1px solid var(--gold)',
        color: ghost ? 'var(--muted)' : 'var(--fg)',
        padding: '5px 12px',
        borderRadius: 'var(--r-pill)',
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        letterSpacing: '0.06em',
        textTransform: 'uppercase' as const,
        cursor: 'pointer' as const,
    };
}

interface RotateDialogProps {
    t: (k: string) => string;
    busy: boolean;
    onCancel: () => void;
    onConfirm: () => void;
}

function RotateDialog({ t, busy, onCancel, onConfirm }: RotateDialogProps) {
    const [confirmed, setConfirmed] = useState(false);
    return (
        <div
            role="dialog"
            aria-modal="true"
            onClick={onCancel}
            style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0,0,0,0.6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 200,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    background: 'var(--surface-1)',
                    border: '1px solid var(--line-soft)',
                    borderRadius: 12,
                    padding: 24,
                    width: 'min(440px, 92vw)',
                }}
            >
                <h3
                    style={{
                        margin: 0,
                        fontFamily: 'var(--font-display)',
                        fontSize: 18,
                        color: 'var(--fg)',
                    }}
                >
                    {t('settings.custody.rotate.dialog.title')}
                </h3>
                <p
                    style={{
                        marginTop: 8,
                        fontSize: 13,
                        color: 'var(--muted)',
                        lineHeight: 1.5,
                    }}
                >
                    {t('settings.custody.rotate.dialog.body')}
                </p>
                <label
                    style={{
                        display: 'flex',
                        gap: 8,
                        alignItems: 'flex-start',
                        marginTop: 14,
                        fontSize: 12,
                        color: 'var(--muted)',
                        lineHeight: 1.4,
                    }}
                >
                    <input
                        type="checkbox"
                        checked={confirmed}
                        onChange={(e) => setConfirmed(e.target.checked)}
                    />
                    <span>
                        {t('settings.custody.rotate.dialog.checkbox')}
                    </span>
                </label>
                <div
                    style={{
                        marginTop: 18,
                        display: 'flex',
                        gap: 10,
                        justifyContent: 'flex-end',
                    }}
                >
                    <button onClick={onCancel} style={smallBtn(true)}>
                        {t('settings.custody.rotate.dialog.cancel')}
                    </button>
                    <button
                        onClick={onConfirm}
                        disabled={!confirmed || busy}
                        style={{
                            ...smallBtn(false),
                            background: confirmed
                                ? 'color-mix(in oklab, var(--red) 22%, transparent)'
                                : 'var(--surface-3)',
                            border:
                                '1px solid color-mix(in oklab, var(--red) 60%, transparent)',
                            color: 'var(--red)',
                            opacity: !confirmed || busy ? 0.5 : 1,
                        }}
                    >
                        {busy
                            ? t('settings.custody.rotate.dialog.busy')
                            : t('settings.custody.rotate.dialog.confirm')}
                    </button>
                </div>
            </div>
        </div>
    );
}
