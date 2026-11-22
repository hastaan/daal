// CustodyPanel.tsx — "My Daal address" in Settings → Advanced (spec C5.2).
//
//   - the address, and how this device protects its key, as one Badge
//     (a "Locked" badge while a session-passphrase device is locked);
//   - "Lock now" (only on session-passphrase devices, where lock() does
//     something; hardware and OS keystore re-fetch the key per call);
//   - "Get a new address", which asks first: the old files still open,
//     and the person must send the new address on (MUST KEEP 15, with
//     its checkbox);
//   - a "History" fold: earlier addresses and recent changes.

import { useCallback, useEffect, useState } from 'react';
import {
    DeviceCustody,
    type CustodyEventRow,
    type CustodyLevel,
    type RecipientIdentityHistoryRow,
    type RecipientIdentitySummary,
    RecipientIdentity,
} from '../recipient/recipientCommands';
import type { Locale } from '../lib/i18n';
import { errorText } from '../lib/errorText';
import { formatDate } from '../lib/format';
import { Badge, Button, Card, Disclosure, ListRow, Sheet, StateIcon, useToast } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    locale?: Locale;
}

/** `daal1qm3n8v2k…` → `daal1 qm3n 8v2k …`: easier to read aloud and compare. */
export function groupAddress(addr: string): string {
    const m = /^(daal1)(.*)$/i.exec(addr.trim());
    if (!m) return addr;
    const groups = m[2].match(/.{1,4}/g) ?? [];
    return [m[1], ...groups].join(' ');
}

export default function CustodyPanel({ t, locale = 'en' }: Props) {
    const [level, setLevel] = useState<CustodyLevel | null>(null);
    const [unlocked, setUnlocked] = useState<boolean>(true);
    const [identity, setIdentity] = useState<RecipientIdentitySummary | null>(null);
    const [history, setHistory] = useState<RecipientIdentityHistoryRow[]>([]);
    const [events, setEvents] = useState<CustodyEventRow[]>([]);
    const [showRotate, setShowRotate] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const toast = useToast();

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
            setError(errorText(e));
        }
    }, []);

    useEffect(() => {
        void reload();
    }, [reload]);

    const onLockNow = async () => {
        setBusy(true);
        setError(null);
        try {
            await DeviceCustody.lock();
            setUnlocked(false);
            toast.show('good', t('settings.custody.locked_toast'));
            await reload();
        } catch (e) {
            setError(errorText(e));
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
            toast.show('good', t('settings.custody.rotated_toast'), 6000);
            await reload();
        } catch (e) {
            setShowRotate(false);
            setError(errorText(e));
        } finally {
            setBusy(false);
        }
    };

    const when = (unix: number) => (unix ? formatDate(locale, unix, 'dayTime') : '—');

    const badge = !unlocked ? (
        <Badge tone="warn" size="sm" icon="lock">
            {t('settings.custody.locked')}
        </Badge>
    ) : level ? (
        <Badge tone="neutral" size="sm" icon="lock" title={t(`recipient.address.custody.${level}`)}>
            {t(`settings.custody.badge.${level}`)}
        </Badge>
    ) : null;

    // Nothing to show or do (no address made yet, custody unknown): the
    // card is not drawn rather than shown empty.
    if (!identity && !level && history.length === 0 && events.length === 0 && !error) return null;

    return (
        <Card style={{ paddingBlockEnd: 6 }}>
            <div data-custody-panel style={{ display: 'flex', alignItems: 'center', gap: 10, minHeight: 28, flexWrap: 'wrap' }}>
                <h2
                    style={{
                        margin: 0,
                        flex: '1 1 auto',
                        fontFamily: 'var(--font-display)',
                        fontSize: 17,
                        fontWeight: 500,
                        color: 'var(--fg)',
                    }}
                >
                    {t('settings.custody.section')}
                </h2>
                {badge}
            </div>
            {level && (
                // The full sentence for screen readers ("Protected by
                // secure hardware"); the badge carries the short form.
                <span style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clipPath: 'inset(50%)' }}>
                    {t(`recipient.address.custody.${level}`)}
                </span>
            )}
            {identity && (
                <div
                    dir="ltr"
                    style={{
                        marginBlockStart: 8,
                        fontFamily: 'var(--font-mono)',
                        fontSize: 13,
                        lineHeight: 1.5,
                        color: 'var(--muted)',
                        overflowWrap: 'anywhere',
                        userSelect: 'text',
                        textAlign: 'start',
                    }}
                >
                    {groupAddress(identity.address)}
                </div>
            )}

            <div style={{ marginBlockStart: 4 }}>
                {level === 'session_passphrase' && (
                    <ListRow
                        dataButton="lock-now"
                        title={t('settings.custody.lock_now')}
                        subtitle={t('settings.custody.lock_now.help')}
                        onClick={busy || !unlocked ? undefined : () => void onLockNow()}
                    />
                )}
                {identity && (
                    <ListRow
                        dataButton="new-address"
                        title={t('settings.custody.rotate')}
                        chevron
                        onClick={busy ? undefined : () => setShowRotate(true)}
                        last
                    />
                )}
            </div>

            {error && (
                <div role="alert" style={{ display: 'flex', gap: 8, color: 'var(--red)', fontSize: 13, lineHeight: 1.45, paddingBlock: 6 }}>
                    <StateIcon state="bad" size={16} />
                    <span>{t('settings.failed')}</span>
                </div>
            )}

            {(history.length > 0 || events.length > 0) && (
            <Disclosure summary={t('settings.custody.history')} dataButton="custody-history">
                <div style={{ display: 'grid', gap: 6, fontSize: 13, color: 'var(--muted)' }}>
                    {history.length === 0 ? (
                        <div>{t('settings.custody.history.empty')}</div>
                    ) : (
                        history.map((h) => (
                            <div key={h.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                                <span dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {groupAddress(h.address_str)}
                                </span>
                                <span style={{ flexShrink: 0 }}>{when(h.retired_at_unix)}</span>
                            </div>
                        ))
                    )}
                    {events.length > 0 && (
                        <>
                            <div style={{ marginBlockStart: 8, fontWeight: 600 }}>{t('settings.custody.events')}</div>
                            {events.slice(0, 20).map((e) => (
                                <div key={e.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                                    <span style={{ color: 'var(--fg)' }}>{t(`settings.custody.event.${e.kind}`)}</span>
                                    <span style={{ flexShrink: 0 }}>{when(e.at_unix)}</span>
                                </div>
                            ))}
                        </>
                    )}
                </div>
            </Disclosure>
            )}

            {showRotate && (
                <RotateDialog
                    t={t}
                    busy={busy}
                    onCancel={() => setShowRotate(false)}
                    onConfirm={() => void onRotateConfirm()}
                />
            )}
            {toast.node}
        </Card>
    );
}

interface RotateDialogProps {
    t: (k: string) => string;
    busy: boolean;
    onCancel: () => void;
    onConfirm: () => void;
}

function RotateDialog({ t, busy, onCancel, onConfirm }: RotateDialogProps) {
    const [confirmed, setConfirmed] = useState(false);
    // Back, Escape and a tap outside are Cancel, refused while it runs.
    const close = () => {
        if (!busy) onCancel();
    };
    return (
        <Sheet title={t('settings.custody.rotate.dialog.title')} onClose={close} width={460}>
            <div data-rotate-dialog style={{ display: 'grid', gap: 14, marginBlockStart: 8 }}>
                <p style={{ margin: 0, fontSize: 14, lineHeight: 1.5, color: 'var(--fg)' }}>
                    {t('settings.custody.rotate.dialog.body')}
                </p>
                <label
                    style={{
                        display: 'flex',
                        gap: 12,
                        alignItems: 'center',
                        minHeight: 44,
                        fontSize: 14,
                        color: 'var(--fg)',
                        lineHeight: 1.4,
                        cursor: 'pointer',
                    }}
                >
                    <input
                        type="checkbox"
                        data-button="rotate-understand"
                        checked={confirmed}
                        onChange={(e) => setConfirmed(e.target.checked)}
                        style={{ width: 22, height: 22, flexShrink: 0, accentColor: 'var(--gold)' }}
                    />
                    <span>{t('settings.custody.rotate.dialog.checkbox')}</span>
                </label>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
                    <Button variant="ghost" dataButton="rotate-cancel" onClick={close} disabled={busy}>
                        {t('settings.custody.rotate.dialog.cancel')}
                    </Button>
                    <Button
                        variant="danger"
                        dataButton="rotate-confirm"
                        onClick={onConfirm}
                        disabled={!confirmed || busy}
                    >
                        {busy ? t('settings.custody.rotate.dialog.busy') : t('settings.custody.rotate.dialog.confirm')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}
