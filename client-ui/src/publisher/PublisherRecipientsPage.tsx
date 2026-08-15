// PublisherRecipientsPage — Gap 1 standalone recipient dashboard.
//
// Distinct from the in-flow Step-7 ("Distribute") recipient subview
// of the PublisherWizard. This page is the operator's everyday
// surface AFTER they've completed setup: add a new friend, revoke
// an existing one, resend an .sbpx via the share-sheet, and sync
// the local roster against the server-side ledger.
//
// All Tauri commands are already wired (wizardCommands.ts:362-393).
// All copy is i18n-keyed under `pub.recipients.*` (with a few
// reused `wiz.recipients.*` keys from PublisherWizard).

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Wizard } from './wizardCommands';
import type {
    OperatorSummary,
    RecipientSummary,
} from './wizardCommands';
import { Card, ListRow, Button, Section } from '../design/primitives';
import { Sheet } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

// daal1… bech32 lower bound; we don't decode the bech32 here (the
// Rust side does), but we sanity-check the HRP and length so paste
// errors fail fast rather than going to a 30 s mgmt round-trip.
function looksLikeDaalAddress(s: string): boolean {
    const trimmed = s.trim().toLowerCase();
    if (!trimmed.startsWith('daal1')) return false;
    if (trimmed.length < 20) return false;
    // bech32 character set
    return /^[a-z0-9]+$/.test(trimmed);
}

function shortAddr(s: string): string {
    if (s.length <= 18) return s;
    return s.slice(0, 10) + '…' + s.slice(-6);
}

function tsLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 16).replace('T', ' ');
    } catch {
        return '';
    }
}

interface ConfirmRevoke {
    recipient: RecipientSummary;
}

interface ConfirmRemove {
    recipient: RecipientSummary;
}

export default function PublisherRecipientsPage({ t }: Props) {
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [operatorId, setOperatorId] = useState<number | null>(null);
    const [recipients, setRecipients] = useState<RecipientSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Add-sheet state
    const [showAdd, setShowAdd] = useState(false);
    const [addAddress, setAddAddress] = useState('');
    const [addDisplayName, setAddDisplayName] = useState('');
    const [addPin, setAddPin] = useState('');
    const [addHelperIp, setAddHelperIp] = useState('');
    const [addBusy, setAddBusy] = useState(false);
    const [addElapsed, setAddElapsed] = useState(0);
    const [addError, setAddError] = useState<string | null>(null);

    useEffect(() => {
        if (!addBusy) {
            setAddElapsed(0);
            return;
        }
        const start = Date.now();
        const h = window.setInterval(() => {
            setAddElapsed(Math.floor((Date.now() - start) / 1000));
        }, 500);
        return () => window.clearInterval(h);
    }, [addBusy]);

    // Revoke confirm
    const [confirmRevoke, setConfirmRevoke] = useState<ConfirmRevoke | null>(null);
    const [revokePin, setRevokePin] = useState('');
    const [revokeHelperIp, setRevokeHelperIp] = useState('');
    const [revokeBusy, setRevokeBusy] = useState(false);
    const [revokeError, setRevokeError] = useState<string | null>(null);

    // Remove confirm — hard-deletes an already-revoked row from the
    // local roster. Local-only (no PIN / no box round-trip).
    const [confirmRemove, setConfirmRemove] = useState<ConfirmRemove | null>(null);
    const [removeBusy, setRemoveBusy] = useState(false);
    const [removeError, setRemoveError] = useState<string | null>(null);

    // Sync
    const [syncing, setSyncing] = useState(false);
    const [syncResult, setSyncResult] = useState<string | null>(null);

    const reloadOperators = useCallback(async () => {
        try {
            const ops = await Wizard.listOperators();
            setOperators(ops);
            if (ops.length > 0 && operatorId === null) {
                setOperatorId(ops[0].id);
            }
        } catch (e) {
            setError(String(e));
        }
    }, [operatorId]);

    const reloadRecipients = useCallback(async (oid: number) => {
        setLoading(true);
        try {
            const rs = await Wizard.recipientList(oid);
            setRecipients(rs);
            setError(null);
        } catch (e) {
            setError(String(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void reloadOperators();
    }, [reloadOperators]);

    useEffect(() => {
        if (operatorId === null) return;
        void reloadRecipients(operatorId);
    }, [operatorId, reloadRecipients]);

    const activeOperator = useMemo(
        () => operators.find((o) => o.id === operatorId) ?? null,
        [operators, operatorId],
    );

    const onAddSubmit = async () => {
        if (operatorId === null) return;
        if (!looksLikeDaalAddress(addAddress)) {
            setAddError(t('pub.recipients.add.bad_address'));
            return;
        }
        if (addPin.trim().length === 0) {
            setAddError(t('pub.recipients.add.missing_pin'));
            return;
        }
        setAddBusy(true);
        setAddError(null);
        try {
            const s = await Wizard.recipientProvision(
                operatorId,
                addPin,
                addHelperIp.trim(),
                addAddress.trim(),
                addDisplayName.trim(),
            );
            setRecipients((prev) => [s, ...prev]);
            setAddAddress('');
            setAddDisplayName('');
            setAddPin('');
            setShowAdd(false);
        } catch (e) {
            setAddError(String(e));
        } finally {
            setAddBusy(false);
        }
    };

    const onRevokeConfirm = async () => {
        if (operatorId === null || !confirmRevoke) return;
        if (revokePin.trim().length === 0) {
            setRevokeError(t('pub.recipients.add.missing_pin'));
            return;
        }
        setRevokeBusy(true);
        setRevokeError(null);
        try {
            const s = await Wizard.recipientRevoke(
                operatorId,
                revokePin,
                revokeHelperIp.trim(),
                confirmRevoke.recipient.id,
            );
            setRecipients((prev) =>
                prev.map((r) => (r.id === s.id ? s : r)),
            );
            setConfirmRevoke(null);
            setRevokePin('');
        } catch (e) {
            setRevokeError(String(e));
        } finally {
            setRevokeBusy(false);
        }
    };

    const onRemoveConfirm = async () => {
        if (operatorId === null || !confirmRemove) return;
        setRemoveBusy(true);
        setRemoveError(null);
        try {
            await Wizard.recipientDelete(operatorId, confirmRemove.recipient.id);
            setRecipients((prev) =>
                prev.filter((r) => r.id !== confirmRemove.recipient.id),
            );
            setConfirmRemove(null);
        } catch (e) {
            setRemoveError(String(e));
        } finally {
            setRemoveBusy(false);
        }
    };

    const onResend = async (r: RecipientSummary) => {
        if (!r.sbpx_path) return;
        try {
            await Wizard.shareInviteSbpx(r.sbpx_path, r.display_name || r.name);
        } catch (e) {
            setError(String(e));
        }
    };

    const onSync = async () => {
        if (operatorId === null) return;
        setSyncing(true);
        setSyncResult(null);
        try {
            // Helper IP is reused from whichever sheet last set it;
            // for sync we use the operator's helper_ip default
            // (empty falls through to the Tauri command's default).
            const remote = await Wizard.recipientListRemote(
                operatorId,
                '', // PIN unused for read; mgmt API gates on operator session
                '',
            );
            const local = new Set(
                recipients
                    .filter((r) => r.revoked_at_unix === 0)
                    .map((r) => r.address_str.toLowerCase()),
            );
            const remoteSet = new Set(remote.map((s) => s.toLowerCase()));
            const onlyLocal = [...local].filter((a) => !remoteSet.has(a));
            const onlyRemote = [...remoteSet].filter((a) => !local.has(a));
            if (onlyLocal.length === 0 && onlyRemote.length === 0) {
                setSyncResult(t('pub.recipients.sync.in_sync'));
            } else {
                setSyncResult(
                    t('pub.recipients.sync.drift')
                        .replace('{onlyLocal}', String(onlyLocal.length))
                        .replace('{onlyRemote}', String(onlyRemote.length)),
                );
            }
        } catch (e) {
            setSyncResult(String(e));
        } finally {
            setSyncing(false);
        }
    };

    return (
        <div style={{ padding: '12px 16px 24px 16px' }}>
            <Section
                eyebrow={t('pub.recipients.eyebrow')}
                title={t('pub.recipients.title')}
                action={
                    <span style={{ display: 'inline-flex', gap: 8 }}>
                        <Button onClick={onSync} disabled={syncing || operatorId === null}>
                            {syncing
                                ? t('pub.recipients.syncing')
                                : t('pub.recipients.sync')}
                        </Button>
                        <Button
                            onClick={() => setShowAdd(true)}
                            disabled={operatorId === null}
                        >
                            {t('pub.recipients.add')}
                        </Button>
                    </span>
                }
            >
                {operators.length > 1 && (
                    <div style={{ marginBottom: 10 }}>
                        <label
                            style={{
                                fontSize: 11,
                                color: 'var(--muted)',
                                letterSpacing: '0.04em',
                                textTransform: 'uppercase',
                                display: 'block',
                                marginBottom: 4,
                            }}
                        >
                            {t('pub.recipients.operator')}
                        </label>
                        <select
                            value={operatorId ?? ''}
                            onChange={(e) =>
                                setOperatorId(Number(e.target.value))
                            }
                            style={{
                                width: '100%',
                                padding: '6px 8px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                            }}
                        >
                            {operators.map((o) => (
                                <option key={o.id} value={o.id}>
                                    {o.provider} / {o.region} (#{o.id})
                                </option>
                            ))}
                        </select>
                    </div>
                )}
                {operatorId === null && (
                    <Card>
                        <ListRow
                            title={t('pub.recipients.no_operator.title')}
                            subtitle={t('pub.recipients.no_operator.help')}
                            last
                        />
                    </Card>
                )}
                {error && (
                    <div style={{ color: 'var(--red)', fontSize: 12, padding: '6px 4px' }}>
                        {error}
                    </div>
                )}
                {syncResult && (
                    <div
                        style={{
                            color: 'var(--muted)',
                            fontSize: 12,
                            padding: '6px 4px',
                            fontFamily: 'var(--font-mono)',
                        }}
                    >
                        {syncResult}
                    </div>
                )}
                {operatorId !== null && recipients.length === 0 && !loading && (
                    <Card>
                        <ListRow
                            title={t('pub.recipients.empty.title')}
                            subtitle={t('pub.recipients.empty.help')}
                            last
                        />
                    </Card>
                )}
                {recipients.length > 0 && (
                    <Card>
                        {recipients.map((r, i) => {
                            const revoked = r.revoked_at_unix > 0;
                            return (
                                <ListRow
                                    key={r.id}
                                    title={
                                        <span>
                                            {r.display_name || r.name || `#${r.id}`}
                                            {revoked && (
                                                <span
                                                    style={{
                                                        marginInlineStart: 8,
                                                        color: 'var(--red)',
                                                        fontSize: 11,
                                                        fontFamily: 'var(--font-mono)',
                                                    }}
                                                >
                                                    {t('pub.recipients.revoked')}
                                                </span>
                                            )}
                                        </span>
                                    }
                                    subtitle={
                                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                            {shortAddr(r.address_str)}
                                            {r.provisioned_at_unix > 0 && (
                                                <>
                                                    {' · '}
                                                    {t('pub.recipients.added')}{' '}
                                                    {tsLabel(r.provisioned_at_unix)}
                                                </>
                                            )}
                                        </span>
                                    }
                                    trailing={
                                        <span style={{ display: 'inline-flex', gap: 6 }}>
                                            {!revoked && r.sbpx_path && (
                                                <Button onClick={() => onResend(r)}>
                                                    {t('pub.recipients.resend')}
                                                </Button>
                                            )}
                                            {!revoked && (
                                                <Button
                                                    onClick={() => {
                                                        setConfirmRevoke({ recipient: r });
                                                        setRevokeError(null);
                                                    }}
                                                >
                                                    {t('pub.recipients.revoke')}
                                                </Button>
                                            )}
                                            {/* Once revoked (on-box teardown done)
                                                the greyed-out row can be purged from
                                                the local roster for good. */}
                                            {revoked && (
                                                <Button
                                                    onClick={() => {
                                                        setConfirmRemove({ recipient: r });
                                                        setRemoveError(null);
                                                    }}
                                                >
                                                    {t('pub.recipients.remove')}
                                                </Button>
                                            )}
                                        </span>
                                    }
                                    last={i === recipients.length - 1}
                                />
                            );
                        })}
                    </Card>
                )}
            </Section>

            {showAdd && (
                <Sheet
                    title={t('pub.recipients.add.title')}
                    onClose={() => {
                        if (!addBusy) setShowAdd(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                onClick={() => setShowAdd(false)}
                                disabled={addBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button onClick={onAddSubmit} disabled={addBusy}>
                                {addBusy
                                    ? `${t('wiz.recipients.adding')} (${addElapsed}s)`
                                    : t('pub.recipients.add.submit')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.address')}
                        </label>
                        <input
                            type="text"
                            value={addAddress}
                            onChange={(e) => setAddAddress(e.target.value)}
                            placeholder="daal1…"
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                                fontFamily: 'var(--font-mono)',
                            }}
                        />
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.display_name')}
                        </label>
                        <input
                            type="text"
                            value={addDisplayName}
                            onChange={(e) => setAddDisplayName(e.target.value)}
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                            }}
                        />
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.pin')}
                        </label>
                        <input
                            type="password"
                            value={addPin}
                            onChange={(e) => setAddPin(e.target.value)}
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                                fontFamily: 'var(--font-mono)',
                            }}
                        />
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.helper_ip')}
                        </label>
                        <input
                            type="text"
                            value={addHelperIp}
                            onChange={(e) => setAddHelperIp(e.target.value)}
                            placeholder={t('pub.recipients.add.helper_ip.placeholder')}
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                                fontFamily: 'var(--font-mono)',
                            }}
                        />
                        {addBusy && (
                            <div
                                style={{
                                    fontSize: 11,
                                    color: 'var(--muted)',
                                    fontFamily: 'var(--font-mono)',
                                    lineHeight: 1.5,
                                }}
                            >
                                {t('wiz.recipients.adding_detail')}
                            </div>
                        )}
                        {addError && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>
                                {addError}
                            </div>
                        )}
                        {activeOperator && (
                            <div
                                style={{
                                    fontSize: 11,
                                    color: 'var(--dim)',
                                    fontFamily: 'var(--font-mono)',
                                }}
                            >
                                {t('pub.recipients.operator')}: #{activeOperator.id} ·{' '}
                                {activeOperator.provider}/{activeOperator.region}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}

            {confirmRevoke && (
                <Sheet
                    title={t('pub.recipients.revoke.title')}
                    onClose={() => {
                        if (!revokeBusy) setConfirmRevoke(null);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                onClick={() => setConfirmRevoke(null)}
                                disabled={revokeBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button onClick={onRevokeConfirm} disabled={revokeBusy}>
                                {revokeBusy
                                    ? t('pub.recipients.revoking')
                                    : t('pub.recipients.revoke')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div style={{ fontSize: 13, color: 'var(--fg)' }}>
                            {t('pub.recipients.revoke.body').replace(
                                '{name}',
                                confirmRevoke.recipient.display_name ||
                                    confirmRevoke.recipient.name ||
                                    `#${confirmRevoke.recipient.id}`,
                            )}
                        </div>
                        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
                            {confirmRevoke.recipient.address_str}
                        </div>
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.pin')}
                        </label>
                        <input
                            type="password"
                            value={revokePin}
                            onChange={(e) => setRevokePin(e.target.value)}
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                                fontFamily: 'var(--font-mono)',
                            }}
                        />
                        <label style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {t('pub.recipients.add.helper_ip')}
                        </label>
                        <input
                            type="text"
                            value={revokeHelperIp}
                            onChange={(e) => setRevokeHelperIp(e.target.value)}
                            placeholder={t('pub.recipients.add.helper_ip.placeholder')}
                            style={{
                                padding: '8px 10px',
                                background: 'var(--surface)',
                                color: 'var(--fg)',
                                border: '1px solid var(--line-soft)',
                                borderRadius: 'var(--r-control)',
                                fontFamily: 'var(--font-mono)',
                            }}
                        />
                        {revokeError && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>
                                {revokeError}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}

            {confirmRemove && (
                <Sheet
                    title={t('pub.recipients.remove.title')}
                    onClose={() => {
                        if (!removeBusy) setConfirmRemove(null);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                onClick={() => setConfirmRemove(null)}
                                disabled={removeBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button onClick={onRemoveConfirm} disabled={removeBusy}>
                                {removeBusy
                                    ? t('pub.recipients.removing')
                                    : t('pub.recipients.remove')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div style={{ fontSize: 13, color: 'var(--fg)' }}>
                            {t('pub.recipients.remove.body').replace(
                                '{name}',
                                confirmRemove.recipient.display_name ||
                                    confirmRemove.recipient.name ||
                                    `#${confirmRemove.recipient.id}`,
                            )}
                        </div>
                        <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
                            {confirmRemove.recipient.address_str}
                        </div>
                        {removeError && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>
                                {removeError}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}
        </div>
    );
}
