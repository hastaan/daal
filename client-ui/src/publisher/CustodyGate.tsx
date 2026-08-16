// CustodyGate — the only thing standing between the user and the
// publisher surface, and on a healthy device it renders nothing at all.
//
// The publisher's two secrets (the Ed25519 signing key and the cloud
// API token) used to be sealed under a 6-digit PIN the user typed on
// every visit. They now live under DeviceCustody: hardware-backed on
// Android (StrongBox/TEE via AndroidKeyStore), the OS keyring on
// desktop, and a session passphrase only where neither exists. This
// component covers the three cases where that transition is visible:
//
//   1. The keystore is broken (unwritable state dir, JNI failure). Every
//      publisher action would fail halfway; we say so instead of
//      letting the user walk into a half-working wizard.
//   2. Session-passphrase custody needs one unlock per process run —
//      or, on a device that has never had one, one *choice*.
//   3. A device upgrading from the PIN build still has PIN-sealed blobs
//      on disk. They must be moved under custody exactly once, and
//      until they are, the signing key is only reachable with the old
//      PIN — so this gate blocks (§3.5).
//
// The order matters and is checked in that order: a locked custody
// cannot accept the migration's writes, so asking for the PIN first
// produces a card that can never succeed and can never be dismissed.
//
// On a fresh install none of those apply: every alias is absent, the
// probe succeeds, and the user sees zero prompts and zero taps. That
// silence is the entire point of removing the PIN — if this component
// ever renders on a clean hardware-backed device, it is a bug.

import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { Wizard, classifyPublisherError } from './wizardCommands';
import type {
    CustodyMigrationReport,
    OperatorSummary,
    PublisherCustodyStatus,
} from './wizardCommands';
import { Card, Button, Input } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    /** Relays known at boot. Used only by the broken-keystore branch,
     *  which offers to export a recovery key while one is still
     *  readable. */
    operators: OperatorSummary[];
    /** Rendered only when custody is not blocking. */
    children: ReactNode;
}

// ---------------------------------------------------------------------
// Shared status access
// ---------------------------------------------------------------------
//
// `publisher_custody_status` is not free: it does a live put/get/forget
// probe because `is_unlocked()` lies (both AndroidKeystoreDwk and
// KeyringDwk return `is_ready() == true` unconditionally, so a broken
// backend looks healthy until the first real read). One probe per screen
// mount is fine; one per render is not. This module-level promise is the
// process-lifetime cache both the gate and the relay-detail header read
// from.

let statusPromise: Promise<PublisherCustodyStatus> | null = null;

/** Fetch (and cache) the custody probe. `force` re-probes. */
export function fetchCustodyStatus(
    force = false,
): Promise<PublisherCustodyStatus> {
    if (force || !statusPromise) {
        const p = Wizard.custodyStatus();
        statusPromise = p;
        // A failed probe must not poison the cache forever — the next
        // caller should get a fresh attempt.
        p.catch(() => {
            if (statusPromise === p) statusPromise = null;
        });
        return p;
    }
    return statusPromise;
}

/**
 * i18n key for the one-line custody label. device_custody.rs:69-70 is
 * explicit that these strings carry the security promise to the user,
 * so each tier gets its own honest sentence — we never claim hardware
 * backing on a device that fell back to a passphrase.
 */
export function custodyLabelKey(level: string): string {
    switch (level) {
        case 'hardware':
            return 'pub.custody.label.hardware';
        case 'os_keystore':
            return 'pub.custody.label.os_keystore';
        case 'session_passphrase':
            return 'pub.custody.label.session_passphrase';
        default:
            return 'pub.custody.label.unknown';
    }
}

const LABEL: React.CSSProperties = {
    fontSize: 12,
    color: 'var(--muted)',
};

const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--fg)',
    lineHeight: 1.55,
};

const MONO_SMALL: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--dim)',
    lineHeight: 1.5,
    wordBreak: 'break-all',
};

export default function CustodyGate({ t, operators, children }: Props) {
    const [status, setStatus] = useState<PublisherCustodyStatus | null>(null);
    const [probeError, setProbeError] = useState<string | null>(null);

    // Migration sheet
    const [pin, setPin] = useState('');
    const [migrating, setMigrating] = useState(false);
    const [migrateError, setMigrateError] = useState<string | null>(null);
    const [report, setReport] = useState<CustodyMigrationReport | null>(null);
    const [dismissed, setDismissed] = useState(false);

    // Session-passphrase unlock. `pass2` is only rendered when this
    // device has no custody blob yet — i.e. the sheet is *setting* the
    // passphrase, not checking it.
    const [pass, setPass] = useState('');
    const [pass2, setPass2] = useState('');
    const [unlocking, setUnlocking] = useState(false);
    const [unlockError, setUnlockError] = useState<string | null>(null);

    // Recovery export (broken-keystore branch only)
    const [recoveryMsg, setRecoveryMsg] = useState<string | null>(null);

    // Migration dead-end escape ("I don't have the PIN").
    const [showStuck, setShowStuck] = useState(false);
    const [stuckBusy, setStuckBusy] = useState<number | null>(null);

    const refresh = useCallback(async (force: boolean) => {
        try {
            const s = await fetchCustodyStatus(force);
            setStatus(s);
            setProbeError(null);
        } catch (e) {
            // The status command itself failing is not a reason to lock
            // the user out — that would make an unrelated IPC hiccup as
            // severe as a lost signing key. Note it and let them through.
            setProbeError(String(e));
        }
    }, []);

    useEffect(() => {
        void refresh(false);
    }, [refresh]);

    const onMigrate = useCallback(async () => {
        setMigrating(true);
        setMigrateError(null);
        try {
            const r = await Wizard.migrateFromPin(pin);
            setReport(r);
            setPin('');
            await refresh(true);
        } catch (e) {
            const msg = String(e);
            setMigrateError(
                /wrong\s*pin|wrongpin/i.test(msg)
                    ? t('pub.custody.migrate.wrong_pin')
                    : msg,
            );
        } finally {
            setMigrating(false);
        }
    }, [pin, refresh, t]);

    const onUnlock = useCallback(
        async (creating: boolean) => {
            // Creating: the backend cannot help us here. With no stored
            // blob nothing can fail to open, so `custody_unlock` accepts
            // whatever is typed and it silently becomes the wrap key for
            // a signing key generated minutes later. A typo at this
            // moment is unrecoverable, so the second field is the only
            // check that exists.
            if (creating && pass !== pass2) {
                setUnlockError(t('pub.custody.unlock.create.mismatch'));
                return;
            }
            setUnlocking(true);
            setUnlockError(null);
            try {
                const s = await Wizard.custodyUnlock(pass);
                setStatus(s);
                setPass('');
                setPass2('');
                // Seed the shared cache so the relay header doesn't
                // re-probe.
                statusPromise = Promise.resolve(s);
            } catch (e) {
                const msg = String(e);
                setUnlockError(
                    msg.startsWith('E_CUSTODY_WRONG_PASS')
                        ? t('pub.custody.unlock.wrong')
                        : msg,
                );
            } finally {
                setUnlocking(false);
            }
        },
        [pass, pass2, t],
    );

    /**
     * The escape from a migration that can never succeed.
     *
     * The PIN was never persisted anywhere — that is *why* it is being
     * removed — so a user who has forgotten it faces a non-dismissable
     * card in front of the entire publisher surface, on every launch,
     * with one button that will always fail. They cannot reach the
     * relay list, cannot start a new relay, and cannot even read the
     * old box's IP to go clean it up in their cloud console.
     *
     * `cancelAndCleanup` sweeps both stores for that relay and deletes
     * its row, which is the only thing that clears the gate. It does
     * NOT touch the cloud server — the confirm says so, and shows the
     * IP so the user can delete it in their provider's console.
     */
    const onForgetRelay = useCallback(
        async (op: OperatorSummary) => {
            const name = op.nickname || `#${op.id}`;
            const where = op.public_ip || op.public_ipv6 || op.server_id || '—';
            const msg = t('pub.custody.migrate.stuck.confirm')
                .replace('{name}', name)
                .replace('{ip}', where);
            if (!window.confirm(msg)) return;
            setStuckBusy(op.id);
            try {
                await Wizard.cancelAndCleanup(op.id);
                await refresh(true);
            } catch (e) {
                setMigrateError(String(e));
            } finally {
                setStuckBusy(null);
            }
        },
        [refresh, t],
    );

    const onExportRecovery = useCallback(
        async (op: OperatorSummary) => {
            setRecoveryMsg(null);
            const name = op.nickname || `daal-relay-${op.id}`;
            // The blob is the raw signing key in base64, and it lands in
            // the shared Downloads collection where any app with storage
            // access can read it — and where panic-wipe cannot reach it.
            // That is the deliberate trade (a non-exportable DWK dies
            // with the device, and there is no escrow), but it is not a
            // trade to make on a single unannounced tap.
            if (!window.confirm(t('pub.custody.recovery.confirm'))) return;
            try {
                const path = await Wizard.saveRecoveryKey(
                    op.id,
                    `${name}-recovery.daalkey`,
                );
                setRecoveryMsg(
                    `${t('pub.custody.recovery.saved')} ${path}`,
                );
            } catch (e) {
                setRecoveryMsg(String(e));
            }
        },
        [t],
    );

    // Still probing, or the probe itself errored — either way, don't
    // flash a gate. `probeError` is surfaced as a passive line so a
    // broken IPC isn't completely silent.
    if (!status) {
        return (
            <>
                {probeError && (
                    <div style={{ padding: '10px 16px 0 16px' }}>
                        <div style={{ ...MONO_SMALL, color: 'var(--red)' }}>
                            {probeError}
                        </div>
                    </div>
                )}
                {children}
            </>
        );
    }

    // -----------------------------------------------------------------
    // 1. Broken keystore. Non-dismissable; every publisher action would
    //    fail somewhere in the middle, which is worse than not starting.
    //
    //    A *locked* session-passphrase custody is not broken, but it
    //    reports `ok: false` too — the probe writes through the wrap key,
    //    and a locked wrap key has no way to succeed. Its error carries
    //    `E_CUSTODY_LOCKED` precisely so this branch can tell the two
    //    apart. Without that check, the very devices that need the
    //    unlock sheet below would see a dead-end "can't reach the key
    //    store" card on every launch and could never reach it —
    //    a permanently bricked publisher surface on any device with no
    //    OS keystore. A locked OS keyring keeps the card on purpose:
    //    the unlock branch does not cover it, and its Retry is the right
    //    affordance once the user unlocks the keyring outside Daal.
    // -----------------------------------------------------------------
    const awaitingPassphrase =
        status.level === 'session_passphrase' &&
        !status.unlocked &&
        classifyPublisherError(status.error) === 'E_CUSTODY_LOCKED';

    if (!status.ok && !awaitingPassphrase) {
        return (
            <div style={{ padding: '14px 16px 24px 16px', display: 'grid', gap: 12 }}>
                <Card>
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: 19,
                                color: 'var(--red)',
                            }}
                        >
                            {t('pub.custody.broken.title')}
                        </div>
                        <div style={BODY}>{t('pub.custody.broken.body')}</div>
                        {status.error && (
                            <div style={MONO_SMALL}>{status.error}</div>
                        )}
                        {operators.length > 0 && (
                            <>
                                <div style={LABEL}>
                                    {t('pub.custody.recovery.help')}
                                </div>
                                <div
                                    style={{
                                        display: 'flex',
                                        gap: 8,
                                        flexWrap: 'wrap',
                                    }}
                                >
                                    {operators.map((op) => (
                                        <Button
                                            key={op.id}
                                            variant="secondary"
                                            onClick={() =>
                                                void onExportRecovery(op)
                                            }
                                        >
                                            {`${t('pub.custody.recovery.export')} · ${
                                                op.nickname || `#${op.id}`
                                            }`}
                                        </Button>
                                    ))}
                                </div>
                            </>
                        )}
                        {recoveryMsg && (
                            <div style={MONO_SMALL}>{recoveryMsg}</div>
                        )}
                        <div>
                            <Button
                                variant="secondary"
                                onClick={() => void refresh(true)}
                            >
                                {t('pub.custody.broken.retry')}
                            </Button>
                        </div>
                    </div>
                </Card>
            </div>
        );
    }

    // -----------------------------------------------------------------
    // 2. Session-passphrase custody, not yet unlocked this run. There is
    //    no idle timer and no auto-lock — PassphraseDwk holds the derived
    //    key until lock()/Drop — so this is once per process launch.
    //
    //    This MUST come before the migration branch. On a device with no
    //    usable OS keystore, a locked custody cannot accept a single
    //    `put`, so the migration would unseal every legacy secret with
    //    the PIN and then fail at the write; `signing_keys_safe` would
    //    never flip, the card has no dismiss control while a signing key
    //    is at stake, and there is no unlock affordance on it. The user
    //    would be locked out of the publisher surface on every launch,
    //    permanently. Unlock first, then migrate into a writable store.
    // -----------------------------------------------------------------
    if (status.level === 'session_passphrase' && !status.unlocked) {
        // `passphrase_set` is the difference between "type the
        // passphrase you chose" and "choose a passphrase" — and the
        // backend cannot tell the user apart from a typo on the second
        // one, because with no stored blob there is nothing that can
        // fail to open. Whatever is typed becomes the wrap key.
        const creating = !status.passphrase_set;
        return (
            <div style={{ padding: '14px 16px 24px 16px', display: 'grid', gap: 12 }}>
                <Card>
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: 19,
                                color: 'var(--fg)',
                            }}
                        >
                            {t(
                                creating
                                    ? 'pub.custody.unlock.create.title'
                                    : 'pub.custody.unlock.title',
                            )}
                        </div>
                        <div style={BODY}>
                            {t(
                                creating
                                    ? 'pub.custody.unlock.create.body'
                                    : 'pub.custody.unlock.body',
                            )}
                        </div>
                        {!creating && (
                            <>
                                {/* A device whose OS keyring stopped
                                    answering falls back to this same
                                    sheet, and the user has never set a
                                    passphrase in their life. Telling
                                    them only "that passphrase doesn't
                                    match" sends them hunting for a typo
                                    that does not exist. */}
                                <div style={{ ...BODY, color: 'var(--muted)' }}>
                                    {t('pub.custody.unlock.regression')}
                                </div>
                                {status.error && (
                                    <div style={MONO_SMALL}>{status.error}</div>
                                )}
                            </>
                        )}
                        <Input
                            type="password"
                            value={pass}
                            onChange={(e) => setPass(e.target.value)}
                            placeholder={t('pub.custody.unlock.placeholder')}
                        />
                        {creating && (
                            <Input
                                type="password"
                                value={pass2}
                                onChange={(e) => setPass2(e.target.value)}
                                placeholder={t(
                                    'pub.custody.unlock.create.confirm_placeholder',
                                )}
                            />
                        )}
                        {unlockError && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>
                                {unlockError}
                            </div>
                        )}
                        <div>
                            <Button
                                onClick={() => void onUnlock(creating)}
                                disabled={
                                    unlocking ||
                                    pass.length === 0 ||
                                    (creating && pass2.length === 0)
                                }
                            >
                                {unlocking
                                    ? t('pub.custody.unlock.working')
                                    : t(
                                          creating
                                              ? 'pub.custody.unlock.create.submit'
                                              : 'pub.custody.unlock.submit',
                                      )}
                            </Button>
                        </div>
                    </div>
                </Card>
            </div>
        );
    }

    // -----------------------------------------------------------------
    // 3. Legacy PIN-sealed blobs still on disk. Blocking whenever a
    //    signing key is among them: skipping would orphan the relay
    //    permanently (no new recipient, no revoke, ever — there is no
    //    escrow anywhere in the system).
    // -----------------------------------------------------------------
    const signingKeyAtRisk = status.legacy_aliases.some((a) =>
        a.endsWith('.priv'),
    );
    // Aliases are `daal.<kind>.<operatorId>.<what>`. Map them back to
    // relays so the dead-end escape can name what it is about to erase
    // and show where the server lives.
    const stuckIds = new Set(
        status.legacy_aliases
            .map((a) => Number(a.split('.')[2]))
            .filter((n) => Number.isFinite(n)),
    );
    const stuckOperators = operators.filter((o) => stuckIds.has(o.id));
    // A run that reported signing_keys_safe has already re-probed via
    // refresh(true); if we are still here, some token failed. Keep the
    // report on screen but stop re-asking for the PIN.
    const migrationDone = report?.signing_keys_safe === true;

    if (status.legacy_pending && !dismissed) {
        return (
            <div style={{ padding: '14px 16px 24px 16px', display: 'grid', gap: 12 }}>
                <Card>
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: 19,
                                color: 'var(--fg)',
                            }}
                        >
                            {t('pub.custody.migrate.title')}
                        </div>
                        <div style={BODY}>{t('pub.custody.migrate.body')}</div>
                        <div style={BODY}>
                            {t('pub.custody.migrate.protected_by').replace(
                                '{tier}',
                                t(custodyLabelKey(status.level)),
                            )}
                        </div>
                        {signingKeyAtRisk && (
                            <div
                                style={{
                                    ...BODY,
                                    color: 'var(--amber)',
                                }}
                            >
                                {t('pub.custody.migrate.warn').replace(
                                    '{n}',
                                    String(
                                        status.legacy_aliases.filter((a) =>
                                            a.endsWith('.priv'),
                                        ).length,
                                    ),
                                )}
                            </div>
                        )}
                        <div style={MONO_SMALL}>
                            {status.legacy_aliases.join('\n')}
                        </div>

                        {!migrationDone && (
                            <>
                                <label style={LABEL}>
                                    {t('pub.custody.migrate.pin_label')}
                                </label>
                                <Input
                                    type="password"
                                    inputMode="numeric"
                                    value={pin}
                                    onChange={(e) => setPin(e.target.value)}
                                    placeholder={t(
                                        'pub.custody.migrate.pin_placeholder',
                                    )}
                                    style={{ fontFamily: 'var(--font-mono)' }}
                                />
                                {migrateError && (
                                    <div
                                        style={{
                                            color: 'var(--red)',
                                            fontSize: 12,
                                        }}
                                    >
                                        {migrateError}
                                    </div>
                                )}
                                <div
                                    style={{
                                        display: 'flex',
                                        gap: 8,
                                        flexWrap: 'wrap',
                                    }}
                                >
                                    <Button
                                        onClick={() => void onMigrate()}
                                        disabled={migrating || pin.length === 0}
                                    >
                                        {migrating
                                            ? t('pub.custody.migrate.working')
                                            : t('pub.custody.migrate.submit')}
                                    </Button>
                                    {/* A "Not now" escape exists only when
                                        nothing irreplaceable is at stake.
                                        Cloud tokens can be re-pasted; a
                                        signing key cannot be re-anything. */}
                                    {!signingKeyAtRisk && (
                                        <Button
                                            variant="ghost"
                                            onClick={() => setDismissed(true)}
                                            disabled={migrating}
                                        >
                                            {t('pub.custody.migrate.later')}
                                        </Button>
                                    )}
                                    {/* There must always be a way out.
                                        The PIN was never persisted
                                        anywhere — that is why it is
                                        being removed — so "I forgot it"
                                        is a real state, and without this
                                        it means a card that blocks the
                                        entire publisher surface forever
                                        with one button that can only
                                        fail. */}
                                    {stuckOperators.length > 0 && (
                                        <Button
                                            variant="ghost"
                                            onClick={() => setShowStuck((v) => !v)}
                                            disabled={migrating}
                                        >
                                            {t('pub.custody.migrate.stuck.toggle')}
                                        </Button>
                                    )}
                                </div>
                                {showStuck && (
                                    <div style={{ display: 'grid', gap: 8 }}>
                                        <div style={{ ...BODY, color: 'var(--amber)' }}>
                                            {t('pub.custody.migrate.stuck.body')}
                                        </div>
                                        <div
                                            style={{
                                                display: 'flex',
                                                gap: 8,
                                                flexWrap: 'wrap',
                                            }}
                                        >
                                            {stuckOperators.map((op) => (
                                                <Button
                                                    key={op.id}
                                                    variant="danger"
                                                    disabled={stuckBusy === op.id}
                                                    onClick={() =>
                                                        void onForgetRelay(op)
                                                    }
                                                >
                                                    {t(
                                                        'pub.custody.migrate.stuck.remove',
                                                    ).replace(
                                                        '{name}',
                                                        op.nickname || `#${op.id}`,
                                                    )}
                                                </Button>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </>
                        )}

                        {report && (
                            <div style={{ display: 'grid', gap: 6 }}>
                                <div style={BODY}>
                                    {report.signing_keys_safe
                                        ? t('pub.custody.migrate.done')
                                        : t('pub.custody.migrate.partial')}
                                </div>
                                <div style={MONO_SMALL}>
                                    {t('pub.custody.migrate.moved')}:{' '}
                                    {report.migrated.length} ·{' '}
                                    {t('pub.custody.migrate.skipped')}:{' '}
                                    {report.skipped.length}
                                </div>
                                {report.failed.length > 0 && (
                                    <div
                                        style={{
                                            ...MONO_SMALL,
                                            color: 'var(--red)',
                                        }}
                                    >
                                        {report.failed.join('\n')}
                                    </div>
                                )}
                                {report.signing_keys_safe && (
                                    <div>
                                        <Button
                                            onClick={() => setDismissed(true)}
                                        >
                                            {t('pub.custody.migrate.continue')}
                                        </Button>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </Card>
            </div>
        );
    }

    // Healthy. Render nothing of our own.
    return <>{children}</>;
}
