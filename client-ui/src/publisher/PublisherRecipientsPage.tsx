// PublisherRecipientsPage — RELAY DETAIL.
//
// This file used to be a standalone "recipients dashboard" that sat
// behind a RECIPIENTS tab, next to a SETUP tab holding the 7-step
// wizard. Setup is a one-time event, not a permanent tab, and the
// wizard's step 7 ("distribute") was a second copy of this screen — so
// routine work (hand the pack to a new phone, revoke a lost one) meant
// walking *backwards* through a setup wizard. Both are gone. This is
// now the single permanent home for everything you do with a relay
// after it exists:
//
//   header     — which relay this is, and what is protecting its key
//   ARTIFACTS  — the files you actually hand out (goal 3)
//   RECIPIENTS — the roster
//   DANGER     — recovery key, decommission
//
// Three things that were load-bearing in the old file are simply not
// here any more, and their absence is the feature:
//
//   * The PIN. Every action used to demand a 6-digit PIN before it
//     would talk to the box. The signing key now lives under
//     DeviceCustody (hardware-backed where the device has it), so the
//     honest thing to show is a one-line label saying which tier is
//     protecting it — not a prompt.
//   * The helper-IP text fields. They were optional-looking inputs
//     whose placeholder promised a "saved one" that did not exist
//     anywhere. The address now lives in operators.helper_ip and
//     repairs itself (see helperIp.ts); the user only ever sees a
//     field if automatic detection failed twice.
//   * The operator <select>. Relay choice happens on RelayListPage,
//     explicitly. This page is told which relay it is.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Wizard, classifyPublisherError } from './wizardCommands';
import type {
    ArtifactInfo,
    OperatorSummary,
    PublisherCustodyStatus,
    RecipientSummary,
} from './wizardCommands';
import {
    Card,
    ListRow,
    Button,
    Section,
    Sheet,
    Input,
    StatusPill,
} from '../design/primitives';
import {
    detectPublicIp,
    setHelperIpManually,
    withHelperIp,
} from './helperIp';
import { custodyLabelKey, fetchCustodyStatus } from './CustodyGate';
import { relayTitle } from './RelayListPage';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    onBack: () => void;
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

function baseName(path: string): string {
    const i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
    return i >= 0 ? path.slice(i + 1) : path;
}

function sizeLabel(bytes: number): string {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** True when the mgmt round-trip died before it reached the relay. The
 *  only recovery for a box provisioned before the ufw fix shipped is a
 *  fresh deploy, so we say so instead of showing a raw Go error. */
function looksUnreachable(msg: string): boolean {
    return /(context deadline exceeded|connection refused|i\/o timeout|no route to host)/i.test(
        msg,
    );
}

interface ConfirmRevoke {
    recipient: RecipientSummary;
}

interface ConfirmRemove {
    recipient: RecipientSummary;
}

type MgmtRunner = (
    fn: () => Promise<void>,
    setErr: (s: string | null) => void,
) => Promise<boolean>;

const LABEL: React.CSSProperties = { fontSize: 12, color: 'var(--muted)' };
const MONO: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--dim)',
    wordBreak: 'break-all',
};

export default function PublisherRecipientsPage({
    t,
    operatorId,
    onBack,
}: Props) {
    const [operator, setOperator] = useState<OperatorSummary | null>(null);
    const [recipients, setRecipients] = useState<RecipientSummary[]>([]);
    const [artifacts, setArtifacts] = useState<ArtifactInfo[]>([]);
    const [custody, setCustody] = useState<PublisherCustodyStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [notice, setNotice] = useState<string | null>(null);

    // Header rename
    const [renaming, setRenaming] = useState(false);
    const [draftName, setDraftName] = useState('');

    // Add-sheet state — address + display name only. No PIN, no helper IP.
    const [showAdd, setShowAdd] = useState(false);
    const [addAddress, setAddAddress] = useState('');
    const [addDisplayName, setAddDisplayName] = useState('');
    const [addBusy, setAddBusy] = useState(false);
    const [addElapsed, setAddElapsed] = useState(0);
    const [addError, setAddError] = useState<string | null>(null);

    // Revoke / remove confirms
    const [confirmRevoke, setConfirmRevoke] = useState<ConfirmRevoke | null>(null);
    const [revokeBusy, setRevokeBusy] = useState(false);
    const [revokeError, setRevokeError] = useState<string | null>(null);
    const [confirmRemove, setConfirmRemove] = useState<ConfirmRemove | null>(null);
    const [removeBusy, setRemoveBusy] = useState(false);
    const [removeError, setRemoveError] = useState<string | null>(null);

    // Rotate-and-re-share confirm. Kept deliberately separate from the
    // plain Share action — see the sheet copy.
    const [confirmRotate, setConfirmRotate] = useState(false);
    /** First-build confirm. Same command as rotate, same consequence for
     *  anyone already holding a shared pack — see onBuildShared. */
    const [confirmBuild, setConfirmBuild] = useState(false);
    const [artifactBusy, setArtifactBusy] = useState<string | null>(null);

    // Sync
    const [syncing, setSyncing] = useState(false);

    // Recovery key / decommission
    const [dangerBusy, setDangerBusy] = useState(false);

    // Helper-IP repair card. Only ever rendered after the automatic
    // detect-and-retry in withHelperIp has already failed once — no
    // button is disabled waiting for it.
    const [ipRepair, setIpRepair] = useState<{
        retry: () => Promise<boolean>;
    } | null>(null);
    const [ipDraft, setIpDraft] = useState('');
    const [ipBusy, setIpBusy] = useState(false);

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

    // ---- loaders -----------------------------------------------------

    const reloadOperator = useCallback(async () => {
        try {
            const ops = await Wizard.listOperators();
            setOperator(ops.find((o) => o.id === operatorId) ?? null);
        } catch (e) {
            setError(String(e));
        }
    }, [operatorId]);

    const reloadRecipients = useCallback(async () => {
        try {
            setRecipients(await Wizard.recipientList(operatorId));
        } catch (e) {
            setError(String(e));
        }
    }, [operatorId]);

    const reloadArtifacts = useCallback(async () => {
        try {
            // Pure fs::metadata on the Rust side — safe to call after
            // every action that could have produced or invalidated a file.
            setArtifacts(await Wizard.listArtifacts(operatorId));
        } catch (e) {
            setError(String(e));
        }
    }, [operatorId]);

    useEffect(() => {
        let alive = true;
        setLoading(true);
        void (async () => {
            await Promise.all([
                reloadOperator(),
                reloadRecipients(),
                reloadArtifacts(),
            ]);
            try {
                const s = await fetchCustodyStatus();
                if (alive) setCustody(s);
            } catch {
                // A missing custody label is cosmetic; never block the
                // screen on it.
            }
            if (alive) setLoading(false);
        })();
        return () => {
            alive = false;
        };
    }, [reloadOperator, reloadRecipients, reloadArtifacts]);

    // ---- naming ------------------------------------------------------

    // Every share-sheet and Downloads filename is derived from this.
    // The old code passed the constants 'daal-connection' and
    // 'My Family Relay', so two relays silently overwrote each other's
    // staged file and each other's download.
    const friendlyName = useMemo(
        () => operator?.nickname || `daal-relay-${operatorId}`,
        [operator, operatorId],
    );

    const title = operator ? relayTitle(operator) : `#${operatorId}`;

    const commitRename = useCallback(async () => {
        try {
            await Wizard.setOperatorNickname(operatorId, draftName.trim());
            setRenaming(false);
            await reloadOperator();
        } catch (e) {
            setError(String(e));
        }
    }, [draftName, operatorId, reloadOperator]);

    // ---- mgmt-plane action wrapper ------------------------------------

    // Every call that reaches the box goes through here. withHelperIp
    // already re-detects and retries once; this adds the *user-visible*
    // last resort — a card with an editable address — instead of the old
    // behaviour, which was an inertly disabled button and a hint saying
    // "need helper IP".
    const runMgmt: MgmtRunner = useCallback(
        async (fn, setErr) => {
            setErr(null);
            try {
                await withHelperIp(operatorId, fn);
                setIpRepair(null);
                return true;
            } catch (e) {
                const code = classifyPublisherError(e);
                if (
                    code === 'E_HELPER_IP_MISSING' ||
                    code === 'E_HELPER_IP_STALE'
                ) {
                    const detected = await detectPublicIp();
                    setIpDraft(detected?.ip ?? '');
                    setIpRepair({ retry: () => runMgmt(fn, setErr) });
                    setErr(t('pub.helper_ip.stale'));
                } else {
                    setErr(String(e));
                }
                return false;
            }
        },
        [operatorId, t],
    );

    const onIpRetry = useCallback(async () => {
        if (!ipRepair) return;
        setIpBusy(true);
        try {
            const typed = ipDraft.trim();
            if (typed) await setHelperIpManually(operatorId, typed);
            await ipRepair.retry();
        } catch (e) {
            setError(String(e));
        } finally {
            setIpBusy(false);
        }
    }, [ipDraft, ipRepair, operatorId]);

    // ---- artifact actions ---------------------------------------------

    const sharedArtifact = artifacts.find((a) => a.kind === 'shared_sbp') ?? null;
    const rawArtifact = artifacts.find((a) => a.kind === 'raw_sbp') ?? null;
    const sbpxArtifacts = artifacts.filter((a) => a.kind === 'sbpx');
    const sharedIsLastRow =
        !rawArtifact?.exists && sbpxArtifacts.length === 0;

    const onShareShared = useCallback(async () => {
        setArtifactBusy('share');
        setNotice(null);
        try {
            await Wizard.shareInvite(operatorId, friendlyName);
        } catch (e) {
            setError(String(e));
        } finally {
            setArtifactBusy(null);
        }
    }, [friendlyName, operatorId]);

    const onSaveShared = useCallback(async () => {
        setArtifactBusy('save');
        setNotice(null);
        try {
            await Wizard.saveSharedSbpToDownloads(
                operatorId,
                `${friendlyName}.sbp`,
            );
            setNotice(t('pub.share.saved'));
        } catch (e) {
            setError(String(e));
        } finally {
            setArtifactBusy(null);
        }
    }, [friendlyName, operatorId, t]);

    /** Build the shared pack when the staged file is missing.
     *
     *  It runs the *same* destructive command as "Rotate & re-share":
     *  `produce_shared_sbp` unconditionally revokes the shared `r0` user
     *  before re-minting it, which invalidates every shared pack already
     *  handed out. It used to be the one unguarded caller, gated purely
     *  on whether the staged file happened to exist — and file existence
     *  is not a proxy for "nothing has been distributed": the staging
     *  dir is wiped by panic-wipe, skipped by app-data restores, and
     *  cleanable by hand while the whole family still holds working
     *  copies. In that state the screen said "missing — build it" and
     *  one tap silently killed every relative's connection.
     *
     *  So both paths confirm. The copy differs because the situations
     *  read differently to the user, but the warning is the same. */
    const onBuildShared = useCallback(async () => {
        setArtifactBusy('build');
        setNotice(null);
        const ok = await runMgmt(async () => {
            await Wizard.produceSharedSbp(operatorId);
        }, setError);
        setConfirmBuild(false);
        if (ok) {
            await reloadArtifacts();
            setNotice(t('pub.artifacts.shared.built'));
        }
        setArtifactBusy(null);
    }, [operatorId, reloadArtifacts, runMgmt, t]);

    /** Rotate: re-mints the shared r0 user, which INVALIDATES every
     *  shared pack already distributed. Behind a confirm for exactly
     *  that reason. */
    const onRotateShared = useCallback(async () => {
        setArtifactBusy('rotate');
        setNotice(null);
        const ok = await runMgmt(async () => {
            await Wizard.produceSharedSbp(operatorId);
        }, setError);
        setConfirmRotate(false);
        if (ok) {
            await reloadArtifacts();
            try {
                await Wizard.shareInvite(operatorId, friendlyName);
            } catch (e) {
                setError(String(e));
            }
        }
        setArtifactBusy(null);
    }, [friendlyName, operatorId, reloadArtifacts, runMgmt]);

    const onResendSbpx = useCallback(
        async (path: string, label: string) => {
            setArtifactBusy(path);
            setNotice(null);
            try {
                await Wizard.shareInviteSbpx(path, label);
            } catch (e) {
                setError(String(e));
            } finally {
                setArtifactBusy(null);
            }
        },
        [],
    );

    const onSaveSbpx = useCallback(
        async (path: string, label: string) => {
            setArtifactBusy(path);
            setNotice(null);
            try {
                await Wizard.saveSbpxToDownloads(path, `${label}.sbpx`);
                setNotice(t('pub.share.saved'));
            } catch (e) {
                setError(String(e));
            } finally {
                setArtifactBusy(null);
            }
        },
        [t],
    );

    /** A recipient row whose .sbpx never got written — the rewrite fails
     *  closed on a pre-Tier-2 box. Until now there was no way to ask for
     *  a retry anywhere in the app.
     *
     *  It calls `recipientRepackSbpx`, NOT `recipientProvision`. The
     *  latter has no upsert path: it burns a fresh `r<n>`, mints a
     *  second live user on the relay, and only then hits the roster's
     *  UNIQUE (operator_id, pubkey) constraint and errors — so every tap
     *  would leave another credential set on the box that this app can
     *  never see or revoke, counting against the 128-recipient cap. The
     *  repack re-mints the recipient's *existing* box user instead. */
    const onRebuildSbpx = useCallback(
        async (r: RecipientSummary) => {
            setArtifactBusy(`rebuild:${r.id}`);
            setNotice(null);
            const ok = await runMgmt(async () => {
                await Wizard.recipientRepackSbpx(operatorId, r.id);
            }, setError);
            if (ok) {
                await Promise.all([reloadRecipients(), reloadArtifacts()]);
            }
            setArtifactBusy(null);
        },
        [operatorId, reloadArtifacts, reloadRecipients, runMgmt],
    );

    // ---- recipient actions --------------------------------------------

    const onAddSubmit = useCallback(async () => {
        if (!looksLikeDaalAddress(addAddress)) {
            setAddError(t('pub.recipients.add.bad_address'));
            return;
        }
        setAddBusy(true);
        const ok = await runMgmt(async () => {
            const s = await Wizard.recipientProvision(
                operatorId,
                addAddress.trim(),
                addDisplayName.trim(),
            );
            setRecipients((prev) => [s, ...prev]);
        }, setAddError);
        setAddBusy(false);
        if (ok) {
            setAddAddress('');
            setAddDisplayName('');
            setShowAdd(false);
            await reloadArtifacts();
        }
    }, [
        addAddress,
        addDisplayName,
        operatorId,
        reloadArtifacts,
        runMgmt,
        t,
    ]);

    const onRevokeConfirm = useCallback(async () => {
        if (!confirmRevoke) return;
        setRevokeBusy(true);
        const target = confirmRevoke.recipient;
        const ok = await runMgmt(async () => {
            const s = await Wizard.recipientRevoke(operatorId, target.id);
            setRecipients((prev) => prev.map((r) => (r.id === s.id ? s : r)));
        }, setRevokeError);
        setRevokeBusy(false);
        if (ok) {
            setConfirmRevoke(null);
            await reloadArtifacts();
        }
    }, [confirmRevoke, operatorId, reloadArtifacts, runMgmt]);

    const onRemoveConfirm = useCallback(async () => {
        if (!confirmRemove) return;
        setRemoveBusy(true);
        setRemoveError(null);
        try {
            await Wizard.recipientDelete(operatorId, confirmRemove.recipient.id);
            setRecipients((prev) =>
                prev.filter((r) => r.id !== confirmRemove.recipient.id),
            );
            setConfirmRemove(null);
            await reloadArtifacts();
        } catch (e) {
            setRemoveError(String(e));
        } finally {
            setRemoveBusy(false);
        }
    }, [confirmRemove, operatorId, reloadArtifacts]);

    // The Sync button was dead in the shipped build: it passed pin: ''
    // and validate_pin rejected it before the call ever left the app.
    // Dropping the parameter is what fixes it.
    const onSync = useCallback(async () => {
        setSyncing(true);
        setNotice(null);
        await runMgmt(async () => {
            const remote = await Wizard.recipientListRemote(operatorId);
            const local = new Set(
                recipients
                    .filter((r) => r.revoked_at_unix === 0)
                    .map((r) => r.address_str.toLowerCase()),
            );
            const remoteSet = new Set(remote.map((s) => s.toLowerCase()));
            const onlyLocal = [...local].filter((a) => !remoteSet.has(a));
            const onlyRemote = [...remoteSet].filter((a) => !local.has(a));
            setNotice(
                onlyLocal.length === 0 && onlyRemote.length === 0
                    ? t('pub.recipients.sync.in_sync')
                    : t('pub.recipients.sync.drift')
                          .replace('{onlyLocal}', String(onlyLocal.length))
                          .replace('{onlyRemote}', String(onlyRemote.length)),
            );
        }, setError);
        setSyncing(false);
    }, [operatorId, recipients, runMgmt, t]);

    // ---- danger zone ---------------------------------------------------

    const onSaveRecoveryKey = useCallback(async () => {
        // The exported blob is the relay's raw Ed25519 signing key in
        // base64 — not encrypted — and it lands in the shared Downloads
        // collection, readable by any app with storage access and out
        // of reach of panic-wipe. That is a deliberate trade (the DWK
        // is non-exportable, so a factory reset otherwise destroys every
        // relay this device publishes, and there is no escrow), but it
        // is not one to make on an unannounced single tap.
        if (!window.confirm(t('pub.danger.recovery.confirm'))) return;
        setDangerBusy(true);
        setNotice(null);
        try {
            const path = await Wizard.saveRecoveryKey(
                operatorId,
                `${friendlyName}-recovery.daalkey`,
            );
            setNotice(`${t('pub.danger.recovery.saved')} ${path}`);
        } catch (e) {
            setError(String(e));
        } finally {
            setDangerBusy(false);
        }
    }, [friendlyName, operatorId, t]);

    const onDecommission = useCallback(async () => {
        // Same honesty rule as the relay list: this removes the relay
        // from Daal and erases its secrets. It does NOT destroy the
        // cloud server — no CliRunner verb can — so the confirm prints
        // the address, because afterwards the app can no longer show it.
        const where =
            operator?.public_ip ||
            operator?.public_ipv6 ||
            operator?.server_id ||
            '—';
        if (
            !window.confirm(
                t('pub.relays.decommission.confirm')
                    .replace('{name}', title)
                    .replace('{ip}', where),
            )
        ) {
            return;
        }
        setDangerBusy(true);
        try {
            await Wizard.cancelAndCleanup(operatorId);
            onBack();
        } catch (e) {
            setError(String(e));
        } finally {
            setDangerBusy(false);
        }
    }, [onBack, operator, operatorId, t, title]);

    // ---- render --------------------------------------------------------

    return (
        <div style={{ padding: '12px 16px 24px 16px', display: 'grid', gap: 16 }}>
            {/* ---------------- Header ---------------- */}
            <div style={{ display: 'grid', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* Android's hardware back button is not wired to any
                        in-app navigation, so the only way out of a detail
                        screen has to be on screen. */}
                    <Button variant="ghost" onClick={onBack}>
                        {t('pub.relay.back')}
                    </Button>
                    {operator && (
                        <StatusPill
                            tone={
                                operator.status === 'provisioned'
                                    ? 'good'
                                    : 'gold'
                            }
                        >
                            {operator.status}
                        </StatusPill>
                    )}
                </div>

                {renaming ? (
                    <div style={{ display: 'grid', gap: 8 }}>
                        <Input
                            autoFocus
                            value={draftName}
                            onChange={(e) => setDraftName(e.target.value)}
                            placeholder={t('pub.relays.rename.placeholder')}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter') void commitRename();
                                else if (e.key === 'Escape') setRenaming(false);
                            }}
                        />
                        <div style={{ display: 'flex', gap: 8 }}>
                            <Button onClick={() => void commitRename()}>
                                {t('common.save')}
                            </Button>
                            <Button
                                variant="ghost"
                                onClick={() => setRenaming(false)}
                            >
                                {t('common.cancel')}
                            </Button>
                        </div>
                    </div>
                ) : (
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'baseline',
                            gap: 10,
                            flexWrap: 'wrap',
                        }}
                    >
                        <h2
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: 24,
                                fontWeight: 500,
                                margin: 0,
                                color: 'var(--fg)',
                            }}
                        >
                            {title}
                        </h2>
                        <Button
                            variant="ghost"
                            onClick={() => {
                                setDraftName(operator?.nickname ?? '');
                                setRenaming(true);
                            }}
                        >
                            {t('pub.relays.rename')}
                        </Button>
                    </div>
                )}

                <div style={MONO}>
                    {operator
                        ? [
                              operator.public_ip ||
                                  operator.public_ipv6 ||
                                  t('pub.relays.no_ip'),
                              operator.server_type,
                              operator.region,
                          ]
                              .filter(Boolean)
                              .join(' · ')
                        : ''}
                </div>

                {/* The custody tier, stated plainly. device_custody.rs is
                    explicit that these strings carry the security promise,
                    so we never print the hardware line on a device that
                    fell back to a weaker tier. */}
                {custody && (
                    <div style={LABEL}>{t(custodyLabelKey(custody.level))}</div>
                )}

                {error && (
                    <div style={{ color: 'var(--red)', fontSize: 12 }}>
                        {error}
                        {looksUnreachable(error) && (
                            <div
                                style={{
                                    color: 'var(--muted)',
                                    lineHeight: 1.5,
                                    marginTop: 4,
                                }}
                            >
                                {t('pub.recipients.err_unreachable')}
                            </div>
                        )}
                    </div>
                )}
                {notice && <div style={MONO}>{notice}</div>}

                {/* Last-resort helper-IP repair. Never a gate: by the time
                    this renders, the action has already tried a fresh
                    detection and one silent retry. */}
                {ipRepair && (
                    <Card>
                        <div style={{ display: 'grid', gap: 8 }}>
                            <div style={{ fontSize: 13, color: 'var(--fg)' }}>
                                {t('pub.helper_ip.title')}
                            </div>
                            <div style={LABEL}>{t('pub.helper_ip.body')}</div>
                            <Input
                                value={ipDraft}
                                onChange={(e) => setIpDraft(e.target.value)}
                                placeholder={t('pub.helper_ip.placeholder')}
                                style={{ fontFamily: 'var(--font-mono)' }}
                            />
                            <div style={{ display: 'flex', gap: 8 }}>
                                <Button
                                    onClick={() => void onIpRetry()}
                                    disabled={ipBusy}
                                >
                                    {ipBusy
                                        ? t('pub.helper_ip.retrying')
                                        : t('pub.helper_ip.retry')}
                                </Button>
                                <Button
                                    variant="ghost"
                                    onClick={() => setIpRepair(null)}
                                    disabled={ipBusy}
                                >
                                    {t('common.cancel')}
                                </Button>
                            </div>
                        </div>
                    </Card>
                )}
            </div>

            {/* ---------------- Artifacts ---------------- */}
            <Section
                eyebrow={t('pub.artifacts.eyebrow')}
                title={t('pub.artifacts.title')}
            >
                {/* Say out loud which relay these files belong to. With
                    several relays provisioned, a bare filename is not
                    enough to know what you are about to hand someone. */}
                <div style={{ ...LABEL, marginBottom: 8 }}>
                    {t('pub.artifacts.for').replace('{relay}', title)}
                </div>

                <Card>
                    {/* --- the "everyone" pack --- */}
                    {sharedArtifact?.exists ? (
                        <ListRow
                            title={t('pub.artifacts.shared.title')}
                            subtitle={
                                <span style={MONO}>
                                    {baseName(sharedArtifact.path)}
                                    {sharedArtifact.size_bytes > 0 && (
                                        <>
                                            {' · '}
                                            {sizeLabel(sharedArtifact.size_bytes)}
                                        </>
                                    )}
                                    {sharedArtifact.modified_at_unix > 0 && (
                                        <>
                                            {' · '}
                                            {tsLabel(
                                                sharedArtifact.modified_at_unix,
                                            )}
                                        </>
                                    )}
                                </span>
                            }
                            trailing={
                                <span
                                    style={{
                                        display: 'inline-flex',
                                        gap: 6,
                                        flexWrap: 'wrap',
                                    }}
                                >
                                    <Button
                                        onClick={() => void onShareShared()}
                                        disabled={artifactBusy !== null}
                                    >
                                        {t('pub.artifacts.share')}
                                    </Button>
                                    <Button
                                        variant="secondary"
                                        onClick={() => void onSaveShared()}
                                        disabled={artifactBusy !== null}
                                    >
                                        {t('pub.share.save')}
                                    </Button>
                                    <Button
                                        variant="secondary"
                                        onClick={() => setConfirmRotate(true)}
                                        disabled={artifactBusy !== null}
                                    >
                                        {t('pub.artifacts.rotate')}
                                    </Button>
                                </span>
                            }
                            last={sharedIsLastRow}
                        />
                    ) : (
                        <ListRow
                            title={t('pub.artifacts.shared.missing.title')}
                            subtitle={t('pub.artifacts.shared.missing.body')}
                            last={sharedIsLastRow}
                            trailing={
                                <Button
                                    onClick={() => setConfirmBuild(true)}
                                    disabled={artifactBusy !== null}
                                >
                                    {artifactBusy === 'build'
                                        ? t('pub.artifacts.building')
                                        : t('pub.artifacts.shared.build')}
                                </Button>
                            }
                        />
                    )}

                    {/* --- the raw signed bundle --- */}
                    {rawArtifact?.exists && (
                        <ListRow
                            title={
                                <span style={{ color: 'var(--muted)' }}>
                                    {t('pub.artifacts.raw.title')}
                                </span>
                            }
                            subtitle={
                                <span style={MONO}>
                                    {baseName(rawArtifact.path)}
                                    {' · '}
                                    {t('pub.artifacts.raw.not_connectable')}
                                </span>
                            }
                            last={sbpxArtifacts.length === 0}
                        />
                    )}

                    {/* --- one row per recipient --- */}
                    {sbpxArtifacts.map((a, i) => {
                        const label =
                            a.recipient_label || `#${a.recipient_id ?? '?'}`;
                        const r =
                            recipients.find((x) => x.id === a.recipient_id) ??
                            null;
                        const last = i === sbpxArtifacts.length - 1;
                        if (!a.exists) {
                            return (
                                <ListRow
                                    key={`${a.recipient_id}-missing`}
                                    title={label}
                                    subtitle={t(
                                        r && r.revoked_at_unix > 0
                                            ? 'pub.artifacts.sbpx.revoked'
                                            : 'pub.artifacts.sbpx.missing',
                                    )}
                                    trailing={
                                        /* Revoked rows keep their
                                           artifact row (the roster shows
                                           history) but must NOT offer a
                                           rebuild: re-minting would hand
                                           a working credential back to
                                           someone deliberately cut off. */
                                        r && r.revoked_at_unix === 0 && (
                                            <Button
                                                onClick={() =>
                                                    void onRebuildSbpx(r)
                                                }
                                                disabled={artifactBusy !== null}
                                            >
                                                {artifactBusy ===
                                                `rebuild:${r.id}`
                                                    ? t('pub.artifacts.building')
                                                    : t('pub.artifacts.sbpx.rebuild')}
                                            </Button>
                                        )
                                    }
                                    last={last}
                                />
                            );
                        }
                        return (
                            <ListRow
                                key={a.path}
                                title={label}
                                subtitle={
                                    <span style={MONO}>
                                        {baseName(a.path)}
                                        {a.size_bytes > 0 && (
                                            <>
                                                {' · '}
                                                {sizeLabel(a.size_bytes)}
                                            </>
                                        )}
                                        {a.modified_at_unix > 0 && (
                                            <>
                                                {' · '}
                                                {tsLabel(a.modified_at_unix)}
                                            </>
                                        )}
                                    </span>
                                }
                                trailing={
                                    <span
                                        style={{
                                            display: 'inline-flex',
                                            gap: 6,
                                            flexWrap: 'wrap',
                                        }}
                                    >
                                        <Button
                                            onClick={() =>
                                                void onResendSbpx(a.path, label)
                                            }
                                            disabled={artifactBusy !== null}
                                        >
                                            {t('pub.recipients.resend')}
                                        </Button>
                                        <Button
                                            variant="secondary"
                                            onClick={() =>
                                                void onSaveSbpx(a.path, label)
                                            }
                                            disabled={artifactBusy !== null}
                                        >
                                            {t('pub.share.save')}
                                        </Button>
                                    </span>
                                }
                                last={last}
                            />
                        );
                    })}
                </Card>
            </Section>

            {/* ---------------- Recipients ---------------- */}
            <Section
                eyebrow={t('pub.recipients.eyebrow')}
                title={t('pub.recipients.title')}
                action={
                    <span style={{ display: 'inline-flex', gap: 8 }}>
                        <Button variant="secondary" onClick={() => void onSync()} disabled={syncing}>
                            {syncing
                                ? t('pub.recipients.syncing')
                                : t('pub.recipients.sync')}
                        </Button>
                        <Button onClick={() => setShowAdd(true)}>
                            {t('pub.recipients.add')}
                        </Button>
                    </span>
                }
            >
                {recipients.length === 0 && !loading && (
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
                                                        fontFamily:
                                                            'var(--font-mono)',
                                                    }}
                                                >
                                                    {t('pub.recipients.revoked')}
                                                </span>
                                            )}
                                        </span>
                                    }
                                    subtitle={
                                        <span
                                            style={{
                                                fontFamily: 'var(--font-mono)',
                                                fontSize: 11,
                                            }}
                                        >
                                            {shortAddr(r.address_str)}
                                            {r.provisioned_at_unix > 0 && (
                                                <>
                                                    {' · '}
                                                    {t('pub.recipients.added')}{' '}
                                                    {tsLabel(
                                                        r.provisioned_at_unix,
                                                    )}
                                                </>
                                            )}
                                        </span>
                                    }
                                    trailing={
                                        <span
                                            style={{
                                                display: 'inline-flex',
                                                gap: 6,
                                                flexWrap: 'wrap',
                                            }}
                                        >
                                            {!revoked && (
                                                <Button
                                                    variant="danger"
                                                    onClick={() => {
                                                        setConfirmRevoke({
                                                            recipient: r,
                                                        });
                                                        setRevokeError(null);
                                                    }}
                                                >
                                                    {t('pub.recipients.revoke')}
                                                </Button>
                                            )}
                                            {/* Once revoked (on-box teardown
                                                done) the greyed-out row can be
                                                purged from the local roster. */}
                                            {revoked && (
                                                <Button
                                                    variant="secondary"
                                                    onClick={() => {
                                                        setConfirmRemove({
                                                            recipient: r,
                                                        });
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

            {/* ---------------- Danger ---------------- */}
            <Section
                eyebrow={t('pub.danger.eyebrow')}
                title={t('pub.danger.title')}
            >
                <Card>
                    <ListRow
                        title={t('pub.danger.recovery.title')}
                        subtitle={t('pub.danger.recovery.body')}
                        trailing={
                            <Button
                                variant="secondary"
                                onClick={() => void onSaveRecoveryKey()}
                                disabled={dangerBusy}
                            >
                                {t('pub.danger.recovery.action')}
                            </Button>
                        }
                    />
                    <ListRow
                        title={t('pub.danger.decommission.title')}
                        subtitle={t('pub.danger.decommission.body')}
                        trailing={
                            <Button
                                variant="danger"
                                onClick={() => void onDecommission()}
                                disabled={dangerBusy}
                            >
                                {t('pub.relays.decommission')}
                            </Button>
                        }
                        last
                    />
                </Card>
            </Section>

            {/* ---------------- Sheets ---------------- */}

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
                                variant="ghost"
                                onClick={() => setShowAdd(false)}
                                disabled={addBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button onClick={() => void onAddSubmit()} disabled={addBusy}>
                                {addBusy
                                    ? `${t('pub.recipients.adding')} (${addElapsed}s)`
                                    : t('pub.recipients.add.submit')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <label style={LABEL}>
                            {t('pub.recipients.add.address')}
                        </label>
                        <Input
                            value={addAddress}
                            onChange={(e) => setAddAddress(e.target.value)}
                            placeholder="daal1…"
                            style={{ fontFamily: 'var(--font-mono)' }}
                        />
                        <label style={LABEL}>
                            {t('pub.recipients.add.display_name')}
                        </label>
                        <Input
                            value={addDisplayName}
                            onChange={(e) => setAddDisplayName(e.target.value)}
                        />
                        {/* While the add is in flight, spell out the stages
                            so the user knows the app is alive and roughly
                            how long the ~30 s round-trip has to go. */}
                        {addBusy && (
                            <div
                                style={{
                                    fontSize: 11,
                                    color: 'var(--muted)',
                                    fontFamily: 'var(--font-mono)',
                                    lineHeight: 1.5,
                                }}
                            >
                                {t('pub.recipients.adding_detail')}
                            </div>
                        )}
                        {addError && (
                            <>
                                <div
                                    style={{ color: 'var(--red)', fontSize: 12 }}
                                >
                                    {addError}
                                </div>
                                {looksUnreachable(addError) && (
                                    <div
                                        style={{
                                            fontSize: 11,
                                            color: 'var(--muted)',
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t('pub.recipients.err_unreachable')}
                                    </div>
                                )}
                            </>
                        )}
                        <div style={MONO}>
                            {t('pub.artifacts.for').replace('{relay}', title)}
                        </div>
                    </div>
                </Sheet>
            )}

            {confirmRotate && (
                <Sheet
                    title={t('pub.artifacts.rotate.title')}
                    onClose={() => {
                        if (artifactBusy === null) setConfirmRotate(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmRotate(false)}
                                disabled={artifactBusy !== null}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void onRotateShared()}
                                disabled={artifactBusy !== null}
                            >
                                {artifactBusy === 'rotate'
                                    ? t('pub.artifacts.building')
                                    : t('pub.artifacts.rotate.confirm')}
                            </Button>
                        </span>
                    }
                >
                    {/* Sharing the existing pack and rotating it are
                        different acts with different blast radii; the old
                        UI conflated them under one "Re-share relay"
                        button. Rotating best-effort revokes and re-mints
                        the shared r0 user, so every copy already handed
                        out stops working. */}
                    <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                        {t('pub.artifacts.rotate.body')}
                    </div>
                </Sheet>
            )}

            {confirmBuild && (
                <Sheet
                    title={t('pub.artifacts.shared.build.title')}
                    onClose={() => {
                        if (artifactBusy === null) setConfirmBuild(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmBuild(false)}
                                disabled={artifactBusy !== null}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                onClick={() => void onBuildShared()}
                                disabled={artifactBusy !== null}
                            >
                                {artifactBusy === 'build'
                                    ? t('pub.artifacts.building')
                                    : t('pub.artifacts.shared.build')}
                            </Button>
                        </span>
                    }
                >
                    {/* "The file is missing" and "nothing has been handed
                        out" are not the same statement — the staging dir
                        can be wiped while the family still holds working
                        copies. Building re-mints r0 either way, so say
                        what that costs before doing it. */}
                    <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                        {t('pub.artifacts.shared.build.body')}
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
                                variant="ghost"
                                onClick={() => setConfirmRevoke(null)}
                                disabled={revokeBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void onRevokeConfirm()}
                                disabled={revokeBusy}
                            >
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
                        <div style={MONO}>
                            {confirmRevoke.recipient.address_str}
                        </div>
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
                                variant="ghost"
                                onClick={() => setConfirmRemove(null)}
                                disabled={removeBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void onRemoveConfirm()}
                                disabled={removeBusy}
                            >
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
                        <div style={MONO}>
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
