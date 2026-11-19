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
//   header        — which relay this is
//   1 PEOPLE      — who has access; each person's own file is on
//                   their row (PeopleSection)
//   2 ONE FILE    — the file that works for anybody
//                   (EveryoneFileSection)
//   3 KEEP IT     — whether people's apps can repair themselves, and
//     WORKING       the settings behind that (FreshnessPanel), closed
//                   until tapped
//   4 DANGER      — recovery key, rotations, removal; closed until
//                   tapped
//   details       — what only a maintainer asks about
//
// Each section has ONE job and ONE visible sentence. The page was
// reorganised after the first real-phone session, where the owner could
// not tell what was for everyone and what was for one person, what
// "refresh" meant, or how "+ Add" differed from "+ Add address" — and
// pressed Save four times because nothing answered. Longer explanations
// sit behind "What is this?"; every action answers through `useAction`.
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
    RotateCredentialsSummary,
    RotateTlsSummary,
} from './wizardCommands';
import {
    Card,
    ListRow,
    Button,
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
// Wave 3 Step 8 + 9. Both live in their own files because both are
// substantial screens in their own right, and this page is already the
// single busiest file in the publisher surface.
import { FreshnessPanel } from './FreshnessPanel';
import { AddressSwap } from './AddressSwap';
import { RelayRebuild } from './RelayRebuild';
import { RelayGonePanel } from './RelayGonePanel';
import { RotationAdvice } from './RotationAdvice';
import { RelayDestroySheet, relayTitle } from './RelayListPage';
// Wave 4 Step 11. The one share affordance that needs no network at
// all: the pack leaves this device as light, off the screen.
import { QrSendSheet } from './QrSendSheet';
import { ActionButton, ActionToast, useAction } from './useAction';
import { explainFailure, failureBlock } from './failureText';
import { Collapsible } from './Disclosure';
import { PeopleSection, joinPeople, personLabel } from './PeopleSection';
import { EveryoneFileSection } from './EveryoneFileSection';
import { relayBadge } from './relayStatus';
import { rotateTlsVerdict } from './rotateTlsVerdict';

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

/** Anything the relay or the cloud plane said during a rotation, shown
 *  verbatim.
 *
 *  Verbatim is the whole point. These strings are the only channel by
 *  which a box reports a half-applied change — a config that reloaded
 *  but a firewall rule that did not, a field an older mgmt binary could
 *  not set — and paraphrasing them into a friendly summary is how a
 *  partial rotation gets mistaken for a clean one. */
function RotationWarnings({
    t,
    warnings,
}: {
    t: (k: string) => string;
    warnings: string[];
}) {
    if (!warnings.length) return null;
    return (
        <div style={{ display: 'grid', gap: 4 }}>
            <div style={LABEL}>{t('pub.rotate.warnings')}</div>
            {warnings.map((w, i) => (
                <div key={i} style={{ ...MONO, color: 'var(--red)' }}>
                    {w}
                </div>
            ))}
        </div>
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
    /** Gets the untouched error, for callers that explain it themselves. */
    onRaw?: (e: unknown) => void,
) => Promise<boolean>;

/** A failure held in one string: the plain explanation, a blank line,
 *  then the relay's own words. */
const ERR_BLOCK: React.CSSProperties = {
    color: 'var(--red)',
    fontSize: 12,
    whiteSpace: 'pre-line',
    lineHeight: 1.5,
};

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
    // Wave 3 Step 8. `freshTick` is bumped after anything that re-signs
    // the pack, because the freshness panel's headline answer ("can the
    // files people hold repair themselves?") is stamped at sign time and
    // would otherwise sit there stale.
    const [freshTick, setFreshTick] = useState(0);
    // How many refresh addresses are inside the SIGNED pack. Drives the
    // consequence copy on the address swap; loaded alongside the relay
    // so the sheet never has to ask while the operator is reading it.
    const [mirrorsInPack, setMirrorsInPack] = useState(0);
    const [recipients, setRecipients] = useState<RecipientSummary[]>([]);
    const [artifacts, setArtifacts] = useState<ArtifactInfo[]>([]);
    const [custody, setCustody] = useState<PublisherCustodyStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // One lock and one result banner for the whole screen: while any
    // action runs no other can start, and every one of them ends with a
    // sentence the person can see wherever the page is scrolled.
    const explain = useCallback((e: unknown) => explainFailure(t, e), [t]);
    const action = useAction(explain);

    // Sections that are one line until tapped.
    const [dangerOpen, setDangerOpen] = useState(false);
    const [detailsOpen, setDetailsOpen] = useState(false);

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
    const [qrSend, setQrSend] = useState(false);

    // Wave 3 Step 7 — the two rotations, kept apart all the way down to
    // their state. Per-recipient re-keying affects ONE person and lives
    // on that person's row; moving the relay's disguise kills every file
    // ever handed out and lives in the danger zone. Nothing here offers
    // to do both at once.
    const [confirmRotateCreds, setConfirmRotateCreds] =
        useState<RecipientSummary | null>(null);
    const [rotateCredsBusy, setRotateCredsBusy] = useState(false);
    const [rotateCredsError, setRotateCredsError] = useState<string | null>(null);
    const [rotateCredsDone, setRotateCredsDone] =
        useState<RotateCredentialsSummary | null>(null);

    const [confirmRotateTls, setConfirmRotateTls] = useState(false);
    const [rotateTlsBusy, setRotateTlsBusy] = useState(false);
    const [rotateTlsError, setRotateTlsError] = useState<string | null>(null);
    const [rotateTlsDone, setRotateTlsDone] = useState<RotateTlsSummary | null>(
        null,
    );

    // Nothing in the danger zone may start while another action runs.
    const dangerBusy = action.busy !== null;
    /** Teardown sheet — the two-outcome confirm shared with the relay
     *  list. See RelayDestroySheet. */
    const [confirmDestroy, setConfirmDestroy] = useState(false);

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
            setError(failureBlock(t, e));
        }
        // Best-effort: a relay with no freshness configured is the
        // common case and must not turn the whole page red.
        try {
            const f = await Wizard.freshnessStatus(operatorId);
            setMirrorsInPack(f.mirrors_in_pack.length);
        } catch {
            setMirrorsInPack(0);
        }
    }, [operatorId, t]);

    const reloadRecipients = useCallback(async () => {
        try {
            setRecipients(await Wizard.recipientList(operatorId));
        } catch (e) {
            setError(failureBlock(t, e));
        }
    }, [operatorId, t]);

    const reloadArtifacts = useCallback(async () => {
        try {
            // Pure fs::metadata on the Rust side — safe to call after
            // every action that could have produced or invalidated a file.
            setArtifacts(await Wizard.listArtifacts(operatorId));
        } catch (e) {
            setError(failureBlock(t, e));
        }
    }, [operatorId, t]);

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

    /** How many people are holding a working file from this relay. The
     *  relay-level rotation confirm needs it to say "N people" instead
     *  of "everyone", which is what turns an abstract warning into a
     *  decision the operator can actually weigh. */
    const liveRecipientCount = useMemo(
        () => recipients.filter((r) => r.revoked_at_unix === 0).length,
        [recipients],
    );

    const commitRename = useCallback(async () => {
        const r = await action.run(
            'rename',
            () => Wizard.setOperatorNickname(operatorId, draftName.trim()),
            { ok: t('pub.fb.renamed'), fail: t('pub.fb.renamed.fail') },
        );
        if (r.ok) {
            setRenaming(false);
            await reloadOperator();
        }
    }, [action.run, draftName, operatorId, reloadOperator, t]);

    // ---- mgmt-plane action wrapper ------------------------------------

    // Every call that reaches the box goes through here. withHelperIp
    // already re-detects and retries once; this adds the *user-visible*
    // last resort — a card with an editable address — instead of the old
    // behaviour, which was an inertly disabled button and a hint saying
    // "need helper IP".
    const runMgmt: MgmtRunner = useCallback(
        async (fn, setErr, onRaw) => {
            setErr(null);
            try {
                await withHelperIp(operatorId, fn);
                setIpRepair(null);
                return true;
            } catch (e) {
                onRaw?.(e);
                const code = classifyPublisherError(e);
                if (
                    code === 'E_HELPER_IP_MISSING' ||
                    code === 'E_HELPER_IP_STALE'
                ) {
                    const detected = await detectPublicIp();
                    setIpDraft(detected?.ip ?? '');
                    setIpRepair({ retry: () => runMgmt(fn, setErr, onRaw) });
                }
                // Plain words first, then the relay's own words under
                // them. The raw tail is not noise: for a relay too old
                // to do something it names which half was refused, and
                // for changed keys it names which key — the bit a
                // maintainer needs and the bit a user can forward. But
                // it is never the sentence.
                setErr(failureBlock(t, e));
                return false;
            }
        },
        [operatorId, t],
    );

    /** `runMgmt` for an action that reports through the banner: the
     *  same helper-address repair, but it throws the untouched error so
     *  `action.run` can explain it. */
    const viaMgmt = useCallback(
        <T,>(fn: () => Promise<T>) =>
            async (): Promise<T> => {
                const out: { v?: T } = {};
                const raw: { e: unknown } = { e: null };
                const ok = await runMgmt(
                    async () => {
                        out.v = await fn();
                    },
                    () => {},
                    (e) => {
                        raw.e = e;
                    },
                );
                if (!ok) throw raw.e;
                return out.v as T;
            },
        [runMgmt],
    );

    const onIpRetry = useCallback(async () => {
        if (!ipRepair) return;
        setIpBusy(true);
        try {
            const typed = ipDraft.trim();
            if (typed) await setHelperIpManually(operatorId, typed);
            const ok = await ipRepair.retry();
            if (ok) {
                // The retry re-ran only the call to the relay, not
                // whatever the original button did afterwards — so
                // re-read everything it could have changed, and say it
                // worked.
                await Promise.all([
                    reloadOperator(),
                    reloadRecipients(),
                    reloadArtifacts(),
                ]);
                setFreshTick((n) => n + 1);
                action.report('ip', 'ok', t('pub.fb.retry_ok'));
            } else {
                action.report('ip', 'fail', t('pub.helper_ip.stale'));
            }
        } catch (e) {
            const f = explainFailure(t, e);
            action.report('ip', 'fail', f.message, f.detail);
        } finally {
            setIpBusy(false);
        }
    }, [
        action.report,
        ipDraft,
        ipRepair,
        operatorId,
        reloadArtifacts,
        reloadOperator,
        reloadRecipients,
        t,
    ]);

    // ---- artifact actions ---------------------------------------------

    const sharedArtifact = artifacts.find((a) => a.kind === 'shared_sbp') ?? null;
    const rawArtifact = artifacts.find((a) => a.kind === 'raw_sbp') ?? null;
    const people = useMemo(
        () => joinPeople(recipients, artifacts),
        [recipients, artifacts],
    );

    /** "Send" hands the file to the system: the share menu on a phone,
     *  the file's folder on a computer. Daal cannot know whether the
     *  person then actually sent it, so the result says what DID happen
     *  — the file is ready and a window opened — and not "sent". */
    const onShareShared = useCallback(async () => {
        await action.run(
            'everyone:send',
            () => Wizard.shareInvite(operatorId, friendlyName),
            { ok: t('pub.fb.send.ok'), fail: t('pub.fb.send.fail') },
        );
    }, [action.run, friendlyName, operatorId, t]);

    const onSaveShared = useCallback(async () => {
        const name = `${friendlyName}.sbp`;
        await action.run(
            'everyone:save',
            () => Wizard.saveSharedSbpToDownloads(operatorId, name),
            {
                ok: t('pub.fb.save.ok').replace('{name}', name),
                fail: t('pub.fb.save.fail'),
            },
        );
    }, [action.run, friendlyName, operatorId, t]);

    /** Copy the everyone file as pasteable text.
     *
     *  The other half of the paste lane: the client can already IMPORT
     *  a pasted file, but until this button there was no way inside any
     *  Daal app to PRODUCE one — the operator's only offline options
     *  were a QR (needs both people in one room) or a file (the thing
     *  the messenger bans). This is the affordance that still works on
     *  the day file transfer stops.
     *
     *  'shared' is deliberate and matches the QR button: the everyone
     *  file is the only one that can connect anybody.
     */
    const onCopyPasteable = useCallback(async () => {
        await action.run(
            'everyone:copy',
            async () => {
                const text = await Wizard.copyPasteable(operatorId, 'shared');
                await navigator.clipboard.writeText(text);
            },
            { ok: t('pub.artifacts.copied'), fail: t('pub.fb.copy.fail') },
        );
    }, [action.run, operatorId, t]);

    /** Make the everyone file when it is missing from this device.
     *
     *  It runs the *same* destructive command as "Replace this file":
     *  `produce_shared_sbp` unconditionally revokes the shared `r0` user
     *  before re-minting it, which invalidates every everyone file
     *  already handed out. It used to be the one unguarded caller, gated
     *  purely on whether the staged file happened to exist — and file
     *  existence is not a proxy for "nothing has been distributed": the
     *  staging dir is wiped by panic-wipe, skipped by app-data restores,
     *  and cleanable by hand while the whole family still holds working
     *  copies. In that state the screen said "missing — build it" and
     *  one tap silently killed every relative's connection.
     *
     *  So both paths confirm. The copy differs because the situations
     *  read differently to the user, but the warning is the same. */
    const onBuildShared = useCallback(async () => {
        const r = await action.run(
            'everyone:make',
            viaMgmt(() => Wizard.produceSharedSbp(operatorId)),
            { ok: t('pub.fb.everyone_made'), fail: t('pub.fb.everyone_made.fail') },
        );
        if (!r.ran) return;
        setConfirmBuild(false);
        if (r.ok) await reloadArtifacts();
    }, [action.run, operatorId, reloadArtifacts, t, viaMgmt]);

    /** Replace: re-mints the shared r0 user, which INVALIDATES every
     *  everyone file already distributed. Behind a confirm for exactly
     *  that reason.
     *
     *  Two steps, reported separately: a share window that fails to
     *  open after the file WAS replaced must not be reported as "the
     *  file was not replaced" — every copy out there is already dead. */
    const onRotateShared = useCallback(async () => {
        const made = await action.run(
            'everyone:replace',
            viaMgmt(() => Wizard.produceSharedSbp(operatorId)),
            { ok: null, fail: t('pub.fb.everyone_replaced.fail') },
        );
        if (!made.ran) return;
        setConfirmRotate(false);
        if (!made.ok) return;
        await reloadArtifacts();
        await action.run(
            'everyone:replace',
            () => Wizard.shareInvite(operatorId, friendlyName),
            {
                ok: t('pub.fb.everyone_replaced'),
                fail: t('pub.fb.everyone_replaced.send_fail'),
            },
        );
    }, [action.run, friendlyName, operatorId, reloadArtifacts, t, viaMgmt]);

    const onResendSbpx = useCallback(
        async (path: string, label: string) => {
            await action.run(
                `send:${path}`,
                () => Wizard.shareInviteSbpx(path, label),
                { ok: t('pub.fb.send.ok'), fail: t('pub.fb.send.fail') },
            );
        },
        [action.run, t],
    );

    /** The action the owner pressed four times. It always worked; it
     *  never said so. */
    const onSaveSbpx = useCallback(
        async (path: string, label: string) => {
            const name = `${label}.sbpx`;
            await action.run(
                `save:${path}`,
                () => Wizard.saveSbpxToDownloads(path, name),
                {
                    ok: t('pub.fb.save.ok').replace('{name}', name),
                    fail: t('pub.fb.save.fail'),
                },
            );
        },
        [action.run, t],
    );

    /** A person whose file never got written — the rewrite fails closed
     *  on a pre-Tier-2 box.
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
            const res = await action.run(
                `remake:${r.id}`,
                viaMgmt(() => Wizard.recipientRepackSbpx(operatorId, r.id)),
                {
                    ok: t('pub.fb.person_file_made').replace('{name}', personLabel(r)),
                    fail: t('pub.fb.person_file_made.fail'),
                },
            );
            if (res.ok) {
                await Promise.all([reloadRecipients(), reloadArtifacts()]);
            }
        },
        [action.run, operatorId, reloadArtifacts, reloadRecipients, t, viaMgmt],
    );

    // ---- people actions -------------------------------------------------
    //
    // The sheets below keep their own busy flag and print a failure
    // inside the sheet, next to the button that caused it. What they
    // lacked was the other half: on success they simply closed. Each
    // one now says what it did.

    const onAddSubmit = useCallback(async () => {
        if (!looksLikeDaalAddress(addAddress)) {
            setAddError(t('pub.recipients.add.bad_address'));
            return;
        }
        setAddBusy(true);
        const added: { v: RecipientSummary | null } = { v: null };
        const ok = await runMgmt(async () => {
            const s = await Wizard.recipientProvision(
                operatorId,
                addAddress.trim(),
                addDisplayName.trim(),
            );
            added.v = s;
            setRecipients((prev) => [s, ...prev]);
        }, setAddError);
        setAddBusy(false);
        if (ok) {
            setAddAddress('');
            setAddDisplayName('');
            setShowAdd(false);
            await reloadArtifacts();
            action.report(
                'person:add',
                'ok',
                t('pub.fb.person_added').replace(
                    '{name}',
                    added.v ? personLabel(added.v) : '',
                ),
            );
        }
    }, [
        action.report,
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
            action.report(
                'person:revoke',
                'ok',
                t('pub.fb.access_removed').replace('{name}', personLabel(target)),
            );
        }
    }, [action.report, confirmRevoke, operatorId, reloadArtifacts, runMgmt, t]);

    const onRemoveConfirm = useCallback(async () => {
        if (!confirmRemove) return;
        const target = confirmRemove.recipient;
        setRemoveBusy(true);
        setRemoveError(null);
        try {
            await Wizard.recipientDelete(operatorId, target.id);
            setRecipients((prev) => prev.filter((r) => r.id !== target.id));
            setConfirmRemove(null);
            await reloadArtifacts();
            action.report(
                'person:remove',
                'ok',
                t('pub.fb.person_removed').replace('{name}', personLabel(target)),
            );
        } catch (e) {
            setRemoveError(failureBlock(t, e));
        } finally {
            setRemoveBusy(false);
        }
    }, [action.report, confirmRemove, operatorId, reloadArtifacts, t]);

    // ---- Wave 3 Step 7: rotations ---------------------------------------

    /** Re-key ONE recipient. The relay issues them a fresh credential
     *  across every inbound and cancels the old one; the roster row and
     *  their `.sbpx` are rebuilt in the same call.
     *
     *  Deliberately NOT the same control as "Change disguise" below.
     *  This is a targeted revocation — one person's file dies and
     *  everyone else is untouched — and the relay used to conflate it
     *  with re-keying the whole box, which would have taken every
     *  recipient down at once from a per-row button. */
    const onRotateCredsConfirm = useCallback(async () => {
        if (!confirmRotateCreds) return;
        const target = confirmRotateCreds;
        setRotateCredsBusy(true);
        // Boxed because runMgmt's callback returns void; a bare `let`
        // assigned inside it narrows to null for the compiler.
        const out: { v: RotateCredentialsSummary | null } = { v: null };
        const ok = await runMgmt(async () => {
            out.v = await Wizard.rotateCredentials(operatorId, target.name);
        }, setRotateCredsError);
        setRotateCredsBusy(false);
        if (ok && out.v) {
            setConfirmRotateCreds(null);
            setRotateCredsDone(out.v);
            await Promise.all([reloadRecipients(), reloadArtifacts()]);
        }
    }, [confirmRotateCreds, operatorId, reloadArtifacts, reloadRecipients, runMgmt]);

    /** Move the relay's cover hostname. Nobody's key changes — but every
     *  file already handed out pins the old hostname, so all of them die
     *  at once. Step 8 (remote pack replacement) does not exist, so the
     *  result panel has to send the user back up this page to rebuild
     *  and hand-deliver each file. */
    const onRotateTlsConfirm = useCallback(async () => {
        setRotateTlsBusy(true);
        const out: { v: RotateTlsSummary | null } = { v: null };
        const ok = await runMgmt(async () => {
            out.v = await Wizard.rotateTls(operatorId);
        }, setRotateTlsError);
        setRotateTlsBusy(false);
        if (ok && out.v) {
            setConfirmRotateTls(false);
            setRotateTlsDone(out.v);
            await Promise.all([reloadOperator(), reloadArtifacts()]);
        }
    }, [operatorId, reloadArtifacts, reloadOperator, runMgmt]);

    // Compare the list here with the list on the relay. (It was dead in
    // one shipped build: it passed pin: '' and validate_pin rejected it
    // before the call ever left the app.) A maintainer's check, so it
    // lives under Details — but it reaches the relay, takes seconds, and
    // used to answer in grey text at the top of the page.
    const onSync = useCallback(async () => {
        await action.run(
            'details:compare',
            viaMgmt(async () => {
                const remote = await Wizard.recipientListRemote(operatorId);
                const local = new Set(
                    recipients
                        .filter((r) => r.revoked_at_unix === 0)
                        .map((r) => r.address_str.toLowerCase()),
                );
                const remoteSet = new Set(remote.map((s) => s.toLowerCase()));
                const onlyLocal = [...local].filter((a) => !remoteSet.has(a));
                const onlyRemote = [...remoteSet].filter((a) => !local.has(a));
                return onlyLocal.length === 0 && onlyRemote.length === 0
                    ? t('pub.details.compare.same')
                    : t('pub.details.compare.differ')
                          .replace('{onlyLocal}', String(onlyLocal.length))
                          .replace('{onlyRemote}', String(onlyRemote.length));
            }),
            { ok: (msg) => msg, fail: t('pub.details.compare.fail') },
        );
    }, [action.run, operatorId, recipients, t, viaMgmt]);

    // ---- danger zone ---------------------------------------------------

    const onSaveRecoveryKey = useCallback(async () => {
        // The exported blob is the relay's raw Ed25519 signing key in
        // base64 — not encrypted — and it lands in the shared Downloads
        // collection, readable by any app with storage access and out
        // of reach of panic-wipe. That is a deliberate trade (the DWK
        // is non-exportable, so a factory reset otherwise destroys every
        // relay this device publishes, and there is no escrow), but it
        // is not one to make on an unannounced single tap.
        if (action.busy !== null) return;
        if (!window.confirm(t('pub.danger.recovery.confirm'))) return;
        await action.run(
            'danger:recovery',
            () =>
                Wizard.saveRecoveryKey(
                    operatorId,
                    `${friendlyName}-recovery.daalkey`,
                ),
            {
                ok: (path) => `${t('pub.danger.recovery.saved')} ${path}`,
                fail: t('pub.fb.recovery.fail'),
            },
        );
    }, [action.busy, action.run, friendlyName, operatorId, t]);

    /** What the teardown sheet is about to destroy. Detail can be
     *  rendered before the summary lands, so fall back to the id — the
     *  sheet still has to be able to name the relay. */
    const destroyTargetForRelay = useMemo(
        () => ({
            operatorId,
            name: title,
            where:
                operator?.public_ip ||
                operator?.public_ipv6 ||
                operator?.server_id ||
                '',
        }),
        [operator, operatorId, title],
    );

    // ---- render --------------------------------------------------------

    const badge = operator ? relayBadge(operator.status) : null;
    const tlsVerdict = rotateTlsDone
        ? rotateTlsVerdict(rotateTlsDone, mirrorsInPack)
        : null;
    const relayGone = operator?.status === 'rebuild_failed';

    return (
        <div style={{ padding: '12px 16px 24px 16px', display: 'grid', gap: 20 }}>
            {/* ---------------- Header ---------------- */}
            <div style={{ display: 'grid', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* Android's hardware back button is not wired to any
                        in-app navigation, so the only way out of a detail
                        screen has to be on screen. */}
                    <Button variant="ghost" onClick={onBack}>
                        {t('pub.relay.back')}
                    </Button>
                    {/* What the app last recorded about this relay, in
                        words — never the raw state token, and never
                        green: nothing here has checked that it answers. */}
                    {badge && (
                        <StatusPill tone={badge.tone}>{t(badge.labelKey)}</StatusPill>
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
                            <ActionButton
                                action={action}
                                k="rename"
                                busyLabel={t('pub.fb.saving')}
                                onClick={() => void commitRename()}
                            >
                                {t('common.save')}
                            </ActionButton>
                            <Button
                                variant="ghost"
                                onClick={() => setRenaming(false)}
                                disabled={action.busy !== null}
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

                {/* A page that could not load says so here, in plain
                    words with the relay's own words under them. Results
                    of things the person DID are in the banner at the
                    bottom of the screen, not here: this spot scrolls
                    away. */}
                {error && <div style={ERR_BLOCK}>{error}</div>}

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

            {/* THE RELAY IS GONE. Above everything, and never folded
                away: every section below offers an action against a
                server that no longer exists. Set by a rebuild whose
                delete leg succeeded and whose build leg did not — the
                one failure on this ladder with no way back. */}
            {relayGone && <RelayGonePanel t={t} operatorId={operatorId} />}

            {/* ---------------- 1. People ---------------- */}
            <PeopleSection
                t={t}
                action={action}
                loading={loading}
                people={people}
                onAdd={() => {
                    setAddError(null);
                    setShowAdd(true);
                }}
                onSend={(path, label) => void onResendSbpx(path, label)}
                onSave={(path, label) => void onSaveSbpx(path, label)}
                onRemake={(r) => void onRebuildSbpx(r)}
                // Re-key this one person. It belongs on their row
                // because that is its whole blast radius — one file
                // dies, nobody else notices. The relay-wide change
                // lives in the danger zone and is never offered here.
                onReplace={(r) => {
                    setRotateCredsError(null);
                    setConfirmRotateCreds(r);
                }}
                onRemoveAccess={(r) => {
                    setRevokeError(null);
                    setConfirmRevoke({ recipient: r });
                }}
                // Once access is removed (the relay has forgotten them)
                // the greyed-out row can be cleared from the list here.
                onRemoveFromList={(r) => {
                    setRemoveError(null);
                    setConfirmRemove({ recipient: r });
                }}
            />

            {/* ---------------- 2. One file for everyone ---------------- */}
            <EveryoneFileSection
                t={t}
                action={action}
                file={sharedArtifact}
                onSend={() => void onShareShared()}
                onSave={() => void onSaveShared()}
                // The offline lane: the same file, travelling as light
                // instead of as a file, for the days when sending a
                // file is the thing that cannot happen.
                onQr={() => setQrSend(true)}
                onCopy={() => void onCopyPasteable()}
                onMake={() => setConfirmBuild(true)}
                onReplace={() => setConfirmRotate(true)}
            />

            {/* ---------------- 3. Keep it working ---------------- */}
            <FreshnessPanel
                t={t}
                operatorId={operatorId}
                reloadToken={freshTick}
                action={action}
            />

            {/* ---------------- 4. Danger zone ---------------- */}
            <Collapsible
                title={t('pub.danger.title')}
                summary={t('pub.danger.line')}
                open={dangerOpen}
                onToggle={() => setDangerOpen((v) => !v)}
            >
                <Card>
                    {/* Wave 6. The rotation recommender finally has a
                        caller, and this is where it belongs: above the
                        rungs, because it is the question you ask before
                        you choose one, and inside the danger zone so it
                        is read in the same breath as the warnings.

                        It never rotates anything. Three of the six rungs
                        destroy the server and rebuild it, and
                        provisioning has no rollback — advice with an
                        action attached is how a relay gets rebuilt by
                        accident. */}
                    <RotationAdvice
                        t={t}
                        operatorId={operatorId}
                        reloadToken={freshTick}
                    />
                    <ListRow
                        title={t('pub.danger.recovery.title')}
                        subtitle={t('pub.danger.recovery.body')}
                        trailing={
                            <ActionButton
                                action={action}
                                k="danger:recovery"
                                busyLabel={t('pub.fb.saving')}
                                variant="secondary"
                                onClick={() => void onSaveRecoveryKey()}
                            >
                                {t('pub.danger.recovery.action')}
                            </ActionButton>
                        }
                    />
                    {/* Wave 3 Step 7 (L2). It is relay-wide, which is
                        why it sits here and not next to the
                        per-recipient re-key — but it does NOT invalidate
                        every file: it costs the one route that carries
                        the cover host, and the app signs the relay's
                        file again and publishes the refresh note
                        itself. The result panel says who, if anyone,
                        needs a new file. */}
                    <ListRow
                        title={t('pub.danger.rotate_tls.title')}
                        subtitle={t('pub.danger.rotate_tls.body')}
                        trailing={
                            <Button
                                variant="danger"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setRotateTlsError(null);
                                    setConfirmRotateTls(true);
                                }}
                                disabled={dangerBusy || rotateTlsBusy}
                            >
                                {t('pub.danger.rotate_tls.action')}
                            </Button>
                        }
                    />
                    {/* Wave 3 Step 9 (L3). Placed ABOVE decommission and
                        below the disguise change, which is the order of
                        increasing blast radius: this one keeps the
                        server, its keys and everyone's credentials —
                        only the address people dial moves. */}
                    <AddressSwap
                        t={t}
                        operatorId={operatorId}
                        relayLabel={title}
                        currentFloatingIpId={operator?.floating_ip_id ?? ''}
                        canReserve={operator?.can_reserve_address ?? false}
                        mirrorsInPack={mirrorsInPack}
                        liveRecipients={operator?.live_recipient_count ?? 0}
                        disabled={dangerBusy || rotateTlsBusy}
                        // L3 is a mgmt-plane call now (it tells the
                        // relay to configure the new address on its
                        // interface), so it goes through the same
                        // wrapper as every other box-touching action:
                        // helper-IP repair on a stale allowlist, and
                        // translated copy for a relay too old to bind.
                        runMgmt={runMgmt}
                        onDone={() => {
                            void reloadOperator();
                            void reloadArtifacts();
                            setFreshTick((n) => n + 1);
                        }}
                    />
                    {/* Wave 6 (L4, L5, L6). Below the address swap and
                        above decommission, which keeps the whole card
                        in one order: increasing blast radius. L3 keeps
                        the server and everyone's keys; these three
                        delete the server, so every file ever handed out
                        dies and only the operator can repair it. Below
                        them sits the one action that ends the relay for
                        good.

                        L5 is offered only where there is somewhere to
                        go: the sheet's own destination list is the
                        providers with a live adapter minus the one this
                        relay is already on, and the row is shown
                        disabled with a reason when that list is empty
                        (rebuildPlan.ts, REBUILD_PROVIDERS). */}
                    <RelayRebuild
                        t={t}
                        operatorId={operatorId}
                        relayLabel={title}
                        // The name every filename this screen produces
                        // already uses, so the string the operator is
                        // asked to type is one they have seen.
                        confirmPhrase={friendlyName}
                        provider={operator?.provider ?? ''}
                        currentRegion={operator?.region ?? ''}
                        serverType={operator?.server_type ?? ''}
                        currentProfile={operator?.toolbox_profile ?? ''}
                        servedFamilies={operator?.served_families ?? []}
                        mirrorsInPack={mirrorsInPack}
                        liveRecipients={operator?.live_recipient_count ?? 0}
                        disabled={dangerBusy || rotateTlsBusy}
                        runMgmt={runMgmt}
                        onDone={() => {
                            void reloadOperator();
                            void reloadArtifacts();
                            setFreshTick((n) => n + 1);
                        }}
                    />
                    <ListRow
                        title={t('pub.danger.decommission.title')}
                        subtitle={t('pub.danger.decommission.body')}
                        trailing={
                            <Button
                                variant="danger"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setConfirmDestroy(true);
                                }}
                                disabled={dangerBusy}
                            >
                                {t('pub.relays.decommission')}
                            </Button>
                        }
                        last
                    />
                </Card>
            </Collapsible>

            {/* ---------------- Details ----------------
                What a maintainer asks about and a family member never
                does. The signed bundle with nobody's access in it used
                to sit in the files list between the everyone file and
                the first person's, labelled "not connectable — internal
                build artifact": true, and of no use to the person
                reading it. */}
            <Collapsible
                title={t('pub.details.title')}
                summary={t('pub.details.line')}
                open={detailsOpen}
                onToggle={() => setDetailsOpen((v) => !v)}
            >
                <Card>
                    <ListRow
                        title={t('pub.details.server')}
                        subtitle={
                            <span style={MONO} dir="ltr">
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
                            </span>
                        }
                    />
                    {/* The custody tier, stated plainly. device_custody.rs
                        is explicit that these strings carry the security
                        promise, so we never print the hardware line on a
                        device that fell back to a weaker tier. */}
                    {custody && (
                        <ListRow
                            title={t('pub.details.key')}
                            subtitle={t(custodyLabelKey(custody.level))}
                            stack
                        />
                    )}
                    {rawArtifact?.exists && (
                        <ListRow
                            title={t('pub.details.signed_file')}
                            subtitle={
                                <span style={{ display: 'grid', gap: 3 }}>
                                    <span>{t('pub.details.signed_file.line')}</span>
                                    <span style={MONO} dir="ltr">
                                        {baseName(rawArtifact.path)}
                                        {rawArtifact.modified_at_unix > 0 && (
                                            <>
                                                {' · '}
                                                {tsLabel(rawArtifact.modified_at_unix)}
                                            </>
                                        )}
                                    </span>
                                </span>
                            }
                            stack
                        />
                    )}
                    <ListRow
                        title={t('pub.details.compare')}
                        subtitle={t('pub.details.compare.line')}
                        trailing={
                            <ActionButton
                                action={action}
                                k="details:compare"
                                busyLabel={t('pub.fb.checking')}
                                variant="secondary"
                                size="sm"
                                onClick={() => void onSync()}
                            >
                                {t('pub.details.compare.action')}
                            </ActionButton>
                        }
                        last
                    />
                </Card>
            </Collapsible>

            {/* The answer to every tap. Pinned to the screen, above any
                open sheet, so it is seen wherever the page is scrolled. */}
            <ActionToast t={t} outcome={action.outcome} onDismiss={action.dismiss} />

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
                                <div style={ERR_BLOCK}>{addError}</div>
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
                        if (action.busy === null) setConfirmRotate(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmRotate(false)}
                                disabled={action.busy !== null}
                            >
                                {t('common.cancel')}
                            </Button>
                            <ActionButton
                                action={action}
                                k="everyone:replace"
                                busyLabel={t('pub.artifacts.building')}
                                variant="danger"
                                onClick={() => void onRotateShared()}
                            >
                                {t('pub.artifacts.rotate.confirm')}
                            </ActionButton>
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
                        if (action.busy === null) setConfirmBuild(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmBuild(false)}
                                disabled={action.busy !== null}
                            >
                                {t('common.cancel')}
                            </Button>
                            <ActionButton
                                action={action}
                                k="everyone:make"
                                busyLabel={t('pub.artifacts.building')}
                                onClick={() => void onBuildShared()}
                            >
                                {t('pub.everyone.make')}
                            </ActionButton>
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
                                personLabel(confirmRevoke.recipient),
                            )}
                        </div>
                        <div style={MONO}>
                            {confirmRevoke.recipient.address_str}
                        </div>
                        {revokeError && (
                            <div style={ERR_BLOCK}>{revokeError}</div>
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
                                personLabel(confirmRemove.recipient),
                            )}
                        </div>
                        <div style={MONO}>
                            {confirmRemove.recipient.address_str}
                        </div>
                        {removeError && (
                            <div style={ERR_BLOCK}>{removeError}</div>
                        )}
                    </div>
                </Sheet>
            )}

            {/* ---- Wave 3 Step 7: per-recipient re-key ---- */}

            {confirmRotateCreds && (
                <Sheet
                    title={t('pub.recipients.rotate.title').replace(
                        '{name}',
                        personLabel(confirmRotateCreds),
                    )}
                    onClose={() => {
                        if (!rotateCredsBusy) setConfirmRotateCreds(null);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmRotateCreds(null)}
                                disabled={rotateCredsBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void onRotateCredsConfirm()}
                                disabled={rotateCredsBusy}
                            >
                                {rotateCredsBusy
                                    ? t('pub.recipients.rotating')
                                    : t('pub.recipients.rotate.confirm').replace(
                                          '{name}',
                                          personLabel(confirmRotateCreds),
                                      )}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        {/* The one sentence that has to land: this hits
                            exactly one person. The relay-wide rotation is
                            a different button in a different section. */}
                        <div
                            style={{
                                fontSize: 13,
                                color: 'var(--fg)',
                                lineHeight: 1.55,
                            }}
                        >
                            {t('pub.recipients.rotate.body').replace(
                                /\{name\}/g,
                                personLabel(confirmRotateCreds),
                            )}
                        </div>
                        <div style={MONO}>
                            {confirmRotateCreds.address_str}
                        </div>
                        {rotateCredsError && (
                            <div
                                style={{
                                    color: 'var(--red)',
                                    fontSize: 12,
                                    whiteSpace: 'pre-line',
                                    lineHeight: 1.5,
                                }}
                            >
                                {rotateCredsError}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}

            {rotateCredsDone && (
                <Sheet
                    title={t('pub.recipients.rotate.done.title').replace(
                        '{name}',
                        rotateCredsDone.display_name || rotateCredsDone.name,
                    )}
                    onClose={() => setRotateCredsDone(null)}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setRotateCredsDone(null)}
                            >
                                {t('common.close')}
                            </Button>
                            {/* The rotation is only half the job — the
                                other half is getting the file into their
                                hands, and nothing does that for them. */}
                            {rotateCredsDone.sbpx_path && (
                                <ActionButton
                                    action={action}
                                    k={`send:${rotateCredsDone.sbpx_path}`}
                                    busyLabel={t('pub.fb.opening')}
                                    onClick={(e) => {
                                        e.stopPropagation();
                                        void onResendSbpx(
                                            rotateCredsDone.sbpx_path,
                                            rotateCredsDone.display_name ||
                                                rotateCredsDone.name,
                                        );
                                    }}
                                >
                                    {t('pub.recipients.rotate.done.send')}
                                </ActionButton>
                            )}
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        {/* The relay is supposed to touch this one
                            recipient. If it reports that it replaced its
                            own identity too, the blast radius silently
                            became the whole roster — so that supersedes
                            the ordinary "one person needs a new file"
                            result rather than sitting below it. */}
                        {rotateCredsDone.box_keys_rotated ? (
                            <div
                                style={{
                                    fontSize: 13,
                                    color: 'var(--red)',
                                    lineHeight: 1.55,
                                }}
                            >
                                {t('pub.recipients.rotate.done.box_keys').replace(
                                    /\{name\}/g,
                                    rotateCredsDone.display_name ||
                                        rotateCredsDone.name,
                                )}
                            </div>
                        ) : (
                            <div
                                style={{
                                    fontSize: 13,
                                    color: 'var(--fg)',
                                    lineHeight: 1.55,
                                }}
                            >
                                {t('pub.recipients.rotate.done.body').replace(
                                    /\{name\}/g,
                                    rotateCredsDone.display_name ||
                                        rotateCredsDone.name,
                                )}
                            </div>
                        )}
                        {/* No inbound list means nothing confirmed the
                            old key is gone everywhere. "We don't know"
                            and "all of them" must not look alike. */}
                        {rotateCredsDone.updated_inbounds.length === 0 && (
                            <div style={{ color: 'var(--red)', fontSize: 12, lineHeight: 1.5 }}>
                                {t('pub.recipients.rotate.done.unverified')}
                            </div>
                        )}
                        {/* An empty path is NOT "nothing happened": the
                            relay already moved, so their old file is dead
                            either way. Say that, and point at Rebuild. */}
                        {!rotateCredsDone.sbpx_path && (
                            <div style={{ color: 'var(--red)', fontSize: 12, lineHeight: 1.5 }}>
                                {t('pub.recipients.rotate.done.nofile').replace(
                                    /\{name\}/g,
                                    rotateCredsDone.display_name ||
                                        rotateCredsDone.name,
                                )}
                            </div>
                        )}
                        <RotationWarnings t={t} warnings={rotateCredsDone.warnings} />
                    </div>
                </Sheet>
            )}

            {/* ---- Wave 3 Step 7: relay-level TLS rotation ---- */}

            {confirmRotateTls && (
                <Sheet
                    title={t('pub.danger.rotate_tls.confirm.title').replace(
                        '{relay}',
                        title,
                    )}
                    onClose={() => {
                        if (!rotateTlsBusy) setConfirmRotateTls(false);
                    }}
                    width={520}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setConfirmRotateTls(false)}
                                disabled={rotateTlsBusy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void onRotateTlsConfirm()}
                                disabled={rotateTlsBusy}
                            >
                                {rotateTlsBusy
                                    ? t('pub.danger.rotate_tls.working')
                                    : t('pub.danger.rotate_tls.confirm.action')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div
                            style={{
                                fontSize: 13,
                                color: 'var(--fg)',
                                lineHeight: 1.55,
                            }}
                        >
                            {/* Wave 3 Step 8 made half of this
                                sentence obsolete. The old copy said
                                flatly that Daal cannot send new settings
                                over the network — still true for a pack
                                with no refresh addresses in it, and a
                                lie for one that has them. It branches on
                                the SIGNED pack, not on what is
                                configured. */}
                            {mirrorsInPack > 0
                                ? t('pub.danger.rotate_tls.confirm.body_fresh')
                                : t('pub.danger.rotate_tls.confirm.body')}
                        </div>
                        {/* How many people hold a file — not how many
                            are about to be cut off, which for most
                            relays is nobody. Default colour for that
                            reason. */}
                        <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                            {liveRecipientCount === 0
                                ? t('pub.danger.rotate_tls.confirm.count_none')
                                : t('pub.danger.rotate_tls.confirm.count').replace(
                                      '{count}',
                                      String(liveRecipientCount),
                                  )}
                        </div>
                        {rotateTlsError && (
                            <div
                                style={{
                                    color: 'var(--red)',
                                    fontSize: 12,
                                    whiteSpace: 'pre-line',
                                    lineHeight: 1.5,
                                }}
                            >
                                {rotateTlsError}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}

            {rotateTlsDone && tlsVerdict && (
                <Sheet
                    title={t('pub.danger.rotate_tls.done.title')}
                    onClose={() => setRotateTlsDone(null)}
                    width={520}
                    footer={
                        <Button
                            variant="ghost"
                            onClick={() => setRotateTlsDone(null)}
                        >
                            {t('common.close')}
                        </Button>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        {/* Name the new host — it is what the packs built
                            from here on will carry, so the operator has to
                            see it. But when the relay would not ECHO what
                            it applied, that name is what was REQUESTED and
                            not what was checked, and the caveat rides with
                            it rather than replacing it. Showing only the
                            name would present an unverified value as fact;
                            showing only the caveat would hide the value
                            the packs actually use. */}
                        {rotateTlsDone.cover_sni && (
                            <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                                {t('pub.danger.rotate_tls.done.now').replace(
                                    '{sni}',
                                    rotateTlsDone.cover_sni,
                                )}
                            </div>
                        )}
                        {rotateTlsDone.cover_sni_unknown && (
                            <div style={{ color: 'var(--red)', fontSize: 12, lineHeight: 1.5 }}>
                                {t('pub.danger.rotate_tls.done.unknown')}
                            </div>
                        )}
                        {rotateTlsDone.previous_cover_sni && (
                            <div style={MONO}>
                                {t('pub.danger.rotate_tls.done.was').replace(
                                    '{sni}',
                                    rotateTlsDone.previous_cover_sni,
                                )}
                            </div>
                        )}
                        {/* WHO NEEDS A NEW FILE — the answer, first.
                            This panel used to say "every file you have
                            handed out is dead; rebuild each and deliver
                            it by hand", whatever the relay. That was
                            measured to be false: a disguise change costs
                            the one route that carries the cover host,
                            and the app now signs the relay's file again
                            and publishes the note by itself. The backend
                            decides which of five things is true for
                            THIS relay; the copy never widens it.

                            With one exception, and it narrows rather
                            than widens: when signing the relay's file
                            again FAILED, the backend can still answer
                            "nobody", and this used to print "Nobody
                            needs a new file" above the warning that
                            said signing had failed. rotateTlsVerdict
                            never lets that sentence stand. */}
                        <div
                            style={{
                                fontSize: 13,
                                lineHeight: 1.55,
                                color: tlsVerdict.alarming ? 'var(--red)' : 'var(--fg)',
                            }}
                        >
                            {t(tlsVerdict.verdictKey)}
                        </div>
                        {/* The one step the app cannot take: Daal
                            publishes the note, never the file. */}
                        {tlsVerdict.showUpload && (
                            <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                                {t('pub.danger.rotate_tls.done.upload')}
                                {rotateTlsDone.signed_pack_path && (
                                    <div style={MONO} dir="ltr">
                                        {rotateTlsDone.signed_pack_path}
                                    </div>
                                )}
                            </div>
                        )}
                        {/* Why the change is NOT reaching people by
                            itself, when it is not — each with the thing
                            that fixes it. */}
                        {tlsVerdict.whyKey && (
                            <div style={{ fontSize: 12, color: 'var(--fg)', lineHeight: 1.5 }}>
                                {t(tlsVerdict.whyKey)}
                            </div>
                        )}
                        {/* What to do when the relay's file could not
                            be signed again. */}
                        {tlsVerdict.nextKey && (
                            <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                                {t(tlsVerdict.nextKey)}
                            </div>
                        )}
                        {/* A count of who HOLDS a file, in the default
                            colour: it is not a count of who is cut off,
                            and red would say that it is. */}
                        <div style={{ fontSize: 12, color: 'var(--fg)', lineHeight: 1.5 }}>
                            {rotateTlsDone.live_recipients === 0 &&
                            !rotateTlsDone.shared_pack_stale
                                ? t('pub.danger.rotate_tls.done.count_none')
                                : t('pub.danger.rotate_tls.done.count').replace(
                                      '{count}',
                                      String(rotateTlsDone.live_recipients),
                                  )}
                        </div>
                        {tlsVerdict.showLocalFiles && (
                            <div style={{ fontSize: 12, color: 'var(--fg)', lineHeight: 1.5 }}>
                                {t('pub.danger.rotate_tls.done.local_files')}
                            </div>
                        )}
                        <RotationWarnings t={t} warnings={rotateTlsDone.warnings} />
                    </div>
                </Sheet>
            )}

            {qrSend && (
                <QrSendSheet
                    t={t}
                    operatorId={operatorId}
                    relayName={title}
                    onClose={() => setQrSend(false)}
                />
            )}

            {confirmDestroy && (
                <RelayDestroySheet
                    t={t}
                    target={destroyTargetForRelay}
                    onClose={(removed) => {
                        setConfirmDestroy(false);
                        // Only leave when the row is actually gone. A
                        // failed cloud teardown keeps the relay — and
                        // this screen is where the user retries it.
                        if (removed) onBack();
                        else void reloadOperator();
                    }}
                />
            )}
        </div>
    );
}
