// RelayListPage — the publisher's home once at least one relay exists.
//
// Replaces the bare `<select>` that used to sit at the top of the
// recipients dashboard, whose option label was `provider / region (#id)`.
// With one relay that was merely redundant; with three it was unusable —
// "hetzner / fsn1 (#3)" and "hetzner / fsn1 (#5)" are the same string to
// a human, and nothing on screen said which box was which, which one had
// the family on it, or which one still had no shareable pack.
//
// Every field on the card answers a question the user actually asks:
//   nickname          -> "which one is this?"
//   public IP         -> "is this the box I'm looking at in the console?"
//   recipients        -> "who is on it?"
//   pack state        -> "have I got something to hand out yet?"
//   live since        -> "how long have I been paying for this?"
//
// Health (D3): when the list opens, each finished relay is checked once,
// one after another (Rust answers from a cache younger than ten
// minutes). The chip turns green only for a check that just said the
// relay works from here; otherwise it reports what the app last
// recorded, in words that say so ("Set up", never a green "LIVE") — see
// relayStatus.ts.

import { useCallback, useEffect, useState } from 'react';
import { Wizard } from './wizardCommands';
import type {
    BackupStatus,
    DestroyReport,
    OperatorSummary,
    ReleaseAddressResult,
    RelayHealth,
    SetupRecovery,
} from './wizardCommands';
import { AccountCheckSheet } from './AccountCheckSheet';
import { checkHealth, checkSequentially, checkedWorking, nowUnix, overallKey } from './relayHealth';
import {
    Card,
    Button,
    Input,
    Section,
    Sheet,
    StatusPill,
} from '../design/primitives';
import { relayBadge } from './relayStatus';
import { ActionButton, ActionToast, useAction } from './useAction';
import { explainFailure, failureBlock } from './failureText';
import { WhatIsThis } from './Disclosure';
import { AddressLines, UnreleasedAddresses, retryNeeded, stillBills } from './DestroyAddresses';
import {
    releaseLiveAddresses,
    releaseResultKey,
    releaseRetryFor,
    releaseStillBills,
    retryRelease as runReleaseRetry,
} from './destroyReport';
import { CancelSetupSheet } from './SetupRecoveryCard';
import { deleteMine, keepMine, listDeleteFor } from './listDelete';
import { BackupCard } from './BackupCard';
import { NewHostingKeySheet, RestoreNoticeCard } from './RestoreNotice';
import { backupApi } from './backupHarness';
import type { BackupApi } from './backupHarness';
import type { Failure } from './failureText';
import { OtherServerNote, otherServerId } from './OtherServerNote';
import { mix } from '../design/mix';

interface Props {
    t: (k: string) => string;
    /** Open relay detail (provisioned relays only). */
    onOpen: (operatorId: number) => void;
    /** Start a brand-new relay in the wizard. */
    onNew: () => void;
    /** Re-enter the wizard for a half-built relay. */
    onResume: (operatorId: number) => void;
    /** Open the backup page. */
    onBackup?: () => void;
    /** Open the restore page. */
    onRestore?: () => void;
    /** Backup and restore commands (the harness passes a fake). */
    backup?: BackupApi;
}

/** PA-1: what a live relay's address release said, one line each. */
export function ReleaseResults({
    t,
    results,
    failure,
    retryBusy,
    onRetry,
}: {
    t: (k: string) => string;
    results: ReleaseAddressResult[];
    failure: Failure | null;
    retryBusy?: boolean;
    onRetry?: () => void;
}) {
    if (results.length === 0 && !failure) return null;
    const anyFailed = failure !== null || results.some((r) => r.code === 'release_failed');
    return (
        <div style={{ display: 'grid', gap: 6 }} data-testid="release-results">
            {results.map((r) => (
                <div
                    key={r.address}
                    data-code={r.code}
                    style={{
                        fontSize: 12,
                        lineHeight: 1.55,
                        color:
                            r.code === 'release_failed' || r.code === 'still_attached' ? 'var(--red)' : 'var(--fg)',
                    }}
                >
                    <span dir="ltr" style={{ fontFamily: 'var(--font-mono)' }}>
                        {r.address}
                    </span>
                    {' · '}
                    {t(releaseResultKey(r.code))}
                </div>
            ))}
            {failure && <div style={{ fontSize: 12, color: 'var(--red)', lineHeight: 1.55 }}>{failure.message}</div>}
            {anyFailed && onRetry && (
                <div>
                    <Button
                        variant="danger"
                        size="sm"
                        disabled={retryBusy}
                        onClick={(e) => {
                            e.stopPropagation();
                            onRetry();
                        }}
                    >
                        {retryBusy ? t('pub.relays.destroy.addr.retrying') : t('pub.relays.destroy.addr.retry')}
                    </Button>
                </div>
            )}
            {(failure?.detail || results.some((r) => r.error)) && (
                <WhatIsThis label={t('pub.fb.details')}>
                    {failure?.detail && (
                        <div style={META} dir="ltr">
                            {failure.detail}
                        </div>
                    )}
                    {results
                        .filter((r) => r.error)
                        .map((r) => (
                            <div key={r.address} style={META} dir="ltr">
                                {r.address}: {r.error}
                            </div>
                        ))}
                </WhatIsThis>
            )}
        </div>
    );
}

function dateLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 10);
    } catch {
        return '';
    }
}

/** The card title. Falls back to something at least *unique* when the
 *  user never named the relay. */
export function relayTitle(op: OperatorSummary): string {
    return op.nickname || `#${op.id} · ${op.provider}/${op.region}`;
}

const META: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--dim)',
    letterSpacing: '0.02em',
};

const LINE: React.CSSProperties = {
    fontSize: 12,
    color: 'var(--muted)',
};

// ---------------------------------------------------------------------
// Teardown
//
// "Remove" is two different acts wearing one word, and the difference is
// money: forgetting the relay leaves a server running and billing
// forever, while deleting the server stops the charges and cuts off
// everyone on it in the same second. The old confirm picked the first
// for the user and spent a paragraph apologising for it. This sheet
// makes them choose, and neither is preselected.
//
// It lives here rather than in relay detail because both surfaces show
// it and detail already imports `relayTitle` from this file.
// ---------------------------------------------------------------------

/** Everything the sheet needs to name what it is about to destroy.
 *  Flattened because relay detail may still be loading its summary. */
export interface DestroyTarget {
    operatorId: number;
    /** What the user calls this relay. */
    name: string;
    /** The best handle we have on the box itself — IPv4, else IPv6, else
     *  the provider's server id. Empty when it never provisioned. */
    where: string;
}

export function destroyTarget(op: OperatorSummary): DestroyTarget {
    return {
        operatorId: op.id,
        name: relayTitle(op),
        where: op.public_ip || op.public_ipv6 || op.server_id || '',
    };
}

type DestroyChoice = 'local' | 'server';

const OPTION_TITLE: React.CSSProperties = {
    fontSize: 14,
    fontWeight: 600,
    lineHeight: 1.3,
};

const OPTION_BODY: React.CSSProperties = {
    fontSize: 12,
    color: 'var(--muted)',
    lineHeight: 1.55,
    marginTop: 6,
};

/** One of the two outcomes. A real radio (not a checkbox in prose) so
 *  the user has to state which one they mean before anything is armed. */
function DestroyOption({
    selected,
    heavy,
    title,
    body,
    extra,
    disabled,
    onSelect,
}: {
    selected: boolean;
    /** The irreversible one: red accent, and it stays red unselected so
     *  its weight is visible before it is chosen. */
    heavy?: boolean;
    title: string;
    body: string;
    extra?: React.ReactNode;
    disabled?: boolean;
    onSelect: () => void;
}) {
    const accent = heavy ? 'var(--red)' : 'var(--gold)';
    return (
        <button
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={disabled}
            onClick={onSelect}
            style={{
                display: 'block',
                width: '100%',
                textAlign: 'start',
                font: 'inherit',
                color: 'var(--fg)',
                background: selected
                    ? mix(accent, 12, 'var(--surface-2)')
                    : 'var(--surface-2)',
                border: `1px solid ${
                    selected
                        ? accent
                        : heavy
                          ? mix('var(--red)', 40, 'transparent')
                          : 'var(--line)'
                }`,
                borderRadius: 'var(--radius-md)',
                padding: '12px 14px',
                cursor: disabled ? 'not-allowed' : 'pointer',
                opacity: disabled ? 0.55 : 1,
            }}
        >
            <span
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    ...OPTION_TITLE,
                    color: heavy ? 'var(--red)' : 'var(--fg)',
                }}
            >
                <span aria-hidden style={{ fontSize: 13 }}>
                    {selected ? '◉' : '◯'}
                </span>
                {title}
            </span>
            <span style={{ display: 'block', ...OPTION_BODY }}>{body}</span>
            {extra}
        </button>
    );
}

/** One resource line in the report. `skip` means "you did not ask for
 *  this", which is not the same as "it failed" and must not read like
 *  it. */
function ReportRow({
    label,
    state,
    value,
}: {
    label: string;
    state: 'yes' | 'no' | 'skip';
    value: string;
}) {
    const glyph = state === 'yes' ? '✓' : state === 'no' ? '✗' : '·';
    const color =
        state === 'yes'
            ? 'var(--green)'
            : state === 'no'
              ? 'var(--red)'
              : 'var(--dim)';
    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 8,
                fontSize: 12,
                padding: '4px 0',
            }}
        >
            <span aria-hidden style={{ color, width: 12 }}>
                {glyph}
            </span>
            <span style={{ color: 'var(--fg)', flex: 1 }}>{label}</span>
            <span style={{ color, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                {value}
            </span>
        </div>
    );
}

export function RelayDestroySheet({
    t,
    target,
    onClose,
}: {
    t: (k: string) => string;
    target: DestroyTarget;
    /** `removed` is true once the relay is gone from Daal's database, so
     *  the caller must stop rendering anything that reads that row. */
    onClose: (removed: boolean) => void;
}) {
    const [choice, setChoice] = useState<DestroyChoice | null>(null);
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<DestroyReport | null>(null);
    const [failure, setFailure] = useState<string | null>(null);

    const addr = target.where;

    const run = useCallback(async () => {
        if (!choice) return;
        setBusy(true);
        setFailure(null);
        try {
            // Never the person's own server from here: that choice is
            // asked first (PA-7, `listDeleteFor`), and only "Delete my
            // server" passes it.
            const r = await Wizard.relayDestroy(
                target.operatorId,
                choice === 'server',
                false,
            );
            setReport(r);
        } catch (e) {
            setFailure(String(e));
        } finally {
            setBusy(false);
        }
    }, [choice, target.operatorId]);

    const askedForServer = choice === 'server';

    /** One cloud resource's line in the report. "Not requested" is a
     *  third state: with `delete_server: false` nothing was attempted,
     *  and printing that as a failure would be a lie. */
    const resourceRow = (
        deleted: boolean,
    ): { state: 'yes' | 'no' | 'skip'; value: string } =>
        !askedForServer
            ? { state: 'skip', value: t('pub.relays.destroy.report.skipped') }
            : deleted
              ? { state: 'yes', value: t('pub.relays.destroy.report.yes') }
              : { state: 'no', value: t('pub.relays.destroy.report.no') };

    /** The address, printed on its own line and never interpolated into
     *  a sentence — half-built relays have no address, and "the server
     *  at (none) is still billing" is worse than saying nothing. */
    const addressLine = (
        <div style={{ ...META, color: 'var(--fg)' }}>
            {addr
                ? t('pub.relays.destroy.address').replace('{ip}', addr)
                : t('pub.relays.destroy.address.unknown')}
        </div>
    );

    const confirmLabel = busy
        ? askedForServer
            ? t('pub.relays.destroy.working.server')
            : t('pub.relays.decommissioning')
        : choice === null
          ? t('pub.relays.destroy.choose')
          : choice === 'local'
            ? t('pub.relays.destroy.confirm.local')
            : addr
              ? t('pub.relays.destroy.confirm.server').replace('{ip}', addr)
              : t('pub.relays.destroy.confirm.server_noaddr');

    return (
        <Sheet
            title={t('pub.relays.destroy.title').replace('{name}', target.name)}
            width={560}
            onClose={() => {
                if (busy) return;
                onClose(report?.local_removed ?? false);
            }}
            footer={
                report ? (
                    <span style={{ display: 'inline-flex', gap: 8 }}>
                        <Button onClick={() => onClose(report.local_removed)}>
                            {t('pub.relays.destroy.report.close')}
                        </Button>
                    </span>
                ) : (
                    <span style={{ display: 'inline-flex', gap: 8 }}>
                        <Button
                            variant="ghost"
                            onClick={() => onClose(false)}
                            disabled={busy}
                        >
                            {t('common.cancel')}
                        </Button>
                        <Button
                            variant={askedForServer ? 'danger' : 'secondary'}
                            onClick={() => void run()}
                            disabled={busy || choice === null}
                        >
                            {confirmLabel}
                        </Button>
                    </span>
                )
            }
        >
            {report ? (
                <div style={{ display: 'grid', gap: 12 }}>
                    <div
                        style={{
                            fontSize: 12,
                            color: 'var(--muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.08em',
                        }}
                    >
                        {t('pub.relays.destroy.report.title')}
                    </div>
                    <div>
                        <ReportRow
                            label={t('pub.relays.destroy.report.server')}
                            {...resourceRow(report.server_deleted)}
                        />
                        <ReportRow
                            label={t('pub.relays.destroy.report.ssh_key')}
                            {...resourceRow(report.ssh_key_deleted)}
                        />
                        <ReportRow
                            label={t('pub.relays.destroy.report.firewall')}
                            {...resourceRow(report.firewall_deleted)}
                        />
                        <ReportRow
                            label={t('pub.relays.destroy.report.local')}
                            state={report.local_removed ? 'yes' : 'no'}
                            value={
                                report.local_removed
                                    ? t('pub.relays.destroy.report.local.yes')
                                    : t('pub.relays.destroy.report.local.no')
                            }
                        />
                    </div>

                    {/* The verdict, in the order that matters to a
                        person: is anything still costing me money? */}
                    {/* PA-3: another Daal server carries this relay's
                        name. Not deleted, relay kept: say that instead
                        of "the server was not deleted". */}
                    {askedForServer && !report.server_deleted && otherServerId(report) !== '' && (
                        <OtherServerNote t={t} report={report} />
                    )}
                    {askedForServer && !report.server_deleted && otherServerId(report) === '' && (
                        <div
                            style={{
                                border: '1px solid var(--red)',
                                borderRadius: 'var(--radius-md)',
                                padding: '10px 12px',
                                display: 'grid',
                                gap: 6,
                            }}
                        >
                            <div
                                style={{
                                    color: 'var(--red)',
                                    fontSize: 13,
                                    fontWeight: 600,
                                    lineHeight: 1.5,
                                }}
                            >
                                {t('pub.relays.destroy.report.server_failed')}
                            </div>
                            {addressLine}
                        </div>
                    )}
                    {askedForServer && report.server_deleted && (
                        <div
                            style={{
                                fontSize: 13,
                                color: stillBills(report) ? 'var(--red)' : 'var(--fg)',
                                lineHeight: 1.55,
                            }}
                        >
                            {/* "Billing has stopped" is only true when no
                                address Daal reserved is still held. */}
                            {retryNeeded(report)
                                ? t('pub.relays.destroy.addr.server_gone_address_kept')
                                : stillBills(report)
                                  ? t('pub.relays.destroy.addr.server_gone_address_left')
                                  : t('pub.relays.destroy.report.ok')}
                        </div>
                    )}
                    {askedForServer &&
                        report.server_deleted &&
                        (!report.ssh_key_deleted || !report.firewall_deleted) && (
                            <div style={{ ...LINE, lineHeight: 1.55 }}>
                                {t('pub.relays.destroy.report.leftovers')}
                            </div>
                        )}
                    {!askedForServer && (
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div
                                style={{
                                    fontSize: 13,
                                    color: 'var(--fg)',
                                    lineHeight: 1.55,
                                }}
                            >
                                {t('pub.relays.destroy.report.local_only')}
                            </div>
                            {addressLine}
                        </div>
                    )}
                    {!report.local_removed && (
                        <div style={{ ...LINE, lineHeight: 1.55 }}>
                            {t('pub.relays.destroy.report.local_kept')}
                        </div>
                    )}

                    {/* D4: every address Daal reserved for this relay,
                        and whether it still costs money. A failed
                        release offers the same delete again — it is
                        idempotent, because a server that is already gone
                        counts as deleted. */}
                    <AddressLines
                        t={t}
                        addresses={report.addresses ?? []}
                        retryBusy={busy}
                        onRetry={() => void run()}
                    />
                    {failure && (
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div style={{ color: 'var(--red)', fontSize: 13, lineHeight: 1.5 }}>
                                {t('pub.relays.destroy.addr.retry_failed')}
                            </div>
                            <WhatIsThis label={t('pub.fb.details')}>
                                <div style={META} dir="ltr">
                                    {failure}
                                </div>
                            </WhatIsThis>
                        </div>
                    )}

                    {/* Provider text goes under Details, untranslated:
                        it is what a helper works from, and some of it
                        names a command, which the main copy never
                        shows. The `?? []` is not paranoia about the
                        type — this view renders *after* the only chance
                        to read the report, so a malformed field must not
                        blank the screen. */}
                    {(report.warnings ?? []).length > 0 && (
                        <WhatIsThis label={t('pub.fb.details')}>
                            <div style={LINE}>
                                {t('pub.relays.destroy.report.warnings')}
                            </div>
                            {(report.warnings ?? []).map((w: string, i: number) => (
                                <div key={i} style={META} dir="ltr">
                                    {w}
                                </div>
                            ))}
                        </WhatIsThis>
                    )}
                </div>
            ) : (
                <div
                    style={{ display: 'grid', gap: 10 }}
                    role="radiogroup"
                    aria-label={t('pub.relays.destroy.intro')}
                >
                    <div style={{ fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 }}>
                        {t('pub.relays.destroy.intro')}
                    </div>

                    <DestroyOption
                        selected={choice === 'local'}
                        disabled={busy}
                        onSelect={() => setChoice('local')}
                        title={t('pub.relays.destroy.local.title')}
                        body={t('pub.relays.destroy.local.body')}
                        extra={
                            <span
                                style={{
                                    ...META,
                                    display: 'block',
                                    marginTop: 8,
                                    color: 'var(--fg)',
                                }}
                            >
                                {addr
                                    ? t('pub.relays.destroy.address').replace(
                                          '{ip}',
                                          addr,
                                      )
                                    : t('pub.relays.destroy.address.unknown')}
                            </span>
                        }
                    />

                    <DestroyOption
                        heavy
                        selected={choice === 'server'}
                        disabled={busy}
                        onSelect={() => setChoice('server')}
                        title={t('pub.relays.destroy.server.title')}
                        body={t('pub.relays.destroy.server.body')}
                        extra={
                            addr ? undefined : (
                                <span
                                    style={{
                                        ...OPTION_BODY,
                                        display: 'block',
                                        marginTop: 8,
                                    }}
                                >
                                    {t('pub.relays.destroy.server.noaddr')}
                                </span>
                            )
                        }
                    />

                    {/* A cloud failure rejects with everything intact —
                        including the server, which is still billing. The
                        raw provider error goes through verbatim and the
                        address stays on screen, because at this point
                        the provider's console is the fallback plan and
                        both options are still one tap away. */}
                    {failure && (
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div
                                style={{
                                    color: 'var(--red)',
                                    fontSize: 13,
                                    fontWeight: 600,
                                    lineHeight: 1.5,
                                }}
                            >
                                {askedForServer
                                    ? t('pub.relays.destroy.error.server')
                                    : t('pub.relays.destroy.error.local')}
                            </div>
                            {askedForServer && addressLine}
                            <div style={{ ...META, color: 'var(--red)' }}>
                                {failure}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </Sheet>
    );
}

/** The list's delete for an unfinished setup on the person's own
 *  server, or one still running (PA-7). */
interface ListCancel {
    op: OperatorSummary;
    rec: SetupRecovery;
    busy: boolean;
    outcome: DestroyReport | null;
    error: Failure | null;
}

export default function RelayListPage({
    t,
    onOpen,
    onNew,
    onResume,
    onBackup,
    onRestore,
    backup = backupApi(),
}: Props) {
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Inline rename: id being renamed + the draft text.
    const [renamingId, setRenamingId] = useState<number | null>(null);
    const [draftName, setDraftName] = useState('');
    // Every action on this screen answers: progress on the button, a
    // result pinned to the screen when it ends.
    const explain = useCallback((e: unknown) => explainFailure(t, e), [t]);
    const action = useAction(explain);
    const renameBusy = action.busy !== null;

    // The relay whose teardown sheet is open. Modal, so the card behind
    // it needs no busy state of its own.
    const [destroying, setDestroying] = useState<DestroyTarget | null>(null);

    // D3: the last health result per relay, filled one by one on open.
    const [health, setHealth] = useState<Record<number, RelayHealth | null>>({});
    const [healthStarted, setHealthStarted] = useState(false);
    // D1: the account check sheet.
    const [accountOpen, setAccountOpen] = useState(false);
    // D1/D2: backup status (null: unknown or an older shell) and the
    // "new hosting key" sheet the restore notice opens.
    const [backupStatus, setBackupStatus] = useState<BackupStatus | null>(null);
    const [keySheet, setKeySheet] = useState(false);
    // PA-7.
    const [listCancel, setListCancel] = useState<ListCancel | null>(null);
    // PA-1: per relay, what the last address release said.
    const [releases, setReleases] = useState<
        Record<number, { results: ReleaseAddressResult[]; failure: Failure | null }>
    >({});

    const reload = useCallback(async () => {
        setLoading(true);
        try {
            const ops = await Wizard.listOperators();
            // Live relays first; decommissioned ones sink to the bottom
            // where they read as history rather than as choices.
            setOperators(
                [...ops].sort((a, b) => {
                    const ad = a.status === 'decommissioned' ? 1 : 0;
                    const bd = b.status === 'decommissioned' ? 1 : 0;
                    if (ad !== bd) return ad - bd;
                    return a.id - b.id;
                }),
            );
            setError(null);
        } catch (e) {
            setError(failureBlock(t, e));
        } finally {
            setLoading(false);
        }
    }, [t]);

    useEffect(() => {
        void reload();
    }, [reload]);

    const reloadBackup = useCallback(async () => {
        try {
            setBackupStatus(await backup.status());
        } catch {
            // An older shell, or the store could not be read: the list
            // still works, it just does not show the backup card.
            setBackupStatus(null);
        }
    }, [backup]);

    useEffect(() => {
        void reloadBackup();
    }, [reloadBackup]);

    /** PA-7: delete pressed on a card. An unfinished setup asks first. */
    const startDelete = useCallback(
        async (op: OperatorSummary) => {
            const plan = await listDeleteFor(op, (id) => Wizard.setupRecovery(id));
            if (plan.kind === 'destroy') setDestroying(destroyTarget(op));
            else setListCancel({ op, rec: plan.rec, busy: false, outcome: null, error: null });
        },
        [],
    );

    const listCancelRun = useCallback(
        async (which: 'delete' | 'keep' | 'check') => {
            if (!listCancel) return;
            const cur = listCancel;
            setListCancel({ ...cur, busy: true, error: null });
            try {
                if (which === 'check') {
                    const plan = await listDeleteFor(cur.op, (id) => Wizard.setupRecovery(id));
                    if (plan.kind === 'destroy') {
                        setListCancel(null);
                        setDestroying(destroyTarget(cur.op));
                    } else {
                        setListCancel({ ...cur, rec: plan.rec, busy: false });
                    }
                    return;
                }
                if (which === 'keep') {
                    await keepMine(cur.op.id, (id, del, own) => Wizard.relayDestroy(id, del, own));
                    setListCancel(null);
                    action.report('keep-mine', 'ok', t('pub.relays.keep_mine.done'));
                    void reload();
                    void reloadBackup();
                    return;
                }
                const r = await deleteMine(cur.op.id, (id, del, own) => Wizard.relayDestroy(id, del, own));
                setListCancel({ ...cur, busy: false, outcome: r });
            } catch (e) {
                setListCancel({ ...cur, busy: false, error: explainFailure(t, e) });
            }
        },
        [action.report, listCancel, reload, reloadBackup, t],
    );
    useEffect(() => {
        if (healthStarted || loading) return;
        const ids = operators.filter((o) => o.status === 'provisioned').map((o) => o.id);
        if (ids.length === 0) return;
        setHealthStarted(true);
        void checkSequentially(
            ids,
            (id) => checkHealth(id, false),
            (id, h) => setHealth((m) => ({ ...m, [id]: h })),
        );
    }, [healthStarted, loading, operators]);

    /** D4: delete again — the same call, idempotent once the server is
     *  gone — for a relay whose reserved address is still billing. */
    const retryRelease = useCallback(
        async (op: OperatorSummary) => {
            if (releaseRetryFor(op.status) === 'release_address') {
                // PA-1: a working relay. Give back each listed address on
                // its own; never a delete.
                setReleases((m) => ({ ...m, [op.id]: { results: m[op.id]?.results ?? [], failure: null } }));
                await action.run(
                    `release:${op.id}`,
                    async () => {
                        try {
                            const results = await releaseLiveAddresses(
                                op,
                                op.unreleased_addresses ?? [],
                                (id, a) => Wizard.releaseAddress(id, a),
                            );
                            setReleases((m) => ({ ...m, [op.id]: { results, failure: null } }));
                            if (results.some((r) => r.code === 'release_failed')) throw new Error('release_failed');
                            return results;
                        } catch (e) {
                            if (!(e instanceof Error && e.message === 'release_failed')) {
                                setReleases((m) => ({
                                    ...m,
                                    [op.id]: { results: m[op.id]?.results ?? [], failure: explainFailure(t, e) },
                                }));
                            }
                            throw e;
                        }
                    },
                    {
                        ok: (r) =>
                            releaseStillBills(r)
                                ? t('pub.relays.destroy.addr.retry_ok_some_left')
                                : t('pub.relays.destroy.addr.retry_ok'),
                        fail: t('pub.relays.destroy.addr.retry_failed'),
                    },
                );
                await reload();
                return;
            }
            await action.run(
                `release:${op.id}`,
                async () => {
                    // Never a delete of a working relay: the shell's
                    // status decides which call (if any) is the retry.
                    const r = await runReleaseRetry(op, {
                        relayDestroy: (id, del) => Wizard.relayDestroy(id, del),
                        setupRemoveServer: (id) => Wizard.setupRemoveServer(id),
                    });
                    if (!r || retryNeeded(r)) throw new Error('release_failed');
                    return r;
                },
                {
                    ok: (r) =>
                        stillBills(r)
                            ? t('pub.relays.destroy.addr.retry_ok_some_left')
                            : t('pub.relays.destroy.addr.retry_ok'),
                    fail: t('pub.relays.destroy.addr.retry_failed'),
                },
            );
            await reload();
        },
        [action.run, reload, t],
    );

    const anyToken = operators.some((o) => o.has_cloud_token === true);

    const commitRename = useCallback(
        async (op: OperatorSummary) => {
            const r = await action.run(
                `rename:${op.id}`,
                () => Wizard.setOperatorNickname(op.id, draftName.trim()),
                { ok: t('pub.fb.renamed'), fail: t('pub.fb.renamed.fail') },
            );
            if (r.ok) {
                setRenamingId(null);
                setDraftName('');
                await reload();
            }
        },
        [action.run, draftName, reload, t],
    );


    /** A relay is finishable — not openable — until it has a signed
     *  pack, whatever its lifecycle status says.
     *
     *  `sign_relaypack` is reachable from exactly one place: the
     *  wizard's build chain. So a relay that provisioned successfully
     *  and then failed at the sign stage used to be a permanent dead
     *  end — the card showed 'provisioned', offered only 'Open', and
     *  relay detail's two actions both need the raw `.sbp` that sign
     *  never wrote ("no signed bundle yet — finish the Sign step
     *  first", for a step the UI no longer exposes). The user paid for
     *  a box the app could never turn into anything shareable.
     *
     *  Rust's `derive_wizard_step` already returns "sign" for this row,
     *  and `runBuild` skips provision when the box is up, so resuming
     *  is exactly the right move. */
    const needsFinishing = useCallback(
        (op: OperatorSummary) =>
            op.status !== 'decommissioned' && !op.has_signed_sbp,
        [],
    );

    const openRelay = useCallback(
        (op: OperatorSummary) => {
            if (op.status === 'decommissioned') return; // not tappable
            if (needsFinishing(op)) onResume(op.id);
            else onOpen(op.id);
        },
        [needsFinishing, onOpen, onResume],
    );

    return (
        <div style={{ padding: '12px 16px 24px 16px' }}>
            <Section
                eyebrow={t('pub.relays.eyebrow')}
                title={t('pub.relays.title')}
                action={<Button onClick={onNew}>{t('pub.relays.new')}</Button>}
            >
                {/* D2: a restore committed here; the truth about the
                    old phone stays until the person has read it. */}
                {backupStatus?.restore_notice && (
                    <div style={{ marginBottom: 10 }}>
                        <RestoreNoticeCard
                            t={t}
                            notice={backupStatus.restore_notice}
                            onEnterKey={() => setKeySheet(true)}
                            onDismiss={async () => {
                                try {
                                    await backup.dismissNotice();
                                } catch {
                                    /* shown again next time; nothing lost */
                                }
                                void reloadBackup();
                            }}
                        />
                    </div>
                )}
                {/* D1: only this phone can manage the relays. */}
                <div style={{ marginBottom: 10, display: 'grid', gap: 6 }}>
                    <BackupCard t={t} status={backupStatus} onBackup={onBackup} />
                    {onRestore && (
                        <div>
                            <Button variant="ghost" size="sm" onClick={onRestore} data-button="restore-link">
                                {t('pub.restore.link')}
                            </Button>
                        </div>
                    )}
                </div>
                {anyToken && (
                    <div style={{ marginBottom: 10 }}>
                        <Button variant="secondary" onClick={() => setAccountOpen(true)}>
                            {t('pub.account.open')}
                        </Button>
                    </div>
                )}
                {error && (
                    <div
                        style={{
                            color: 'var(--red)',
                            fontSize: 12,
                            padding: '6px 4px',
                            whiteSpace: 'pre-line',
                            lineHeight: 1.5,
                        }}
                    >
                        {error}
                    </div>
                )}

                {loading && operators.length === 0 && (
                    <Card>
                        <div style={LINE}>{t('common.loading')}</div>
                    </Card>
                )}

                {!loading && operators.length === 0 && (
                    <Card>
                        <div style={{ display: 'grid', gap: 10 }}>
                            <div
                                style={{
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 19,
                                    color: 'var(--fg)',
                                }}
                            >
                                {t('pub.relays.empty.title')}
                            </div>
                            <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.55 }}>
                                {t('pub.relays.empty.body')}
                            </div>
                            <div>
                                <Button onClick={onNew}>
                                    {t('pub.relays.new')}
                                </Button>
                            </div>
                        </div>
                    </Card>
                )}

                <div style={{ display: 'grid', gap: 10 }}>
                    {operators.map((op) => {
                        const dead = op.status === 'decommissioned';
                        const ip =
                            op.public_ip || op.public_ipv6 || '';
                        const since =
                            op.last_provisioned_at_unix || op.created_at_unix;
                        const renaming = renamingId === op.id;
                        const h = health[op.id] ?? null;
                        const badge = relayBadge(op.status, checkedWorking(h, nowUnix()));
                        const interrupted =
                            op.status === 'pre-provision' && op.setup_interrupted === true;
                        const unreleased = op.unreleased_addresses ?? [];
                        return (
                            <Card
                                key={op.id}
                                // The whole card is the tap target, so the row
                                // needs no "Open" button competing with it —
                                // the only thing tapping a relay can mean is
                                // "show me this relay". Buttons inside stop
                                // propagation so they keep their own meaning.
                                onClick={
                                    renaming || dead
                                        ? undefined
                                        : () => openRelay(op)
                                }
                                role={renaming || dead ? undefined : 'button'}
                                aria-label={
                                    renaming || dead ? undefined : relayTitle(op)
                                }
                                style={{
                                    opacity: dead ? 0.5 : 1,
                                    cursor: dead ? 'default' : 'pointer',
                                }}
                            >
                                <div style={{ display: 'grid', gap: 8 }}>
                                    {/* Title + lifecycle chip */}
                                    <div
                                        style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            justifyContent: 'space-between',
                                            gap: 10,
                                        }}
                                    >
                                        {renaming ? (
                                            <Input
                                                autoFocus
                                                value={draftName}
                                                onChange={(e) =>
                                                    setDraftName(e.target.value)
                                                }
                                                placeholder={t(
                                                    'pub.relays.rename.placeholder',
                                                )}
                                                onKeyDown={(e) => {
                                                    if (e.key === 'Enter') {
                                                        void commitRename(op);
                                                    } else if (e.key === 'Escape') {
                                                        setRenamingId(null);
                                                    }
                                                }}
                                            />
                                        ) : (
                                            <div
                                                style={{
                                                    fontFamily:
                                                        'var(--font-display)',
                                                    fontSize: 18,
                                                    color: 'var(--fg)',
                                                    lineHeight: 1.2,
                                                    minWidth: 0,
                                                    overflow: 'hidden',
                                                    textOverflow: 'ellipsis',
                                                    whiteSpace: 'nowrap',
                                                }}
                                            >
                                                {relayTitle(op)}
                                            </div>
                                        )}
                                        {!renaming && (
                                            <span
                                                style={{
                                                    display: 'inline-flex',
                                                    alignItems: 'center',
                                                    gap: 6,
                                                    flex: '0 0 auto',
                                                }}
                                            >
                                                <StatusPill tone={badge.tone}>
                                                    {t(badge.labelKey)}
                                                </StatusPill>
                                                {/* Affordance for the card-wide
                                                    tap target that replaced the
                                                    "Open" button. */}
                                                {!dead && (
                                                    <span
                                                        aria-hidden
                                                        style={{
                                                            color: 'var(--dim)',
                                                            fontSize: 18,
                                                            lineHeight: 1,
                                                        }}
                                                    >
                                                        ›
                                                    </span>
                                                )}
                                            </span>
                                        )}
                                    </div>

                                    {/* Identity: the address the user can
                                        cross-check against their cloud
                                        console. */}
                                    <div style={META}>
                                        {ip || t('pub.relays.no_ip')}
                                    </div>

                                    {/* Plan */}
                                    <div style={LINE}>
                                        {op.provider} · {op.server_type || '—'} ·{' '}
                                        {op.region}
                                    </div>

                                    {/* Who is on it, and is there anything to
                                        hand out yet. */}
                                    <div style={LINE}>
                                        {t('pub.relays.recipients')
                                            .replace(
                                                '{live}',
                                                String(op.live_recipient_count),
                                            )
                                            .replace(
                                                '{total}',
                                                String(op.total_recipient_count),
                                            )}
                                        {' · '}
                                        {op.has_signed_sbp
                                            ? t('pub.relays.pack.built').replace(
                                                  '{date}',
                                                  dateLabel(op.signed_sbp_at_unix),
                                              )
                                            : t('pub.relays.pack.none')}
                                    </div>

                                    <div style={META}>
                                        {t('pub.relays.since').replace(
                                            '{date}',
                                            dateLabel(since),
                                        )}
                                    </div>

                                    {/* The chip above is what the app
                                        last recorded, not a check — say
                                        so, and only while that is what
                                        it is. Badge and caption come
                                        from the same value, so they
                                        cannot disagree again. */}
                                    {/* D1: a setup that stopped part-way may
                                        have left a server billing. */}
                                    {interrupted && (
                                        <div style={{ ...LINE, color: 'var(--gold)' }}>
                                            {t('pub.relays.interrupted')}
                                        </div>
                                    )}

                                    {/* D3: the last check, in one line. */}
                                    {h && !dead && (
                                        <div style={LINE} data-testid="card-health">
                                            {t(overallKey(h.overall))}
                                        </div>
                                    )}

                                    {/* D4: a delete that could not release
                                        an address Daal reserved. */}
                                    {unreleased.length > 0 && (
                                        <UnreleasedAddresses
                                            t={t}
                                            ips={unreleased}
                                            live={releaseRetryFor(op.status) === 'release_address'}
                                            retryBusy={action.busy === `release:${op.id}`}
                                            onRetry={
                                                releaseRetryFor(op.status)
                                                    ? () => void retryRelease(op)
                                                    : undefined
                                            }
                                        />
                                    )}

                                    {releases[op.id] && (
                                        <ReleaseResults
                                            t={t}
                                            results={releases[op.id].results}
                                            failure={releases[op.id].failure}
                                        />
                                    )}

                                    {badge.recordedOnly && !dead && (
                                        <div
                                            style={{
                                                ...META,
                                                color: 'var(--dim)',
                                                fontStyle: 'italic',
                                            }}
                                        >
                                            {t('pub.relays.status.disclaimer')}
                                        </div>
                                    )}

                                    <div
                                        style={{
                                            display: 'flex',
                                            gap: 8,
                                            flexWrap: 'wrap',
                                            marginTop: 2,
                                        }}
                                    >
                                        {renaming ? (
                                            <>
                                                <ActionButton
                                                    action={action}
                                                    k={`rename:${op.id}`}
                                                    busyLabel={t('pub.fb.saving')}
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        void commitRename(op);
                                                    }}
                                                >
                                                    {t('common.save')}
                                                </ActionButton>
                                                <Button
                                                    variant="ghost"
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        setRenamingId(null);
                                                    }}
                                                    disabled={renameBusy}
                                                >
                                                    {t('common.cancel')}
                                                </Button>
                                            </>
                                        ) : (
                                            <>
                                                {/* No "Open": tapping the card
                                                    does that. "Finish setup"
                                                    stays because an unfinished
                                                    relay rents a server when
                                                    resumed — that deserves a
                                                    deliberate press, not a
                                                    stray tap on a card. */}
                                                {!dead && needsFinishing(op) && (
                                                    <Button
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            onResume(op.id);
                                                        }}
                                                    >
                                                        {interrupted
                                                            ? t('pub.relays.open')
                                                            : t('pub.relays.resume')}
                                                    </Button>
                                                )}
                                                {!dead && (
                                                    <Button
                                                        variant="secondary"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            setRenamingId(op.id);
                                                            setDraftName(
                                                                op.nickname,
                                                            );
                                                        }}
                                                    >
                                                        {t('pub.relays.rename')}
                                                    </Button>
                                                )}
                                                {!dead && (
                                                    <Button
                                                        variant="danger"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            // PA-7: an unfinished setup asks
                                                            // the wizard's Cancel question first.
                                                            void startDelete(op);
                                                        }}
                                                    >
                                                        {t(
                                                            'pub.relays.decommission',
                                                        )}
                                                    </Button>
                                                )}
                                            </>
                                        )}
                                    </div>
                                </div>
                            </Card>
                        );
                    })}
                </div>
            </Section>

            {destroying && (
                <RelayDestroySheet
                    t={t}
                    target={destroying}
                    onClose={() => {
                        // Reload whatever happened: a partial teardown
                        // still changes the row (or proves it survived),
                        // and the list is the only place that says so.
                        setDestroying(null);
                        void reload();
                        void reloadBackup();
                    }}
                />
            )}

            {listCancel && (
                <CancelSetupSheet
                    t={t}
                    rec={listCancel.rec}
                    busy={listCancel.busy}
                    outcome={listCancel.outcome}
                    error={listCancel.error}
                    onDelete={() => void listCancelRun('delete')}
                    onKeep={() => void listCancelRun('keep')}
                    onCheckAgain={() => void listCancelRun('check')}
                    onClose={() => {
                        const changed = listCancel.outcome !== null;
                        setListCancel(null);
                        if (changed) {
                            void reload();
                            void reloadBackup();
                        }
                    }}
                    onDone={() => {
                        setListCancel(null);
                        void reload();
                        void reloadBackup();
                    }}
                />
            )}

            {keySheet && backupStatus?.restore_notice && (
                <NewHostingKeySheet
                    t={t}
                    notice={backupStatus.restore_notice}
                    onClose={() => {
                        setKeySheet(false);
                        void reload();
                        void reloadBackup();
                    }}
                />
            )}

            {accountOpen && (
                <AccountCheckSheet
                    t={t}
                    onOpenRelay={(id) => {
                        setAccountOpen(false);
                        onResume(id);
                    }}
                    onClose={(changed) => {
                        setAccountOpen(false);
                        if (changed) void reload();
                    }}
                />
            )}

            <ActionToast t={t} outcome={action.outcome} onDismiss={action.dismiss} />
        </div>
    );
}
