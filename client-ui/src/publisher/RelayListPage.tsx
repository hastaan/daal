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

import { sep } from '../lib/format';
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
import { ReportViewer } from './ReportViewer';
import { checkHealth, checkSequentially, nowUnix } from './relayHealth';
import {
    Card,
    Button,
    Disclosure,
    EmptyState,
    ListRow,
    OverflowMenu,
    PageHeader,
    Sheet,
    StateIcon,
} from '../design/primitives';
import type { MenuItem } from '../design/primitives';
import { formatAgo } from '../lib/format';
import { ActionToast, useAction } from './useAction';
import { PageColumn, RelayBadge, num, relayLook, relayUnfinished, useLocale } from './ui';
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
import { BackupBadge } from './BackupCard';
import { NewHostingKeySheet, RestoreNoticeCard } from './RestoreNotice';
import { backupApi } from './backupHarness';
import type { BackupApi } from './backupHarness';
import type { Failure } from './failureText';
import { OtherServerNote, otherServerId } from './OtherServerNote';
import { mix } from '../design/mix';
import { AddonOutcomeLines } from './addons/AddonOutcomeLines';

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
    /** Open «حساب‌ها». */
    onAccounts?: () => void;
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
                    {sep()}
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

/** The card title. Falls back to something at least *unique* when the
 *  user never named the relay. */
export function relayTitle(op: OperatorSummary): string {
    return op.nickname || `#${op.id} · ${op.provider}/${op.region}`;
}

const META: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    color: 'var(--muted)',
};

const LINE: React.CSSProperties = {
    fontSize: 12,
    color: 'var(--muted)',
};

/** "Server: 203.0.113.7", or "Daal has no address for this server.":
 *  the words in the body face and the page direction (the mono face has
 *  no Persian letters), only the address itself in mono and kept LTR. */
function ServerAddress({
    t,
    addr,
    size = 13,
}: {
    t: (k: string) => string;
    addr: string | null | undefined;
    size?: number;
}) {
    if (!addr) {
        return (
            <span style={{ fontSize: size, color: 'var(--fg)', lineHeight: 1.5 }}>
                {t('pub.relays.destroy.address.unknown')}
            </span>
        );
    }
    const [before, after] = t('pub.relays.destroy.address').split('{ip}');
    return (
        <span data-testid="destroy-address" style={{ fontSize: size, color: 'var(--fg)', lineHeight: 1.5 }}>
            {before}
            <bdi dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                {addr}
            </bdi>
            {after ?? ''}
        </span>
    );
}

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
    fontSize: 13,
    color: 'var(--muted)',
    lineHeight: 1.55,
    marginTop: 6,
};

/** One of the two outcomes. A real radio (not a checkbox in prose) so
 *  the user has to state which one they mean before anything is armed.
 *  One line each (MUST KEEP 2); the long paragraph is behind "More". */
function DestroyOption({
    t,
    selected,
    heavy,
    title,
    line,
    more,
    extra,
    disabled,
    onSelect,
    dataButton,
}: {
    t: (k: string) => string;
    selected: boolean;
    /** The irreversible one: red accent, and it stays red unselected so
     *  its weight is visible before it is chosen. */
    heavy?: boolean;
    title: string;
    line: string;
    more: string;
    extra?: React.ReactNode;
    disabled?: boolean;
    onSelect: () => void;
    dataButton: string;
}) {
    const accent = heavy ? 'var(--red)' : 'var(--gold)';
    return (
        <div
            style={{
                background: selected ? mix(accent, 12, 'var(--surface-2)') : 'var(--surface-2)',
                border: `1px solid ${
                    selected ? accent : heavy ? mix('var(--red)', 40, 'transparent') : 'var(--line)'
                }`,
                borderRadius: 'var(--radius-md)',
                padding: '4px 14px 0',
                opacity: disabled ? 0.55 : 1,
            }}
        >
            <button
                type="button"
                role="radio"
                aria-checked={selected}
                disabled={disabled}
                onClick={onSelect}
                data-button={dataButton}
                style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'start',
                    font: 'inherit',
                    color: 'var(--fg)',
                    background: 'transparent',
                    border: 0,
                    padding: '8px 0 4px',
                    minHeight: 44,
                    cursor: disabled ? 'not-allowed' : 'pointer',
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
                    <span
                        aria-hidden
                        style={{
                            width: 18,
                            height: 18,
                            flexShrink: 0,
                            borderRadius: '50%',
                            border: `2px solid ${selected ? accent : 'var(--muted)'}`,
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                        }}
                    >
                        {selected && <span style={{ width: 8, height: 8, borderRadius: '50%', background: accent }} />}
                    </span>
                    {title}
                </span>
                <span style={{ display: 'block', ...OPTION_BODY }}>{line}</span>
                {extra}
            </button>
            <Disclosure summary={t('pub.relays.destroy.more')} dataButton={`${dataButton}-more`}>
                <div style={{ ...OPTION_BODY, marginTop: 0, paddingBottom: 8 }}>{more}</div>
            </Disclosure>
        </div>
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
        <div>
            <ServerAddress t={t} addr={addr} />
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
            : // The button names the choice (C7.1); the address is on
              // both cards, so the server it deletes is in view.
              t('pub.relays.destroy.confirm.server_noaddr');

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
                            dataButton="destroy-confirm"
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
                            fontSize: 13,
                            fontWeight: 600,
                            color: 'var(--muted)',
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
                    {/* V019: each add-on — removed, gone with the relay,
                        kept for a retry, or left running. */}
                    <AddonOutcomeLines t={t} outcomes={report.addons} />
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
                    <DestroyOption
                        t={t}
                        dataButton="destroy-local"
                        selected={choice === 'local'}
                        disabled={busy}
                        onSelect={() => setChoice('local')}
                        title={t('pub.relays.destroy.local.title')}
                        line={t('pub.relays.destroy.local.line')}
                        more={t('pub.relays.destroy.local.body')}
                        extra={
                            <span style={{ display: 'grid', gap: 2, marginTop: 8 }}>
                                <ServerAddress t={t} addr={addr} />
                                {addr && (
                                    <span style={{ fontSize: 13, color: 'var(--amber)' }}>
                                        {t('pub.relays.destroy.write_down')}
                                    </span>
                                )}
                            </span>
                        }
                    />

                    <DestroyOption
                        t={t}
                        dataButton="destroy-server"
                        heavy
                        selected={choice === 'server'}
                        disabled={busy}
                        onSelect={() => setChoice('server')}
                        title={t('pub.relays.destroy.server.title')}
                        line={t('pub.relays.destroy.server.line')}
                        extra={
                            <span style={{ display: 'grid', gap: 2, marginTop: 8 }}>
                                <ServerAddress t={t} addr={addr} />
                            </span>
                        }
                        more={
                            addr
                                ? t('pub.relays.destroy.server.body')
                                : `${t('pub.relays.destroy.server.body')}\n\n${t('pub.relays.destroy.server.noaddr')}`
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
    onAccounts,
    backup = backupApi(),
}: Props) {
    const locale = useLocale();
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Every action on this screen answers: progress on the button, a
    // result pinned to the screen when it ends.
    const explain = useCallback((e: unknown) => explainFailure(t, e), [t]);
    const action = useAction(explain);


    // D3: the last health result per relay, filled one by one on open.
    const [health, setHealth] = useState<Record<number, RelayHealth | null>>({});
    const [healthStarted, setHealthStarted] = useState(false);
    // D1: the account check sheet.
    const [accountOpen, setAccountOpen] = useState(false);
    // Network test: open a report someone sent.
    const [reportOpen, setReportOpen] = useState(false);
    // D1/D2: backup status (null: unknown or an older shell) and the
    // "new hosting key" sheet the restore notice opens.
    const [backupStatus, setBackupStatus] = useState<BackupStatus | null>(null);
    // The relay whose teardown sheet is open (an unfinished setup's ⋯).
    const [destroying, setDestroying] = useState<DestroyTarget | null>(null);
    // PA-7.
    const [listCancel, setListCancel] = useState<ListCancel | null>(null);
    const [keySheet, setKeySheet] = useState(false);
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
    const needsFinishing = useCallback((op: OperatorSummary) => relayUnfinished(op), []);

    const openRelay = useCallback(
        (op: OperatorSummary) => {
            if (op.status === 'decommissioned') return; // not tappable
            if (needsFinishing(op)) onResume(op.id);
            else onOpen(op.id);
        },
        [needsFinishing, onOpen, onResume],
    );

    const live = operators.filter((o) => o.status !== 'decommissioned');
    const retired = operators.filter((o) => o.status === 'decommissioned');

    const menu: MenuItem[] = [
        ...(onAccounts ? [{ id: 'accounts', label: t('pub.accounts.title'), icon: 'key' as const, onSelect: onAccounts }] : []),
        ...(onBackup ? [{ id: 'backup', label: t('pub.more.backup'), icon: 'shield' as const, onSelect: onBackup }] : []),
        ...(onRestore ? [{ id: 'restore-link', label: t('pub.restore.link'), icon: 'download' as const, onSelect: onRestore }] : []),
        ...(anyToken
            ? [{ id: 'check-account', label: t('pub.account.open'), icon: 'server' as const, onSelect: () => setAccountOpen(true) }]
            : []),
        ...(live.length > 0
            ? [{ id: 'open-report', label: t('pub.report.open'), icon: 'file' as const, onSelect: () => setReportOpen(true) }]
            : []),
    ];

    const row = (op: OperatorSummary, last: boolean) => {
        const dead = op.status === 'decommissioned';
        const h = health[op.id] ?? null;
        const look = relayLook(op, h);
        const unreleased = op.unreleased_addresses ?? [];
        const people = t(op.live_recipient_count === 1 ? 'pub.relays.people.one' : 'pub.relays.people').replace(
            '{n}',
            num(locale, op.live_recipient_count),
        );
        const checked =
            h && h.checked_at_unix > 0
                ? t('pub.relays.checked').replace('{ago}', formatAgo(locale, (nowUnix() - h.checked_at_unix) * 1000))
                : '';
        return (
            <div key={op.id} data-relay={op.id} data-relay-state={look.labelKey}>
                <ListRow
                    leading={<StateIcon state={look.icon} size={22} />}
                    title={relayTitle(op)}
                    // "Unfinished · may cost money" is never cut short: it
                    // takes the line under the name instead of squeezing it.
                    badge={look.wrap ? undefined : <RelayBadge t={t} look={look} size="sm" />}
                    subtitle={
                        look.wrap ? (
                            <span style={{ display: 'inline-flex', marginBlockStart: 4 }}>
                                <RelayBadge t={t} look={look} size="sm" />
                            </span>
                        ) : dead ? undefined : checked ? (
                            `${people} · ${checked}`
                        ) : (
                            people
                        )
                    }
                    wrapSubtitle={look.wrap}
                    chevron={!dead}
                    onClick={dead ? undefined : () => openRelay(op)}
                    // An unfinished setup never reaches the relay page,
                    // so its removal stays here, behind its own ⋯ (PA-7).
                    trailing={
                        !dead && needsFinishing(op) ? (
                            <OverflowMenu
                                label={t('ui.more')}
                                title={relayTitle(op)}
                                dataButton="relay-row-more"
                                items={[
                                    {
                                        id: 'remove',
                                        label: t('pub.more.remove_setup'),
                                        icon: 'trash',
                                        tone: 'danger',
                                        onSelect: () => void startDelete(op),
                                    },
                                ]}
                            />
                        ) : undefined
                    }
                    stack={false}
                    dataButton={dead ? undefined : `relay-${op.id}`}
                    last={last && unreleased.length === 0 && !releases[op.id]}
                />
                {/* D4: a delete that could not release an address Daal
                    reserved — it still costs money, so it stays here. */}
                {unreleased.length > 0 && (
                    <div style={{ paddingBlock: 8 }}>
                        <UnreleasedAddresses
                            t={t}
                            ips={unreleased}
                            live={releaseRetryFor(op.status) === 'release_address'}
                            retryBusy={action.busy === `release:${op.id}`}
                            onRetry={releaseRetryFor(op.status) ? () => void retryRelease(op) : undefined}
                        />
                    </div>
                )}
                {releases[op.id] && (
                    <div style={{ paddingBlock: 8 }}>
                        <ReleaseResults t={t} results={releases[op.id].results} failure={releases[op.id].failure} />
                    </div>
                )}
            </div>
        );
    };

    const empty = !loading && live.length === 0;

    return (
        <PageColumn>
            {!empty && (
                <PageHeader
                    title={t('pub.relays.title')}
                    badge={<BackupBadge t={t} status={backupStatus} onBackup={onBackup} />}
                    actions={
                        <>
                            <Button size="compact" variant="secondary" leading="plus" onClick={onNew} dataButton="new-relay">
                                {t('pub.relays.new')}
                            </Button>
                            <OverflowMenu label={t('ui.more')} title={t('pub.relays.title')} items={menu} dataButton="relays-more" />
                        </>
                    }
                />
            )}

            {/* D2: a restore committed here; the truth about the old
                phone stays until the person has read it. */}
            {backupStatus?.restore_notice && (
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
            )}

            {error && (
                <div
                    style={{
                        color: 'var(--red)',
                        fontSize: 13,
                        padding: '6px 4px',
                        whiteSpace: 'pre-line',
                        lineHeight: 1.5,
                    }}
                >
                    {error}
                </div>
            )}

            {loading && operators.length === 0 && <div style={LINE}>{t('common.loading')}</div>}

            {empty && (
                <EmptyState
                    icon="server"
                    title={t('pub.relays.empty.title')}
                    // MUST KEEP 4: what it costs, before the first tap.
                    body={t('pub.relays.empty.line')}
                    action={
                        <Button onClick={onNew} dataButton="new-relay">
                            {t('pub.relays.empty.start')}
                        </Button>
                    }
                    secondary={
                        onRestore ? (
                            <Button variant="link" onClick={onRestore} dataButton="restore-link">
                                {t('pub.restore.link')}
                            </Button>
                        ) : undefined
                    }
                />
            )}

            {live.length > 0 && <Card>{live.map((op, i) => row(op, i === live.length - 1))}</Card>}

            {retired.length > 0 && <Card>{retired.map((op, i) => row(op, i === retired.length - 1))}</Card>}

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

            {reportOpen && <ReportViewer t={t} onClose={() => setReportOpen(false)} />}
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
        </PageColumn>
    );
}
