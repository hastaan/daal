// AddonsSection — «More protection» on the relay page (the build wizard
// asks the same three on its own step: WizardAddons.tsx)
// (docs/optional-addons-plan.md, X3; owner review
// 2026-11-21: "Hetzner setup is very straightforward", make these so).
//
// Three rows: a title, ONE short line, the cost, a switch. Daal decides
// everything else (the standby is always sealed, no plain fallback, ECH
// as the zone allows); none of it is a choice here.
//
//   switch on, account missing → that account's sheet (Accounts); once
//                                connected, the switch carries on. Google
//                                is an account like Cloudflare: its sheet
//                                adds the one script, and the switch only
//                                takes a place in it
//   switch on                  → «Setting up…», then «On», or one plain
//                                failure line with «Try again»
//   switch off                 → one sentence naming what is given back
//                                or keeps billing, then it runs
//
// The standby code shows only after a switch to the standby, or from
// «Details».
//
// The two update-note switches (GitHub, DNS) write by themselves from
// then on; their row says when the last write went through, or that it
// did not and Daal will try again. Right after one is turned on, people
// who already have a file are told once that they need a new one, with
// «New files for everyone» when the page can offer it. The engine's choices (open standby, plain fallback) stay in
// the CLI and the Rust layer; this UI never asks for them.

import { useCallback, useEffect, useRef, useState } from 'react';
import { Button, Sheet, StateIcon, Toggle } from '../../design/primitives';
import { WhatIsThis } from '../Disclosure';
import { useConfirm } from '../ui';
import { Addons } from '../wizardCommands';
import type { AddonKind, AddonRemoveReport, AddonRow } from './addonTypes';
import { ADDON_COPY, NOTE_KINDS, liveRow } from './addonText';
import type { AddonCopy } from './addonText';
import { classifyAddonError } from './addonErrors';
import { CloudflareSheet, GithubSheet, GoogleSheet, githubPermissionList } from './AccountSheets';
import { useDensity } from '../../design/DensityProvider';
import { accountConnected, useAccounts } from './accounts';
import type { AccountsState } from './accounts';
import { BODY, ErrorNote, MONO, MUTED, copyText, useRun } from './addonUi';
import { formatAgo } from '../../lib/format';
import type { NotesDetail } from './addonTypes';
import { addonNeed, clearAddonFailure, failedAddons, runAddon, waitsForPerson } from './wizardAddons';

export interface AddonsSectionProps {
    t: (key: string) => string;
    /** The relay; absent while it does not exist yet. */
    operatorId?: number | null;
    /** `relay`: the relay page (the only place it is shown). */
    variant?: 'relay';
    /** The accounts, for tests; read from the shell otherwise. */
    accounts?: AccountsState;
    /** «New files for everyone» (the people section's sheet), when the
     *  page can offer it: shown once after a note switch is turned on
     *  while people already have files. */
    onNewFiles?: () => void;
    /** The relay has a file for everyone: the note switches never reach
     *  it, and people get new files one by one from their own menu. */
    everyoneFile?: boolean;
}

/** What a row is doing now, beyond what the ledger says. */
type Phase =
    | { k: 'idle' }
    | { k: 'running' }
    | { k: 'stopping' }
    | { k: 'failed'; op: 'on' | 'off'; error: unknown }
    | { k: 'billing'; what: string[]; repo?: string };

type Open =
    | { k: 'cloudflare'; then?: AddonKind }
    | { k: 'google'; then?: AddonKind }
    | { k: 'github'; then?: AddonKind; newKey?: boolean }
    | { k: 'code'; code: string; wrapped: boolean; plain?: string };

export function AddonsSection({
    t,
    operatorId,
    variant = 'relay',
    accounts: given,
    onNewFiles,
    everyoneFile = false,
}: AddonsSectionProps) {
    const [rows, setRows] = useState<AddonRow[]>([]);
    const [generation, setGeneration] = useState(0);
    const reload = useCallback(() => setGeneration((g) => g + 1), []);
    const read = useAccounts(given == null);
    const accounts = given ?? read.accounts;
    const [phases, setPhases] = useState<Partial<Record<AddonKind, Phase>>>({});
    const [open, setOpen] = useState<Open | null>(null);
    const confirm = useConfirm();
    const code = useRun();

    // An extra chosen in the build wizard that did not turn on: one line
    // with «Try again» here, never a failed relay (wizardAddons.ts).
    useEffect(() => {
        if (operatorId == null) return;
        const failed = failedAddons(operatorId);
        const kinds = Object.keys(failed) as AddonKind[];
        if (kinds.length === 0) return;
        setPhases((all) => {
            const next = { ...all };
            for (const k of kinds) if (next[k] == null) next[k] = { k: 'failed', op: 'on', error: failed[k] };
            return next;
        });
    }, [operatorId]);

    useEffect(() => {
        let gone = false;
        if (operatorId == null) {
            setRows([]);
            return;
        }
        // A shell that predates the ledger, or a relay that went: all
        // off. Never an error on a section about extras.
        Addons.list(operatorId)
            .then((r) => {
                if (!gone) setRows(Array.isArray(r) ? r : []);
            })
            .catch(() => {
                if (!gone) setRows([]);
            });
        return () => {
            gone = true;
        };
    }, [operatorId, generation]);

    // A Cloudflare door that waits for the relay's first person: ask
    // once per visit whether it can open now (someone may have been
    // added since; the shell only asks the relay when this phone knows
    // of someone on it). Quiet: the row keeps its one line either way.
    const doorAsked = useRef(false);
    const cdnWaits = waitsForPerson(liveRow(rows, 'cdn'));
    useEffect(() => {
        if (operatorId == null || !cdnWaits || doorAsked.current) return;
        doorAsked.current = true;
        Addons.cdnPosture({ operator_id: operatorId, test: true })
            .then((p) => {
                if (p && p.door_waits === false) reload();
            })
            .catch(() => {});
    }, [operatorId, cdnWaits, reload]);

    const setPhase = (kind: AddonKind, p: Phase) => setPhases((all) => ({ ...all, [kind]: p }));

    /** Turn one on with what is connected now (`acc`, since a sheet may
     *  have just connected the account). */
    const turnOn = async (kind: AddonKind, acc: AccountsState = accounts) => {
        if (operatorId == null) return;
        const need = addonNeed(kind, acc);
        if (need !== 'ready') {
            setOpen({ k: need, then: kind });
            return;
        }
        setPhase(kind, { k: 'running' });
        clearAddonFailure(operatorId, kind);
        try {
            await runAddon(kind, operatorId, acc);
            setPhase(kind, { k: 'idle' });
        } catch (e) {
            setPhase(kind, { k: 'failed', op: 'on', error: e });
            // The key went (a restore, another phone): connect again.
            const code = classifyAddonError(e);
            if (code === 'E_CDN_NO_TOKEN') {
                read.reload();
                setOpen({ k: 'cloudflare', then: kind });
            } else if (code === 'E_GOOGLE_NO_ACCOUNT') {
                read.reload();
                setOpen({ k: 'google', then: 'google' });
            } else if (code === 'E_GITHUB_NO_ACCOUNT') {
                read.reload();
                setOpen({ k: 'github', then: 'gittag' });
            } else if (code === 'E_GITTAG_REFUSED') {
                // The kept key cannot do it (a permission, expired,
                // revoked): the row names what, and the sheet takes a new one.
                read.reload();
                setOpen({ k: 'github', then: 'gittag', newKey: true });
            }
        }
        reload();
    };

    const turnOff = async (kind: AddonKind, ask: boolean) => {
        const row = liveRow(rows, kind);
        const copy = ADDON_COPY.find((c) => c.kind === kind)!;
        if (!row) return;
        if (ask) {
            const yes = await confirm.ask({
                title: t('pub.addons.off.title').replace('{name}', t(copy.titleKey)),
                body: t(copy.offKey),
                confirmLabel: t('pub.addons.off.go'),
                cancelLabel: t('pub.addons.cancel'),
                danger: true,
            });
            if (!yes) return;
        }
        setPhase(kind, { k: 'stopping' });
        try {
            const r: AddonRemoveReport = await Addons.remove(row.id);
            // What stays: what still bills, and a GitHub repository the
            // publisher may delete themselves.
            const billing = [...(r.still_billing ?? []), ...(r.by_hand ?? []).filter((w) => w === 'github_repository')];
            const repo = typeof row.detail?.repo === 'string' ? (row.detail.repo as string) : '';
            if (!r.removed) setPhase(kind, { k: 'failed', op: 'off', error: '' });
            else setPhase(kind, billing.length > 0 ? { k: 'billing', what: billing, repo } : { k: 'idle' });
        } catch (e) {
            setPhase(kind, { k: 'failed', op: 'off', error: e });
        }
        reload();
    };

    const retry = (kind: AddonKind) => {
        const p = phases[kind];
        const row = liveRow(rows, kind);
        if ((p?.k === 'failed' && p.op === 'off') || row?.state === 'removing') void turnOff(kind, false);
        else void turnOn(kind);
    };

    const showCode = async () => {
        if (operatorId == null) return;
        const r = await code.run(() => Addons.standbyKey({ operator_id: operatorId }));
        if (r) setOpen({ k: 'code', code: r.key, wrapped: r.form === 'wrapped', plain: r.plain_key });
    };
    const switchToStandby = async () => {
        if (operatorId == null) return;
        const yes = await confirm.ask({
            title: t('pub.addons.standby.switch.title'),
            body: t('pub.addons.standby.switch.body'),
            confirmLabel: t('pub.addons.standby.switch.go'),
            cancelLabel: t('pub.addons.cancel'),
        });
        if (!yes) return;
        const r = await code.run(() => Addons.standbyPromote({ operator_id: operatorId }));
        reload();
        if (r) setOpen({ k: 'code', code: r.key, wrapped: r.key_form === 'wrapped', plain: r.plain_key });
    };

    const standby = liveRow(rows, 'standby');
    const promoted = rows.some((r) => r.kind === 'standby' && r.state === 'promoted');
    const cdn = liveRow(rows, 'cdn');
    const nameHidden = cdn?.state === 'ready' && cdn.detail?.name_hidden === true;
    const details = standby?.state === 'ready' || promoted || nameHidden;

    const afterConnect = (kind: AddonKind | undefined, acc: AccountsState) => {
        setOpen(null);
        read.reload();
        if (kind) void turnOn(kind, acc);
    };

    return (
        <section data-testid={`addons-${variant}`} style={{ width: '100%', textAlign: 'start', display: 'grid', gap: 8 }}>
            <h2 style={H2}>{t('pub.addons.title')}</h2>
            <div
                style={{
                    background: 'var(--surface)',
                    border: '1px solid var(--line-soft)',
                    borderRadius: 'var(--r-card)',
                    padding: '0 16px',
                }}
            >
                {ADDON_COPY.map((c, i) => (
                    <ProtectRow
                        key={c.kind}
                        t={t}
                        copy={c}
                        row={liveRow(rows, c.kind)}
                        phase={phases[c.kind] ?? { k: 'idle' }}
                        connected={c.needs == null || accountConnected(accounts, c.needs)}
                        needsStandby={c.kind === 'dnsnote' && !standby && !promoted}
                        everyoneFile={everyoneFile}
                        onNewFiles={onNewFiles}
                        onFixKey={(acct) => setOpen(acct === 'github' ? { k: 'github', newKey: true } : { k: 'cloudflare' })}
                        first={i === 0}
                        disabled={operatorId == null}
                        onToggle={(on) => void (on ? turnOn(c.kind) : turnOff(c.kind, true))}
                        onRetry={() => retry(c.kind)}
                    />
                ))}
                {details && (
                    <div data-testid="addons-details" style={{ borderTop: '1px solid var(--line)', padding: '10px 0' }}>
                        <WhatIsThis label={t('pub.addons.details')} dataButton="addons-details">
                            <div style={{ display: 'grid', gap: 10, paddingTop: 6 }}>
                                {promoted && !standby && <p style={MUTED}>{t('pub.addons.standby.in_use')}</p>}
                                {(standby?.state === 'ready' || promoted) && (
                                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                        {standby?.state === 'ready' && (
                                            <Button size="sm" variant="secondary" onClick={() => void switchToStandby()} disabled={code.busy} dataButton="standby-switch">
                                                {t('pub.addons.standby.switch')}
                                            </Button>
                                        )}
                                        <Button size="sm" variant="ghost" onClick={() => void showCode()} disabled={code.busy} dataButton="standby-show-key">
                                            {t('pub.addons.standby.key.show')}
                                        </Button>
                                    </div>
                                )}
                                {code.error != null && <ErrorNote t={t} error={code.error} />}
                                {nameHidden && (
                                    <p data-testid="cdn-name-hidden" style={MUTED}>
                                        {t('pub.addons.cdn.name_hidden')}
                                    </p>
                                )}
                            </div>
                        </WhatIsThis>
                    </div>
                )}
            </div>

            {open?.k === 'cloudflare' && (
                <CloudflareSheet
                    t={t}
                    zone={accounts.cloudflare.connected ? accounts.cloudflare.zone : null}
                    extra={accounts.cloudflare.extra}
                    onClose={() => setOpen(null)}
                    onConnected={(zone) => {
                        const acc = { ...accounts, cloudflare: { connected: true, zone } };
                        afterConnect(open.then, acc);
                    }}
                />
            )}
            {open?.k === 'google' && (
                <GoogleSheet
                    t={t}
                    google={accounts.google}
                    onClose={() => setOpen(null)}
                    onConnected={() => afterConnect(open.then, { ...accounts, google: { ...accounts.google, connected: true } })}
                />
            )}
            {open?.k === 'github' && (
                <GithubSheet
                    t={t}
                    github={accounts.github}
                    newKey={open.newKey}
                    onClose={() => setOpen(null)}
                    onConnected={(login) =>
                        afterConnect(open.then, { ...accounts, github: { connected: true, login } })
                    }
                />
            )}
            {open?.k === 'code' && (
                <CodeSheet t={t} code={open.code} wrapped={open.wrapped} plain={open.plain} onClose={() => setOpen(null)} />
            )}
            {confirm.node}
        </section>
    );
}

function ProtectRow({
    t,
    copy,
    row,
    phase,
    connected,
    first,
    disabled,
    onToggle,
    onRetry,
    onNewFiles,
    needsStandby = false,
    everyoneFile = false,
    onFixKey,
}: {
    t: (key: string) => string;
    copy: AddonCopy;
    onNewFiles?: () => void;
    /** The DNS switch carries only the standby address: none is held. */
    needsStandby?: boolean;
    /** The relay has a file for everyone (notes never reach it). */
    everyoneFile?: boolean;
    /** Open the account's sheet to take a new key. */
    onFixKey?: (account: 'github' | 'cloudflare') => void;
    row: AddonRow | null;
    phase: Phase;
    /** The account it needs is connected (or it needs none). */
    connected: boolean;
    first: boolean;
    disabled: boolean;
    onToggle: (on: boolean) => void;
    onRetry: () => void;
}) {
    const titleId = `addon-${copy.kind}-title`;
    const busy = phase.k === 'running' || phase.k === 'stopping';
    const checked = phase.k === 'running' || (phase.k !== 'stopping' && row != null);
    // The same words on or off: the cost never loses its "+ VAT".
    const cost = t(copy.costKey);
    const { isRTL } = useDensity();
    const needList = [
        !connected && copy.needs ? t(`pub.addons.needs.${copy.needs}`) : '',
        needsStandby ? t('pub.addons.needs.standby') : '',
    ].filter(Boolean);
    const needs = needList.join(' · ');
    const isNote = NOTE_KINDS.includes(copy.kind);
    // People had files when the switch went on: they need new ones. Read
    // from the row, so the line comes back on the next visit too.
    const newFiles = isNote && row?.state === 'ready' && Number(row.detail?.people_before ?? 0) > 0;
    // A refused GitHub write names what GitHub said.
    const failLine = phase.k === 'failed' && copy.kind === 'gittag' ? gittagRefusalLine(t, phase.error, isRTL) : undefined;
    const state =
        phase.k === 'idle' || phase.k === 'billing' ? (row ? row.state : 'off') : phase.k;

    return (
        <div
            data-testid={`addon-${copy.kind}`}
            data-state={state}
            role="group"
            aria-labelledby={titleId}
            style={{ display: 'grid', gap: 6, padding: '14px 0', borderTop: first ? 'none' : '1px solid var(--line)' }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2 }}>
                    <span id={titleId} style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>
                        {t(copy.titleKey)}
                    </span>
                    <span style={MUTED}>{t(copy.lineKey)}</span>
                    <span data-testid={`addon-${copy.kind}-cost`} style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>
                        {needs ? `${cost} · ${needs}` : cost}
                    </span>
                </span>
                <Toggle
                    checked={checked}
                    onChange={onToggle}
                    disabled={disabled || busy}
                    ariaLabel={t(copy.titleKey)}
                    dataButton={`addon-${copy.kind}-toggle`}
                />
            </div>

            {busy && (
                <div data-testid={`addon-${copy.kind}-status`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <StateIcon state="busy" size={16} />
                    <span style={MUTED}>{t(phase.k === 'running' ? 'pub.addons.state.running' : 'pub.addons.state.stopping')}</span>
                </div>
            )}

            {!busy && phase.k !== 'failed' && row?.state === 'ready' && !waitsForPerson(row) && (
                <div data-testid={`addon-${copy.kind}-status`} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <StateIcon state="ok" size={16} />
                    <span style={{ ...MUTED, color: 'var(--green)', fontWeight: 600 }}>{t('pub.addons.state.on')}</span>
                </div>
            )}

            {/* A note switch writes by itself: how the last write went. */}
            {!busy && phase.k !== 'failed' && row?.state === 'ready' && isNote && (
                <NoteStatus t={t} kind={copy.kind} detail={row.detail as NotesDetail} onFix={onFixKey} />
            )}

            {!busy && phase.k !== 'failed' && newFiles && (
                <div data-testid={`addon-${copy.kind}-new-files`} style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
                    <p style={MUTED}>{t(everyoneFile ? 'pub.addons.notes.new_files_each' : `pub.addons.${copy.kind}.new_files`)}</p>
                    {onNewFiles && !everyoneFile && (
                        <Button size="sm" variant="secondary" onClick={onNewFiles} dataButton={`addon-${copy.kind}-new-files`}>
                            {t('pub.refile.menu')}
                        </Button>
                    )}
                </div>
            )}

            {isNote && everyoneFile && (row != null || phase.k === 'running') && (
                <p data-testid={`addon-${copy.kind}-not-everyone`} style={MUTED}>
                    {t('pub.addons.notes.not_everyone')}
                </p>
            )}

            {/* Set up and signed; the relay's door opens with the first
                person (addon_cdn.rs `door_waits`). Not a failure. */}
            {!busy && phase.k !== 'failed' && waitsForPerson(row) && (
                <p data-testid={`addon-${copy.kind}-waits`} style={MUTED}>
                    {t('pub.addons.cdn.waits_person')}
                </p>
            )}

            {!busy && phase.k !== 'failed' && (row?.state === 'building' || row?.state === 'removing') && (
                <Failed t={t} line={t(`pub.addons.state.${row.state}`)} onRetry={onRetry} kind={copy.kind} />
            )}

            {phase.k === 'failed' && (
                <Failed
                    t={t}
                    error={phase.error}
                    line={failLine ?? (phase.error ? undefined : t('pub.addons.state.removing'))}
                    onRetry={onRetry}
                    kind={copy.kind}
                />
            )}

            {phase.k === 'billing' &&
                phase.what.map((w) =>
                    w === 'github_repository' ? (
                        // Nothing is wrong: the repository is the publisher's
                        // to delete. Named on this screen only, never logged.
                        <p key={w} data-testid={`addon-${copy.kind}-billing`} style={MUTED}>
                            {t('pub.addons.gittag.repo_left').replace('{name}', phase.repo || '…')}
                        </p>
                    ) : (
                        <p key={w} data-testid={`addon-${copy.kind}-billing`} style={{ ...MUTED, color: 'var(--amber)' }}>
                            {t(w === 'domain' ? 'pub.addons.billing.domain' : 'pub.addons.billing.address')}
                        </p>
                    ),
                )}
        </div>
    );
}

/** The last write's code words that retrying never fixes: the person
 *  must act (a new key, the account connected again). */
const NOTE_ACT_CODES: Record<string, 'github' | 'cloudflare'> = {
    e_gittag_refused: 'github',
    e_github_no_account: 'github',
    e_dnsnote_refused: 'cloudflare',
    e_cdn_no_token: 'cloudflare',
};

/** The line for a refused GitHub write: what GitHub said is missing, or
 *  that it does not accept the key; undefined for anything else. */
export function gittagRefusalLine(t: (k: string) => string, e: unknown, rtl: boolean): string | undefined {
    const msg = typeof e === 'string' ? e : e instanceof Error ? e.message : '';
    const m = /^E_GITTAG_REFUSED:\s*([a-z_]+)(?::\s*(.*))?/.exec(msg);
    if (!m) return undefined;
    if (m[1] === 'invalid_token') return t('pub.accounts.github.verdict.invalid');
    if (m[1] !== 'missing_permission') return undefined;
    const names = (m[2] ?? '').split(',').map((x) => x.trim()).filter(Boolean);
    const list = githubPermissionList(t, names, rtl) || t('pub.accounts.cf.perm.some');
    return t('pub.accounts.github.verdict.missing_permission').replace('{list}', list);
}

/** «Updated 2 hours ago», or «Could not update. Daal will try again.»
 *  when the last try did not go through for a reason that may pass. A
 *  refused key, or an account that is gone, will never pass by itself:
 *  that says what is wrong, in amber, with a way to give a new key. */
export function NoteStatus({
    t,
    kind,
    detail,
    onFix,
}: {
    t: (k: string) => string;
    kind: AddonKind;
    detail: NotesDetail | undefined;
    onFix?: (account: 'github' | 'cloudflare') => void;
}) {
    // The reader's words follow the catalogue `t` reads (as money() does).
    const locale = /[؀-ۿ]/.test(t('pub.addons.title')) ? 'fa' : 'en';
    const ok = Number(detail?.last_ok_at_unix ?? 0);
    const tried = Number(detail?.last_try_at_unix ?? 0);
    const code = String(detail?.last_error ?? '').toLowerCase();
    const failed = !!code && tried >= ok;
    if (!failed && ok <= 0) return null;
    const act = failed ? NOTE_ACT_CODES[code] : undefined;
    if (act) {
        return (
            <div data-testid={`addon-${kind}-note`} data-note="act" style={{ display: 'grid', gap: 6, justifyItems: 'start' }}>
                <p style={{ ...MUTED, color: 'var(--amber)' }}>{t(`pub.addons.err.${code.toUpperCase()}`)}</p>
                {onFix && (
                    <Button size="sm" variant="secondary" onClick={() => onFix(act)} dataButton={`addon-${kind}-fix-key`}>
                        {act === 'github' ? t('pub.accounts.github.new_key') : t('pub.addons.notes.fix')}
                    </Button>
                )}
            </div>
        );
    }
    const line = failed
        ? t(`pub.addons.${kind}.retry`)
        : t(`pub.addons.${kind}.updated`).replace('{when}', formatAgo(locale, Date.now() - ok * 1000));
    return (
        <p data-testid={`addon-${kind}-note`} data-note={failed ? 'retry' : 'updated'} style={MUTED}>
            {line}
        </p>
    );
}

function Failed({
    t,
    kind,
    error,
    line,
    onRetry,
}: {
    t: (k: string) => string;
    kind: AddonKind;
    error?: unknown;
    line?: string;
    onRetry: () => void;
}) {
    return (
        <div data-testid={`addon-${kind}-failed`} style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
            {line ? <p style={{ ...MUTED, color: 'var(--red)' }}>{line}</p> : <ErrorNote t={t} error={error} />}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <Button size="sm" variant="secondary" onClick={onRetry} dataButton={`addon-${kind}-retry`}>
                    {t('pub.addons.try_again')}
                </Button>
            </div>
        </div>
    );
}

/** The standby code: after a switch, or from Details. A wrapped code
 *  opens only with the person's own file, so the sheet says it may go by
 *  SMS, a call or a messenger; a plain one keeps the earlier wording.
 *  Beside a wrapped code, one quiet action shows the plain one, with the
 *  plain code's caution: for a person whose phone cannot open the
 *  wrapped form (an older build, or a file not imported yet). */
function CodeSheet({
    t,
    code: shown,
    wrapped: shownWrapped,
    plain,
    onClose,
}: {
    t: (k: string) => string;
    code: string;
    wrapped: boolean;
    plain?: string;
    onClose: () => void;
}) {
    const [copied, setCopied] = useState(false);
    const [showPlain, setShowPlain] = useState(false);
    const usePlain = showPlain && shownWrapped && !!plain;
    const code = usePlain ? plain! : shown;
    const wrapped = shownWrapped && !usePlain;
    const share = async () => {
        const nav = navigator as Navigator & { share?: (d: { text: string }) => Promise<void> };
        if (typeof nav.share === 'function') {
            try {
                await nav.share({ text: code });
                return;
            } catch {
                /* closed, or not allowed: copy instead */
            }
        }
        setCopied(await copyText(code));
    };
    return (
        <Sheet title={t('pub.addons.standby.key.title')} onClose={onClose} width={440}>
            <div data-testid="standby-code-sheet" style={{ display: 'grid', gap: 12 }}>
                <div
                    data-testid="standby-key"
                    dir="ltr"
                    style={{ ...MONO, fontSize: 20, letterSpacing: 1, textAlign: 'center', padding: '12px 0', userSelect: 'all' }}
                >
                    {code}
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
                    <Button variant="secondary" leading="copy" onClick={async () => setCopied(await copyText(code))} dataButton="standby-key-copy">
                        {copied ? t('pub.addons.copied') : t('pub.addons.copy')}
                    </Button>
                    <Button variant="secondary" leading="share" onClick={() => void share()} dataButton="standby-key-share">
                        {t('pub.addons.share')}
                    </Button>
                </div>
                <p style={BODY} data-form={wrapped ? 'wrapped' : 'plain'}>
                    {t(wrapped ? 'standby.wrap.body' : 'pub.addons.standby.key.body')}
                </p>
                {wrapped && plain && (
                    <div>
                        <Button
                            size="sm"
                            variant="link"
                            onClick={() => {
                                setCopied(false);
                                setShowPlain(true);
                            }}
                            dataButton="standby-key-plain"
                        >
                            {t('standby.wrap.fallback')}
                        </Button>
                    </div>
                )}
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button onClick={onClose} dataButton="standby-key-close">
                        {t('pub.addons.close')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}

const H2: React.CSSProperties = {
    fontFamily: 'var(--font-display)',
    fontSize: 20,
    fontWeight: 500,
    lineHeight: 1.2,
    margin: 0,
    color: 'var(--fg)',
};
