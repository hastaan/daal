// AccountCheckSheet — what Daal finds in each hosting account this
// phone holds a token for, and the one place leftovers can be deleted
// (D1). Sorting and the deletability rule live in accountCheck.ts.

import { useCallback, useEffect, useState } from 'react';
import { Badge, Button, Sheet } from '../design/primitives';
import { Wizard } from './wizardCommands';
import type {
    AccountCheck,
    AccountCheckAccount,
    AccountCleanupReport,
    AccountItem,
    ResourceRef,
} from './wizardCommands';
import { WhatIsThis } from './Disclosure';
import {
    GROUP_ORDER,
    defaultSelection,
    deletable,
    errorKey,
    groupItems,
    outcomeKey,
    refKey,
    selectedRefs,
} from './accountCheck';
import type { AccountGroup } from './accountCheck';
import { kindKey } from './setupRecovery';

const BODY: React.CSSProperties = { fontSize: 13, color: 'var(--fg)', lineHeight: 1.55 };
const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 };
// The raw name a provider console shows: a secondary detail, readable
// (--muted, never --dim for text) but quieter than the line above it.
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' };

/** "Hetzner", not the raw token "hetzner". */
export function providerLabel(t: (k: string) => string, provider: string): string {
    const k = `pub.danger.rebuild.provider.name.${provider}`;
    const v = t(k);
    if (v && v !== k) return v;
    return provider ? provider.charAt(0).toUpperCase() + provider.slice(1) : provider;
}

function groupTitleKey(g: AccountGroup): string {
    return `pub.account.group.${g}`;
}

function ItemLine({
    t,
    item,
    checkbox,
    onOpenRelay,
}: {
    t: (k: string) => string;
    item: AccountItem;
    checkbox?: { checked: boolean; onChange: (v: boolean) => void };
    onOpenRelay?: (relayId: number) => void;
}) {
    return (
        <div style={{ display: 'grid', gap: 4, padding: '6px 0' }}>
            <label style={{ display: 'flex', gap: 8, alignItems: 'baseline', cursor: checkbox ? 'pointer' : 'default' }}>
                {checkbox && (
                    <input
                        type="checkbox"
                        checked={checkbox.checked}
                        onChange={(e) => checkbox.onChange(e.target.checked)}
                    />
                )}
                <span style={{ ...BODY, flex: 1 }}>
                    {t(kindKey(item.kind))}
                    {item.address ? ` · ${item.address}` : ''}
                </span>
                {item.billing ? (
                    <Badge tone="warn" size="sm">
                        {t('pub.account.billing.yes')}
                    </Badge>
                ) : (
                    <span style={SUB}>{t('pub.account.billing.no')}</span>
                )}
            </label>
            <div style={MONO} dir="ltr">
                {item.name || item.id}
            </div>
            {item.finding === 'not_on_this_phone' && item.kind === 'server' && (
                <div style={{ ...SUB, color: 'var(--amber)' }}>{t('pub.account.warn.other_phone')}</div>
            )}
            {item.finding === 'unfinished_setup' && item.belongs_to_relay_id != null && onOpenRelay && (
                <div>
                    <Button size="sm" variant="secondary" onClick={() => onOpenRelay(item.belongs_to_relay_id!)}>
                        {t('pub.account.open_setup')}
                    </Button>
                </div>
            )}
        </div>
    );
}

/** One account's block. Exported for the tests. */
export function AccountBlock({
    t,
    acc,
    selection,
    onToggle,
    onOpenRelay,
}: {
    t: (k: string) => string;
    acc: AccountCheckAccount;
    selection: Set<string>;
    onToggle: (key: string, on: boolean) => void;
    onOpenRelay?: (relayId: number) => void;
}) {
    const groups = groupItems(acc);
    const err = errorKey(acc.error_code);
    const empty = (acc.items ?? []).length === 0;
    return (
        <div style={{ display: 'grid', gap: 10, padding: '10px 0', borderBottom: '1px solid var(--line-soft)' }}>
            <div style={{ ...BODY, fontWeight: 600 }}>
                {t('pub.account.account_title').replace('{provider}', providerLabel(t, acc.provider))}
            </div>
            {err && <div style={{ ...SUB, color: 'var(--red)' }}>{t(err)}</div>}
            {!acc.complete && <div style={{ ...SUB, color: 'var(--red)' }}>{t('pub.account.incomplete')}</div>}
            {acc.complete && empty && <div style={SUB}>{t('pub.account.nothing_found')}</div>}
            {GROUP_ORDER.filter((g) => g !== 'in_use' && groups[g].length > 0).map((g) => (
                <div key={g} style={{ display: 'grid', gap: 2 }} data-group={g}>
                    <div style={{ ...SUB, fontWeight: 600, color: 'var(--fg)' }}>{t(groupTitleKey(g))}</div>
                    {g === 'cannot_tell' && <div style={SUB}>{t('pub.account.group.cannot_tell.line')}</div>}
                    {groups[g].map((i) => (
                        <ItemLine
                            key={refKey(i)}
                            t={t}
                            item={i}
                            onOpenRelay={onOpenRelay}
                            checkbox={
                                deletable(acc, i)
                                    ? { checked: selection.has(refKey(i)), onChange: (v) => onToggle(refKey(i), v) }
                                    : undefined
                            }
                        />
                    ))}
                </div>
            ))}
            {groups.in_use.length > 0 && (
                <WhatIsThis label={t('pub.account.group.in_use').replace('{n}', String(groups.in_use.length))}>
                    {groups.in_use.map((i) => (
                        <ItemLine key={refKey(i)} t={t} item={i} />
                    ))}
                </WhatIsThis>
            )}
            {acc.details.length > 0 && (
                <WhatIsThis label={t('pub.fb.details')}>
                    {acc.details.map((d, n) => (
                        <div key={n} dir="ltr" style={MONO}>
                            {d}
                        </div>
                    ))}
                </WhatIsThis>
            )}
        </div>
    );
}

type Stage =
    | { k: 'loading' }
    | { k: 'failed'; detail: string }
    | { k: 'list'; check: AccountCheck }
    | { k: 'confirm'; check: AccountCheck; acc: AccountCheckAccount; refs: ResourceRef[] }
    | { k: 'deleting'; check: AccountCheck; acc: AccountCheckAccount; refs: ResourceRef[] }
    | { k: 'done'; report: AccountCleanupReport }
    | { k: 'cleanup_failed'; detail: string };

export function AccountCheckSheet({
    t,
    onClose,
    onOpenRelay,
    load = Wizard.accountCheck,
    cleanup = Wizard.accountCleanup,
}: {
    t: (k: string) => string;
    onClose: (changed: boolean) => void;
    onOpenRelay?: (relayId: number) => void;
    load?: () => Promise<AccountCheck>;
    cleanup?: (key: string, items: ResourceRef[]) => Promise<AccountCleanupReport>;
}) {
    const [stage, setStage] = useState<Stage>({ k: 'loading' });
    const [sel, setSel] = useState<Record<string, Set<string>>>({});

    const refresh = useCallback(async () => {
        setStage({ k: 'loading' });
        try {
            const check = await load();
            setSel(Object.fromEntries(check.accounts.map((a) => [a.account_key, defaultSelection(a)])));
            setStage({ k: 'list', check });
        } catch (e) {
            setStage({ k: 'failed', detail: String(e) });
        }
    }, [load]);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    const runCleanup = async (acc: AccountCheckAccount, refs: ResourceRef[], check: AccountCheck) => {
        setStage({ k: 'deleting', check, acc, refs });
        try {
            setStage({ k: 'done', report: await cleanup(acc.account_key, refs) });
        } catch (e) {
            setStage({ k: 'cleanup_failed', detail: String(e) });
        }
    };

    const changed = stage.k === 'done' || stage.k === 'cleanup_failed';
    const busy = stage.k === 'loading' || stage.k === 'deleting';

    return (
        <Sheet
            title={t('pub.account.title')}
            width={600}
            onClose={() => {
                if (!busy) onClose(changed);
            }}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    {(stage.k === 'confirm' || stage.k === 'deleting') && (
                        <>
                            <Button
                                variant="ghost"
                                disabled={busy}
                                onClick={() => setStage({ k: 'list', check: stage.check })}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                disabled={busy}
                                onClick={() => void runCleanup(stage.acc, stage.refs, stage.check)}
                            >
                                {busy ? t('pub.account.deleting') : t('pub.account.delete_confirm')}
                            </Button>
                        </>
                    )}
                    {(stage.k === 'done' || stage.k === 'cleanup_failed' || stage.k === 'failed') && (
                        <Button variant="secondary" onClick={() => void refresh()}>
                            {t('pub.account.check_again')}
                        </Button>
                    )}
                    {stage.k !== 'confirm' && stage.k !== 'deleting' && (
                        <Button disabled={busy} onClick={() => onClose(changed)}>
                            {t('common.close')}
                        </Button>
                    )}
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 10 }}>
                <div style={SUB}>{t('pub.account.rule')}</div>

                {stage.k === 'loading' && <div style={BODY}>{t('pub.account.loading')}</div>}

                {stage.k === 'failed' && (
                    <div style={{ display: 'grid', gap: 6 }}>
                        <div style={{ ...BODY, color: 'var(--red)' }}>{t('pub.account.load_failed')}</div>
                        <WhatIsThis label={t('pub.fb.details')}>
                            <div dir="ltr">{stage.detail}</div>
                        </WhatIsThis>
                    </div>
                )}

                {stage.k === 'list' && (
                    <>
                        {stage.check.accounts.length === 0 && <div style={BODY}>{t('pub.account.no_accounts')}</div>}
                        {stage.check.accounts.map((acc) => {
                            const s = sel[acc.account_key] ?? new Set<string>();
                            const refs = selectedRefs(acc, s);
                            return (
                                <div key={acc.account_key} style={{ display: 'grid', gap: 8 }}>
                                    <AccountBlock
                                        t={t}
                                        acc={acc}
                                        selection={s}
                                        onOpenRelay={onOpenRelay}
                                        onToggle={(k, on) =>
                                            setSel((prev) => {
                                                const next = new Set(prev[acc.account_key] ?? []);
                                                if (on) next.add(k);
                                                else next.delete(k);
                                                return { ...prev, [acc.account_key]: next };
                                            })
                                        }
                                    />
                                    {acc.complete && (acc.items ?? []).some((i) => deletable(acc, i)) && (
                                        <div>
                                            <Button
                                                variant="danger"
                                                disabled={refs.length === 0}
                                                onClick={() =>
                                                    setStage({ k: 'confirm', check: stage.check, acc, refs })
                                                }
                                            >
                                                {t('pub.account.delete_selected').replace('{n}', String(refs.length))}
                                            </Button>
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </>
                )}

                {(stage.k === 'confirm' || stage.k === 'deleting') && (
                    <div style={{ display: 'grid', gap: 8 }}>
                        <div style={BODY}>{t('pub.account.confirm.body')}</div>
                        {stage.acc.items
                            .filter((i) => stage.refs.some((r) => r.kind === i.kind && r.id === i.id))
                            .map((i) => (
                                <ItemLine key={refKey(i)} t={t} item={i} />
                            ))}
                        <div style={{ ...SUB, color: 'var(--red)' }}>{t('pub.account.confirm.final')}</div>
                    </div>
                )}

                {stage.k === 'done' && (
                    <div style={{ display: 'grid', gap: 6 }} data-testid="cleanup-outcomes">
                        {stage.report.outcomes.map((o) => (
                            <div key={refKey(o)} style={{ ...BODY, color: o.code === 'delete_failed' ? 'var(--red)' : 'var(--fg)' }}>
                                {t(kindKey(o.kind))}{' '}
                                <span style={MONO} dir="ltr">
                                    {o.name || o.id}
                                </span>
                                {': '}
                                {t(outcomeKey(o.code))}
                            </div>
                        ))}
                        {stage.report.details.length > 0 && (
                            <WhatIsThis label={t('pub.fb.details')}>
                                {stage.report.details.map((d, n) => (
                                    <div key={n} dir="ltr" style={MONO}>
                                        {d}
                                    </div>
                                ))}
                            </WhatIsThis>
                        )}
                    </div>
                )}

                {stage.k === 'cleanup_failed' && (
                    <div style={{ display: 'grid', gap: 6 }}>
                        <div style={{ ...BODY, color: 'var(--red)' }}>{t('pub.account.cleanup_failed')}</div>
                        <WhatIsThis label={t('pub.fb.details')}>
                            <div dir="ltr">{stage.detail}</div>
                        </WhatIsThis>
                    </div>
                )}
            </div>
        </Sheet>
    );
}
