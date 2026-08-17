// FreshnessPanel — Wave 3 Step 8, the publisher-facing half of remote
// pack replacement.
//
// WHAT THIS SCREEN IS FOR
//
// Until now every rotation ended with the same sentence in the UI:
// "rebuild each file and deliver it by hand". That sentence was
// honest, and it was also the reason rotating was something publishers
// avoided. A refresh address is the way out: Daal puts a small signed
// note on ordinary web hosting and each recipient's app finds the new
// settings on its own.
//
// THREE HONESTY RULES, EACH OF WHICH HAD TO BE DESIGNED FOR
//
//  1. A green tick is only ever drawn from a provider's own 2xx. There
//     is no "probably fine", no optimistic state, and no state derived
//     from configuration. `last_publish_ok` is the one field allowed to
//     produce it; `has_credential` is a custody probe, not a guess.
//
//  2. Configuring a mirror does not repair a file somebody already
//     imported. The panel therefore has TWO status lines that people
//     will want to conflate and must not: what is configured, and what
//     is inside the pack recipients are holding (`mirrors_in_pack`,
//     stamped at sign time). Only a fresh signature moves the second
//     one, and until it does, a rotation still needs a courier.
//
//  3. One mirror is worse than none, and the copy says so rather than
//     showing a lone green row. A freshness URL is a fixed address in
//     every file the publisher hands out — small, unique, pollable. A
//     censor who can block the relay can block one hosting company just
//     as easily, and then the recovery path is off while the publisher
//     believes it is on. Daal refuses to bake a single address into a
//     pack (`freshness::mirror_args` returns nothing below the floor),
//     so the panel's job is to explain that refusal, not to hide it.
//
// AND ONE COST THAT IS NOT HIDDEN
//
// Everyone holding a file polls the same addresses on a schedule.
// Whoever can read that host's logs can count and locate a publisher's
// readers. Because refresh fails closed while a tunnel is up (Wave 1),
// the request goes over the plain network — which is what makes it
// visible to the local ISP, and also the only reason it still works
// when the tunnel is already dead. Both halves are in the copy.

import { useCallback, useEffect, useState } from 'react';
import { Wizard } from './wizardCommands';
import type {
    FreshnessEndpointInput,
    FreshnessStatus,
    PublishReport,
} from './wizardCommands';
import { Card, ListRow, Button, Section, Sheet, Input, StatusPill } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    /** Bumped by the parent after anything that re-signs the pack, so
     *  the "inside the pack" line cannot go stale while the operator is
     *  looking at it. */
    reloadToken?: number;
}

const LABEL: React.CSSProperties = { fontSize: 12, color: 'var(--muted)' };
const MONO: React.CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--muted)',
    wordBreak: 'break-all',
};
const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--fg)',
    lineHeight: 1.55,
};

function dayLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 10);
    } catch {
        return '';
    }
}

/** Provider label. Kept as an i18n key rather than the raw token so
 *  "ghpages" never reaches a screen. */
function providerKey(kind: string): string {
    return kind === 'r2' ? 'pub.fresh.provider.r2' : 'pub.fresh.provider.ghpages';
}

export function FreshnessPanel({ t, operatorId, reloadToken }: Props) {
    const [status, setStatus] = useState<FreshnessStatus | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [report, setReport] = useState<PublishReport | null>(null);
    const [showAdd, setShowAdd] = useState(false);
    const [packUrlDraft, setPackUrlDraft] = useState('');
    const [packUrlSaved, setPackUrlSaved] = useState(false);

    const reload = useCallback(async () => {
        try {
            const s = await Wizard.freshnessStatus(operatorId);
            setStatus(s);
            setPackUrlDraft(s.pack_url);
        } catch (e) {
            setErr(String(e));
        }
    }, [operatorId]);

    useEffect(() => {
        void reload();
    }, [reload, reloadToken]);

    const onSavePackUrl = async () => {
        setErr(null);
        setPackUrlSaved(false);
        try {
            await Wizard.setFreshnessPackUrl(operatorId, packUrlDraft.trim());
            setPackUrlSaved(true);
            await reload();
        } catch (e) {
            setErr(String(e));
        }
    };

    const onPublish = async () => {
        setBusy(true);
        setErr(null);
        setReport(null);
        try {
            const r = await Wizard.publishFreshness(operatorId);
            setReport(r);
        } catch (e) {
            setErr(String(e));
        } finally {
            setBusy(false);
            await reload();
        }
    };

    const onDelete = async (id: number) => {
        if (!window.confirm(t('pub.fresh.remove.confirm'))) return;
        setErr(null);
        try {
            await Wizard.deleteFreshnessEndpoint(id);
            await reload();
        } catch (e) {
            setErr(String(e));
        }
    };

    if (!status) {
        return (
            <Section eyebrow={t('pub.fresh.eyebrow')} title={t('pub.fresh.title')}>
                <Card>
                    <ListRow title={t('common.loading')} last />
                </Card>
            </Section>
        );
    }

    const enough = status.distinct_providers >= status.min_mirrors;
    const packCanHeal = status.mirrors_in_pack.length > 0;

    return (
        <Section
            eyebrow={t('pub.fresh.eyebrow')}
            title={t('pub.fresh.title')}
            action={
                <Button variant="secondary" onClick={() => setShowAdd(true)}>
                    {t('pub.fresh.add.action')}
                </Button>
            }
        >
            <Card>
                {/* ---- What the files people already hold can do. This
                    is FIRST because it is the only line that answers
                    "do I still need to walk files around?", and it is
                    computed from the signed pack, never from the list
                    below it. ---- */}
                <ListRow
                    title={
                        packCanHeal
                            ? t('pub.fresh.pack.healing')
                            : t('pub.fresh.pack.not_healing')
                    }
                    subtitle={
                        packCanHeal
                            ? t('pub.fresh.pack.healing.body').replace(
                                  '{count}',
                                  String(status.mirrors_in_pack.length),
                              )
                            : status.pack_signed_at_unix
                              ? t('pub.fresh.pack.not_healing.body_dated').replace(
                                    '{date}',
                                    dayLabel(status.pack_signed_at_unix),
                                )
                              : t('pub.fresh.pack.not_healing.body')
                    }
                    trailing={
                        <StatusPill tone={packCanHeal ? 'good' : 'warn'}>
                            {packCanHeal
                                ? t('pub.fresh.pill.healing')
                                : t('pub.fresh.pill.manual')}
                        </StatusPill>
                    }
                />

                {/* ---- The intent-vs-reality warning. Shown whenever
                    fewer than the floor of DISTINCT providers exist,
                    including the "exactly one" case, which is the one
                    that feels done and is not. ---- */}
                {!enough && (
                    <ListRow
                        title={
                            status.distinct_providers === 0
                                ? t('pub.fresh.none.title')
                                : t('pub.fresh.single.title')
                        }
                        subtitle={
                            status.distinct_providers === 0
                                ? t('pub.fresh.none.body')
                                : t('pub.fresh.single.body')
                        }
                    />
                )}

                {/* ---- Where the rebuilt pack will be downloadable.
                    The note says "the file changed, get it here"; with
                    no "here" there is nothing to publish at all. ---- */}
                <ListRow
                    title={t('pub.fresh.pack_url.title')}
                    subtitle={t('pub.fresh.pack_url.body')}
                    stack
                    trailing={
                        <span
                            style={{
                                display: 'inline-flex',
                                gap: 8,
                                width: '100%',
                            }}
                        >
                            <Input
                                value={packUrlDraft}
                                onChange={(e) => {
                                    setPackUrlDraft(e.target.value);
                                    setPackUrlSaved(false);
                                }}
                                placeholder="https://…/relay.sbp"
                                style={{ flex: 1, fontFamily: 'var(--font-mono)' }}
                            />
                            <Button variant="secondary" onClick={() => void onSavePackUrl()}>
                                {packUrlSaved ? t('common.saved') : t('common.save')}
                            </Button>
                        </span>
                    }
                />

                {/* ---- The mirrors themselves. ---- */}
                {status.endpoints.map((ep, i) => {
                    const never = ep.last_publish_at_unix === 0;
                    const tone = never ? 'neutral' : ep.last_publish_ok ? 'good' : 'bad';
                    return (
                        <ListRow
                            key={ep.id}
                            title={t(providerKey(ep.kind))}
                            subtitle={
                                <span style={{ display: 'grid', gap: 3 }}>
                                    <span style={MONO}>{ep.public_url}</span>
                                    <span style={MONO}>{ep.target}</span>
                                    {/* The provider's own words, verbatim.
                                        "SignatureDoesNotMatch" is worth an
                                        hour of a publisher's life;
                                        "publish failed" is worth none. */}
                                    {!ep.last_publish_ok && !never && (
                                        <span style={{ ...MONO, color: 'var(--red)' }}>
                                            {ep.last_publish_detail}
                                        </span>
                                    )}
                                    {!ep.has_credential && (
                                        <span style={{ ...MONO, color: 'var(--amber)' }}>
                                            {t('pub.fresh.no_credential')}
                                        </span>
                                    )}
                                </span>
                            }
                            meta={
                                <StatusPill tone={tone}>
                                    {never
                                        ? t('pub.fresh.state.never')
                                        : ep.last_publish_ok
                                          ? `${t('pub.fresh.state.published')} ${dayLabel(ep.last_publish_at_unix)}`
                                          : `${t('pub.fresh.state.refused')} ${dayLabel(ep.last_publish_at_unix)}`}
                                </StatusPill>
                            }
                            trailing={
                                <Button variant="ghost" onClick={() => void onDelete(ep.id)}>
                                    {t('common.remove')}
                                </Button>
                            }
                            last={i === status.endpoints.length - 1 && !enough}
                        />
                    );
                })}

                {enough && (
                    <ListRow
                        title={t('pub.fresh.publish.title')}
                        subtitle={t('pub.fresh.publish.body')}
                        trailing={
                            <Button onClick={() => void onPublish()} disabled={busy}>
                                {busy ? t('pub.fresh.publish.working') : t('pub.fresh.publish.action')}
                            </Button>
                        }
                        last
                    />
                )}
            </Card>

            {/* ---- The result of the last publish, spelled out per
                provider. Never collapsed into one line: "R2 took it and
                GitHub refused" is the case the operator has to act on,
                and it is neither a success nor a failure. ---- */}
            {report && (
                <Card>
                    {report.blocked_reason ? (
                        <ListRow
                            title={t('pub.fresh.blocked.title')}
                            subtitle={t(`pub.fresh.blocked.${report.blocked_reason}`)}
                            last
                        />
                    ) : (
                        <>
                            <ListRow
                                title={
                                    report.succeeded >= report.min_mirrors
                                        ? t('pub.fresh.result.ok')
                                        : t('pub.fresh.result.degraded')
                                }
                                subtitle={t('pub.fresh.result.count')
                                    .replace('{ok}', String(report.succeeded))
                                    .replace('{total}', String(report.results.length))
                                    .replace('{min}', String(report.min_mirrors))}
                                trailing={
                                    <StatusPill
                                        tone={
                                            report.succeeded >= report.min_mirrors
                                                ? 'good'
                                                : 'bad'
                                        }
                                    >
                                        {`${report.succeeded}/${report.results.length}`}
                                    </StatusPill>
                                }
                            />
                            {report.results.map((r, i) => (
                                <ListRow
                                    key={r.endpoint_id}
                                    title={t(providerKey(r.kind))}
                                    subtitle={
                                        <span style={{ ...MONO, color: r.ok ? undefined : 'var(--red)' }}>
                                            {r.ok ? r.url : r.detail}
                                        </span>
                                    }
                                    trailing={
                                        <StatusPill tone={r.ok ? 'good' : 'bad'}>
                                            {r.ok
                                                ? t('pub.fresh.state.accepted')
                                                : t('pub.fresh.state.refused_short')}
                                        </StatusPill>
                                    }
                                    last={i === report.results.length - 1}
                                />
                            ))}
                        </>
                    )}
                </Card>
            )}

            {/* ---- The cost. Not buried in a tooltip: a publisher
                deciding whether to switch this on is deciding whether
                their readership becomes countable at a hosting
                company. ---- */}
            <Card>
                <ListRow
                    title={t('pub.fresh.privacy.title')}
                    subtitle={t('pub.fresh.privacy.body')}
                    last
                />
            </Card>

            {err && <div style={{ color: 'var(--red)', fontSize: 12 }}>{err}</div>}

            {showAdd && (
                <AddEndpointSheet
                    t={t}
                    operatorId={operatorId}
                    existingKinds={status.endpoints.map((e) => e.kind)}
                    onClose={() => setShowAdd(false)}
                    onAdded={() => {
                        setShowAdd(false);
                        void reload();
                    }}
                />
            )}
        </Section>
    );
}

/** The add form. Two providers, two field sets; the credential is typed
 *  here, handed to Rust once, and never comes back. */
function AddEndpointSheet({
    t,
    operatorId,
    existingKinds,
    onClose,
    onAdded,
}: {
    t: (k: string) => string;
    operatorId: number;
    existingKinds: string[];
    onClose: () => void;
    onAdded: () => void;
}) {
    // Default to a provider the relay does NOT have yet: adding a second
    // endpoint at the same company is refused by Rust, and offering it
    // as the default would make the refusal look like a bug.
    const [kind, setKind] = useState<'r2' | 'ghpages'>(
        existingKinds.includes('r2') ? 'ghpages' : 'r2',
    );
    const [f, setF] = useState<FreshnessEndpointInput>({ kind: 'r2', public_url: '' });
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);

    const set = (k: keyof FreshnessEndpointInput, v: string) =>
        setF((prev) => ({ ...prev, [k]: v }));

    const submit = async () => {
        setBusy(true);
        setErr(null);
        try {
            await Wizard.addFreshnessEndpoint(operatorId, { ...f, kind });
            onAdded();
        } catch (e) {
            setErr(String(e));
        } finally {
            setBusy(false);
        }
    };

    const field = (labelKey: string, k: keyof FreshnessEndpointInput, ph?: string) => (
        <>
            <label style={LABEL}>{t(labelKey)}</label>
            <Input
                value={(f[k] as string) ?? ''}
                onChange={(e) => set(k, e.target.value)}
                placeholder={ph}
                style={{ fontFamily: 'var(--font-mono)' }}
            />
        </>
    );

    return (
        <Sheet
            title={t('pub.fresh.add.title')}
            onClose={() => {
                if (!busy) onClose();
            }}
            width={560}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    <Button variant="ghost" onClick={onClose} disabled={busy}>
                        {t('common.cancel')}
                    </Button>
                    <Button onClick={() => void submit()} disabled={busy}>
                        {busy ? t('pub.fresh.add.working') : t('pub.fresh.add.submit')}
                    </Button>
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 10 }}>
                <div style={BODY}>{t('pub.fresh.add.body')}</div>

                <label style={LABEL}>{t('pub.fresh.add.provider')}</label>
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    <Button
                        variant={kind === 'r2' ? 'primary' : 'ghost'}
                        onClick={() => setKind('r2')}
                        disabled={existingKinds.includes('r2')}
                    >
                        {t('pub.fresh.provider.r2')}
                    </Button>
                    <Button
                        variant={kind === 'ghpages' ? 'primary' : 'ghost'}
                        onClick={() => setKind('ghpages')}
                        disabled={existingKinds.includes('ghpages')}
                    >
                        {t('pub.fresh.provider.ghpages')}
                    </Button>
                </span>

                {field('pub.fresh.field.public_url', 'public_url', 'https://…/freshness.json')}

                {kind === 'r2' ? (
                    <>
                        {field('pub.fresh.field.account_id', 'account_id')}
                        {field('pub.fresh.field.bucket', 'bucket')}
                        {field('pub.fresh.field.object_key', 'object_key', 'freshness.json')}
                        {field('pub.fresh.field.access_key_id', 'access_key_id')}
                        {field('pub.fresh.field.secret_access_key', 'secret_access_key')}
                    </>
                ) : (
                    <>
                        {field('pub.fresh.field.gh_owner', 'gh_owner')}
                        {field('pub.fresh.field.gh_repo', 'gh_repo')}
                        {field('pub.fresh.field.gh_path', 'gh_path', 'freshness.json')}
                        {field('pub.fresh.field.gh_branch', 'gh_branch', 'main')}
                        {field('pub.fresh.field.gh_pat', 'gh_pat')}
                    </>
                )}

                <div style={{ ...BODY, color: 'var(--muted)' }}>
                    {t('pub.fresh.add.credential_note')}
                </div>

                {err && <div style={{ color: 'var(--red)', fontSize: 12 }}>{err}</div>}
            </div>
        </Sheet>
    );
}
