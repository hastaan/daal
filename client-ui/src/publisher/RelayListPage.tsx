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
// One deliberate omission: there is NO health indicator. The mgmt plane
// has no health or ping verb (cli_bridge.rs's CliRunner trait exposes
// none), so a green dot here would be a guess dressed as a fact. The
// chip reports lifecycle only and its subtitle says so.

import { useCallback, useEffect, useState } from 'react';
import { Wizard } from './wizardCommands';
import type { OperatorSummary } from './wizardCommands';
import { Card, Button, Input, Section, StatusPill } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    /** Open relay detail (provisioned relays only). */
    onOpen: (operatorId: number) => void;
    /** Start a brand-new relay in the wizard. */
    onNew: () => void;
    /** Re-enter the wizard for a half-built relay. */
    onResume: (operatorId: number) => void;
}

function dateLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 10);
    } catch {
        return '';
    }
}

type Tone = 'good' | 'warn' | 'bad' | 'neutral' | 'gold';

function statusTone(status: string): Tone {
    switch (status) {
        case 'provisioned':
            return 'good';
        case 'pre-provision':
            return 'gold';
        case 'decommissioned':
            return 'neutral';
        default:
            return 'neutral';
    }
}

function statusKey(status: string): string {
    switch (status) {
        case 'provisioned':
            return 'pub.relays.status.provisioned';
        case 'pre-provision':
            return 'pub.relays.status.pre_provision';
        case 'decommissioned':
            return 'pub.relays.status.decommissioned';
        default:
            return 'pub.relays.status.unknown';
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

export default function RelayListPage({ t, onOpen, onNew, onResume }: Props) {
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Inline rename: id being renamed + the draft text.
    const [renamingId, setRenamingId] = useState<number | null>(null);
    const [draftName, setDraftName] = useState('');
    const [renameBusy, setRenameBusy] = useState(false);

    const [busyId, setBusyId] = useState<number | null>(null);

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
            setError(String(e));
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        void reload();
    }, [reload]);

    const commitRename = useCallback(
        async (op: OperatorSummary) => {
            setRenameBusy(true);
            try {
                await Wizard.setOperatorNickname(op.id, draftName.trim());
                setRenamingId(null);
                setDraftName('');
                await reload();
            } catch (e) {
                setError(String(e));
            } finally {
                setRenameBusy(false);
            }
        },
        [draftName, reload],
    );

    const onDecommission = useCallback(
        async (op: OperatorSummary) => {
            const name = relayTitle(op);
            // The confirm names the server the app is about to lose the
            // ability to reach. `cancelAndCleanup` erases the cloud
            // token and the signing key along with the row, so after
            // this the IP printed here is the only thread back to a box
            // that keeps running and keeps billing.
            const where = op.public_ip || op.public_ipv6 || op.server_id || '—';
            if (
                !window.confirm(
                    t('pub.relays.decommission.confirm')
                        .replace('{name}', name)
                        .replace('{ip}', where),
                )
            ) {
                return;
            }
            setBusyId(op.id);
            try {
                await Wizard.cancelAndCleanup(op.id);
                await reload();
            } catch (e) {
                setError(String(e));
            } finally {
                setBusyId(null);
            }
        },
        [reload, t],
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
                {error && (
                    <div
                        style={{
                            color: 'var(--red)',
                            fontSize: 12,
                            padding: '6px 4px',
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
                                                <StatusPill
                                                    tone={statusTone(op.status)}
                                                >
                                                    {t(statusKey(op.status))}
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

                                    {/* The chip above is lifecycle, not
                                        health — say it out loud rather than
                                        letting a green dot imply an uptime
                                        check nobody performed. */}
                                    <div
                                        style={{
                                            ...META,
                                            color: 'var(--dim)',
                                            fontStyle: 'italic',
                                        }}
                                    >
                                        {t('pub.relays.status.disclaimer')}
                                    </div>

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
                                                <Button
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        void commitRename(op);
                                                    }}
                                                    disabled={renameBusy}
                                                >
                                                    {t('common.save')}
                                                </Button>
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
                                                        {t('pub.relays.resume')}
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
                                                            void onDecommission(op);
                                                        }}
                                                        disabled={busyId === op.id}
                                                    >
                                                        {busyId === op.id
                                                            ? t(
                                                                  'pub.relays.decommissioning',
                                                              )
                                                            : t(
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
        </div>
    );
}
