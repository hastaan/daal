// AddressSwap — Wave 3 Step 9, the rotation ladder's L3 rung, given a
// screen for the first time.
//
// WHY IT HAD NONE UNTIL NOW
//
// L3 replaces the internet address a relay answers on by re-pointing a
// reserved ("floating") IP. It is the rung that attacks the failure
// mode that actually kills a relay — an address-level block — and it is
// the only rung that finishes in seconds instead of minutes, because
// nothing is rebuilt.
//
// It was unreachable from the UI, and the reason is instructive: the
// command needed `new_floating_ip_id`, a numeric id issued by the cloud
// provider, and no screen ever asked for one. A publisher could not
// have guessed it.
//
// THE FIRST VERSION OF THIS FILE THEN RE-CREATED THE PROBLEM, and it is
// worth writing down because the mistake is subtle and it disabled the
// whole wave. It gated the rung on `currentFloatingIpId !== ''` and
// pre-filled the field with that same id. Both halves were wrong for
// the same reason: before Step 9 nothing in the repo could MINT a
// floating IP, so no relay in the field has one, so the gate disabled
// L3 on 100% of relays — and on the few where it did open, the default
// action was to re-attach the address the relay was already on, which
// completes, reports a successful rotation, writes a history row and
// publishes a freshness document while the relay stays on the burned
// address. The whole point of Step 9 is that an empty id now means
// "reserve one for this relay", so availability is a property of the
// PROVIDER ADAPTER (`can_reserve_address`), not of what happens to be
// attached today, and the field starts empty.
//
// THE THING THE OPERATOR MUST BE TOLD, AND THE REASON THIS FILE EXISTS
//
// Swapping the address invalidates nothing about anyone's keys, and the
// server keeps running — but every file already handed out names the
// OLD address. What happens next depends entirely on whether those
// files carry refresh addresses:
//
//   * they do  → the apps find the new address themselves. Not
//     instantly, and NOT while someone's tunnel is up: Daal refuses to
//     fetch new settings through the tunnel it is trying to repair
//     (Wave 1's fail-closed rule), so a recipient who is still
//     connected on the old address follows only once that connection
//     drops. Saying "instant" here would be a lie with a support
//     ticket attached.
//   * they do not → nothing tells them. Every file dies at the moment
//     the swap completes and each one has to be rebuilt and delivered
//     by hand.
//
// The confirm sheet branches on `mirrorsInPack`, which comes from the
// SIGNED PACK and not from what the publisher has configured — see
// FreshnessPanel's header for why those are different questions.

import { useState } from 'react';
import { Wizard } from './wizardCommands';
import type { RotateExecuteOutput } from './wizardCommands';
import { ListRow, Button, Sheet, Input } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    relayLabel: string;
    /** Provider-side id of the floating IP already attached, or "" when
     *  the relay has none. Read from the operator record — never typed
     *  by a human, never invented.
     *
     *  Used to SHOW which address the relay is on and to refuse a
     *  re-attach of it. NOT an availability gate: see `canReserve`. */
    currentFloatingIpId: string;
    /** Whether this relay's provider adapter can reserve an address on
     *  its own. When true, leaving the field empty is a valid answer
     *  and the rung is available on a relay that has never had an
     *  address — which is every relay provisioned before this wave. */
    canReserve: boolean;
    /** How many refresh addresses are inside the pack recipients hold.
     *  Zero means this swap ends in hand-delivery. */
    mirrorsInPack: number;
    /** How many people are holding a file from this relay. */
    liveRecipients: number;
    disabled?: boolean;
    /** Called after a successful swap so the parent can re-read the
     *  relay (the address it displays has just changed). */
    onDone: () => void;
}

const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--fg)',
    lineHeight: 1.55,
};
const LABEL: React.CSSProperties = { fontSize: 12, color: 'var(--muted)' };

export function AddressSwap({
    t,
    operatorId,
    relayLabel,
    currentFloatingIpId,
    canReserve,
    mirrorsInPack,
    liveRecipients,
    disabled,
    onDone,
}: Props) {
    const [open, setOpen] = useState(false);
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const [done, setDone] = useState<RotateExecuteOutput | null>(null);
    // Starts EMPTY, never pre-filled with the current id. A pre-filled
    // field makes "press the confirm button" mean "re-attach the
    // address you are already on", which is a no-op the system used to
    // report as a successful rotation.
    const [fipId, setFipId] = useState('');
    const [reason, setReason] = useState('');

    // Available when the adapter can mint an address, or when one is
    // already attached and can be swapped for another. Gating on the
    // attached id alone disabled the rung on every relay in the field.
    const available = canReserve || currentFloatingIpId !== '';
    // Re-attaching the same address changes nothing a censor can see.
    // The wizard refuses it and the CLI's post-condition would catch it
    // anyway; saying so before the press is cheaper than either.
    const isNoOp = fipId.trim() !== '' && fipId.trim() === currentFloatingIpId;
    // An empty field is a valid answer only where the adapter can
    // reserve. Elsewhere the operator has to supply an id they reserved
    // in the provider console.
    const canSubmit = !isNoOp && (canReserve || fipId.trim() !== '');

    const run = async () => {
        setBusy(true);
        setErr(null);
        try {
            const out = await Wizard.rotateExecute(
                operatorId,
                'L3',
                reason.trim() || 'address blocked',
                // Empty means "reserve one" — the self-service path.
                // Sending an empty string rather than omitting it keeps
                // the boundary explicit; the Rust side trims either way.
                { newFloatingIpId: fipId.trim() },
            );
            setDone(out);
            setOpen(false);
            onDone();
        } catch (e) {
            setErr(String(e));
        } finally {
            setBusy(false);
        }
    };

    return (
        <>
            <ListRow
                title={t('pub.danger.address.title')}
                subtitle={
                    available
                        ? t('pub.danger.address.body')
                        : t('pub.danger.address.unavailable')
                }
                trailing={
                    <Button
                        variant="danger"
                        onClick={(e) => {
                            e.stopPropagation();
                            setErr(null);
                            setOpen(true);
                        }}
                        // Not hidden when unavailable: a rung the
                        // operator cannot see is a rung they will never
                        // learn exists. It is shown, disabled, with the
                        // subtitle explaining what to go and do.
                        disabled={disabled || busy || !available}
                    >
                        {t('pub.danger.address.action')}
                    </Button>
                }
            />

            {open && (
                <Sheet
                    title={t('pub.danger.address.confirm.title').replace(
                        '{relay}',
                        relayLabel,
                    )}
                    onClose={() => {
                        if (!busy) setOpen(false);
                    }}
                    width={560}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() => setOpen(false)}
                                disabled={busy}
                            >
                                {t('common.cancel')}
                            </Button>
                            <Button
                                variant="danger"
                                onClick={() => void run()}
                                disabled={busy || !canSubmit}
                            >
                                {busy
                                    ? t('pub.danger.address.working')
                                    : t('pub.danger.address.confirm.action')}
                            </Button>
                        </span>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div style={BODY}>{t('pub.danger.address.confirm.body')}</div>

                        {/* The consequence for people who have not
                            refreshed yet. This is the whole point of the
                            sheet and it branches on the signed pack. */}
                        <div style={BODY}>
                            {mirrorsInPack > 0
                                ? t('pub.danger.address.confirm.self_heal')
                                : t('pub.danger.address.confirm.no_self_heal')}
                        </div>

                        <div style={BODY}>
                            {liveRecipients === 0
                                ? t('pub.danger.address.confirm.count_none')
                                : t('pub.danger.address.confirm.count').replace(
                                      '{count}',
                                      String(liveRecipients),
                                  )}
                        </div>

                        <div style={BODY}>{t('pub.danger.address.confirm.old_ip')}</div>

                        <label style={LABEL}>{t('pub.danger.address.field.fip')}</label>
                        <Input
                            value={fipId}
                            onChange={(e) => setFipId(e.target.value)}
                            style={{ fontFamily: 'var(--font-mono)' }}
                        />
                        <div style={{ ...BODY, color: 'var(--muted)' }}>
                            {canReserve
                                ? t('pub.danger.address.field.fip_help')
                                : t('pub.danger.address.field.fip_help_manual')}
                        </div>
                        {isNoOp && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>
                                {t('pub.danger.address.field.fip_same')}
                            </div>
                        )}

                        <label style={LABEL}>{t('pub.danger.address.field.reason')}</label>
                        <Input
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                        />

                        {err && (
                            <div style={{ color: 'var(--red)', fontSize: 12 }}>{err}</div>
                        )}
                    </div>
                </Sheet>
            )}

            {done && (
                <Sheet
                    title={t('pub.danger.address.done.title')}
                    onClose={() => setDone(null)}
                    width={520}
                    footer={
                        <Button onClick={() => setDone(null)}>{t('common.close')}</Button>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div style={BODY}>{t('pub.danger.address.done.body')}</div>
                        <div style={BODY}>
                            {mirrorsInPack > 0
                                ? t('pub.danger.address.done.self_heal')
                                : t('pub.danger.address.done.no_self_heal')}
                        </div>
                        {/* The success copy above says the old address no
                            longer serves. That is only true once the
                            previous reservation has been released, and
                            that leg runs after the commit and can fail on
                            its own. When it does, the truth goes here
                            rather than the screen asserting the opposite. */}
                        {(done.warnings ?? []).length > 0 && (
                            <div style={{ display: 'grid', gap: 6 }}>
                                <div style={{ ...BODY, color: 'var(--red)' }}>
                                    {t('pub.danger.address.done.warnings')}
                                </div>
                                {(done.warnings ?? []).map((w, i) => (
                                    <div
                                        key={i}
                                        style={{ ...BODY, color: 'var(--muted)', fontSize: 12 }}
                                    >
                                        {w}
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </Sheet>
            )}
        </>
    );
}
