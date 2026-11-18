// RelayRebuild — L4 (different datacentre), L5 (different hosting
// company) and L6 (different set of ways in): the three rungs of the
// rotation ladder that had no caller.
//
// WHY THEY SHARE ONE FILE AND ONE CONFIRM SHEET
//
// They differ only in what they put into the rebuild. Everything the
// operator has to be told is identical, because all three do the same
// thing to the relay: `reprovision` DELETES the server
// (hetzner/provider.go:475 — it deliberately does not re-create) and
// `provision` then builds a different one. New address, new mgmt pin,
// new keys, and every .sbp ever handed out dead. Writing that warning
// twice is how the two copies drift until one of them is comforting.
//
// HOW THIS IS NOT AddressSwap, AND WHY THE SHEET IS STRONGER
//
// L3 keeps the box. Its sheet can honestly say "the server keeps
// running, nobody's key changes, and it takes a few seconds", and its
// worst case is an address left billing that the success sheet names.
// A press here is not recoverable by pressing anything:
//
//   * The server is gone. `rotate_revert` (commands.rs:3185) only flips
//     which row of this relay's signed-pack history is marked active —
//     after a rebuild that row names a server that no longer exists.
//   * The old box is deleted BEFORE the new one is built, so a failure
//     in the second half leaves the operator with no relay at all.
//   * It costs money, and a failure can leave orphans on the account.
//
// So the sheet is two steps and the second one asks the operator to
// type the relay's name. That is deliberately the gesture people
// already know from every irreversible delete they have met, and it is
// the cheapest thing that cannot be satisfied by muscle memory on a
// red button sitting three rows below a button that is safe.
//
// WHAT THIS SCREEN REFUSES, AND WHY THE WIZARD'S OWN REFUSALS ARE NOT
// ENOUGH
//
// The wizard refuses an L4 with no new region and an L6 onto the
// profile the relay is already on (commands.rs:2536/2559), before the
// provider is touched. Both are correct and both are narrower than
// "this rung would change nothing":
//
//   * L4 into a region that does not offer this relay's server type is
//     accepted by every check and fails at `provision` — with the old
//     box already deleted. This screen asks the provider what the
//     target region actually offers, before the press.
//   * L6 onto a DIFFERENT profile that yields the SAME family set is
//     accepted by every check and rebuilds an identical wire shape at
//     a new address, for the price of everyone's file. See
//     rebuildPlan.ts for why intersection means this rung can only
//     ever remove a family, never add one.
//
//   * L5 to a destination that cannot build this relay. Every one of
//     its four inputs is a value this relay has never used, on an
//     account Daal has never talked to, and a wrong one is not found
//     until the create leg — after the delete leg. So the sheet asks
//     the destination account what it actually sells, with the
//     credential the operator just typed, before the button arms.
//
// Both refusals disable the button and say which one fired, rather
// than letting the operator find out from an error after the relay is
// gone.
//
// WHY L5 IS HERE AND NOT IN A FILE OF ITS OWN
//
// It was deferred for one wave with a written reason: L5 is the only
// rotation that needs TWO cloud credentials live at once — one to
// delete on the provider being left, one to create on the one being
// joined — and an operator row stores exactly one. That is a custody
// question, not a layout question, and the answer is what the sheet
// had to be built around:
//
//   THE SECOND CREDENTIAL IS NEVER STORED BY THIS SCREEN. It is held
//   in component state for the life of the sheet, sent to a read-only
//   catalogue lookup, and passed to the rotation. Daal takes custody of
//   it exactly once — in the L5 arm of `rotate_execute`, AFTER
//   `provision` has returned a live server (commands.rs, `custody_put`
//   then `update_token_alias` then `set_cloud_provider`). Storing it
//   earlier would leave the operator row holding a credential for a
//   relay that may not exist, on a row that still names the old
//   provider: the exact shape that strands a paid box.
//
//   Closing the sheet drops it. There is no draft, no retry buffer and
//   no keystore entry, so an abandoned L5 leaves nothing behind.

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Wizard } from './wizardCommands';
import type { RotateExecuteOutput, ServerTypeOption } from './wizardCommands';
import { ListRow, Button, Sheet, Input } from '../design/primitives';
import {
    EST_WALLCLOCK,
    TOOLBOX_PROFILES,
    planProfileChange,
    planProviderChange,
    planRegionChange,
    profileBySlug,
    rebuildDestinations,
    regionsFor,
    serverTypeAvailable,
    formatPlanPrice,
} from './rebuildPlan';

export type RebuildLevel = 'L4' | 'L5' | 'L6';

interface Props {
    t: (k: string) => string;
    operatorId: number;
    /** Shown in the sheet's title. */
    relayLabel: string;
    /** What the operator must TYPE to arm the second step. The relay's
     *  own name — nickname when it has one, otherwise the derived
     *  daal-relay-<id> every filename already uses — so it is a string
     *  they have seen, not a ceremony phrase. */
    confirmPhrase: string;
    provider: string;
    currentRegion: string;
    /** The size of box this relay runs on. The target region has to
     *  offer it or the rebuild's second half fails with the first half
     *  already done. */
    serverType: string;
    currentProfile: string;
    /** The families this relay serves today, exactly as
     *  `rotation_families` will compute them for the rebuild. */
    servedFamilies: string[];
    /** How many refresh addresses are inside the pack recipients hold.
     *  Zero means this rebuild ends in hand-delivery. */
    mirrorsInPack: number;
    liveRecipients: number;
    disabled?: boolean;
    /** The page's shared mgmt-call wrapper — same one L3 uses. Both
     *  rungs re-run cloud-init firewall allowlisting for this device's
     *  address, so they fail in the helper-IP ways every other
     *  box-touching action fails and need the page's classification
     *  rather than String(e) in front of a Farsi-speaking operator. */
    runMgmt: (
        fn: () => Promise<void>,
        setErr: (s: string | null) => void,
    ) => Promise<boolean>;
    onDone: () => void;
}

const BODY: React.CSSProperties = {
    fontSize: 13,
    color: 'var(--fg)',
    lineHeight: 1.55,
};
const LABEL: React.CSSProperties = { fontSize: 12, color: 'var(--muted)' };
const BAD: React.CSSProperties = { fontSize: 12, color: 'var(--red)', lineHeight: 1.5 };
const MUTED: React.CSSProperties = { ...BODY, color: 'var(--muted)', fontSize: 12 };
const MONO: React.CSSProperties = { fontFamily: 'var(--font-mono)' };

/** The reason recorded against the rotation when the operator leaves
 *  the field blank. It lands in the relay's own history, so it says
 *  what was done rather than "rotation". */
const DEFAULT_REASON: Record<RebuildLevel, string> = {
    L4: 'datacentre blocked',
    L5: 'hosting company blocked',
    L6: 'protocol mix burned',
};

function fmt(s: string, args: Record<string, string | number>): string {
    return s.replace(/\{(\w+)\}/g, (_, k) =>
        args[k] !== undefined ? String(args[k]) : `{${k}}`,
    );
}

/** A region's human name, or the provider's own code when this build
 *  has no name for it.
 *
 *  `translate` returns the KEY when it misses, so a relay sitting in a
 *  region the mirror does not carry would otherwise print
 *  "pub.danger.rebuild.region.name.xyz" inside a sentence. The code is
 *  ugly and correct; the key is neither. Reachable because the region
 *  the relay is IN comes from its record, not from the list this
 *  screen offers. */
function regionName(t: (k: string) => string, code: string): string {
    if (!code) return '';
    const key = `pub.danger.rebuild.region.name.${code}`;
    const name = t(key);
    return name === key ? code : name;
}

/** One pickable option. Not a <select>: each choice here carries a
 *  consequence, and a consequence the operator has to open a dropdown
 *  to read is a consequence they will not read. */
function OptionRow({
    label,
    detail,
    selected,
    disabled,
    onPick,
}: {
    label: string;
    detail?: string;
    selected: boolean;
    disabled?: boolean;
    onPick: () => void;
}) {
    return (
        <button
            type="button"
            onClick={onPick}
            disabled={disabled}
            aria-pressed={selected}
            style={{
                display: 'block',
                width: '100%',
                textAlign: 'start',
                padding: '8px 10px',
                borderRadius: 'var(--radius-md)',
                border: `1px solid ${selected ? 'var(--gold-warm)' : 'var(--line)'}`,
                background: selected ? 'var(--surface-2)' : 'transparent',
                color: 'var(--fg)',
                cursor: disabled ? 'default' : 'pointer',
                opacity: disabled ? 0.5 : 1,
            }}
        >
            <span style={{ fontSize: 13 }}>{label}</span>
            {detail && (
                <span style={{ display: 'block', ...MUTED, marginTop: 2 }}>{detail}</span>
            )}
        </button>
    );
}

export function RelayRebuild({
    t,
    operatorId,
    relayLabel,
    confirmPhrase,
    provider,
    currentRegion,
    serverType,
    currentProfile,
    servedFamilies,
    mirrorsInPack,
    liveRecipients,
    disabled,
    runMgmt,
    onDone,
}: Props) {
    const [mode, setMode] = useState<RebuildLevel | null>(null);
    const [step, setStep] = useState<'choose' | 'confirm'>('choose');
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const [done, setDone] = useState<RotateExecuteOutput | null>(null);

    const [region, setRegion] = useState('');
    const [profile, setProfile] = useState('');
    const [reason, setReason] = useState('');
    const [typed, setTyped] = useState('');

    // L5's four inputs. `destToken` is the second cloud credential and
    // it lives HERE and nowhere else: no draft, no keystore, no
    // database. `close()` clears it, so an abandoned sheet leaves Daal
    // holding nothing. It reaches disk only if the rebuild succeeds,
    // and then it is the backend that stores it.
    const [destProvider, setDestProvider] = useState('');
    const [destToken, setDestToken] = useState('');
    const [destType, setDestType] = useState('');

    // The live answer to "can the target region build this box?".
    // `null` = not asked yet or the ask failed, and that is NOT a yes:
    // the old server is deleted first, so an optimistic default here
    // is a relay that stops existing.
    const [types, setTypes] = useState<ServerTypeOption[] | null>(null);
    const [typesBusy, setTypesBusy] = useState(false);
    // Bumped to re-ask. Without it the only way to retry a failed
    // lookup is to pick a different region and come back, because the
    // effect keys on the region and the region did not change — and
    // "ask again" is the ONLY repair for the one state that blocks the
    // rung, so leaving it unreachable would make a transient network
    // failure look like a permanently unavailable rung.
    const [probeTick, setProbeTick] = useState(0);

    const regions = useMemo(() => regionsFor(provider), [provider]);
    const regionAvailable = regions.length > 0;

    // L5's destinations: every live provider except the one the relay
    // is already on. Empty means this build has no second cloud, and
    // the row says so instead of opening onto an empty list.
    const destinations = useMemo(() => rebuildDestinations(provider), [provider]);
    const providerAvailable = destinations.length > 0;
    // The region list belongs to the DESTINATION, not to the relay.
    // Region codes are provider-scoped and they collide: "fra" is
    // Vultr's Frankfurt and Stark's, and Hetzner has no such code at
    // all. Offering this relay's own region list would produce a code
    // the destination has never heard of.
    const destRegions = useMemo(() => regionsFor(destProvider), [destProvider]);
    const providerPlan = useMemo(
        () => planProviderChange(provider, destProvider),
        [provider, destProvider],
    );

    const regionPlan = useMemo(
        () => planRegionChange(provider, currentRegion, region),
        [provider, currentRegion, region],
    );
    const targetProfile = profile ? profileBySlug(profile) : undefined;
    const profilePlan = useMemo(
        () => (targetProfile ? planProfileChange(servedFamilies, targetProfile) : null),
        [servedFamilies, targetProfile],
    );
    // L4 keeps this relay's plan; L5 picks one from the destination's
    // own catalogue, because plan ids are provider-scoped ("cx22" is
    // Hetzner's, Vultr sells "vc2-1c-1gb").
    const typeOk = serverTypeAvailable(types, mode === 'L5' ? destType : serverType);

    // WHICH ACCOUNT THE CATALOGUE QUESTION GOES TO.
    //
    // L5's destination is an account Daal has never talked to, so there
    // is no stored credential to ask with and no stored provider to ask
    // on. It is a different command taking all three explicitly.
    //
    // Not fired on every keystroke. A token is typed one character at a
    // time and a partial one is a failed authentication; sending those
    // to a live API is how an account gets rate-limited before the
    // operator has finished typing. The operator asks explicitly, and
    // any edit to the tuple invalidates the answer.
    const [l5Probe, setL5Probe] = useState<{
        p: string;
        r: string;
        t: string;
    } | null>(null);
    useEffect(() => {
        if (mode !== 'L5') return;
        // An edit after a lookup must not leave the previous
        // catalogue on screen: it is the thing that arms the button,
        // and a catalogue for a different account is a yes to a
        // question nobody asked.
        setTypes(null);
        setDestType('');
        setL5Probe(null);
    }, [mode, destProvider, region, destToken]);

    // Ask the provider what the chosen region offers. This is the one
    // network call the sheet makes before the destructive one, and it
    // is the difference between "the rebuild failed" and "the rebuild
    // failed after the old relay was deleted".
    useEffect(() => {
        if (mode === 'L5') {
            if (!l5Probe) return;
            let alive = true;
            setTypes(null);
            setTypesBusy(true);
            (async () => {
                try {
                    const list = await Wizard.listServerTypesFor(
                        l5Probe.p,
                        l5Probe.r,
                        l5Probe.t,
                    );
                    if (alive) setTypes(list);
                } catch (e) {
                    // The provider's own words. A 401 here is the
                    // single most useful thing this sheet can say, and
                    // it is free — the alternative is finding out from
                    // the create leg, after the delete leg.
                    if (alive) {
                        setTypes(null);
                        setErr(String(e));
                    }
                } finally {
                    if (alive) setTypesBusy(false);
                }
            })();
            return () => {
                alive = false;
            };
        }
        if (mode !== 'L4' || region === '' || region === currentRegion) {
            setTypes(null);
            return;
        }
        let alive = true;
        setTypes(null);
        setTypesBusy(true);
        (async () => {
            try {
                const list = await Wizard.listServerTypes(operatorId, region);
                if (alive) setTypes(list);
            } catch {
                // Left at null on purpose: an unanswered question must
                // read as unanswered, never as a yes.
                if (alive) setTypes(null);
            } finally {
                if (alive) setTypesBusy(false);
            }
        })();
        return () => {
            alive = false;
        };
    }, [mode, region, currentRegion, operatorId, probeTick, l5Probe]);

    const canContinue =
        mode === 'L4'
            ? region !== '' && !regionPlan.isSameRegion && typeOk === true
            : mode === 'L5'
              ? destProvider !== '' &&
                !providerPlan.isSameProvider &&
                providerPlan.isKnownProvider &&
                region !== '' &&
                destToken.trim() !== '' &&
                destType !== '' &&
                // The catalogue must have ANSWERED, and must contain
                // the plan being asked for. `typeOk === null` is an
                // unasked or failed question, and treating it as a yes
                // is what deletes a relay it cannot rebuild.
                typeOk === true
              : profile !== '' &&
                profile !== currentProfile &&
                profilePlan !== null &&
                !profilePlan.noWireChange &&
                // A profile change that leaves NOTHING is not a
                // narrower relay, it is a rebuild that fails after the
                // delete: `CandidatesForProfile` returns "yields no
                // candidates" and the box is already gone. Not
                // reachable through today's wizard (every relay carries
                // iran-default's four defaults), and one family picker
                // away from being reachable.
                profilePlan.after.length > 0;

    const armed = typed.trim() === confirmPhrase.trim();

    const close = useCallback(() => {
        if (busy) return;
        setMode(null);
        setStep('choose');
        setRegion('');
        setProfile('');
        setReason('');
        setTyped('');
        setTypes(null);
        setErr(null);
        // THE SECOND CLOUD CREDENTIAL DIES WITH THE SHEET. It was never
        // written anywhere else, so this is the whole of forgetting it.
        setDestProvider('');
        setDestToken('');
        setDestType('');
        setL5Probe(null);
    }, [busy]);

    const open = (m: RebuildLevel) => {
        setErr(null);
        setStep('choose');
        setRegion('');
        setProfile('');
        setTyped('');
        setTypes(null);
        setDestProvider('');
        setDestToken('');
        setDestType('');
        setL5Probe(null);
        setMode(m);
    };

    const run = async () => {
        if (!mode || !armed) return;
        setBusy(true);
        const out: { v: RotateExecuteOutput | null } = { v: null };
        const ok = await runMgmt(async () => {
            out.v = await Wizard.rotateExecute(
                operatorId,
                mode,
                reason.trim() || DEFAULT_REASON[mode],
                mode === 'L4'
                    ? { newRegion: region }
                    : mode === 'L5'
                      ? {
                            newProvider: destProvider,
                            newRegion: region,
                            newServerType: destType,
                            // Passed, not stored. The backend takes
                            // custody only after the replacement relay
                            // exists.
                            newProviderToken: destToken.trim(),
                        }
                      : { newToolboxProfile: profile },
            );
        }, setErr);
        setBusy(false);
        if (ok && out.v) {
            setDone(out.v);
            setMode(null);
            setStep('choose');
            setTyped('');
            // Drop the credential from the component the moment it is
            // no longer needed. On success the backend has already
            // taken custody of it; on any other path it was never
            // stored at all.
            setDestToken('');
            setDestProvider('');
            setDestType('');
            setL5Probe(null);
            onDone();
        }
    };

    const est = mode ? EST_WALLCLOCK[mode] : EST_WALLCLOCK.L4;

    return (
        <>
            <ListRow
                title={t('pub.danger.rebuild.region.title')}
                subtitle={
                    regionAvailable
                        ? t('pub.danger.rebuild.region.body')
                        : t('pub.danger.rebuild.region.unavailable')
                }
                trailing={
                    <Button
                        variant="danger"
                        onClick={(e) => {
                            e.stopPropagation();
                            open('L4');
                        }}
                        // Shown disabled rather than hidden, for the
                        // same reason L3 is: a rung nobody can see is a
                        // rung nobody learns exists, and the subtitle
                        // says what to do instead.
                        disabled={disabled || busy || !regionAvailable}
                    >
                        {t('pub.danger.rebuild.region.action')}
                    </Button>
                }
            />
            <ListRow
                title={t('pub.danger.rebuild.provider.title')}
                subtitle={
                    providerAvailable
                        ? t('pub.danger.rebuild.provider.body')
                        : t('pub.danger.rebuild.provider.unavailable')
                }
                trailing={
                    <Button
                        variant="danger"
                        onClick={(e) => {
                            e.stopPropagation();
                            open('L5');
                        }}
                        disabled={disabled || busy || !providerAvailable}
                    >
                        {t('pub.danger.rebuild.provider.action')}
                    </Button>
                }
            />
            <ListRow
                title={t('pub.danger.rebuild.profile.title')}
                subtitle={t('pub.danger.rebuild.profile.body')}
                trailing={
                    <Button
                        variant="danger"
                        onClick={(e) => {
                            e.stopPropagation();
                            open('L6');
                        }}
                        disabled={disabled || busy}
                    >
                        {t('pub.danger.rebuild.profile.action')}
                    </Button>
                }
            />

            {mode && (
                <Sheet
                    title={fmt(t('pub.danger.rebuild.confirm.title'), {
                        relay: relayLabel,
                    })}
                    onClose={close}
                    width={580}
                    footer={
                        <span style={{ display: 'inline-flex', gap: 8 }}>
                            <Button
                                variant="ghost"
                                onClick={() =>
                                    step === 'choose' ? close() : setStep('choose')
                                }
                                disabled={busy}
                            >
                                {step === 'choose'
                                    ? t('common.cancel')
                                    : t('pub.danger.rebuild.confirm.back')}
                            </Button>
                            {step === 'choose' ? (
                                <Button
                                    variant="danger"
                                    onClick={() => setStep('confirm')}
                                    disabled={!canContinue}
                                >
                                    {t('pub.danger.rebuild.confirm.next')}
                                </Button>
                            ) : (
                                <Button
                                    variant="danger"
                                    onClick={() => void run()}
                                    disabled={busy || !armed}
                                >
                                    {busy
                                        ? t('pub.danger.rebuild.working')
                                        : t('pub.danger.rebuild.go')}
                                </Button>
                            )}
                        </span>
                    }
                >
                    {step === 'choose' ? (
                        <div style={{ display: 'grid', gap: 10 }}>
                            {mode === 'L4' ? (
                                <>
                                    <label style={LABEL}>
                                        {t('pub.danger.rebuild.region.field')}
                                    </label>
                                    <div style={{ display: 'grid', gap: 6 }}>
                                        {regions.map((r) => (
                                            <OptionRow
                                                key={r.code}
                                                label={regionName(t, r.code)}
                                                detail={t(
                                                    `pub.danger.rebuild.zone.${r.zone}`,
                                                )}
                                                selected={region === r.code}
                                                // The relay's own region
                                                // is offered but dead:
                                                // seeing where you are
                                                // is what makes the
                                                // other rows a choice.
                                                disabled={r.code === currentRegion}
                                                onPick={() => setRegion(r.code)}
                                            />
                                        ))}
                                    </div>
                                    {region !== '' && !regionPlan.isSameRegion && (
                                        <div style={BODY}>
                                            {regionPlan.isSameZone
                                                ? fmt(
                                                      t(
                                                          'pub.danger.rebuild.region.same_zone',
                                                      ),
                                                      {
                                                          from: regionName(
                                                              t,
                                                              currentRegion,
                                                          ),
                                                          to: regionName(t, region),
                                                      },
                                                  )
                                                : fmt(
                                                      t(
                                                          'pub.danger.rebuild.region.other_zone',
                                                      ),
                                                      {
                                                          from: regionName(
                                                              t,
                                                              currentRegion,
                                                          ),
                                                          to: regionName(t, region),
                                                          zone_from: regionPlan.zoneFrom
                                                              ? t(
                                                                    `pub.danger.rebuild.zone.${regionPlan.zoneFrom}`,
                                                                )
                                                              : '',
                                                          zone_to: regionPlan.zoneTo
                                                              ? t(
                                                                    `pub.danger.rebuild.zone.${regionPlan.zoneTo}`,
                                                                )
                                                              : '',
                                                      },
                                                  )}
                                        </div>
                                    )}
                                    {/* The pre-flight. Never collapsed
                                        into "ready": an unanswered
                                        question and a yes are different
                                        answers here. */}
                                    {region !== '' && !regionPlan.isSameRegion && (
                                        <div
                                            style={
                                                typesBusy || typeOk === true
                                                    ? MUTED
                                                    : BAD
                                            }
                                        >
                                            {typesBusy
                                                ? fmt(
                                                      t(
                                                          'pub.danger.rebuild.region.checking',
                                                      ),
                                                      { region: regionName(t, region) },
                                                  )
                                                : typeOk === true
                                                  ? fmt(
                                                        t(
                                                            'pub.danger.rebuild.region.type_ok',
                                                        ),
                                                        {
                                                            region: regionName(t, region),
                                                            type: serverType,
                                                        },
                                                    )
                                                  : typeOk === false
                                                    ? fmt(
                                                          t(
                                                              'pub.danger.rebuild.region.type_missing',
                                                          ),
                                                          {
                                                              region: regionName(
                                                                  t,
                                                                  region,
                                                              ),
                                                              type: serverType,
                                                          },
                                                      )
                                                    : fmt(
                                                          t(
                                                              'pub.danger.rebuild.region.type_unknown',
                                                          ),
                                                          {
                                                              region: regionName(
                                                                  t,
                                                                  region,
                                                              ),
                                                          },
                                                      )}
                                        </div>
                                    )}
                                    {!typesBusy &&
                                        region !== '' &&
                                        !regionPlan.isSameRegion &&
                                        typeOk === null && (
                                            <span>
                                                <Button
                                                    variant="secondary"
                                                    onClick={() =>
                                                        setProbeTick((n) => n + 1)
                                                    }
                                                >
                                                    {t('pub.danger.rebuild.region.retry')}
                                                </Button>
                                            </span>
                                        )}
                                </>
                            ) : mode === 'L5' ? (
                                <>
                                    {/* THE DESTINATION. Four fields,
                                        in the order they depend on each
                                        other: the company, then the
                                        credential for it, then a
                                        datacentre it has, then a size
                                        it sells there. Each one is
                                        meaningless without the one
                                        above it, and the last two
                                        cannot be answered at all
                                        without asking that account. */}
                                    <label style={LABEL}>
                                        {t('pub.danger.rebuild.provider.field')}
                                    </label>
                                    <div style={{ display: 'grid', gap: 6 }}>
                                        {destinations.map((d) => (
                                            <OptionRow
                                                key={d}
                                                label={t(
                                                    `pub.danger.rebuild.provider.name.${d}`,
                                                )}
                                                detail={t(
                                                    `pub.danger.rebuild.provider.where.${d}`,
                                                )}
                                                selected={destProvider === d}
                                                onPick={() => {
                                                    setDestProvider(d);
                                                    setRegion('');
                                                }}
                                            />
                                        ))}
                                    </div>
                                    {/* Said before the credential is
                                        asked for, not after: the
                                        operator is about to move a
                                        relay into a different legal
                                        jurisdiction, and which one is
                                        part of the decision. */}
                                    {destProvider !== '' && (
                                        <div style={MUTED}>
                                            {t(
                                                `pub.danger.rebuild.provider.jurisdiction.${destProvider}`,
                                            )}
                                        </div>
                                    )}

                                    {destProvider !== '' && (
                                        <>
                                            <label style={LABEL}>
                                                {t(
                                                    'pub.danger.rebuild.provider.field_token',
                                                )}
                                            </label>
                                            <Input
                                                type="password"
                                                value={destToken}
                                                onChange={(e) =>
                                                    setDestToken(e.target.value)
                                                }
                                                style={MONO}
                                            />
                                            <div style={MUTED}>
                                                {t(
                                                    'pub.danger.rebuild.provider.token_help',
                                                )}
                                            </div>

                                            <label style={LABEL}>
                                                {t(
                                                    'pub.danger.rebuild.provider.field_region',
                                                )}
                                            </label>
                                            <div style={{ display: 'grid', gap: 6 }}>
                                                {destRegions.map((r) => (
                                                    <OptionRow
                                                        key={r.code}
                                                        label={regionName(t, r.code)}
                                                        detail={t(
                                                            `pub.danger.rebuild.zone.${r.zone}`,
                                                        )}
                                                        selected={region === r.code}
                                                        onPick={() => setRegion(r.code)}
                                                    />
                                                ))}
                                            </div>
                                        </>
                                    )}

                                    {/* THE ONE READ-ONLY CALL. It
                                        proves the credential
                                        authenticates on this account,
                                        that the datacentre exists in
                                        THIS company's vocabulary, and
                                        what it actually sells there.
                                        All three are otherwise learned
                                        from the create leg, which runs
                                        after the old relay has been
                                        deleted. */}
                                    {destProvider !== '' &&
                                        region !== '' &&
                                        destToken.trim() !== '' &&
                                        types === null &&
                                        !typesBusy && (
                                            <span>
                                                <Button
                                                    variant="secondary"
                                                    onClick={() =>
                                                        setL5Probe({
                                                            p: destProvider,
                                                            r: region,
                                                            t: destToken.trim(),
                                                        })
                                                    }
                                                >
                                                    {t(
                                                        'pub.danger.rebuild.provider.check',
                                                    )}
                                                </Button>
                                            </span>
                                        )}
                                    {typesBusy && (
                                        <div style={MUTED}>
                                            {t('pub.danger.rebuild.provider.checking')}
                                        </div>
                                    )}
                                    {types !== null && (
                                        <>
                                            <label style={LABEL}>
                                                {t(
                                                    'pub.danger.rebuild.provider.field_type',
                                                )}
                                            </label>
                                            {types.length === 0 ? (
                                                <div style={BAD}>
                                                    {t(
                                                        'pub.danger.rebuild.provider.type_none',
                                                    )}
                                                </div>
                                            ) : (
                                                <div
                                                    style={{
                                                        display: 'grid',
                                                        gap: 6,
                                                        maxHeight: 220,
                                                        overflowY: 'auto',
                                                    }}
                                                >
                                                    {types.map((ty) => (
                                                        <OptionRow
                                                            key={ty.id}
                                                            label={ty.id}
                                                            detail={fmt(
                                                                t(
                                                                    'pub.danger.rebuild.provider.type_detail',
                                                                ),
                                                                {
                                                                    cpus: ty.cpus,
                                                                    memory: ty.memory_gb,
                                                                    disk: ty.disk_gb,
                                                                    price: formatPlanPrice(
                                                                        ty,
                                                                    ),
                                                                },
                                                            )}
                                                            selected={destType === ty.id}
                                                            onPick={() =>
                                                                setDestType(ty.id)
                                                            }
                                                        />
                                                    ))}
                                                </div>
                                            )}
                                        </>
                                    )}

                                    {/* The cost this rung has and the
                                        others do not: a second bill,
                                        and an address on the OLD
                                        account that cannot follow. */}
                                    {destProvider !== '' && (
                                        <div style={BODY}>
                                            {fmt(
                                                t('pub.danger.rebuild.provider.two_bills'),
                                                {
                                                    from: t(
                                                        `pub.danger.rebuild.provider.name.${provider}`,
                                                    ),
                                                    to: t(
                                                        `pub.danger.rebuild.provider.name.${destProvider}`,
                                                    ),
                                                },
                                            )}
                                        </div>
                                    )}
                                </>
                            ) : (
                                <>
                                    <label style={LABEL}>
                                        {t('pub.danger.rebuild.profile.field')}
                                    </label>
                                    <div style={{ display: 'grid', gap: 6 }}>
                                        {TOOLBOX_PROFILES.map((p) => {
                                            const plan = planProfileChange(
                                                servedFamilies,
                                                p,
                                            );
                                            return (
                                                <OptionRow
                                                    key={p.slug}
                                                    label={p.slug}
                                                    detail={plan.after.join(', ')}
                                                    selected={profile === p.slug}
                                                    disabled={p.slug === currentProfile}
                                                    onPick={() => setProfile(p.slug)}
                                                />
                                            );
                                        })}
                                    </div>
                                    <div style={MUTED}>
                                        {t('pub.danger.rebuild.profile.never_adds')}
                                    </div>
                                    {profilePlan && (
                                        <>
                                            <div style={BODY}>
                                                {fmt(
                                                    t(
                                                        'pub.danger.rebuild.profile.keeps',
                                                    ),
                                                    {
                                                        families:
                                                            profilePlan.after.join(', '),
                                                    },
                                                )}
                                            </div>
                                            {profilePlan.removed.length > 0 && (
                                                <div style={BODY}>
                                                    {fmt(
                                                        t(
                                                            'pub.danger.rebuild.profile.drops',
                                                        ),
                                                        {
                                                            families:
                                                                profilePlan.removed.join(
                                                                    ', ',
                                                                ),
                                                        },
                                                    )}
                                                </div>
                                            )}
                                            {profilePlan.removedUdp.length > 0 && (
                                                <div style={MUTED}>
                                                    {t(
                                                        'pub.danger.rebuild.profile.drops_udp',
                                                    )}
                                                </div>
                                            )}
                                            {/* Only when the rebuild
                                                genuinely INTRODUCES the
                                                family. A relay that
                                                already serves anytls
                                                has already met this
                                                cost, and repeating it
                                                would be noise on the
                                                one screen that cannot
                                                afford any. */}
                                            {profilePlan.addsAnyTLS && (
                                                <div style={BAD}>
                                                    {t(
                                                        'pub.danger.rebuild.profile.anytls',
                                                    )}
                                                </div>
                                            )}
                                            {profilePlan.noWireChange && (
                                                <div style={BAD}>
                                                    {t(
                                                        'pub.danger.rebuild.profile.no_change',
                                                    )}
                                                </div>
                                            )}
                                            {/* The mirror of
                                                no_change, and the worse
                                                half. A profile that
                                                removes EVERYTHING is
                                                not a narrower relay: the
                                                rebuild deletes the box
                                                and then
                                                CandidatesForProfile
                                                refuses with "yields no
                                                candidates", leaving no
                                                relay at all. Refused
                                                here and again before
                                                the provider is touched. */}
                                            {profilePlan.after.length === 0 && (
                                                <div style={BAD}>
                                                    {t(
                                                        'pub.danger.rebuild.profile.no_families',
                                                    )}
                                                </div>
                                            )}
                                        </>
                                    )}
                                </>
                            )}
                        </div>
                    ) : (
                        <div style={{ display: 'grid', gap: 10 }}>
                            <div style={BODY}>
                                {t('pub.danger.rebuild.confirm.destroys')}
                            </div>
                            <div style={BODY}>
                                {fmt(t('pub.danger.rebuild.confirm.downtime'), { est })}
                            </div>
                            <div style={BODY}>
                                {t('pub.danger.rebuild.confirm.half_way')}
                            </div>
                            <div style={BODY}>
                                {liveRecipients === 0
                                    ? t('pub.danger.rebuild.confirm.count_none')
                                    : fmt(t('pub.danger.rebuild.confirm.count'), {
                                          count: liveRecipients,
                                      })}
                            </div>
                            {/* Branches on the SIGNED PACK, not on what
                                the publisher has configured — the same
                                distinction AddressSwap draws, and for
                                the same reason: a mirror added after
                                the last signature is not in anyone's
                                hands. */}
                            <div style={BODY}>
                                {mirrorsInPack > 0
                                    ? t('pub.danger.rebuild.confirm.by_hand_fresh')
                                    : t('pub.danger.rebuild.confirm.by_hand')}
                            </div>
                            <div style={BODY}>
                                {t('pub.danger.rebuild.confirm.no_undo')}
                            </div>

                            <label style={LABEL}>
                                {t('pub.danger.rebuild.confirm.reason')}
                            </label>
                            <Input
                                value={reason}
                                onChange={(e) => setReason(e.target.value)}
                            />

                            <label style={LABEL}>
                                {t('pub.danger.rebuild.type_name')}{' '}
                                <span style={MONO}>{confirmPhrase}</span>
                            </label>
                            <Input
                                value={typed}
                                onChange={(e) => setTyped(e.target.value)}
                                style={MONO}
                            />
                            {typed.trim() !== '' && !armed && (
                                <div style={BAD}>
                                    {t('pub.danger.rebuild.type_name_wrong')}
                                </div>
                            )}

                            {err && <div style={BAD}>{err}</div>}
                        </div>
                    )}
                </Sheet>
            )}

            {done && (
                <Sheet
                    title={t('pub.danger.rebuild.done.title')}
                    onClose={() => setDone(null)}
                    width={520}
                    footer={
                        <Button onClick={() => setDone(null)}>{t('common.close')}</Button>
                    }
                >
                    <div style={{ display: 'grid', gap: 10 }}>
                        <div style={BODY}>{t('pub.danger.rebuild.done.body')}</div>
                        <div style={BODY}>
                            {mirrorsInPack > 0
                                ? t('pub.danger.rebuild.done.by_hand_fresh')
                                : t('pub.danger.rebuild.done.by_hand')}
                        </div>
                        {/* The rebuild carries a reserved address
                            forward in the record but does NOT re-attach
                            it, and an L5-shaped move cannot carry it at
                            all — both come back as warnings that the
                            success copy would otherwise contradict. */}
                        {(done.warnings ?? []).length > 0 && (
                            <div style={{ display: 'grid', gap: 6 }}>
                                <div style={{ ...BODY, color: 'var(--red)' }}>
                                    {t('pub.danger.rebuild.done.warnings')}
                                </div>
                                {(done.warnings ?? []).map((w, i) => (
                                    <div key={i} style={MUTED}>
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
