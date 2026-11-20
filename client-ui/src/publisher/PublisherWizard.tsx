// PublisherWizard.tsx — three-screen Family Relay setup.
//
// This file used to be a seven-step wizard. Six of those seven steps
// held no decision: "keys", "provision" and "sign" were buttons that
// kicked off machine work, "pricing" was a review page with nothing to
// review, and "distribute" was a *routine operation* (send the pack,
// add a recipient) wearing a setup step's clothes — its own blurb told
// the user to walk backwards through the wizard to do it again. The
// only real questions are: which cloud account, and how big a box.
//
// So there are now three screens:
//   1. cloud  — provider + API token.                (a real decision)
//   2. plan   — name + region/size + real price.     (a real decision)
//   3. build  — one continuous progress screen that runs profile →
//               keygen → provision → sign → shared-pack back to back
//               and then hands off to the relay home via onDone().
//
// Two things that used to live here are deliberately gone:
//   * The PIN. Publisher secrets now sit under DeviceCustody
//     (hardware-backed where the platform offers it), so there is
//     nothing for the user to type and nothing to forget.
//   * Recipient management / re-sharing. That is the relay home's job
//     and exists in exactly one place now.
//
// In harness / plain-browser dev (engine not available) the wizard uses
// an in-memory mock so the screens render meaningfully and you can click
// through end-to-end. In Tauri it talks to the real wizard_* commands.

import { useEffect, useMemo, useRef, useState } from 'react';
import {
    Wizard,
    onProvisionEvent,
    onSignEvent,
    classifyPublisherError,
    type Fingerprint,
    type ProgressEvent,
    type BindResult,
    type ServerTypeOption,
    type ExistingServer,
    type DestroyReport,
    type SetupRecovery,
} from './wizardCommands';
import { SetupRecoveryCard, CancelSetupSheet } from './SetupRecoveryCard';
import {
    afterRecovery,
    cancelDelete,
    cancelPlan,
    existingAfterFailure,
    isMissingCommand,
    performRecovery,
    recoveryCheckFailed,
    recoveryFixture,
} from './setupRecovery';
import type { RecoveryButton } from './setupRecovery';
import { explainFailure } from './failureText';
import { RelayDestroySheet } from './RelayListPage';
import { RELAYPACK_PHASE } from './phase';
import { MoreWaysToConnect } from './MoreWaysToConnect';
import {
    enabledFamiliesFor,
    recallExtraFamilies,
    rememberExtraFamilies,
    toggleExtraFamily,
} from './extraFamilies';
import { ensureHelperIp, reAllowlist, detectPublicIp, isValidIp } from './helperIp';
import { isHarnessActive } from '../harness/scenarios';
import { isTauriRuntime } from '../backends';
import { invoke } from '@tauri-apps/api/core';
import {
    Badge,
    Button,
    Card,
    Disclosure,
    Icon,
    Input,
    PageHeader,
    StateIcon,
} from '../design/primitives';
import { useDensity } from '../design/DensityProvider';
import { useBack } from '../lib/useBack';
import { toFaDigits } from '../lib/i18n';
import { useConfirm, useDeviceT } from './ui';

/** Open a URL in the system's default browser (not Custom Tabs). */
async function openExternal(url: string) {
    if (isTauriRuntime()) {
        try {
            await invoke('open_external_url', { url });
            return;
        } catch { /* fall through */ }
    }
    window.open(url, '_blank');
}

interface Props {
    t: (k: string) => string;
    /** Resume an existing half-built relay. Omit/null for a new one. */
    operatorId?: number | null;
    /** Fired exactly once when the shared .sbp is confirmed live.
     *  PublisherPage routes to relay detail. This IS the death of the
     *  old "distribute" step. */
    /** `addPerson`: open the relay with "Add a person" showing. */
    onDone: (operatorId: number, addPerson?: boolean) => void;
    /** User backed out of screen 1 with no relay created. */
    onCancel: () => void;
    /** System Back at the first step. Set only when the wizard was
     *  opened from the relay list; it goes back there and never cancels
     *  or cleans anything up. Absent on a fresh install, where Back at
     *  the first step leaves the app. */
    rootBack?: () => void;
    /** "I have a backup from another phone" on the first step. */
    onRestore?: () => void;
}

/** What the system Back does in the wizard. */
export type WizardBack = 'refuse' | 'wait' | 'done' | 'step' | 'root' | 'none';

export function wizardBack(o: {
    building: boolean;
    stepIdx: number;
    hasRootBack: boolean;
    /** Another call is running on this screen (a recovery delete, a
     *  cancel): Back would hide its outcome, so it waits. */
    busyElsewhere?: boolean;
    /** The relay row is already gone and the screen leaves only through
     *  Done: Back does what Done does, never a step onto a dead relay. */
    leavesOnlyByDone?: boolean;
}): WizardBack {
    // A setup in progress keeps its guard: Back never interrupts it.
    if (o.building) return 'refuse';
    if (o.busyElsewhere) return 'wait';
    if (o.leavesOnlyByDone) return 'done';
    if (o.stepIdx > 0) return 'step';
    if (o.hasRootBack) return 'root';
    return 'none';
}

// ---- Step model ----

type StepId = 'cloud' | 'plan' | 'build';

interface StepDef {
    id: StepId;
    titleKey: string;
    blurbKey: string;
}

const STEPS: StepDef[] = [
    {
        id: 'cloud',
        titleKey: 'wiz.step.cloud.title',
        // MUST KEEP 4: what it costs, before anything is typed.
        blurbKey: 'wiz.step.cloud.line',
    },
    {
        id: 'plan',
        titleKey: 'wiz.step.plan.title',
        blurbKey: 'wiz.step.plan.blurb',
    },
    {
        id: 'build',
        titleKey: 'wiz.step.build.title',
        blurbKey: 'wiz.step.build.blurb',
    },
];

const NO_MARKS: Record<StepId, boolean> = {
    cloud: false,
    plan: false,
    build: false,
};

/** Rust derives `wizard_step` from DB state and still speaks the old
 *  seven-step vocabulary ("provider" | "pricing" | "keys" | "provision"
 *  | "sign" | "distribute"). Map it onto the three screens here — this
 *  is the ONLY place in the app that knows both vocabularies, and the
 *  Rust strings must not be renamed to match. */
function stepIdToIdx(rustStep: string): number {
    switch (rustStep) {
        case 'provider': return 0;   // cloud
        case 'pricing': return 1;    // plan
        case 'keys':
        case 'provision':
        case 'sign': return 2;       // build
        // PublisherPage never mounts the wizard for a provisioned relay,
        // so "distribute" should be unreachable. Land on the build
        // screen in its already-complete state rather than screen 1.
        case 'distribute': return 2;
        default: return 0;
    }
}

// Provider IDs and engine-side identifiers — labels, region hints and
// token hints are looked up via i18n at render time so Persian
// translations flow through.
//
// `defaultServer` is only a seed for the very first render; the plan
// screen re-syncs it from the live catalogue (see the fetch effect), so
// a deprecated id can never survive a successful lookup. Hetzner's
// cx-series is retired ("server type 104 is deprecated") — cpx12 is the
// cheapest currently-valid type in fsn1.
const CLOUD_PROVIDERS = [
    {
        id: 'hetzner',
        labelKey: 'wiz.provider.hetzner.label',
        regionKey: 'wiz.provider.hetzner.region',
        defaultServer: 'cpx12',
        tokenHintKey: 'wiz.provider.hetzner.tokenHint',
        signupUrl: 'https://console.hetzner.cloud/register',
        recommended: true,
    },
    {
        id: 'vultr',
        labelKey: 'wiz.provider.vultr.label',
        regionKey: 'wiz.provider.vultr.region',
        defaultServer: 'vc2-1c-1gb',
        tokenHintKey: 'wiz.provider.vultr.tokenHint',
        signupUrl: 'https://www.vultr.com/',
        recommended: false,
    },
    {
        id: 'digitalocean',
        labelKey: 'wiz.provider.do.label',
        regionKey: 'wiz.provider.do.region',
        defaultServer: 's-1vcpu-1gb',
        tokenHintKey: 'wiz.provider.do.tokenHint',
        signupUrl: 'https://cloud.digitalocean.com/registrations/new',
        recommended: false,
    },
    {
        id: 'linode',
        labelKey: 'wiz.provider.linode.label',
        regionKey: 'wiz.provider.linode.region',
        defaultServer: 'g6-nanode-1',
        tokenHintKey: 'wiz.provider.linode.tokenHint',
        signupUrl: 'https://login.linode.com/signup',
        recommended: false,
    },
    {
        id: 'custom',
        labelKey: 'wiz.provider.custom.label',
        regionKey: 'wiz.provider.custom.region',
        defaultServer: 'custom',
        tokenHintKey: 'wiz.provider.custom.tokenHint',
        signupUrl: '',
        recommended: false,
    },
] as const;
type ProviderId = (typeof CLOUD_PROVIDERS)[number]['id'];

const REGION_MAP: Record<string, string> = {
    hetzner: 'fsn1',
    vultr: 'fra',
    digitalocean: 'fra1',
    linode: 'eu-central',
};

// Tiny helper for the `{name}` placeholder style used throughout the
// dictionary so callers don't repeat the .replace pattern.
function fmt(s: string, args: Record<string, string | number>): string {
    return s.replace(/\{(\w+)\}/g, (_, k) =>
        args[k] !== undefined ? String(args[k]) : `{${k}}`,
    );
}

/** The only architecture the relay's cloud-init can actually bring up.
 *
 *  `publisher/deploy/cloudinit/artifacts.go` pins one manifest and it is
 *  amd64-only — `sing-box-…-linux-amd64`, `daal-relay-mgmt-…-linux-amd64`,
 *  `daal-relay-health-…-linux-amd64` — with no arm64 variants and no
 *  runtime arch selection. Provisioning an ARM box therefore creates a
 *  server, bills for it, and downloads binaries that cannot execute.
 *
 *  This matters because Hetzner's ARM line (`cax`) is both cheaper and
 *  bigger than every x86 shared type: cax11 is 2 vCPU / 4 GB at €3.79
 *  against cpx12's 1 vCPU / 2 GB at €14.36. Sorting by price and hiding
 *  dominated options would otherwise delete every runnable option from
 *  the list and leave the user with nothing but boxes that cannot work. */
const SUPPORTED_ARCH = 'x86';

/** After an ascending-price sort, drop any option that a
 *  cheaper-or-equal option already beats or matches on every axis.
 *  Offering a strictly worse machine for more money is noise, and the
 *  user has no way to tell that it is worse without doing the
 *  comparison by hand.
 *
 *  `arch` is a comparison axis, not a spec axis: an ARM type can never
 *  dominate an x86 one, because they are not substitutes. The list is
 *  already filtered to SUPPORTED_ARCH before it gets here; this is the
 *  belt to that braces, so a future arm64 manifest cannot silently
 *  reintroduce the same disappearing-options bug. */
function hideDominated(sorted: ServerTypeOption[]): ServerTypeOption[] {
    const kept: ServerTypeOption[] = [];
    for (const opt of sorted) {
        const dominated = kept.some(
            (k) =>
                k.arch === opt.arch &&
                k.cpus >= opt.cpus &&
                k.memory_gb >= opt.memory_gb &&
                k.disk_gb >= opt.disk_gb,
        );
        if (!dominated) kept.push(opt);
    }
    return kept;
}

// ---- Build state machine ----

type BuildStage =
    | 'idle'
    | 'profile'
    | 'keys'
    | 'provision'
    | 'sign'
    | 'share'
    | 'done'
    | 'failed';

/** The sub-stages, in execution order, that get a progress line. */
const BUILD_STAGES: Array<{ id: BuildStage; key: string }> = [
    { id: 'profile', key: 'wiz.build.stage.profile' },
    { id: 'keys', key: 'wiz.build.stage.keys' },
    { id: 'provision', key: 'wiz.build.stage.provision' },
    { id: 'sign', key: 'wiz.build.stage.sign' },
    { id: 'share', key: 'wiz.build.stage.share' },
];

const FAIL_KEY: Partial<Record<BuildStage, string>> = {
    profile: 'wiz.build.fail.profile',
    keys: 'wiz.build.fail.keys',
    provision: 'wiz.build.fail.provision',
    sign: 'wiz.build.fail.sign',
    share: 'wiz.build.fail.share',
};

/** Sentinel returned by `stageRun` when a sub-stage failed. Using a
 *  symbol rather than null/undefined matters: `provisionRun` resolves
 *  to `undefined` on SUCCESS, so a truthiness test would read every
 *  successful provision as a failure. */
const STAGE_FAILED = Symbol('stage-failed');

// Harness-only operator id counter — the real ids come from
// storeCloudToken.
let mockNextId = 1;

const MOCK_FP: Fingerprint = {
    hex: 'aa'.repeat(16),
    en_words: 'phoenix rescue may sky honest stone river hill',
    fa_words: 'ققنوس نجات اردیبهشت آسمان درست سنگ رود تپه',
};

// ---- Component ----

export default function PublisherWizard({
    t,
    operatorId: resumeOperatorId,
    onDone,
    onCancel,
    rootBack,
    onRestore,
}: Props) {
    const { density, isRTL } = useDensity();
    const confirm = useConfirm();
    const isPhone = density === 'phone';
    const dt = useDeviceT(t);
    // Numbers in the reader's digits: Persian digits and the Persian
    // decimal sign (۱۴٫۳۶) in Persian prose, so one card never mixes two.
    const readerNum = (v: number | string): string =>
        isRTL ? toFaDigits(String(v)).replace('.', '\u066B') : String(v);
    const live = isTauriRuntime() && !isHarnessActive();

    // Step navigation.
    const [stepIdx, setStepIdx] = useState(0);
    const [completed, setCompleted] = useState<Record<StepId, boolean>>(NO_MARKS);

    // The relay being built. Seeded from the prop on a resume; set by
    // storeCloudToken on a fresh run.
    const [operatorId, setOperatorId] = useState<number | null>(
        resumeOperatorId ?? null,
    );

    // Screen 1 — provider & token.
    const [provider, setProvider] = useState<ProviderId>('hetzner');
    const [token, setToken] = useState('');
    // On a resume the token is already sealed under custody and never
    // comes back over IPC. Without this flag the Next gate would demand
    // the user re-paste a key they already gave us.
    const [hasStoredToken, setHasStoredToken] = useState(false);
    // A hosting key another relay already saved for this company: a new
    // relay can start with it, so the person does not paste it again.
    const [savedElsewhere, setSavedElsewhere] = useState<
        { operator_id: number; nickname: string } | null
    >(null);
    useEffect(() => {
        let dead = false;
        if (!live || operatorId != null) {
            setSavedElsewhere(null);
            return;
        }
        Wizard.savedCloudToken(provider)
            .then((s) => !dead && setSavedElsewhere(s))
            .catch(() => !dead && setSavedElsewhere(null));
        return () => {
            dead = true;
        };
    }, [live, provider, operatorId]);

    // Screen 2 — name, region, size.
    const providerDef = useMemo(
        () => CLOUD_PROVIDERS.find((p) => p.id === provider)!,
        [provider],
    );
    const autoRegion = REGION_MAP[provider] || 'fsn1';
    const [nickname, setNickname] = useState('');
    const [serverType, setServerType] = useState<string>(providerDef.defaultServer);
    const [serverOptions, setServerOptions] = useState<ServerTypeOption[]>([]);
    const [existingServers, setExistingServers] = useState<ExistingServer[]>([]);
    const [useExisting, setUseExisting] = useState<string | null>(null);
    const [loadingOptions, setLoadingOptions] = useState(false);
    // Toolbox profile name MUST match a profile shipped with
    // daal-deploy. At V1.5 only "iran-default" exists; passing a wrong
    // name (or an empty family list with non-matching identifiers)
    // makes the provider's candidatesForProfile() return [], which
    // later fails bind-and-sign with "OperatorRecord carries no
    // candidates".
    const toolboxProfile = 'iran-default';
    // "More ways to connect": the profile's opt-in families the operator
    // ticked on screen 2. Nothing is ticked by default and the section
    // starts collapsed.
    const [extraFamilies, setExtraFamilies] = useState<string[]>([]);
    const [moreWaysOpen, setMoreWaysOpen] = useState(false);
    // Empty array = use the profile's DefaultEnabled candidates
    // (vless-reality, websocket-tls, naive, hysteria2). Otherwise the
    // defaults PLUS the ticked extras — the list replaces the defaults,
    // it is not added to them (see extraFamilies.ts).
    const enabledFamilies = useMemo<string[]>(
        () => enabledFamiliesFor(toolboxProfile, extraFamilies),
        [extraFamilies],
    );

    // Screen 3 — the build.
    const [stage, setStage] = useState<BuildStage>('idle');
    const [failedAt, setFailedAt] = useState<BuildStage | null>(null);
    const [buildLog, setBuildLog] = useState<ProgressEvent[]>([]);
    const [fp, setFp] = useState<Fingerprint | null>(null);
    // Set from the DB on resume so the chain skips work already done —
    // re-running provision on an already-live box would rent a second
    // server, and re-minting the shared pack would invalidate every
    // copy already handed out.
    const [alreadyProvisioned, setAlreadyProvisioned] = useState(false);
    /** A resume landed on the build screen with no server yet, so the
     *  next thing the chain does is rent one. The consent given on
     *  screen 2 belongs to a session that no longer exists — ask again
     *  rather than auto-starting a purchase. */
    const [awaitingBuildConsent, setAwaitingBuildConsent] = useState(false);
    const [alreadySigned, setAlreadySigned] = useState(false);
    // Non-null while the "your address changed" repair card is open.
    // Holds the draft IP. NOTE: no button is ever disabled because of
    // the helper IP — the action repairs it and retries once, and only
    // if that also fails does this card appear.
    const [helperIpRepair, setHelperIpRepair] = useState<string | null>(null);

    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    // D1 — what an interrupted setup left behind. Asked before a resume
    // does anything that costs money; `null` while the question is out.
    const [recovery, setRecovery] = useState<SetupRecovery | null>(null);
    /** The shell predates the command: fall back to the plain consent
     *  card, which at least never auto-rents. */
    const [recoveryUnavailable, setRecoveryUnavailable] = useState(false);
    const [recoveryBusy, setRecoveryBusy] = useState(false);
    const [recoveryError, setRecoveryError] = useState<{ message: string; detail: string } | null>(null);
    const [recoveryOutcome, setRecoveryOutcome] = useState<DestroyReport | null>(null);
    /** A recovery delete removed (or is removing) the relay itself: the
     *  card shows its report and a Done that leaves. */
    const [recoveryLeaving, setRecoveryLeaving] = useState(false);
    /** The delete button whose report is on the card: its Try again. */
    const [recoveryRetryButton, setRecoveryRetryButton] = useState<RecoveryButton | null>(null);
    /** The server id "Finish setting up on this server" chose: Daal's
     *  own, rolled back (deleted) on failure. */
    const adoptedIdRef = useRef<string | null>(null);
    // Cancel: the sheet for a setup that may have rented something, or
    // the two-choice teardown for one that already has a server.
    const [cancelRec, setCancelRec] = useState<SetupRecovery | null>(null);
    const [cancelBusy, setCancelBusy] = useState(false);
    const [cancelOutcome, setCancelOutcome] = useState<DestroyReport | null>(null);
    const [cancelError, setCancelError] = useState<{ message: string; detail: string } | null>(null);
    const [cancelDestroyOpen, setCancelDestroyOpen] = useState(false);

    // ---- Streaming logs ----

    // Provision and sign both stream into ONE combined log. The old
    // wizard kept two separate EventLists on two separate screens; on
    // a single progress screen that split is meaningless.
    useEffect(() => {
        if (!live) return;
        const unsubs: Array<() => void> = [];
        onProvisionEvent((ev) => setBuildLog((l) => [...l, ev])).then((u) =>
            unsubs.push(u),
        );
        onSignEvent((ev) => setBuildLog((l) => [...l, ev])).then((u) =>
            unsubs.push(u),
        );
        // Fallback: CustomEvent injected via webview.eval() on platforms
        // where the Tauri event bridge is flaky.
        const handleCustom = (e: Event) => {
            const detail = (e as CustomEvent).detail;
            if (detail?.step) {
                setBuildLog((l) => [
                    ...l,
                    { step: detail.step, message: detail.message },
                ]);
            }
        };
        window.addEventListener('daal-provision-event', handleCustom);
        return () => {
            unsubs.forEach((u) => u());
            window.removeEventListener('daal-provision-event', handleCustom);
        };
    }, [live]);

    // ---- Resume ----

    // All wizard state lives in the DB, so a relaunch mid-build resumes
    // exactly where it left off. The wizard no longer *finds* the relay
    // to resume — PublisherPage owns that decision and passes the id —
    // because auto-adopting the first non-decommissioned operator would
    // hijack the "+ New relay" action.
    useEffect(() => {
        setOperatorId(resumeOperatorId ?? null);
        if (!live || !resumeOperatorId) return;
        let cancelled = false;
        Wizard.getOperatorState(resumeOperatorId)
            .then((state) => {
                if (cancelled) return;
                setProvider((state.provider || 'hetzner') as ProviderId);
                if (state.server_type) setServerType(state.server_type);
                if (state.nickname) setNickname(state.nickname);
                // The ticked extras are chosen on screen 2 and used by
                // the build; a relaunch in between must not silently
                // fall back to the defaults.
                const recalled = recallExtraFamilies(resumeOperatorId, toolboxProfile);
                setExtraFamilies(recalled);
                if (recalled.length > 0) setMoreWaysOpen(true);
                setHasStoredToken(state.has_cloud_token);
                // The old wizard never hydrated the fingerprint, so a
                // resumed operator was re-offered "Generate keypair"
                // for a key it already had.
                if (state.publisher_pub_hex) {
                    setFp({
                        hex: state.publisher_pub_hex,
                        en_words: '',
                        fa_words: '',
                    });
                }
                setAlreadyProvisioned(state.is_provisioned);
                setAlreadySigned(state.has_signed_sbp);

                const idx = stepIdToIdx(state.wizard_step);
                const marks = { ...NO_MARKS };
                for (let i = 0; i < idx; i++) marks[STEPS[i].id] = true;
                setCompleted(marks);
                setStepIdx(idx);
                // Resuming straight into a build that would create (and
                // start billing for) a server. See the auto-start effect.
                setAwaitingBuildConsent(
                    idx === 2 && !state.is_provisioned,
                );
                // Defensive: a fully-finished relay should have been
                // routed to relay detail, not here. Render the build
                // screen in its completed state instead of re-running
                // a chain that would re-mint the shared pack.
                if (state.wizard_step === 'distribute') {
                    setStage('done');
                    setCompleted({ cloud: true, plan: true, build: true });
                }
            })
            .catch((e) => setError(String(e)));
        return () => { cancelled = true; };
    }, [live, resumeOperatorId]);

    // ---- Small helpers ----

    const mark = (id: StepId) => setCompleted((c) => ({ ...c, [id]: true }));

    /** Run a command, surfacing failure as an error banner. Returns the
     *  value, or null when it threw. Only safe for value-returning
     *  commands — see STAGE_FAILED for why. */
    const run = async <T,>(fn: () => Promise<T>): Promise<T | null> => {
        setBusy(true);
        setError(null);
        try {
            return await fn();
        } catch (e) {
            setError(String(e));
            return null;
        } finally {
            setBusy(false);
        }
    };

    /**
     * Wrap a mgmt-plane call so a missing or stale helper IP repairs
     * itself instead of surfacing as an inert disabled button.
     *
     * The helper IP is the publisher's own outbound address; daal-deploy
     * punches an ephemeral cloud-firewall rule for it via the provider
     * API before each mgmt call. Because that goes through the cloud
     * API and not the box, a stale value is always repairable from
     * anywhere — no reprovision, no redeploy.
     */
    async function withHelperIp<T>(
        opId: number,
        fn: () => Promise<T>,
    ): Promise<T> {
        await ensureHelperIp(opId); // no-op when already stored
        try {
            return await fn();
        } catch (e) {
            const code = classifyPublisherError(e);
            if (code === 'E_HELPER_IP_MISSING' || code === 'E_HELPER_IP_STALE') {
                const fresh = await reAllowlist(opId);
                if (fresh) return await fn(); // exactly one retry
            }
            throw e;
        }
    }

    /** Run one build sub-stage. On failure it names the stage, shows the
     *  raw error, and — when the failure was an address problem that
     *  survived the automatic retry — opens the repair card with a
     *  freshly detected IP prefilled. */
    const stageRun = async <T,>(
        s: BuildStage,
        fn: () => Promise<T>,
    ): Promise<T | typeof STAGE_FAILED> => {
        setStage(s);
        try {
            return await fn();
        } catch (e) {
            const code = classifyPublisherError(e);
            // D1: provision found a server for this relay already there,
            // or another setup still holds the journal. Neither is a
            // failure to retry — ask what exists and show the card that
            // says so, which never rents a second server.
            if (
                s === 'provision' &&
                (code === 'E_SERVER_EXISTS' || code === 'E_SETUP_RUNNING') &&
                operatorId
            ) {
                setStage('idle');
                setFailedAt(null);
                setError(null);
                // The effect below asks setupRecovery when this flips.
                setAwaitingBuildConsent(true);
                return STAGE_FAILED;
            }
            setError(String(e));
            setFailedAt(s);
            setStage('failed');
            if (code === 'E_HELPER_IP_MISSING' || code === 'E_HELPER_IP_STALE') {
                const guess = await detectPublicIp();
                setHelperIpRepair(guess?.ip ?? '');
            }
            return STAGE_FAILED;
        }
    };

    // ---- D1: interrupted setup ----

    /** Ask the shell what an interrupted setup left behind. */
    async function queryRecovery(opId: number): Promise<SetupRecovery | null> {
        setRecovery(null);
        setRecoveryError(null);
        if (!live) {
            const r = recoveryFixture(harnessRecoverState() ?? 'none');
            setRecovery(r);
            return r;
        }
        try {
            const r = await Wizard.setupRecovery(opId);
            setRecovery(r);
            setRecoveryUnavailable(false);
            return r;
        } catch (e) {
            if (isMissingCommand(e)) {
                // An app whose shell predates the command: keep the old
                // consent card, which at least never rents by itself.
                setRecoveryUnavailable(true);
                setRecoveryError(explainFailure(t, e));
                return null;
            }
            // Any other failure is "we couldn't check", never the old
            // card that says the next step rents a server: a server may
            // already be billing.
            const r = recoveryCheckFailed(e);
            setRecovery(r);
            setRecoveryUnavailable(false);
            return r;
        }
    }

    const onRecoveryButton = async (b: RecoveryButton) => {
        if (!operatorId || !recovery) return;
        const opId = operatorId;
        setRecoveryBusy(true);
        setRecoveryError(null);
        setRecoveryOutcome(null);
        try {
            const res = await performRecovery(b, opId, recovery, {
                // The auto-start effect runs the chain once consent is
                // given; setting the id first makes that run adopt the
                // server that exists instead of renting another.
                setExisting: (id) => {
                    setUseExisting(id);
                    adoptedIdRef.current = b === 'finish_here' ? id : null;
                },
                runBuild: () => {
                    setAwaitingBuildConsent(false);
                },
                setupRemoveServer: (op) =>
                    live ? Wizard.setupRemoveServer(op) : Promise.resolve(mockDestroyReport()),
                relayDestroy: (op, del, own) =>
                    live ? Wizard.relayDestroy(op, del, own) : Promise.resolve(mockDestroyReport()),
            });
            const next = afterRecovery(b, res);
            if (res.kind === 'deleted') {
                // The report stays on the card until the person has read
                // it; a relay that is gone leaves only through Done.
                setRecoveryOutcome(res.report);
                setRecoveryRetryButton(b);
            }
            if (next.leave) setRecoveryLeaving(true);
            if (next.requery) await queryRecovery(opId);
        } catch (e) {
            setRecoveryError(explainFailure(t, e));
        } finally {
            setRecoveryBusy(false);
        }
    };

    /** Forget everything about the relay that was being built. */
    function resetAfterCancel() {
        setOperatorId(null);
        setStepIdx(0);
        setCompleted(NO_MARKS);
        setStage('idle');
        setFailedAt(null);
        setFp(null);
        setAlreadyProvisioned(false);
        setAlreadySigned(false);
        setHasStoredToken(false);
        setCancelRec(null);
        setCancelDestroyOpen(false);
        setRecoveryLeaving(false);
        setRecoveryOutcome(null);
        onCancel();
    }

    /** Cancel. Deleting what a setup rented is offered whenever there is
     *  a token to do it with; forgetting the relay alone is left for the
     *  case where nothing was rented or nothing can be looked at. */
    const onCancelPress = async () => {
        if (operatorId == null) return;
        const opId = operatorId;
        if (live && alreadyProvisioned) {
            // A server exists and is recorded: the same two-choice
            // teardown the relay list uses.
            setCancelDestroyOpen(true);
            return;
        }
        let rec: SetupRecovery | null = null;
        if (live) {
            try {
                rec = await Wizard.setupRecovery(opId);
            } catch (e) {
                // With a token stored, "could not look" must not turn
                // into a local-only cancel that strands a paid server:
                // offer the delete, which refuses safely if it cannot
                // look either.
                rec = hasStoredToken
                    ? recoveryFixture('unknown', {
                          provider: '',
                          check_error: 'failed',
                          started_at_unix: 0,
                          details: [String(e)],
                      })
                    : null;
            }
        } else if (harnessRecoverState()) {
            rec = recoveryFixture(harnessRecoverState()!);
        }
        if (rec && cancelPlan(rec) !== 'local') {
            setCancelOutcome(null);
            setCancelError(null);
            setCancelRec(rec);
            return;
        }
        // The app's own sheet (H-29); the body keeps the money line.
        const yes = await confirm.ask({
            title: t('wiz.cancel'),
            body: t(localCancelKey(rec)),
            confirmLabel: t('wiz.cancel.go'),
            cancelLabel: t('common.cancel'),
            danger: true,
        });
        if (!yes) return;
        if (live) {
            // The command returns nothing, which arrives as null: say
            // `true` ourselves, or success looks like run()'s failure and
            // the wizard stays open on a relay that no longer exists
            // (seen on the phone 2026-11-19).
            const ok = await run(() => Wizard.cancelAndCleanup(opId).then(() => true));
            if (ok === null) return;
        }
        resetAfterCancel();
    };

    const onCancelDelete = async () => {
        if (operatorId == null) return;
        setCancelBusy(true);
        setCancelError(null);
        try {
            // The report is shown in the sheet; the wizard leaves only
            // when the person presses Done (CancelSetupSheet.onDone).
            const { report } = await cancelDelete(operatorId, cancelPlan(cancelRec), (op, del, own) =>
                live ? Wizard.relayDestroy(op, del, own) : Promise.resolve(mockDestroyReport()),
            );
            setCancelOutcome(report);
        } catch (e) {
            setCancelError(explainFailure(t, e));
        } finally {
            setCancelBusy(false);
        }
    };

    const onCancelKeep = async () => {
        if (operatorId == null) return;
        setCancelBusy(true);
        try {
            if (live) await Wizard.cancelAndCleanup(operatorId);
            resetAfterCancel();
        } catch (e) {
            setCancelError(explainFailure(t, e));
        } finally {
            setCancelBusy(false);
        }
    };

    const fakeProgress = async (
        phaseName: string,
        steps: Array<[string, number]>,
    ) => {
        for (const [detail, pct] of steps) {
            await new Promise((r) => setTimeout(r, 220));
            setBuildLog((l) => [
                ...l,
                { step: phaseName, message: detail, phase: phaseName, detail, pct },
            ]);
        }
    };

    // ---- Screen 2: load sizes + existing servers on entry ----

    useEffect(() => {
        if (STEPS[stepIdx]?.id !== 'plan') return;
        if (!operatorId) return;
        setLoadingOptions(true);
        (async () => {
            try {
                if (live) {
                    const [types, existing] = await Promise.all([
                        Wizard.listServerTypes(operatorId, autoRegion),
                        Wizard.listExistingServers(operatorId).catch(
                            () => [] as ExistingServer[],
                        ),
                    ]);
                    const filtered = hideDominated(
                        types
                            .filter(
                                (st) =>
                                    // Never offer a machine the relay
                                    // artifacts cannot run on — see
                                    // SUPPORTED_ARCH.
                                    st.arch === SUPPORTED_ARCH &&
                                    st.monthly_eur > 0 &&
                                    st.monthly_eur <= 20,
                            )
                            .sort((a, b) => a.monthly_eur - b.monthly_eur),
                    );
                    setServerOptions(filtered);
                    setExistingServers(existing);
                    // A stale or hardcoded default must never survive a
                    // successful fetch — that is exactly how the retired
                    // `cx22` kept reaching the provisioner.
                    if (
                        filtered.length > 0 &&
                        !filtered.some((o) => o.id === serverType)
                    ) {
                        setServerType(filtered[0].id);
                    }
                } else {
                    // Harness data mirrors the real catalogue shape,
                    // including the ARM rows the live filter drops —
                    // this is the case that must never reach the UI.
                    setServerOptions(
                        hideDominated(
                            [
                                { id: 'cax11', description: 'CAX11', cpus: 2, memory_gb: 4, disk_gb: 40, monthly_eur: 3.79, hourly_eur: 0.006, location: 'fsn1', arch: 'arm' },
                                { id: 'cpx12', description: 'CPX12', cpus: 1, memory_gb: 2, disk_gb: 40, monthly_eur: 14.36, hourly_eur: 0.023, location: 'fsn1', arch: 'x86' },
                                { id: 'cpx22', description: 'CPX22', cpus: 2, memory_gb: 4, disk_gb: 80, monthly_eur: 19.36, hourly_eur: 0.031, location: 'fsn1', arch: 'x86' },
                            ]
                                .filter((st) => st.arch === SUPPORTED_ARCH)
                                .sort((a, b) => a.monthly_eur - b.monthly_eur),
                        ),
                    );
                    setServerType('cpx12');
                }
            } catch (e) {
                setError(String(e));
            } finally {
                setLoadingOptions(false);
            }
        })();
    }, [stepIdx, operatorId]); // eslint-disable-line react-hooks/exhaustive-deps

    // ---- Screen 3: the build chain ----

    // Ordering is a hard constraint: selectProfile writes region +
    // server_type into the pre-provision record and publisherKeygen
    // writes the pubkey into it; provisionRun reads all three back out.
    const runBuild = async (existingOverride?: string) => {
        if (!operatorId) return;
        const existingId = existingOverride ?? useExisting ?? undefined;
        const opId = operatorId;
        setError(null);
        setFailedAt(null);
        setHelperIpRepair(null);
        setBuildLog([]);
        setBusy(true);
        try {
            // 0. Helper IP must exist before ANY mgmt-plane call.
            //    Detect + persist once; every command reads it from the
            //    DB from here on. Failure here is not fatal — the
            //    per-call withHelperIp wrapper gets a second chance.
            if (live) await ensureHelperIp(opId);

            // 1. Profile — cheap, idempotent, no secrets. Skipped once
            //    the box exists: the record then holds the provisioned
            //    OperatorRecord (mgmt port, TLS pin, box connection
            //    material), and region/server_type are facts about a
            //    running machine rather than a pending choice. Rust
            //    refuses the write for the same reason; this keeps the
            //    stage strip honest about what actually ran.
            if (!alreadyProvisioned) {
                if (
                    (await stageRun('profile', () =>
                        live
                            ? Wizard.selectProfile(
                                  opId,
                                  autoRegion,
                                  serverType,
                                  toolboxProfile,
                                  enabledFamilies,
                              )
                            : Promise.resolve(),
                    )) === STAGE_FAILED
                ) {
                    return;
                }
            } else {
                setStage('profile');
            }

            // 2. Keys — skipped when the operator already has a pubkey.
            if (!fp) {
                const k = await stageRun('keys', () =>
                    live ? Wizard.publisherKeygen(opId) : Promise.resolve(MOCK_FP),
                );
                if (k === STAGE_FAILED) return;
                setFp(k);
            }

            // 3. Provision — streams into the combined log. Skipped on a
            //    resume where the box is already up, or renting a second
            //    server would be the "fix".
            if (!alreadyProvisioned) {
                const p = await stageRun('provision', () =>
                    live
                        ? withHelperIp(opId, () =>
                              Wizard.provisionRun(opId, existingId),
                          )
                        : fakeProgress('provision', [
                              ['create server', 10],
                              ['await SSH', 40],
                              ['toolbox bring-up', 80],
                              ['done', 100],
                          ]),
                );
                if (p === STAGE_FAILED) {
                    // A failed finish-on-this-server was rolled back,
                    // which deleted that server: its id must not ride
                    // into the next try. The person's own server is
                    // never rolled back and stays chosen.
                    const origin = existingId && existingId === adoptedIdRef.current ? 'created' : 'yours';
                    setUseExisting((cur) => existingAfterFailure(cur, origin));
                    adoptedIdRef.current = null;
                    return;
                }
                setAlreadyProvisioned(true);
            } else {
                setStage('provision');
            }

            // 4. Sign — streams wizard://sign-event into the same log.
            //    Skipped once it has succeeded, so a retry triggered by
            //    a later stage doesn't redo the ~30s bind.
            if (!alreadySigned) {
                const bind = await stageRun('sign', () =>
                    live
                        ? Wizard.signRelaypack(
                              opId,
                              // One constant, shared with the Go and
                              // Rust sides; see ./phase.ts.
                              RELAYPACK_PHASE,
                              '',
                              nickname.trim() || `daal-relay-${opId}`,
                          )
                        : fakeProgress('sign', [
                              ['collect endpoints', 25],
                              ['canonicalize', 60],
                              ['sign', 90],
                              ['done', 100],
                          ]).then<BindResult>(() => ({
                              sbp_path: 'Daal app storage',
                              fingerprint_hex: 'aa'.repeat(16),
                              sbp_sha256: 'bb'.repeat(32),
                          })),
                );
                if (bind === STAGE_FAILED) return;
                // The BindResult itself is not kept: the relay home
                // enumerates artifacts from disk, so a React copy of the
                // path would only be a second source of truth.
                setAlreadySigned(true);
            }

            // 5. Produce the CONNECTABLE shared .sbp. This mints the
            //    shared r0 user and rewrites the profiles with its
            //    working credentials (~10-20s). Without it the user
            //    would be handed the raw signed bundle, which no phone
            //    can actually connect with.
            const shared = await stageRun('share', () =>
                live
                    ? withHelperIp(opId, () => Wizard.produceSharedSbp(opId))
                    : Promise.resolve({
                          sbp_path: 'Daal app storage',
                          server: 'mock',
                      }),
            );
            if (shared === STAGE_FAILED) return;

            setStage('done');
            mark('build');
            // No automatic hand-off: the done screen's next step is "Add
            // the first person" (H-54), so it stays until it is chosen.
        } finally {
            setBusy(false);
        }
    };

    // Auto-start the build on entering screen 3. Machine work does not
    // need a consent tap it already got on screen 2; the old "Provision
    // now" and "Build relay pack" buttons only existed because each
    // phase had its own step to fill.
    //
    // The one exception is a RESUME that lands here with no box yet.
    // The consent on screen 2 was given in a session that is gone, and
    // with it the "use a server I already own" choice: `useExisting`
    // lives only in React state, so an auto-started resume takes the
    // create-new branch and rents a second billable server — after the
    // plan screen said "no new charges". Hetzner's idempotency is keyed
    // on the derived name, which an existing server does not have, so
    // nothing catches it. Ask before spending money.
    // A resume that would rent a server first asks what is already
    // there (D1). Re-asked whenever the card comes back.
    useEffect(() => {
        if (!awaitingBuildConsent || !operatorId) return;
        if (STEPS[stepIdx]?.id !== 'build') return;
        void queryRecovery(operatorId);
    }, [awaitingBuildConsent, operatorId, stepIdx]); // eslint-disable-line react-hooks/exhaustive-deps

    // Harness preview: `?recover=<state>` lands on the recovery card.
    useEffect(() => {
        if (live) return;
        if (!harnessRecoverState()) return;
        setOperatorId((id) => id ?? 1);
        setStepIdx(2);
        setAwaitingBuildConsent(true);
    }, [live]);

    const runBuildRef = useRef(runBuild);
    runBuildRef.current = runBuild;
    useEffect(() => {
        if (STEPS[stepIdx]?.id !== 'build') return;
        if (stage !== 'idle') return;
        if (!operatorId) return;
        if (awaitingBuildConsent) return;
        const h = setTimeout(() => { void runBuildRef.current(); }, 400);
        return () => clearTimeout(h);
    }, [stepIdx, stage, operatorId, awaitingBuildConsent]);

    const step = STEPS[stepIdx];
    const building =
        stage !== 'idle' && stage !== 'done' && stage !== 'failed';

    // System Back: one step back, else back to the list it came from.
    // While the build runs it is refused and says why.
    const [backNotice, setBackNotice] = useState<string | null>(null);
    useEffect(() => {
        if (!backNotice) return;
        const h = setTimeout(() => setBackNotice(null), 4000);
        return () => clearTimeout(h);
    }, [backNotice]);
    useBack(
        stepIdx > 0 || !!rootBack || recoveryLeaving,
        () => {
            switch (
                wizardBack({
                    building,
                    stepIdx,
                    hasRootBack: !!rootBack,
                    busyElsewhere: recoveryBusy || cancelBusy || busy,
                    leavesOnlyByDone: recoveryLeaving,
                })
            ) {
                case 'refuse':
                    setBackNotice('pub.back.setup_running');
                    return;
                case 'wait':
                    setBackNotice('pub.back.wait');
                    return;
                case 'done':
                    resetAfterCancel();
                    return;
                case 'step':
                    setStepIdx(stepIdx - 1);
                    return;
                case 'root':
                    rootBack?.();
                    return;
                default:
                    return;
            }
        },
        'page',
    );
    // How far the chain got. On failure `stage` is 'failed', which is
    // not in BUILD_STAGES — fall back to failedAt so the sub-stages that
    // DID succeed keep their green light instead of all reverting to
    // grey (the user needs to see the box was created before the sign
    // failed, or they will assume they lost it).
    const stageIdx = BUILD_STAGES.findIndex(
        (s) => s.id === (stage === 'failed' ? failedAt : stage),
    );

    // ---- Render ----

    return (
        <div
            style={{
                width: '100%',
                boxSizing: 'border-box',
                // A --content-max column on desktop, like every page.
                maxWidth: isPhone ? undefined : 'calc(var(--content-max) + 64px)',
                // On phones the MobileShell <main> already provides the
                // horizontal gutter; doubling it crushes the content.
                padding: isPhone ? '0 0 16px' : '16px 32px 32px',
                color: 'var(--fg)',
            }}
        >
            <PageHeader
                title={t('wiz.heading')}
                badge={
                    !live ? (
                        <Badge tone="neutral" size="sm">
                            {t('wiz.harness.preview')}
                        </Badge>
                    ) : undefined
                }
            />

            {/* Three screens fit in a strip. The old build had a 220px
                desktop side rail and a separate phone pager component
                for seven steps; neither earns its space at three. */}
            {backNotice && (
                <div
                    role="status"
                    data-testid="wizard-back-refused"
                    style={{ fontSize: 13, color: 'var(--gold)', margin: '0 0 10px', lineHeight: 1.5 }}
                >
                    {t(backNotice)}
                </div>
            )}

            <StepStrip
                stepIdx={stepIdx}
                completed={completed}
                ready={step.id === 'build' && stage === 'done'}
                locked={building}
                onJump={setStepIdx}
                t={t}
            />

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                    {!(step.id === 'build' && stage === 'done') && (
                        <p
                            style={{
                                color: step.id === 'cloud' ? 'var(--fg)' : 'var(--muted)',
                                fontSize: 14,
                                lineHeight: 1.5,
                                margin: '0 0 14px',
                                maxInlineSize: '64ch',
                            }}
                            data-testid={step.id === 'cloud' ? 'wizard-cost' : undefined}
                        >
                            {t(step.blurbKey)}
                        </p>
                    )}

                    {error && (
                        <div
                            style={{
                                background: 'rgba(200,85,61,0.10)',
                                border: '1px solid rgba(200,85,61,0.40)',
                                color: 'var(--red)',
                                padding: 10,
                                borderRadius: 'var(--radius-md)',
                                marginBottom: 10,
                                fontSize: 12,
                                wordBreak: 'break-word',
                            }}
                        >
                            {error}
                        </div>
                    )}

                    {/* ===== SCREEN 1: CLOUD ACCOUNT ===== */}
                    {step.id === 'cloud' && (
                        <div>
                            {/* No provider chooser (H-46): Hetzner is the
                                only one that works. The provider code path
                                stays; only the "Coming soon" tiles went.
                                The token path appears once, here, as a
                                numbered guide (H-47). */}
                            <ol
                                data-testid="wizard-guide"
                                style={{
                                    listStyle: 'none',
                                    margin: '0 0 16px',
                                    padding: 0,
                                    display: 'grid',
                                    gap: 10,
                                }}
                            >
                                {(['wiz.guide.1', 'wiz.guide.2', 'wiz.guide.3'] as const).map((k, i) => (
                                    <li key={k} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                                        <span
                                            aria-hidden
                                            style={{
                                                width: 24,
                                                height: 24,
                                                flexShrink: 0,
                                                borderRadius: '50%',
                                                background: 'var(--surface-3)',
                                                color: 'var(--fg)',
                                                display: 'inline-flex',
                                                alignItems: 'center',
                                                justifyContent: 'center',
                                                fontSize: 13,
                                                fontWeight: 600,
                                            }}
                                        >
                                            {isRTL ? toFaDigits(String(i + 1)) : i + 1}
                                        </span>
                                        <span style={{ fontSize: 14, lineHeight: 1.5, color: 'var(--fg)', minWidth: 0 }}>
                                            {t(k)}
                                            {i === 0 && providerDef.signupUrl && (
                                                <>
                                                    {' '}
                                                    <Button
                                                        variant="link"
                                                        trailing={<Icon name="external" size={14} />}
                                                        onClick={() => openExternal(providerDef.signupUrl)}
                                                        dataButton="hetzner-signup"
                                                        style={{ paddingBlock: 0, minHeight: 44, marginBlock: -6 }}
                                                    >
                                                        {t('wiz.provider.signup')}
                                                    </Button>
                                                </>
                                            )}
                                        </span>
                                    </li>
                                ))}
                            </ol>

                            <Label>{t('wiz.provider.token')}</Label>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                                <Input
                                    type="password"
                                    placeholder={t('wiz.provider.token.placeholder')}
                                    value={token}
                                    onChange={(e) => setToken(e.target.value)}
                                    autoCapitalize="off"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <Button
                                    variant="secondary"
                                    leading="paste"
                                    dataButton="paste-key"
                                    onClick={async () => {
                                        try {
                                            const text = await navigator.clipboard.readText();
                                            if (text && text.trim()) {
                                                setToken(text.trim());
                                                return;
                                            }
                                        } catch {
                                            /* the web view would not read it */
                                        }
                                        setError(t('wiz.provider.token.paste_failed'));
                                    }}
                                >
                                    {t('ui.paste')}
                                </Button>
                            </div>
                            <div
                                style={{
                                    fontSize: 13,
                                    color: 'var(--muted)',
                                    lineHeight: 1.5,
                                    marginBottom: 14,
                                }}
                            >
                                {hasStoredToken
                                    ? t('wiz.provider.token.stored')
                                    : canReuseSaved(savedElsewhere, token, hasStoredToken)
                                    ? savedKeyLine(t, savedElsewhere!.nickname)
                                    : dt('wiz.provider.token.kept')}
                            </div>

                            <NavRow
                                t={t}
                                backLabel={t('wiz.nav.cancel')}
                                onBack={onCancel}
                                nextDisabled={
                                    busy ||
                                    (!token.trim() &&
                                        !hasStoredToken &&
                                        !savedElsewhere)
                                }
                                onNext={async () => {
                                    if (!live) {
                                        setOperatorId((id) => id ?? mockNextId++);
                                        mark('cloud');
                                        setStepIdx(1);
                                        return;
                                    }
                                    // Passing the existing operatorId is
                                    // what stops Back→Next from silently
                                    // creating a duplicate operator row:
                                    // store_cloud_token used to INSERT on
                                    // every call.
                                    if (!token.trim() && hasStoredToken) {
                                        mark('cloud');
                                        setStepIdx(1);
                                        return;
                                    }
                                    const dbId = await run(() =>
                                        canReuseSaved(savedElsewhere, token, hasStoredToken)
                                            ? Wizard.reuseCloudToken(provider)
                                            : Wizard.storeCloudToken(
                                                  provider,
                                                  token,
                                                  operatorId ?? undefined,
                                              ),
                                    );
                                    if (dbId == null) return;
                                    setOperatorId(dbId);
                                    setHasStoredToken(true);
                                    mark('cloud');
                                    setStepIdx(1);
                                }}
                            />
                        </div>
                    )}

                    {/* ===== SCREEN 2: NAME, REGION & SIZE ===== */}
                    {step.id === 'plan' && (
                        <div>
                            {/* One name field, not two. The old wizard had
                                a "Server name" on step 1 that was typed and
                                thrown away, plus a separate relay-pack name
                                on step 6 that lived only in React state —
                                so two relays were indistinguishable in the
                                picker and every share staged to the same
                                filename. */}
                            <Label>{t('wiz.plan.name.label')}</Label>
                            <Input
                                placeholder={t('wiz.plan.name.default')}
                                value={nickname}
                                onChange={(e) => setNickname(e.target.value)}
                            />
<div style={{ height: 16 }} />

                            {loadingOptions && (
                                <div
                                    style={{
                                        textAlign: 'center',
                                        padding: 20,
                                        color: 'var(--muted)',
                                        fontSize: 13,
                                    }}
                                >
                                    {t('wiz.plan.loading')}
                                </div>
                            )}

                            {/* Servers already on the account */}
                            {!loadingOptions && existingServers.length > 0 && (
                                <>
                                    <SubHead>{t('wiz.plan.existing.title')}</SubHead>
                                    <div
                                        style={{
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: 8,
                                            marginBottom: 10,
                                        }}
                                    >
                                        {existingServers.map((srv) => {
                                            const sel = useExisting === srv.id;
                                            return (
                                                <button
                                                    key={srv.id}
                                                    onClick={() =>
                                                        setUseExisting(
                                                            sel ? null : srv.id,
                                                        )
                                                    }
                                                    style={optionStyle(
                                                            sel,
                                                            '#4caf50',
                                                            'rgba(76,175,80,0.10)',
                                                        )}
                                                >
                                                    <div style={{ flex: 1 }}>
                                                        <div
                                                            style={{
                                                                display: 'flex',
                                                                alignItems: 'center',
                                                                gap: 6,
                                                            }}
                                                        >
                                                            <span
                                                                style={{
                                                                    fontSize: 14,
                                                                    fontWeight: 600,
                                                                }}
                                                            >
                                                                {srv.name}
                                                            </span>
                                                            <Badge tone={srv.status === 'running' ? 'good' : 'neutral'} size="sm" icon={false}>
                                                                <span dir="ltr">{srv.status}</span>
                                                            </Badge>
                                                        </div>
                                                        <div
                                                            style={{
                                                                fontSize: 11,
                                                                color: 'var(--muted)',
                                                                marginTop: 2,
                                                            }}
                                                        >
                                                            {srv.server_type.toUpperCase()}{' '}
                                                            · {srv.region} ·{' '}
                                                            {srv.public_ip}
                                                        </div>
                                                    </div>
                                                </button>
                                            );
                                        })}
                                    </div>
                                    <div
                                        style={{
                                            fontSize: 10,
                                            color: 'var(--muted)',
                                            marginBottom: 14,
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t('wiz.plan.existing.note')}
                                    </div>
                                </>
                            )}

                            {/* New-server sizes. Strictly dominated plans
                                are filtered out upstream — a worse machine
                                for more money is noise the user has to
                                spot by hand. */}
                            {!loadingOptions &&
                                serverOptions.length > 0 &&
                                !useExisting && (
                                    <>
                                        {existingServers.length > 0 && (
                                            <SubHead>
                                                {t('wiz.plan.new.title')}
                                            </SubHead>
                                        )}
                                        <div
                                            style={{
                                                display: 'flex',
                                                flexDirection: 'column',
                                                gap: 8,
                                                marginBottom: 14,
                                            }}
                                        >
                                            {serverOptions.map((opt, i) => {
                                                const sel = serverType === opt.id;
                                                return (
                                                    <button
                                                        key={opt.id}
                                                        onClick={() => {
                                                            setUseExisting(null);
                                                            setServerType(opt.id);
                                                        }}
                                                        style={optionStyle(
                                                            sel,
                                                            'var(--gold)',
                                                            'rgba(201,162,58,0.10)',
                                                        )}
                                                    >
                                                        <div style={{ flex: 1 }}>
                                                            <div
                                                                style={{
                                                                    display: 'flex',
                                                                    alignItems:
                                                                        'center',
                                                                    gap: 6,
                                                                }}
                                                            >
                                                                <span
                                                                    style={{
                                                                        fontSize: 14,
                                                                        fontWeight: 600,
                                                                    }}
                                                                >
                                                                    {opt.id.toUpperCase()}
                                                                </span>
                                                                {i === 0 && (
                                                                    <Badge tone="gold" size="sm">
                                                                        {t('wiz.plan.badge.best')}
                                                                    </Badge>
                                                                )}
                                                            </div>
                                                            <div
                                                                style={{
                                                                    fontSize: 12,
                                                                    color: 'var(--muted)',
                                                                    marginTop: 2,
                                                                }}
                                                            >
                                                                {fmt(
                                                                    t('wiz.plan.spec'),
                                                                    {
                                                                        cpus: readerNum(opt.cpus),
                                                                        mem: readerNum(opt.memory_gb),
                                                                        disk: readerNum(opt.disk_gb),
                                                                    },
                                                                )}
                                                            </div>
                                                            <div style={{ fontSize: 12, color: 'var(--muted)' }}>
                                                                {t('wiz.plan.traffic')}
                                                            </div>
                                                        </div>
                                                        <div
                                                            style={{
                                                                fontSize: 15,
                                                                fontWeight: 700,
                                                                color: sel
                                                                    ? 'var(--gold)'
                                                                    : 'var(--fg)',
                                                                whiteSpace: 'nowrap',
                                                            }}
                                                        >
                                                            {fmt(
                                                                t('wiz.plan.price'),
                                                                {
                                                                    eur: readerNum(opt.monthly_eur.toFixed(2)),
                                                                },
                                                            )}
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </>
                                )}

                            {/* A failed catalogue fetch used to be
                                invisible: the hardcoded default stayed
                                selected and Next stayed enabled, so the
                                user shipped a dead server type to the
                                provisioner. */}
                            {!loadingOptions &&
                                serverOptions.length === 0 &&
                                existingServers.length === 0 && (
                                    <EmptyHint>{t('wiz.plan.empty')}</EmptyHint>
                                )}

                            {/* Opt-in transport families. Hidden once the
                                box exists: the family set is baked into
                                the server at build time and cannot be
                                changed from here. */}
                            {!alreadyProvisioned && (
                                <MoreWaysToConnect
                                    t={t}
                                    profileSlug={toolboxProfile}
                                    open={moreWaysOpen}
                                    onToggleOpen={() => setMoreWaysOpen((o) => !o)}
                                    selected={extraFamilies}
                                    disabled={busy}
                                    onChange={(family, on) => {
                                        const next = toggleExtraFamily(
                                            toolboxProfile,
                                            extraFamilies,
                                            family,
                                            on,
                                        );
                                        setExtraFamilies(next);
                                        if (operatorId) {
                                            rememberExtraFamilies(
                                                operatorId,
                                                toolboxProfile,
                                                next,
                                            );
                                        }
                                    }}
                                />
                            )}

                            {useExisting && (
                                <div
                                    style={{
                                        fontSize: 13,
                                        color: 'var(--muted)',
                                        margin: '8px 0 14px',
                                        lineHeight: 1.5,
                                    }}
                                >
                                    {t('wiz.plan.footnote.existing')}
                                </div>
                            )}

                            <NavRow
                                t={t}
                                backLabel={t('wiz.nav.back')}
                                onBack={() => setStepIdx(0)}
                                nextDisabled={
                                    busy ||
                                    loadingOptions ||
                                    !operatorId ||
                                    (!serverOptions.some(
                                        (o) => o.id === serverType,
                                    ) &&
                                        !useExisting)
                                }
                                nextLabel={t('wiz.plan.next')}
                                onNext={async () => {
                                    if (!operatorId) return;
                                    if (live) {
                                        await run(() =>
                                            Wizard.setOperatorNickname(
                                                operatorId,
                                                nickname.trim(),
                                            ),
                                        );
                                    }
                                    rememberExtraFamilies(
                                        operatorId,
                                        toolboxProfile,
                                        extraFamilies,
                                    );
                                    mark('plan');
                                    setStepIdx(2);
                                }}
                            />
                        </div>
                    )}

                    {/* ===== SCREEN 3: BUILD ===== */}
                    {step.id === 'build' && (
                        <div>
                            {/* Resumed straight into a build that would
                                rent a server. The consent tap on screen 2
                                belongs to a session that is gone, and so
                                does the "use a server I already own"
                                choice — auto-starting here would silently
                                create a SECOND billable box. */}
                            {awaitingBuildConsent && stage === 'idle' && !recoveryUnavailable && (
                                <SetupRecoveryCard
                                    t={t}
                                    rec={recovery}
                                    busy={recoveryBusy}
                                    error={recoveryError}
                                    outcome={recoveryOutcome}
                                    onButton={(b) => void onRecoveryButton(b)}
                                    onRetry={
                                        recoveryRetryButton
                                            ? () => void onRecoveryButton(recoveryRetryButton)
                                            : undefined
                                    }
                                    onDone={recoveryLeaving ? () => resetAfterCancel() : undefined}
                                    onReview={() => {
                                        setAwaitingBuildConsent(false);
                                        setStepIdx(1);
                                    }}
                                />
                            )}
                            {awaitingBuildConsent && stage === 'idle' && recoveryUnavailable && (
                                <Card
                                    style={{
                                        marginBottom: 14,
                                        background: 'var(--surface-2)',
                                    }}
                                >
                                    <div
                                        style={{
                                            fontSize: 13,
                                            fontWeight: 600,
                                            marginBottom: 4,
                                        }}
                                    >
                                        {t('wiz.build.resume.title')}
                                    </div>
                                    <p
                                        style={{
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            margin: '0 0 10px',
                                            lineHeight: 1.55,
                                        }}
                                    >
                                        {t('wiz.build.resume.body')}
                                    </p>
                                    <div
                                        style={{
                                            display: 'flex',
                                            gap: 8,
                                            flexWrap: 'wrap',
                                        }}
                                    >
                                        <Button
                                            onClick={() => {
                                                setAwaitingBuildConsent(false);
                                            }}
                                        >
                                            {t('wiz.build.resume.start')}
                                        </Button>
                                        <Button
                                            variant="ghost"
                                            onClick={() => {
                                                setAwaitingBuildConsent(false);
                                                setStepIdx(1);
                                            }}
                                        >
                                            {t('wiz.build.resume.review')}
                                        </Button>
                                    </div>
                                </Card>
                            )}

                            {/* Sub-stage checklist. One screen, one chain,
                                no per-phase buttons — the consent tap
                                happened on screen 2. */}
                            <ul
                                style={{
                                    listStyle: 'none',
                                    padding: 0,
                                    margin: '0 0 14px',
                                    display: 'flex',
                                    flexDirection: 'column',
                                    gap: 8,
                                }}
                            >
                                {BUILD_STAGES.map((s, i) => {
                                    const done =
                                        stage === 'done' ||
                                        (stageIdx >= 0 && i < stageIdx);
                                    const active = stage === s.id;
                                    const failed =
                                        stage === 'failed' && failedAt === s.id;
                                    return (
                                        <li
                                            key={s.id}
                                            data-stage={s.id}
                                            style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: 10,
                                                fontSize: 14,
                                                color: done || active
                                                    ? 'var(--fg)'
                                                    : 'var(--muted)',
                                            }}
                                        >
                                            <StateIcon
                                                state={failed ? 'bad' : done ? 'ok' : active ? 'busy' : 'none'}
                                                size={20}
                                            />
                                            <span>{t(buildStageKey(s.id, s.key, !!useExisting))}</span>
                                        </li>
                                    );
                                })}
                            </ul>

                            {building && (
                                <div
                                    style={{
                                        fontSize: 11,
                                        color: 'var(--muted)',
                                        marginBottom: 10,
                                        lineHeight: 1.5,
                                    }}
                                >
                                    {t('wiz.build.hint')}
                                </div>
                            )}

                            {/* The raw log is for someone helping (H-52). */}
                            {buildLog.length > 0 && stage !== 'done' && (
                                <Disclosure summary={t('ui.details')} dataButton="build-log">
                                    <EventList events={buildLog} />
                                </Disclosure>
                            )}

                            {/* Helper-IP repair. Reached only when the
                                automatic detect + one retry both failed;
                                the alternative (what this replaces) was a
                                permanently disabled button with no visible
                                cause. */}
                            {helperIpRepair !== null && (
                                <Card
                                    style={{
                                        marginTop: 12,
                                        background: 'var(--surface-2)',
                                    }}
                                >
                                    <div
                                        style={{
                                            fontSize: 13,
                                            fontWeight: 600,
                                            marginBottom: 4,
                                        }}
                                    >
                                        {t('wiz.helperip.title')}
                                    </div>
                                    <p
                                        style={{
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            margin: '0 0 10px',
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t('wiz.helperip.body')}
                                    </p>
                                    <Label>{t('wiz.helperip.label')}</Label>
                                    <Input
                                        value={helperIpRepair}
                                        placeholder={t('wiz.helperip.placeholder')}
                                        invalid={
                                            helperIpRepair !== '' &&
                                            !isValidIp(helperIpRepair)
                                        }
                                        onChange={(e) =>
                                            setHelperIpRepair(e.target.value)
                                        }
                                        style={{ marginBottom: 8 }}
                                    />
                                    {helperIpRepair !== '' &&
                                        !isValidIp(helperIpRepair) && (
                                            <div
                                                style={{
                                                    fontSize: 11,
                                                    color: 'var(--red)',
                                                    marginBottom: 8,
                                                }}
                                            >
                                                {t('wiz.helperip.invalid')}
                                            </div>
                                        )}
                                    <Button
                                        disabled={
                                            busy || !isValidIp(helperIpRepair)
                                        }
                                        onClick={async () => {
                                            if (!operatorId) return;
                                            const ok = await run(() =>
                                                // Returns nothing (null): see onCancelPress.
                                                Wizard.setHelperIp(
                                                    operatorId,
                                                    helperIpRepair.trim(),
                                                    'manual',
                                                ).then(() => true),
                                            );
                                            if (ok === null) return;
                                            setHelperIpRepair(null);
                                            setStage('idle'); // re-arms auto-start
                                        }}
                                    >
                                        {t('wiz.helperip.retry')}
                                    </Button>
                                </Card>
                            )}

                            {/* Failure. Every sub-stage is idempotent or
                                skipped when already done, so "Try again"
                                can safely re-enter the chain from the
                                top. */}
                            {stage === 'failed' && helperIpRepair === null && (
                                <div style={{ marginTop: 12 }}>
                                    <p
                                        style={{
                                            fontSize: 13,
                                            color: 'var(--fg)',
                                            margin: '0 0 10px',
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t(
                                            (failedAt && FAIL_KEY[failedAt]) ||
                                                'wiz.build.fail.provision',
                                        )}
                                    </p>
                                    <div
                                        style={{
                                            display: 'flex',
                                            gap: 8,
                                            flexWrap: 'wrap',
                                        }}
                                    >
                                        {failedAt === 'profile' ? (
                                            <Button
                                                variant="secondary"
                                                leading="back"
                                                onClick={() => {
                                                    setStage('idle');
                                                    setFailedAt(null);
                                                    setStepIdx(1);
                                                }}
                                            >
                                                {t('wiz.build.back_to_plan')}
                                            </Button>
                                        ) : null}
                                        <Button
                                            disabled={busy}
                                            onClick={() => { void runBuild(); }}
                                        >
                                            {t('wiz.build.retry')}
                                        </Button>
                                        {/* The relay itself exists and is
                                            provisioned by this point — only
                                            the shareable pack is missing,
                                            and the relay home can rebuild
                                            it. Don't strand the user here. */}
                                        {failedAt === 'share' && operatorId && (
                                            <Button
                                                variant="ghost"
                                                onClick={() => onDone(operatorId)}
                                            >
                                                {t('wiz.build.finish_anyway')}
                                            </Button>
                                        )}
                                    </div>
                                </div>
                            )}

                            {stage === 'done' && (
                                <div data-testid="wizard-done" style={{ display: 'grid', gap: 16, justifyItems: 'center', textAlign: 'center' }}>
                                    <StateIcon state="ok" size={56} />
                                    <h2
                                        style={{
                                            fontFamily: 'var(--font-display)',
                                            fontSize: 24,
                                            fontWeight: 500,
                                            margin: 0,
                                            color: 'var(--fg)',
                                        }}
                                    >
                                        {t('wiz.build.done.eyebrow')}
                                    </h2>
                                    {/* The words the family may be asked to
                                        check when they add the file (C-09,
                                        H-53). Both sets: one is not a
                                        translation of the other. */}
                                    {fp && (fp.en_words || fp.fa_words) && (
                                        <div
                                            data-testid="wizard-keys"
                                            style={{
                                                width: '100%',
                                                textAlign: 'start',
                                                background: 'var(--surface-2)',
                                                borderRadius: 'var(--r-card)',
                                                padding: '14px 16px',
                                                display: 'grid',
                                                gap: 10,
                                            }}
                                        >
                                            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)' }}>{t('wiz.keys.title')}</div>
                                            <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>{t('wiz.keys.line')}</div>
                                            {fp.en_words && <WordChips words={fp.en_words} lang="en" label={t('wiz.keys.en_label')} />}
                                            {fp.fa_words && <WordChips words={fp.fa_words} lang="fa" label={t('wiz.keys.fa_label')} />}
                                        </div>
                                    )}
                                    {operatorId && (
                                        <div style={{ display: 'grid', gap: 4, justifyItems: 'center' }}>
                                            <Button leading="plus" onClick={() => onDone(operatorId, true)} dataButton="add-first-person">
                                                {t('wiz.build.done.add')}
                                            </Button>
                                            <Button variant="link" onClick={() => onDone(operatorId)} dataButton="open-relay">
                                                {t('wiz.build.done.open')}
                                            </Button>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                </Card>

                {/* Cancel & clean up. Deliberately kept: wizard state is
                    persisted in the DB and survives relaunch, so this is
                    the only way to abandon a half-built relay and stop it
                    being resumed forever. */}
                {operatorId != null && !building && stepIdx > 0 && stage !== 'done' && (
                    <div>
                        <Button variant="link" onClick={() => void onCancelPress()} dataButton="wizard-cancel" style={{ color: 'var(--red)' }}>
                            {t('wiz.cancel')}
                        </Button>
                    </div>
                )}
                {onRestore && stepIdx === 0 && !resumeOperatorId && (
                    <div>
                        <Button variant="link" onClick={onRestore} dataButton="restore-link">
                            {dt('pub.restore.link.wizard')}
                        </Button>
                    </div>
                )}
                {confirm.node}
                {cancelRec && (
                    <CancelSetupSheet
                        t={t}
                        rec={cancelRec}
                        busy={cancelBusy}
                        outcome={cancelOutcome}
                        error={cancelError}
                        onDelete={() => void onCancelDelete()}
                        onKeep={() => void onCancelKeep()}
                        onCheckAgain={async () => {
                            if (operatorId == null || !live) return;
                            try {
                                setCancelRec(await Wizard.setupRecovery(operatorId));
                            } catch (e) {
                                setCancelError(explainFailure(t, e));
                            }
                        }}
                        onClose={() => setCancelRec(null)}
                        onDone={() => resetAfterCancel()}
                    />
                )}
                {cancelDestroyOpen && operatorId != null && (
                    <RelayDestroySheet
                        t={t}
                        target={{ operatorId, name: nickname.trim() || `#${operatorId}`, where: '' }}
                        onClose={(removed) => {
                            setCancelDestroyOpen(false);
                            if (removed) resetAfterCancel();
                        }}
                    />
                )}
            </div>
        </div>
    );
}

// ---- Helpers ----

/** Shared style for the "pick one" option rows on screen 2. Existing
 *  servers get the green accent (reusing something you already pay for),
 *  new sizes get the gold one. */
function optionStyle(selected: boolean, accent: string, tint: string) {
    return {
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 10,
        padding: '12px 14px',
        background: selected ? tint : 'var(--surface-2)',
        border: `1.5px solid ${selected ? accent : 'var(--line-soft)'}`,
        borderRadius: 'var(--r-tile)',
        cursor: 'pointer',
        color: 'var(--fg)',
        fontFamily: 'var(--font-body)',
        textAlign: 'start' as const,
    };
}

// StepStrip — three equal segments with the current step's title. It
// replaces both the desktop side rail and the phone-only step pager:
// at seven steps those were worth 220px and a whole component, at three
// they are not.
function StepStrip({
    stepIdx,
    completed,
    locked,
    onJump,
    t,
    ready,
}: {
    stepIdx: number;
    completed: Record<StepId, boolean>;
    /** True while the build chain is running — jumping mid-provision
     *  would leave the chain writing into a screen the user left. */
    locked: boolean;
    onJump: (i: number) => void;
    t: (k: string) => string;
    /** The relay is built: the step name says "Ready", not "Building". */
    ready?: boolean;
}) {
    // A compact stepper: three dots, then the current step's name. The
    // dots are buttons (a done step can be revisited); each has a 44 px
    // hit area around a small dot.
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 8, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0, marginInlineStart: -16 }}>
                {STEPS.map((s, i) => {
                    const active = i === stepIdx;
                    const done = completed[s.id];
                    const reachable = !locked && (i < stepIdx || done);
                    return (
                        <button
                            key={s.id}
                            type="button"
                            disabled={!reachable || active}
                            onClick={() => onJump(i)}
                            title={t(s.titleKey)}
                            aria-label={`${fmt(t('wiz.step.label'), {
                                n: i + 1,
                                total: STEPS.length,
                            })} — ${t(s.titleKey)}`}
                            aria-current={active ? 'step' : undefined}
                            data-button={`wizard-step-${i + 1}`}
                            style={{
                                appearance: 'none',
                                background: 'transparent',
                                border: 0,
                                padding: 0,
                                // 44 px, the smallest comfortable tap (E.1.5).
                                inlineSize: 44,
                                blockSize: 44,
                                display: 'grid',
                                placeItems: 'center',
                                cursor: reachable && !active ? 'pointer' : 'default',
                            }}
                        >
                            <span
                                aria-hidden
                                style={{
                                    inlineSize: active ? 12 : 10,
                                    blockSize: active ? 12 : 10,
                                    borderRadius: '50%',
                                    background: active ? 'var(--gold)' : done ? 'var(--green)' : 'transparent',
                                    border: `2px solid ${active ? 'var(--gold)' : done ? 'var(--green)' : 'var(--line)'}`,
                                }}
                            />
                        </button>
                    );
                })}
            </div>
            <h2
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 18,
                    fontWeight: 500,
                    margin: 0,
                    minWidth: 0,
                    color: 'var(--fg)',
                    lineHeight: 1.3,
                }}
            >
                {ready ? t('wiz.step.build.ready') : t(STEPS[stepIdx]?.titleKey ?? 'wiz.step.cloud.title')}
            </h2>
        </div>
    );
}

/** Four check words as chips: the UI's own language first and large. */
function WordChips({ words, lang, label }: { words: string; lang: 'en' | 'fa'; label: string }) {
    const list = words.split(/\s+/).filter(Boolean);
    const { density } = useDensity();
    // Even rows (4 across, 2 on a phone): no word alone on a line.
    const cols = density === 'phone' ? 2 : 4;
    return (
        <div
            role="group"
            aria-label={label}
            lang={lang}
            dir={lang === 'fa' ? 'rtl' : 'ltr'}
            style={{ display: 'flex', gap: 6, alignItems: 'flex-start' }}
        >
            <span aria-hidden style={{ color: 'var(--muted)', display: 'inline-flex', marginInlineEnd: 2, paddingBlockStart: 6 }}>
                <Icon name="globe" size={14} />
            </span>
            <span style={{ flex: 1, minWidth: 0, display: 'grid', gridTemplateColumns: `repeat(${cols}, minmax(max-content, 1fr))`, gap: 6 }}>
            {list.map((w, i) => (
                <span
                    key={i}
                    style={{
                        textAlign: 'center',
                        whiteSpace: 'nowrap',
                        padding: '4px 6px',
                        borderRadius: 'var(--r-pill)',
                        background: 'var(--surface-3)',
                        color: 'var(--fg)',
                        fontSize: 15,
                        fontFamily: lang === 'fa' ? 'var(--font-fa, var(--font-body))' : 'var(--font-body)',
                    }}
                >
                    {w}
                </span>
            ))}
            </span>
        </div>
    );
}

function Label({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                fontSize: 13,
                fontWeight: 600,
                color: 'var(--muted)',
                margin: '4px 0 6px',
            }}
        >
            {children}
        </div>
    );
}

function SubHead({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                fontSize: 14,
                fontWeight: 600,
                color: 'var(--fg)',
                marginBottom: 6,
            }}
        >
            {children}
        </div>
    );
}

function EmptyHint({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                background: 'var(--surface-2)',
                border: '1px dashed var(--line)',
                borderRadius: 'var(--r-tile)',
                padding: 14,
                color: 'var(--muted)',
                fontSize: 13,
                marginBottom: 14,
            }}
        >
            {children}
        </div>
    );
}

function NavRow({
    t,
    backLabel,
    onBack,
    nextDisabled,
    nextLabel,
    onNext,
}: {
    t: (k: string) => string;
    backLabel: string;
    onBack: () => void;
    nextDisabled: boolean;
    nextLabel?: string;
    onNext: () => void;
}) {
    return (
        <div
            style={{
                display: 'flex',
                gap: 8,
                justifyContent: 'space-between',
                marginTop: 8,
            }}
        >
            <Button variant="ghost" leading="back" onClick={onBack} dataButton="wiz-back">
                {backLabel}
            </Button>
            <Button
                disabled={nextDisabled}
                onClick={onNext}
                dataButton="wiz-next"
                trailing={<Icon name="chevron" size={16} />}
            >
                {nextLabel ?? t('wiz.nav.next')}
            </Button>
        </div>
    );
}

function EventList({ events }: { events: ProgressEvent[] }) {
    const listRef = useRef<HTMLUListElement | null>(null);
    useEffect(() => {
        const el = listRef.current;
        if (el) el.scrollTop = el.scrollHeight;
    }, [events.length]);
    if (events.length === 0) return null;
    return (
        <ul
            ref={listRef}
            style={{
                listStyle: 'none',
                margin: '10px 0 0',
                maxHeight: 200,
                overflow: 'auto',
                background: 'var(--bg)',
                borderRadius: 'var(--radius-md)',
                padding: 10,
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                color: 'var(--muted)',
                border: '1px solid var(--line-soft)',
            }}
        >
            {events.map((ev, i) => (
                <li key={i} style={{ whiteSpace: 'pre-wrap', marginBottom: 4 }}>
                    [{ev.step || ev.phase}] {ev.message || ev.detail}
                    {ev.pct !== undefined && ` · ${ev.pct}%`}
                </li>
            ))}
        </ul>
    );
}

/** Harness only: `?recover=<state>` previews the recovery card. */
function harnessRecoverState(): SetupRecovery['state'] | null {
    if (typeof window === 'undefined') return null;
    const q = new URLSearchParams(window.location.search || window.location.hash.split('?')[1] || '');
    const v = q.get('recover');
    const states: SetupRecovery['state'][] = [
        'none',
        'running',
        'finished_unsaved',
        'server_running',
        'nothing_billing',
        'unknown',
    ];
    return v && (states as string[]).includes(v) ? (v as SetupRecovery['state']) : null;
}

function mockDestroyReport(): DestroyReport {
    return {
        server_deleted: true,
        ssh_key_deleted: true,
        firewall_deleted: true,
        local_removed: false,
        warnings: [],
        addresses: [],
        retry_needed: false,
    };
}

/**
 * A new relay may start with the hosting key another relay saved when
 * the person typed no key of their own and this relay has none yet.
 */
export function canReuseSaved(
    saved: { operator_id: number; nickname: string } | null,
    typed: string,
    hasOwn: boolean,
): boolean {
    return saved != null && !typed.trim() && !hasOwn;
}

/** The line under the key box when a saved key will be used. */
export function savedKeyLine(t: (k: string) => string, nickname: string): string {
    return nickname.trim()
        ? fmt(t('wiz.provider.token.saved_other.named'), { relay: nickname.trim() })
        : t('wiz.provider.token.saved_other');
}

/**
 * The question asked before an unfinished relay is only forgotten.
 * When the setup never made anything, say so; the warning about a
 * server that may still be charged is for when Daal could not look.
 */
export function localCancelKey(rec: SetupRecovery | null): string {
    return rec && rec.state === 'none' && !rec.check_error
        ? 'wiz.cancel.confirm.nothing'
        : 'wiz.cancel.confirm';
}

/**
 * The label of a build step. When the setup runs on a server that
 * already exists (the person's own, or one a stopped setup left), no
 * server is rented, so the step must not say "Renting".
 */
export function buildStageKey(id: string, key: string, onExistingServer: boolean): string {
    return id === 'provision' && onExistingServer ? 'wiz.build.stage.provision.existing' : key;
}

