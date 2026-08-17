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

import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
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
} from './wizardCommands';
import { RELAYPACK_PHASE } from './phase';
import { ensureHelperIp, reAllowlist, detectPublicIp, isValidIp } from './helperIp';
import { isHarnessActive } from '../harness/scenarios';
import { isTauriRuntime } from '../backends';
import { invoke } from '@tauri-apps/api/core';
import {
    Button,
    Card,
    Input,
    StatusLight,
    StatusPill,
} from '../design/primitives';
import { useDensity } from '../design/DensityProvider';

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
    onDone: (operatorId: number) => void;
    /** User backed out of screen 1 with no relay created. */
    onCancel: () => void;
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
        blurbKey: 'wiz.step.cloud.blurb',
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
}: Props) {
    const { density } = useDensity();
    const isPhone = density === 'phone';
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
    // Empty array = use the profile's DefaultEnabled candidates
    // (vless-reality, websocket-tls, naive, hysteria2).
    const enabledFamilies = useMemo<string[]>(() => [], []);

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
            setError(String(e));
            setFailedAt(s);
            setStage('failed');
            const code = classifyPublisherError(e);
            if (code === 'E_HELPER_IP_MISSING' || code === 'E_HELPER_IP_STALE') {
                const guess = await detectPublicIp();
                setHelperIpRepair(guess?.ip ?? '');
            }
            return STAGE_FAILED;
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
    const runBuild = async () => {
        if (!operatorId) return;
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
                              Wizard.provisionRun(opId, useExisting ?? undefined),
                          )
                        : fakeProgress('provision', [
                              ['create server', 10],
                              ['await SSH', 40],
                              ['toolbox bring-up', 80],
                              ['done', 100],
                          ]),
                );
                if (p === STAGE_FAILED) return;
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
            // Let the success state actually register before the handoff
            // — a card that renders for one frame reads as a glitch.
            await new Promise((r) => setTimeout(r, 1200));
            onDone(opId);
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
                maxWidth: 720,
                margin: '0 auto',
                // On phones the MobileShell <main> already provides the
                // horizontal gutter; doubling it crushes the content.
                padding: isPhone ? '4px 0 16px' : 'var(--gutter)',
                color: 'var(--fg)',
            }}
        >
            <header style={{ marginBottom: 14 }}>
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        letterSpacing: '0.18em',
                        textTransform: 'uppercase',
                        color: 'var(--gold-warm)',
                    }}
                >
                    {t('wiz.eyebrow')}
                </div>
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: isPhone ? 20 : 24,
                        margin: '6px 0',
                    }}
                >
                    {t('wiz.heading')}
                </h1>
                <p style={{ color: 'var(--muted)', fontSize: 13, margin: 0 }}>
                    {t('wiz.intro.3step')}
                </p>
            </header>

            {/* Three screens fit in a strip. The old build had a 220px
                desktop side rail and a separate phone pager component
                for seven steps; neither earns its space at three. */}
            <StepStrip
                stepIdx={stepIdx}
                completed={completed}
                locked={building}
                onJump={setStepIdx}
                t={t}
            />

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <Card>
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'baseline',
                            gap: 12,
                            justifyContent: 'space-between',
                            flexWrap: 'wrap',
                        }}
                    >
                        <h2
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: isPhone ? 17 : 20,
                                margin: isPhone ? '0 0 4px' : '4px 0',
                            }}
                        >
                            {t(step.titleKey)}
                        </h2>
                        {!live && (
                            <StatusPill tone="warn" dotless>
                                {t('wiz.harness.preview')}
                            </StatusPill>
                        )}
                    </div>
                    <p
                        style={{
                            color: 'var(--muted)',
                            fontSize: 13,
                            margin: '4px 0 14px',
                            maxInlineSize: '64ch',
                        }}
                    >
                        {t(step.blurbKey)}
                    </p>

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
                            <Label>{t('wiz.provider.label')}</Label>
                            <div
                                style={{
                                    display: 'grid',
                                    gridTemplateColumns:
                                        'repeat(auto-fit, minmax(140px, 1fr))',
                                    gap: 8,
                                    marginBottom: 14,
                                }}
                            >
                                {CLOUD_PROVIDERS.map((p) => {
                                    const sel = provider === p.id;
                                    const available = p.id === 'hetzner';
                                    return (
                                        <button
                                            key={p.id}
                                            disabled={!available}
                                            onClick={() => {
                                                if (!available) return;
                                                setProvider(p.id);
                                                setServerType(p.defaultServer);
                                                setServerOptions([]);
                                                setUseExisting(null);
                                            }}
                                            style={{
                                                background: sel
                                                    ? 'rgba(201,162,58,0.10)'
                                                    : 'var(--surface-2)',
                                                border: `1px solid ${
                                                    sel
                                                        ? 'var(--gold)'
                                                        : 'var(--line-soft)'
                                                }`,
                                                color: available
                                                    ? 'var(--fg)'
                                                    : 'var(--muted)',
                                                opacity: available ? 1 : 0.45,
                                                padding: '10px 12px',
                                                borderRadius: 'var(--r-tile)',
                                                cursor: available
                                                    ? 'pointer'
                                                    : 'default',
                                                textAlign: 'start',
                                                fontFamily: 'var(--font-body)',
                                            }}
                                        >
                                            <div
                                                style={{
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    gap: 6,
                                                }}
                                            >
                                                <span
                                                    style={{
                                                        fontSize: 13,
                                                        fontWeight: 600,
                                                    }}
                                                >
                                                    {t(p.labelKey)}
                                                </span>
                                                {p.recommended && (
                                                    <span
                                                        style={{
                                                            fontSize: 9,
                                                            fontWeight: 600,
                                                            color: 'var(--gold)',
                                                            border: '1px solid var(--gold)',
                                                            borderRadius: 4,
                                                            padding: '1px 5px',
                                                            letterSpacing: 0.5,
                                                        }}
                                                    >
                                                        ★
                                                    </span>
                                                )}
                                            </div>
                                            <div
                                                style={{
                                                    fontFamily: 'var(--font-mono)',
                                                    fontSize: 10,
                                                    color: 'var(--muted)',
                                                    marginTop: 4,
                                                }}
                                            >
                                                {available
                                                    ? t(p.regionKey)
                                                    : t('wiz.provider.soon')}
                                            </div>
                                        </button>
                                    );
                                })}
                            </div>

                            {/* Signup link + "you only need an account" tip.
                                Users routinely create a server on the
                                provider's own website first and then get
                                billed twice. */}
                            {providerDef.signupUrl && (
                                <div style={{ marginBottom: 14 }}>
                                    <button
                                        onClick={() =>
                                            openExternal(providerDef.signupUrl)
                                        }
                                        style={{
                                            display: 'block',
                                            fontSize: 12,
                                            color: 'var(--gold)',
                                            marginBottom: 8,
                                            background: 'none',
                                            border: 'none',
                                            padding: 0,
                                            cursor: 'pointer',
                                            fontFamily: 'var(--font-body)',
                                            textAlign: 'start',
                                        }}
                                    >
                                        {t('wiz.provider.signup')}
                                    </button>
                                    <div
                                        style={{
                                            background: 'rgba(201,162,58,0.06)',
                                            border: '1px solid rgba(201,162,58,0.15)',
                                            borderRadius: 'var(--r-tile)',
                                            padding: '10px 12px',
                                            fontSize: 12,
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        <div
                                            style={{
                                                fontWeight: 600,
                                                marginBottom: 4,
                                                color: 'var(--gold)',
                                                fontSize: 11,
                                                textTransform: 'uppercase' as const,
                                                letterSpacing: 0.5,
                                            }}
                                        >
                                            {t('wiz.provider.vps.tip.title')}
                                        </div>
                                        <div style={{ color: 'var(--fg)' }}>
                                            {t('wiz.provider.vps.tip.body')}
                                        </div>
                                    </div>
                                </div>
                            )}

                            <Label>
                                {fmt(t('wiz.provider.token'), {
                                    provider: t(providerDef.labelKey),
                                })}
                            </Label>
                            <Input
                                type="password"
                                placeholder={t(providerDef.tokenHintKey)}
                                value={token}
                                onChange={(e) => setToken(e.target.value)}
                                style={{ marginBottom: 6 }}
                            />
                            <div
                                style={{
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: 10,
                                    color: 'var(--dim)',
                                    marginBottom: 14,
                                }}
                            >
                                {hasStoredToken
                                    ? t('wiz.provider.token.stored')
                                    : fmt(t('wiz.provider.token.help'), {
                                          hint: t(providerDef.tokenHintKey),
                                      })}
                            </div>

                            <NavRow
                                t={t}
                                backLabel={t('wiz.nav.cancel')}
                                onBack={onCancel}
                                nextDisabled={
                                    busy || (!token.trim() && !hasStoredToken)
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
                                        Wizard.storeCloudToken(
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
                            <div
                                style={{
                                    fontSize: 10,
                                    color: 'var(--dim)',
                                    fontFamily: 'var(--font-mono)',
                                    margin: '4px 0 16px',
                                }}
                            >
                                {t('wiz.plan.name.help')}
                            </div>

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
                                                            <span
                                                                style={{
                                                                    fontSize: 9,
                                                                    fontWeight: 600,
                                                                    color:
                                                                        srv.status ===
                                                                        'running'
                                                                            ? '#4caf50'
                                                                            : 'var(--muted)',
                                                                    border: `1px solid ${
                                                                        srv.status ===
                                                                        'running'
                                                                            ? '#4caf50'
                                                                            : 'var(--line-soft)'
                                                                    }`,
                                                                    borderRadius: 4,
                                                                    padding: '1px 5px',
                                                                    textTransform:
                                                                        'uppercase' as const,
                                                                }}
                                                            >
                                                                {srv.status}
                                                            </span>
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
                                                                    <span
                                                                        style={{
                                                                            fontSize: 9,
                                                                            fontWeight: 600,
                                                                            color: 'var(--gold)',
                                                                            border: '1px solid var(--gold)',
                                                                            borderRadius: 4,
                                                                            padding:
                                                                                '1px 5px',
                                                                            textTransform:
                                                                                'uppercase' as const,
                                                                        }}
                                                                    >
                                                                        {t(
                                                                            'wiz.plan.badge.best',
                                                                        )}
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div
                                                                style={{
                                                                    fontSize: 11,
                                                                    color: 'var(--muted)',
                                                                    marginTop: 2,
                                                                }}
                                                            >
                                                                {fmt(
                                                                    t('wiz.plan.spec'),
                                                                    {
                                                                        cpus: opt.cpus,
                                                                        mem: opt.memory_gb,
                                                                        disk: opt.disk_gb,
                                                                    },
                                                                )}
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
                                                                    eur: opt.monthly_eur.toFixed(
                                                                        2,
                                                                    ),
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

                            <div
                                style={{
                                    fontSize: 11,
                                    color: 'var(--muted)',
                                    marginBottom: 14,
                                    lineHeight: 1.5,
                                }}
                            >
                                {useExisting
                                    ? t('wiz.plan.footnote.existing')
                                    : t('wiz.plan.footnote.new')}
                            </div>

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
                            {awaitingBuildConsent && stage === 'idle' && (
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
                                            style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: 10,
                                                fontSize: 13,
                                                color: done || active
                                                    ? 'var(--fg)'
                                                    : 'var(--dim)',
                                            }}
                                        >
                                            <StatusLight
                                                tone={
                                                    failed
                                                        ? 'bad'
                                                        : done
                                                            ? 'good'
                                                            : active
                                                                ? 'warn'
                                                                : 'neutral'
                                                }
                                                size={8}
                                                pulse={active}
                                            />
                                            <span>{t(s.key)}</span>
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

                            <EventList events={buildLog} />

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
                                                Wizard.setHelperIp(
                                                    operatorId,
                                                    helperIpRepair.trim(),
                                                    'manual',
                                                ),
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
                                <Card
                                    style={{
                                        marginTop: 12,
                                        background: 'var(--surface-2)',
                                    }}
                                >
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 10,
                                            color: 'var(--dim)',
                                            letterSpacing: '0.18em',
                                            textTransform: 'uppercase',
                                        }}
                                    >
                                        {t('wiz.build.done.eyebrow')}
                                    </div>
                                    <div
                                        style={{
                                            fontSize: 14,
                                            color: 'var(--fg)',
                                            margin: '6px 0 12px',
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t('wiz.build.done.body')}
                                    </div>
                                    {operatorId && (
                                        <Button onClick={() => onDone(operatorId)}>
                                            {t('wiz.build.done.open')}
                                        </Button>
                                    )}
                                </Card>
                            )}

                            {/* Publisher fingerprint — recipients trust
                                your routes by recognising this, so it is
                                worth showing once even though nothing on
                                this screen asks the user to act on it. */}
                            {fp && fp.hex && (
                                <Card
                                    style={{
                                        marginTop: 12,
                                        background: 'var(--surface-2)',
                                    }}
                                >
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 10,
                                            color: 'var(--dim)',
                                            letterSpacing: '0.18em',
                                            textTransform: 'uppercase',
                                        }}
                                    >
                                        {t('wiz.keys.card.eyebrow')}
                                    </div>
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 12,
                                            color: 'var(--fg)',
                                            marginTop: 4,
                                            wordBreak: 'break-all',
                                        }}
                                    >
                                        {fp.hex}
                                    </div>
                                    {fp.en_words && (
                                        <div
                                            style={{
                                                fontFamily: 'var(--font-mono)',
                                                fontSize: 11,
                                                color: 'var(--muted)',
                                                marginTop: 8,
                                            }}
                                        >
                                            {fmt(t('wiz.keys.en'), {
                                                words: fp.en_words,
                                            })}
                                        </div>
                                    )}
                                    {fp.fa_words && (
                                        <div
                                            style={{
                                                fontFamily: 'var(--font-fa)',
                                                fontSize: 12,
                                                color: 'var(--muted)',
                                                marginTop: 2,
                                                direction: 'rtl',
                                            }}
                                        >
                                            {fmt(t('wiz.keys.fa'), {
                                                words: fp.fa_words,
                                            })}
                                        </div>
                                    )}
                                </Card>
                            )}
                        </div>
                    )}
                </Card>

                {/* Cancel & clean up. Deliberately kept: wizard state is
                    persisted in the DB and survives relaunch, so this is
                    the only way to abandon a half-built relay and stop it
                    being resumed forever. */}
                {operatorId != null && !building && (
                    <Button
                        variant="ghost"
                        onClick={async () => {
                            if (!window.confirm(t('wiz.cancel.confirm'))) return;
                            if (live) {
                                const ok = await run(() =>
                                    Wizard.cancelAndCleanup(operatorId),
                                );
                                if (ok === null) return;
                            }
                            setOperatorId(null);
                            setStepIdx(0);
                            setCompleted(NO_MARKS);
                            setStage('idle');
                            setFailedAt(null);
                            setFp(null);
                            setAlreadyProvisioned(false);
                            setAlreadySigned(false);
                            setHasStoredToken(false);
                            onCancel();
                        }}
                    >
                        {t('wiz.cancel')}
                    </Button>
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
}: {
    stepIdx: number;
    completed: Record<StepId, boolean>;
    /** True while the build chain is running — jumping mid-provision
     *  would leave the chain writing into a screen the user left. */
    locked: boolean;
    onJump: (i: number) => void;
    t: (k: string) => string;
}) {
    // Numbers, not sentences. The card heading directly below already
    // states the current step's title in full, so repeating it here only
    // bought a `nowrap` ellipsis ("Connect your clou…") and a strip wide
    // enough to shove the layout off screen. Three markers say where you
    // are; the accessible name still carries the real title for
    // screen-reader and long-press users.
    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                marginBottom: 14,
            }}
        >
            {STEPS.map((s, i) => {
                const active = i === stepIdx;
                const done = completed[s.id];
                const reachable = !locked && (i < stepIdx || done);
                return (
                    <Fragment key={s.id}>
                        {i > 0 && (
                            <div
                                aria-hidden
                                style={{
                                    flex: 1,
                                    height: 2,
                                    borderRadius: 1,
                                    background: done || active
                                        ? 'var(--green-dim)'
                                        : 'var(--line-soft)',
                                }}
                            />
                        )}
                        <button
                            disabled={!reachable || active}
                            onClick={() => onJump(i)}
                            title={t(s.titleKey)}
                            aria-label={`${fmt(t('wiz.step.label'), {
                                n: i + 1,
                                total: STEPS.length,
                            })} — ${t(s.titleKey)}`}
                            aria-current={active ? 'step' : undefined}
                            style={{
                                appearance: 'none',
                                flex: '0 0 auto',
                                inlineSize: 28,
                                blockSize: 28,
                                borderRadius: '50%',
                                display: 'grid',
                                placeItems: 'center',
                                fontFamily: 'var(--font-mono)',
                                fontSize: 12,
                                lineHeight: 1,
                                background: active
                                    ? 'var(--gold)'
                                    : 'transparent',
                                color: active
                                    ? 'var(--bg)'
                                    : done
                                        ? 'var(--green)'
                                        : 'var(--dim)',
                                border: `1.5px solid ${
                                    active
                                        ? 'var(--gold)'
                                        : done
                                            ? 'var(--green-dim)'
                                            : 'var(--line-soft)'
                                }`,
                                cursor:
                                    reachable && !active ? 'pointer' : 'default',
                            }}
                        >
                            {done && !active ? '✓' : i + 1}
                        </button>
                    </Fragment>
                );
            })}
        </div>
    );
}

function Label({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: 'var(--dim)',
                letterSpacing: '0.14em',
                textTransform: 'uppercase',
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
                fontSize: 12,
                fontWeight: 600,
                color: 'var(--fg)',
                marginBottom: 6,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
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
            <Button variant="ghost" onClick={onBack}>
                {backLabel}
            </Button>
            <Button disabled={nextDisabled} onClick={onNext}>
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
