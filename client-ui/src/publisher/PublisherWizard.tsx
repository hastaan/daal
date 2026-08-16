// PublisherWizard.tsx — refurbished Family Relay Publisher flow.
//
// Goal of this revision: make the wizard understandable without
// out-of-band docs. Every step has:
//   * an explainer paragraph (what this step does and why)
//   * concrete inputs with placeholders + helper text
//   * a status indicator next to the step in the side rail
//   * a primary "Next" button that's disabled until the form is valid
//
// In harness / plain-browser dev (engine not available) the wizard
// uses an in-memory mock so the screens render meaningfully and you
// can click through end-to-end. In Tauri it talks to the real
// wizard_* commands.

import { useEffect, useMemo, useRef, useState } from 'react';
import {
    Wizard,
    onProvisionEvent,
    onSignEvent,
    onQrFrame,
    onRotateEvent,
    type OperatorSummary,
    type Fingerprint,
    type ProgressEvent,
    type FountainFrame,
    type BindResult,
    type ServerTypeOption,
    type ExistingServer,
    type RecipientSummary,
} from './wizardCommands';
import { isHarnessActive } from '../harness/scenarios';
import { isTauriRuntime } from '../backends';
import { invoke } from '@tauri-apps/api/core';

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
import {
    Button,
    Card,
    Input,
    StatusLight,
    StatusPill,
} from '../design/primitives';
import { useDensity } from '../design/DensityProvider';

interface Props {
    t: (k: string) => string;
}

// ---- Step model ----

type StepId =
    | 'operator'
    | 'provider'
    | 'pricing'
    | 'keys'
    | 'provision'
    | 'sign'
    | 'distribute';

interface StepDef {
    id: StepId;
    titleKey: string;
    blurbKey: string;
}

const STEPS: StepDef[] = [
    {
        id: 'operator',
        titleKey: 'wiz.step.operator.title',
        blurbKey: 'wiz.step.operator.blurb',
    },
    {
        id: 'provider',
        titleKey: 'wiz.step.provider.title',
        blurbKey: 'wiz.step.provider.blurb',
    },
    {
        id: 'pricing',
        titleKey: 'wiz.step.pricing.title',
        blurbKey: 'wiz.step.pricing.blurb',
    },
    {
        id: 'keys',
        titleKey: 'wiz.step.keys.title',
        blurbKey: 'wiz.step.keys.blurb',
    },
    {
        id: 'provision',
        titleKey: 'wiz.step.provision.title',
        blurbKey: 'wiz.step.provision.blurb',
    },
    {
        id: 'sign',
        titleKey: 'wiz.step.sign.title',
        blurbKey: 'wiz.step.sign.blurb',
    },
    {
        id: 'distribute',
        titleKey: 'wiz.step.distribute.title',
        blurbKey: 'wiz.step.distribute.blurb',
    },
];

// Provider IDs and engine-side identifiers — labels, region hints
// and token hints are looked up via i18n at render time so Persian
// translations flow through.
const CLOUD_PROVIDERS = [
    {
        id: 'hetzner',
        labelKey: 'wiz.provider.hetzner.label',
        regionKey: 'wiz.provider.hetzner.region',
        defaultServer: 'cx22',
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

// Tiny helper for the `{name}` placeholder style used throughout the
// dictionary so callers don't repeat the .replace pattern.
function fmt(s: string, args: Record<string, string | number>): string {
    return s.replace(/\{(\w+)\}/g, (_, k) =>
        args[k] !== undefined ? String(args[k]) : `{${k}}`,
    );
}

// ---- Harness-friendly mock store ----

interface MockOperator {
    id: number;
    provider: ProviderId;
    region: string;
    server_type: string;
}
const mock = {
    nextId: 1,
    operators: [] as MockOperator[],
};

// ---- Component ----

export default function PublisherWizard({ t }: Props) {
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const live = isTauriRuntime() && !isHarnessActive();

    // Step navigation.
    const [stepIdx, setStepIdx] = useState(0);
    const [completed, setCompleted] = useState<Record<StepId, boolean>>({
        operator: false,
        provider: false,
        pricing: false,
        keys: false,
        provision: false,
        sign: false,
        distribute: false,
    });

    // Operator selection / creation.
    const [operators, setOperators] = useState<OperatorSummary[]>([]);
    const [operatorId, setOperatorId] = useState<number | null>(null);
    const [newLabel, setNewLabel] = useState('');
    const [creatingOperator, setCreatingOperator] = useState(false);

    // Provider & tokens.
    const [provider, setProvider] = useState<ProviderId>('hetzner');
    const [pin, setPin] = useState('');
    const [token, setToken] = useState('');

    // Pricing / sizing.
    const providerDef = useMemo(
        () => CLOUD_PROVIDERS.find((p) => p.id === provider)!,
        [provider],
    );
    const [_region, setRegion] = useState('eu-central');
    const [serverType, setServerType] = useState<string>(providerDef.defaultServer);
    // Toolbox profile name MUST match a profile shipped with
    // daal-deploy. At V1.5 only "iran-default" exists; passing a
    // wrong name (or empty list of families with non-matching
    // identifiers) makes the provider's candidatesForProfile()
    // return [], which later causes bind-and-sign to fail with
    // "OperatorRecord carries no candidates".
    const [toolboxProfile] = useState('iran-default');
    // Empty array = use the profile's DefaultEnabled candidates
    // (vless-reality, websocket-tls, naive, hysteria2).
    const [enabledFamilies] = useState<string[]>([]);
    const [_pricing, setPricing] = useState<{
        monthly_usd: number;
        bandwidth_tib: number;
    } | null>(null);
    const [serverOptions, setServerOptions] = useState<ServerTypeOption[]>([]);
    const [existingServers, setExistingServers] = useState<ExistingServer[]>([]);
    const [useExisting, setUseExisting] = useState<string | null>(null);
    const [loadingOptions, setLoadingOptions] = useState(false);

    // Load server types + existing servers when entering the pricing step.
    const regionMap: Record<string, string> = { hetzner: 'fsn1', vultr: 'fra', digitalocean: 'fra1', linode: 'eu-central' };
    const autoRegion = regionMap[provider] || 'fsn1';
    useEffect(() => {
        if (STEPS[stepIdx]?.id !== 'pricing') return;
        if (!operatorId) return;
        if (loadingOptions) return;
        if (serverOptions.length > 0) return;
        setLoadingOptions(true);
        (async () => {
            try {
                if (live && operatorId) {
                    const [types, existing] = await Promise.all([
                        Wizard.listServerTypes(operatorId, autoRegion, pin),
                        Wizard.listExistingServers(operatorId, pin).catch(() => [] as ExistingServer[]),
                    ]);
                    const filtered = types
                        .filter((st) => st.monthly_eur > 0 && st.monthly_eur <= 20)
                        .sort((a, b) => a.monthly_eur - b.monthly_eur);
                    setServerOptions(filtered);
                    setExistingServers(existing);
                    if (filtered.length > 0) setServerType(filtered[0].id);
                } else {
                    setServerOptions([
                        { id: 'cax11', description: 'CAX11', cpus: 2, memory_gb: 4, disk_gb: 40, monthly_eur: 3.79, hourly_eur: 0.006, location: 'fsn1', arch: 'arm' },
                        { id: 'cx22', description: 'CX22', cpus: 2, memory_gb: 4, disk_gb: 40, monthly_eur: 4.59, hourly_eur: 0.007, location: 'fsn1', arch: 'x86' },
                        { id: 'cax21', description: 'CAX21', cpus: 4, memory_gb: 8, disk_gb: 80, monthly_eur: 6.49, hourly_eur: 0.01, location: 'fsn1', arch: 'arm' },
                    ]);
                    setServerType('cax11');
                }
            } catch (e) {
                setError(String(e));
            } finally {
                setLoadingOptions(false);
            }
        })();
    }, [stepIdx]); // eslint-disable-line react-hooks/exhaustive-deps

    // Keys + provision + sign + distribute.
    const [fp, setFp] = useState<Fingerprint | null>(null);
    const [helperIp, setHelperIp] = useState('');
    const [detectingIp, setDetectingIp] = useState(false);

    const [editingIp, setEditingIp] = useState(false);

    // Auto-detect public IP when entering the provision step, and
    // ALSO when entering the distribute step. On distribute the IP
    // is needed by the per-recipient `users-provision` round-trip
    // (the helper-IP allowlist on the box-side firewall). React
    // state for `helperIp` does NOT survive reinstall / app
    // relaunch, so without this second auto-detect path the user
    // lands on Step 7, the IP comes up blank, and the "Add
    // recipient" button stays disabled with no visible reason.
    useEffect(() => {
        const id = STEPS[stepIdx]?.id;
        if (id !== 'provision' && id !== 'distribute') return;
        if (helperIp) return; // already set
        setDetectingIp(true);
        fetch('https://api.ipify.org?format=text')
            .then((r) => r.text())
            .then((ip) => {
                const trimmed = ip.trim();
                if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
                    setHelperIp(trimmed);
                } else {
                    setEditingIp(true); // bad response, ask user
                }
            })
            .catch(() => setEditingIp(true)) // detection failed, ask user
            .finally(() => setDetectingIp(false));
    }, [stepIdx]); // eslint-disable-line react-hooks/exhaustive-deps

    const [provisionLog, setProvisionLog] = useState<ProgressEvent[]>([]);
    const [signLog, setSignLog] = useState<ProgressEvent[]>([]);
    const [bindResult, setBindResult] = useState<BindResult | null>(null);
    const [qrFrame, setQrFrame] = useState<FountainFrame | null>(null);
    const [publisherName, setPublisherName] = useState('My Family Relay');
    // Absolute path of the signed .sbp invite package on this device.
    // Populated on entering Step 7 (or resumed). Used by the "Share
    // invite" button + Step 1 operator row.
    const [sbpPath, setSbpPath] = useState<string | null>(null);
    const [sharing, setSharing] = useState(false);
    // Feedback line under the Step-7 "Save to phone" button.
    const [saveMsg, setSaveMsg] = useState<string | null>(null);
    // Tracks the operator id for which we've already produced the
    // CONNECTABLE `.shared.sbp` (in the Step-6 sign handler). Once set,
    // the sbpPath loader effect below must NOT clobber that live path
    // with the raw signed (dead) path returned by getSbpPath.
    const sharedSbpReadyForRef = useRef<number | null>(null);

    // FRP-14 recipient book state.
    const [recipients, setRecipients] = useState<RecipientSummary[]>([]);
    const [recipientAddress, setRecipientAddress] = useState('');
    const [recipientDisplayName, setRecipientDisplayName] = useState('');
    const [recipientBusy, setRecipientBusy] = useState(false);
    const [recipientError, setRecipientError] = useState<string | null>(null);
    // Whether to show the inline PIN / helper-IP inputs in the Step 7
    // recipient form. Snapshotted once on step entry (see the
    // distribute effect below) — NOT gated on the live `pin`/`helperIp`
    // values, or the field would unmount the instant the first
    // character is typed (making the PIN un-enterable and every
    // "Add recipient" fail with "invalid PIN").
    const [recipientPinFieldOpen, setRecipientPinFieldOpen] = useState(false);
    const [recipientHelperIpFieldOpen, setRecipientHelperIpFieldOpen] =
        useState(false);
    // FRP-14 UX: live elapsed-seconds counter while "Add recipient"
    // is in flight, so the operator sees that something IS happening
    // during the ~30s mgmt round-trip rather than thinking the app
    // froze.
    const [recipientElapsed, setRecipientElapsed] = useState(0);
    useEffect(() => {
        if (!recipientBusy) {
            setRecipientElapsed(0);
            return;
        }
        const start = Date.now();
        setRecipientElapsed(0);
        const h = setInterval(() => {
            setRecipientElapsed(Math.floor((Date.now() - start) / 1000));
        }, 500);
        return () => clearInterval(h);
    }, [recipientBusy]);

    // Load the .sbp path whenever we know which operator we're on
    // AND have either entered Step 7 or just signed it in Step 6.
    // Also runs on Step 1 so the operator-list row can show "Share".
    useEffect(() => {
        if (!operatorId) {
            setSbpPath(null);
            sharedSbpReadyForRef.current = null;
            return;
        }
        if (!live) {
            if (bindResult) setSbpPath('Daal app storage');
            return;
        }
        // The Step-6 sign handler already put the CONNECTABLE
        // `.shared.sbp` path into sbpPath for this operator — don't
        // overwrite it with getSbpPath's raw signed (dead) path.
        if (sharedSbpReadyForRef.current === operatorId) return;
        const id = STEPS[stepIdx]?.id;
        if (id !== 'distribute' && id !== 'operator' && !bindResult) return;
        Wizard.getSbpPath(operatorId)
            .then((p) => setSbpPath(p))
            .catch(() => setSbpPath(null));
    }, [stepIdx, operatorId, bindResult, live]);

    // FRP-14: load the recipient roster whenever we enter Step 7
    // (the distribute step) and have a live operator.
    useEffect(() => {
        if (!operatorId) {
            setRecipients([]);
            return;
        }
        const id = STEPS[stepIdx]?.id;
        if (id !== 'distribute') return;
        // Snapshot whether the inline PIN / helper-IP fields are needed,
        // ONCE on entry. Gating the inputs on the live values instead
        // would unmount them on the first keystroke.
        setRecipientPinFieldOpen(!pin);
        setRecipientHelperIpFieldOpen(!helperIp);
        if (!live) return;
        Wizard.recipientList(operatorId)
            .then((rs) => setRecipients(rs))
            .catch(() => setRecipients([]));
    }, [stepIdx, operatorId, live]); // eslint-disable-line react-hooks/exhaustive-deps

    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    // Subscribe to streaming events when in a real Tauri runtime.
    useEffect(() => {
        if (!live) return;
        const unsubs: Array<() => void> = [];
        onProvisionEvent((ev) => setProvisionLog((l) => [...l, ev])).then((u) =>
            unsubs.push(u),
        );
        onSignEvent((ev) => setSignLog((l) => [...l, ev])).then((u) =>
            unsubs.push(u),
        );
        onQrFrame((f) => setQrFrame(f)).then((u) => unsubs.push(u));
        onRotateEvent(() => {}).then((u) => unsubs.push(u));
        // Fallback: listen for CustomEvent injected via webview.eval()
        const handleCustom = (e: Event) => {
            const detail = (e as CustomEvent).detail;
            if (detail?.step) {
                setProvisionLog((l) => [...l, { step: detail.step, message: detail.message }]);
            }
        };
        window.addEventListener('daal-provision-event', handleCustom);
        return () => {
            unsubs.forEach((u) => u());
            window.removeEventListener('daal-provision-event', handleCustom);
        };
    }, [live]);

    // Load existing servers on entry and auto-resume if one is
    // in progress. The DB holds all wizard state; we just need
    // the user's PIN to decrypt secrets.
    const stepIdToIdx = (id: string): number => {
        const idx = STEPS.findIndex((s) => s.id === id);
        return idx >= 0 ? idx : 0;
    };
    useEffect(() => {
        if (live) {
            Wizard.listOperators()
                .then(async (rows) => {
                    setOperators(rows);
                    // Auto-resume: pick the first non-decommissioned
                    // operator and jump to its derived step.
                    const active = rows.find(
                        (r) => r.status !== 'decommissioned',
                    );
                    if (active && !operatorId) {
                        try {
                            const state =
                                await Wizard.getOperatorState(active.id);
                            setOperatorId(state.id);
                            setProvider(
                                (state.provider || 'hetzner') as ProviderId,
                            );
                            if (state.server_type)
                                setServerType(state.server_type);
                            // Mark all steps before the resume step as done.
                            const resumeIdx = stepIdToIdx(state.wizard_step);
                            const marks: Record<StepId, boolean> = {
                                operator: false,
                                provider: false,
                                pricing: false,
                                keys: false,
                                provision: false,
                                sign: false,
                                distribute: false,
                            };
                            for (let i = 0; i < resumeIdx; i++) {
                                marks[STEPS[i].id] = true;
                            }
                            setCompleted(marks);
                            setStepIdx(resumeIdx);
                        } catch {
                            // getOperatorState failed — don't crash, just
                            // show from Step 1.
                        }
                    }
                })
                .catch((e) => setError(String(e)));
        } else {
            setOperators(
                mock.operators.map((o) => ({
                    id: o.id,
                    status: '',
                    provider: o.provider,
                    region: o.region,
                    server_type: o.server_type,
                    publisher_pub_hex: '',
                    created_at_unix: Math.floor(Date.now() / 1000),
                })),
            );
        }
    }, [live, creatingOperator]); // eslint-disable-line react-hooks/exhaustive-deps

    const mark = (id: StepId) =>
        setCompleted((c) => ({ ...c, [id]: true }));

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

    const fakeProgress = async (
        phaseName: string,
        target: (l: ProgressEvent[]) => void,
        steps: Array<[string, number]>,
    ) => {
        for (const [detail, pct] of steps) {
            await new Promise((r) => setTimeout(r, 220));
            target([
                ...provisionLog,
                { step: phaseName, message: detail, phase: phaseName, detail, pct },
            ]);
        }
    };

    const step = STEPS[stepIdx];
    const canBack = stepIdx > 0;

    return (
        <div
            style={{
                width: '100%',
                maxWidth: 980,
                margin: '0 auto',
                // On phones the MobileShell <main> already provides the
                // horizontal gutter; doubling it crushes the wizard
                // content. We just add vertical breathing room here.
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
                    {t('wiz.intro')}
                </p>
            </header>

            {/* Phone: compact step pager above the body (no side rail —
                a 220px rail would leave ~140px for content on a 360px
                phone). Desktop / tablet: classic two-column layout. */}
            {isPhone && (
                <PhoneStepPager
                    steps={STEPS}
                    stepIdx={stepIdx}
                    completed={completed}
                    onJump={setStepIdx}
                    t={t}
                />
            )}

            <div
                style={{
                    display: 'grid',
                    gridTemplateColumns: isPhone
                        ? 'minmax(0, 1fr)'
                        : 'minmax(180px, 220px) minmax(0, 1fr)',
                    gap: isPhone ? 12 : 18,
                    alignItems: 'start',
                }}
            >
                {/* SIDE RAIL — desktop / tablet only. On phone the
                    PhoneStepPager above takes its place. */}
                {!isPhone && <ol
                    style={{
                        listStyle: 'none',
                        padding: 0,
                        margin: 0,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 2,
                    }}
                >
                    {STEPS.map((s, i) => {
                        const active = i === stepIdx;
                        const done = completed[s.id];
                        return (
                            <li key={s.id}>
                                <button
                                    onClick={() => setStepIdx(i)}
                                    style={{
                                        width: '100%',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: 10,
                                        padding: '10px 12px',
                                        border: 0,
                                        background: active
                                            ? 'rgba(201,162,58,0.10)'
                                            : 'transparent',
                                        color: active
                                            ? 'var(--fg)'
                                            : done
                                                ? 'var(--muted)'
                                                : 'var(--dim)',
                                        borderInlineStart: `2px solid ${
                                            active
                                                ? 'var(--gold)'
                                                : done
                                                    ? 'var(--green-dim)'
                                                    : 'transparent'
                                        }`,
                                        textAlign: 'start',
                                        cursor: 'pointer',
                                        fontFamily: 'var(--font-body)',
                                        fontSize: 13,
                                    }}
                                >
                                    <StatusLight
                                        tone={done ? 'good' : 'neutral'}
                                        size={8}
                                    />
                                    <span
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 10,
                                            color: 'var(--dim)',
                                            width: 22,
                                        }}
                                    >
                                        {String(i + 1).padStart(2, '0')}
                                    </span>
                                    <span style={{ flex: 1 }}>
                                        {t(s.titleKey)}
                                    </span>
                                </button>
                            </li>
                        );
                    })}
                </ol>}

                {/* STEP BODY */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                    <Card>
                        <div
                            style={{
                                display: 'flex',
                                alignItems: 'baseline',
                                gap: 12,
                                justifyContent: 'space-between',
                                // On phones the preview pill must wrap
                                // under the title so neither gets
                                // clipped at 360-wide screens.
                                flexWrap: 'wrap',
                            }}
                        >
                            <div>
                                {/* On phones the PhoneStepPager above
                                    already shows "Step N / M", so
                                    suppress this inline counter to
                                    avoid showing it twice. */}
                                {!isPhone && (
                                <div
                                    style={{
                                        fontFamily: 'var(--font-mono)',
                                        fontSize: 10,
                                        letterSpacing: '0.18em',
                                        textTransform: 'uppercase',
                                        color: 'var(--dim)',
                                    }}
                                >
                                    {fmt(t('wiz.step.label'), {
                                        n: stepIdx + 1,
                                        total: STEPS.length,
                                    })}
                                </div>
                                )}
                                <h2
                                    style={{
                                        fontFamily: 'var(--font-display)',
                                        fontSize: isPhone ? 17 : 20,
                                        margin: isPhone
                                            ? '0 0 4px'
                                            : '4px 0',
                                    }}
                                >
                                    {t(step.titleKey)}
                                </h2>
                            </div>
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
                                }}
                            >
                                {error}
                            </div>
                        )}

                        {/* ===== STEP 1: OPERATOR ===== */}
                        {step.id === 'operator' && (
                            <div>
                                {operators.length === 0 ? (
                                    <EmptyHint>{t('wiz.op.empty')}</EmptyHint>
                                ) : (
                                    <>
                                    <Label>{t('wiz.op.existing')}</Label>
                                    <ul
                                        style={{
                                            listStyle: 'none',
                                            padding: 0,
                                            margin: '6px 0 14px',
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: 6,
                                        }}
                                    >
                                        {operators.map((o) => {
                                            const sel =
                                                operatorId === o.id;
                                            return (
                                                <li key={o.id}>
                                                    <div
                                                        style={{
                                                            width: '100%',
                                                            display: 'flex',
                                                            alignItems: 'center',
                                                            gap: 0,
                                                        }}
                                                    >
                                                        <button
                                                            onClick={async () => {
                                                                setOperatorId(o.id);
                                                                mark('operator');
                                                                // Resume at the operator's last
                                                                // wizard step. Already-finished
                                                                // operators land on Step 7 so the
                                                                // user can re-share the invite.
                                                                if (live) {
                                                                    try {
                                                                        const st = await Wizard.getOperatorState(o.id);
                                                                        const idx = STEPS.findIndex(
                                                                            (s) => s.id === st.wizard_step,
                                                                        );
                                                                        if (idx >= 0) {
                                                                            const marks: Record<StepId, boolean> = {
                                                                                operator: true,
                                                                                provider: false,
                                                                                pricing: false,
                                                                                keys: false,
                                                                                provision: false,
                                                                                sign: false,
                                                                                distribute: false,
                                                                            };
                                                                            for (let i = 0; i < idx; i++) marks[STEPS[i].id] = true;
                                                                            setCompleted(marks);
                                                                            setStepIdx(idx);
                                                                            return;
                                                                        }
                                                                    } catch { /* fall through */ }
                                                                }
                                                                setStepIdx((i) => i + 1);
                                                            }}
                                                            style={{
                                                                flex: 1,
                                                                display: 'flex',
                                                                alignItems: 'center',
                                                                gap: 10,
                                                                padding: '10px 12px',
                                                                background: sel
                                                                    ? 'rgba(201,162,58,0.10)'
                                                                    : 'var(--surface-2)',
                                                                border: `1px solid ${
                                                                    sel ? 'var(--gold)' : 'var(--line-soft)'
                                                                }`,
                                                                borderRadius: 'var(--r-tile) 0 0 var(--r-tile)',
                                                                cursor: 'pointer',
                                                                color: 'var(--fg)',
                                                                fontFamily: 'var(--font-body)',
                                                                textAlign: 'start',
                                                            }}
                                                        >
                                                            <span style={{ flex: 1, fontSize: 13 }}>
                                                                {`Server #${o.id}`}
                                                            </span>
                                                            {o.region && (
                                                                <span style={{
                                                                    fontFamily: 'var(--font-mono)',
                                                                    fontSize: 10,
                                                                    color: 'var(--muted)',
                                                                }}>
                                                                    {o.region}
                                                                </span>
                                                            )}
                                                        </button>
                                                        <button
                                                            onClick={async () => {
                                                                const ok = window.confirm(
                                                                    'Remove this server from the app?\n\n' +
                                                                    'This only removes it from Daal. ' +
                                                                    'If a cloud server is already running, ' +
                                                                    'it will keep running and you will still be charged. ' +
                                                                    'Delete the server from your cloud provider\'s dashboard to stop billing.',
                                                                );
                                                                if (!ok) return;
                                                                if (live) {
                                                                    await run(() =>
                                                                        Wizard.cancelAndCleanup(o.id),
                                                                    );
                                                                } else {
                                                                    mock.operators = mock.operators.filter(
                                                                        (m) => m.id !== o.id,
                                                                    );
                                                                }
                                                                setOperators((ops) =>
                                                                    ops.filter((x) => x.id !== o.id),
                                                                );
                                                                if (operatorId === o.id) {
                                                                    setOperatorId(null);
                                                                }
                                                            }}
                                                            style={{
                                                                padding: '10px 14px',
                                                                background: 'var(--surface-2)',
                                                                border: '1px solid var(--line-soft)',
                                                                borderLeft: 'none',
                                                                borderRadius: '0 var(--r-tile) var(--r-tile) 0',
                                                                cursor: 'pointer',
                                                                color: 'var(--muted)',
                                                                fontSize: 14,
                                                                fontFamily: 'var(--font-body)',
                                                            }}
                                                            title="Delete"
                                                        >
                                                            ✕
                                                        </button>
                                                    </div>
                                                </li>
                                            );
                                        })}
                                    </ul>
                                    </>
                                )}

                                <Label>{t('wiz.op.create')}</Label>
                                <div
                                    style={{
                                        display: 'flex',
                                        gap: 8,
                                        marginBottom: 14,
                                    }}
                                >
                                    <Input
                                        placeholder={t('wiz.op.placeholder')}
                                        value={newLabel}
                                        onChange={(e) =>
                                            setNewLabel(e.target.value)
                                        }
                                    />
                                </div>

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() =>
                                        setStepIdx((i) => Math.max(0, i - 1))
                                    }
                                    nextDisabled={busy || (operatorId == null && !newLabel)}
                                    onNext={async () => {
                                        // Create a new server if the user
                                        // typed a name (no existing selected).
                                        if (operatorId == null && newLabel) {
                                            setCreatingOperator(true);
                                            try {
                                                if (!live) {
                                                    const id = mock.nextId++;
                                                    mock.operators.push({
                                                        id,
                                                        provider,
                                                        region: 'eu-central',
                                                        server_type:
                                                            providerDef.defaultServer,
                                                    });
                                                    setOperatorId(id);
                                                } else {
                                                    // Temporary placeholder;
                                                    // storeCloudToken in
                                                    // Step 2 replaces this
                                                    // with the real DB id.
                                                    setOperatorId(-1);
                                                }
                                            } finally {
                                                setCreatingOperator(false);
                                            }
                                        }
                                        mark('operator');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 2: PROVIDER & TOKENS ===== */}
                        {step.id === 'provider' && (
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
                                                    setServerType(
                                                        p.defaultServer,
                                                    );
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
                                                    color: available ? 'var(--fg)' : 'var(--muted)',
                                                    opacity: available ? 1 : 0.45,
                                                    padding: '10px 12px',
                                                    borderRadius:
                                                        'var(--r-tile)',
                                                    cursor: available ? 'pointer' : 'default',
                                                    textAlign: 'start',
                                                    fontFamily:
                                                        'var(--font-body)',
                                                }}
                                            >
                                                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                    <span style={{ fontSize: 13, fontWeight: 600 }}>
                                                        {t(p.labelKey)}
                                                    </span>
                                                    {p.recommended && (
                                                        <span style={{
                                                            fontSize: 9,
                                                            fontWeight: 600,
                                                            color: 'var(--gold)',
                                                            border: '1px solid var(--gold)',
                                                            borderRadius: 4,
                                                            padding: '1px 5px',
                                                            textTransform: 'uppercase' as const,
                                                            letterSpacing: 0.5,
                                                        }}>
                                                            ★
                                                        </span>
                                                    )}
                                                </div>
                                                <div
                                                    style={{
                                                        fontFamily:
                                                            'var(--font-mono)',
                                                        fontSize: 10,
                                                        color: 'var(--muted)',
                                                        marginTop: 4,
                                                    }}
                                                >
                                                    {available ? t(p.regionKey) : 'Coming soon'}
                                                </div>
                                            </button>
                                        );
                                    })}
                                </div>

                                {/* Signup link + VPS tip */}
                                {providerDef.signupUrl && (
                                    <div style={{ marginBottom: 14 }}>
                                        <button
                                            onClick={() => openExternal(providerDef.signupUrl)}
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
                                        <div style={{
                                            background: 'rgba(201,162,58,0.06)',
                                            border: '1px solid rgba(201,162,58,0.15)',
                                            borderRadius: 'var(--r-tile)',
                                            padding: '10px 12px',
                                            fontSize: 12,
                                            lineHeight: 1.5,
                                        }}>
                                            <div style={{
                                                fontWeight: 600,
                                                marginBottom: 4,
                                                color: 'var(--gold)',
                                                fontSize: 11,
                                                textTransform: 'uppercase' as const,
                                                letterSpacing: 0.5,
                                            }}>
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
                                    {fmt(t('wiz.provider.token.help'), {
                                        hint: t(providerDef.tokenHintKey),
                                    })}
                                </div>

                                <Label>{t('wiz.provider.pin')}</Label>
                                <Input
                                    type="password"
                                    placeholder={t(
                                        'wiz.provider.pin.placeholder',
                                    )}
                                    value={pin}
                                    onChange={(e) => setPin(e.target.value)}
                                    style={{ marginBottom: 14 }}
                                />

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={
                                        busy || !pin || !token || pin.length < 6
                                    }
                                    onNext={async () => {
                                        if (live) {
                                            const dbId = await run(() =>
                                                Wizard.storeCloudToken(
                                                    provider,
                                                    token,
                                                    pin,
                                                ),
                                            );
                                            // storeCloudToken returns the
                                            // real DB operator ID. Use it
                                            // so subsequent steps find the
                                            // right keystore entry.
                                            if (dbId != null) {
                                                setOperatorId(dbId);
                                            }
                                        }
                                        mark('provider');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 3: PRICING / SIZING ===== */}
                        {step.id === 'pricing' && (
                            <div>
                                {loadingOptions && (
                                    <div style={{ textAlign: 'center', padding: 20, color: 'var(--muted)' }}>
                                        Loading available servers...
                                    </div>
                                )}

                                {/* Existing servers on the account */}
                                {!loadingOptions && existingServers.length > 0 && (
                                    <>
                                        <div style={{
                                            fontSize: 12, fontWeight: 600,
                                            color: 'var(--fg)',
                                            marginBottom: 6,
                                            textTransform: 'uppercase',
                                            letterSpacing: '0.08em',
                                        }}>
                                            Your existing servers
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                                            {existingServers.map((srv) => {
                                                const sel = useExisting === srv.id;
                                                return (
                                                    <button
                                                        key={srv.id}
                                                        onClick={() => {
                                                            setUseExisting(sel ? null : srv.id);
                                                        }}
                                                        style={{
                                                            width: '100%',
                                                            display: 'flex',
                                                            alignItems: 'center',
                                                            justifyContent: 'space-between',
                                                            gap: 10,
                                                            padding: '12px 14px',
                                                            background: sel ? 'rgba(76,175,80,0.10)' : 'var(--surface-2)',
                                                            border: `1.5px solid ${sel ? '#4caf50' : 'var(--line-soft)'}`,
                                                            borderRadius: 'var(--r-tile)',
                                                            cursor: 'pointer',
                                                            color: 'var(--fg)',
                                                            fontFamily: 'var(--font-body)',
                                                            textAlign: 'start',
                                                        }}
                                                    >
                                                        <div style={{ flex: 1 }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                                <span style={{ fontSize: 14, fontWeight: 600 }}>{srv.name}</span>
                                                                <span style={{
                                                                    fontSize: 9, fontWeight: 600,
                                                                    color: srv.status === 'running' ? '#4caf50' : 'var(--muted)',
                                                                    border: `1px solid ${srv.status === 'running' ? '#4caf50' : 'var(--line-soft)'}`,
                                                                    borderRadius: 4, padding: '1px 5px',
                                                                    textTransform: 'uppercase' as const,
                                                                }}>
                                                                    {srv.status}
                                                                </span>
                                                            </div>
                                                            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                                                                {srv.server_type.toUpperCase()} · {srv.region} · {srv.public_ip}
                                                            </div>
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                        <div style={{ fontSize: 10, color: 'var(--muted)', marginBottom: 10 }}>
                                            Selecting an existing server will reinstall it with daal's configuration. Same IP, no extra charges.
                                        </div>
                                    </>
                                )}

                                {/* New server options */}
                                {!loadingOptions && serverOptions.length > 0 && !useExisting && (
                                    <>
                                        {existingServers.length > 0 && (
                                            <div style={{
                                                fontSize: 12, fontWeight: 600,
                                                color: 'var(--fg)',
                                                marginBottom: 6,
                                                textTransform: 'uppercase',
                                                letterSpacing: '0.08em',
                                            }}>
                                                Or create a new server
                                            </div>
                                        )}
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 14 }}>
                                            {serverOptions.map((opt, i) => {
                                                const sel = !useExisting && serverType === opt.id;
                                                const isCheapest = i === 0;
                                                return (
                                                    <button
                                                        key={opt.id}
                                                        onClick={() => {
                                                            setUseExisting(null);
                                                            setServerType(opt.id);
                                                        }}
                                                        style={{
                                                            width: '100%',
                                                            display: 'flex',
                                                            alignItems: 'center',
                                                            justifyContent: 'space-between',
                                                            gap: 10,
                                                            padding: '12px 14px',
                                                            background: sel ? 'rgba(201,162,58,0.10)' : 'var(--surface-2)',
                                                            border: `1.5px solid ${sel ? 'var(--gold)' : 'var(--line-soft)'}`,
                                                            borderRadius: 'var(--r-tile)',
                                                            cursor: 'pointer',
                                                            color: 'var(--fg)',
                                                            fontFamily: 'var(--font-body)',
                                                            textAlign: 'start',
                                                        }}
                                                    >
                                                        <div style={{ flex: 1 }}>
                                                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                                                <span style={{ fontSize: 14, fontWeight: 600 }}>{opt.id.toUpperCase()}</span>
                                                                {isCheapest && (
                                                                    <span style={{
                                                                        fontSize: 9, fontWeight: 600,
                                                                        color: 'var(--gold)', border: '1px solid var(--gold)',
                                                                        borderRadius: 4, padding: '1px 5px',
                                                                        textTransform: 'uppercase' as const,
                                                                    }}>
                                                                        Best value
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <div style={{ fontSize: 11, color: 'var(--muted)', marginTop: 2 }}>
                                                                {opt.cpus} vCPU · {opt.memory_gb} GB RAM · {opt.disk_gb} GB disk
                                                            </div>
                                                        </div>
                                                        <div style={{
                                                            fontSize: 15, fontWeight: 700,
                                                            color: sel ? 'var(--gold)' : 'var(--fg)',
                                                            whiteSpace: 'nowrap',
                                                        }}>
                                                            €{opt.monthly_eur.toFixed(2)}/mo
                                                        </div>
                                                    </button>
                                                );
                                            })}
                                        </div>
                                    </>
                                )}

                                <div style={{
                                    fontSize: 11, color: 'var(--muted)',
                                    marginBottom: 14, lineHeight: 1.5,
                                }}>
                                    {useExisting
                                        ? 'Using your existing server. No new charges.'
                                        : `${t('wiz.pricing.auto.protocols.value')}. All plans include 20 TB bandwidth.`}
                                </div>

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={busy || loadingOptions || !operatorId || (!serverType && !useExisting)}
                                    nextLabel={t('wiz.pricing.next.continue')}
                                    onNext={async () => {
                                        if (!operatorId) return;
                                        setRegion(autoRegion);
                                        if (live) {
                                            const p = await run(() =>
                                                Wizard.pricingLookup(
                                                    operatorId,
                                                    autoRegion,
                                                    serverType,
                                                    pin,
                                                ),
                                            );
                                            if (p) setPricing(p);
                                            await run(() =>
                                                Wizard.selectProfile(
                                                    operatorId,
                                                    autoRegion,
                                                    serverType,
                                                    toolboxProfile,
                                                    enabledFamilies,
                                                ),
                                            );
                                        } else {
                                            setPricing({
                                                monthly_usd: 3.79,
                                                bandwidth_tib: 20,
                                            });
                                        }
                                        mark('pricing');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 4: KEYS ===== */}
                        {step.id === 'keys' && (
                            <div>
                                {fp ? (
                                    <Card
                                        style={{
                                            background: 'var(--surface-2)',
                                            marginBottom: 12,
                                        }}
                                    >
                                        <div
                                            style={{
                                                fontFamily:
                                                    'var(--font-mono)',
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
                                        <div
                                            style={{
                                                fontFamily: 'var(--font-mono)',
                                                fontSize: 11,
                                                color: 'var(--muted)',
                                                marginTop: 8,
                                            }}
                                        >
                                            {fmt(t('wiz.keys.en'), {
                                                words: fp.en_words ?? '',
                                            })}
                                        </div>
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
                                                words: fp.fa_words ?? '',
                                            })}
                                        </div>
                                    </Card>
                                ) : (
                                    <Button
                                        disabled={busy || !operatorId}
                                        onClick={async () => {
                                            if (!operatorId) return;
                                            if (live) {
                                                const f = await run(() =>
                                                    Wizard.publisherKeygen(
                                                        operatorId,
                                                        pin,
                                                    ),
                                                );
                                                if (f) setFp(f);
                                            } else {
                                                setFp({
                                                    hex: 'aa'.repeat(16),
                                                    en_words: 'phoenix rescue may sky honest stone river hill',
                                                    fa_words: 'ققنوس نجات اردیبهشت آسمان درست سنگ رود تپه',
                                                });
                                            }
                                        }}
                                    >
                                        {t('wiz.keys.gen')}
                                    </Button>
                                )}
                                <div style={{ height: 14 }} />
                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={!fp}
                                    onNext={() => {
                                        mark('keys');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 5: PROVISION ===== */}
                        {step.id === 'provision' && (
                            <div>
                                {detectingIp && (
                                    <div style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 12 }}>
                                        Detecting your network...
                                    </div>
                                )}
                                {!detectingIp && (editingIp || !helperIp) && (
                                    <div style={{ marginBottom: 12 }}>
                                        <Label>Your public IP address</Label>
                                        <Input
                                            value={helperIp}
                                            placeholder="e.g. 85.12.34.56"
                                            onChange={(e) => setHelperIp(e.target.value)}
                                        />
                                        <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
                                            Search "what is my IP" in your browser to find it.
                                        </div>
                                    </div>
                                )}
                                {helperIp && !detectingIp && !editingIp && (
                                    <div style={{
                                        fontSize: 11, color: 'var(--muted)',
                                        marginBottom: 12, lineHeight: 1.5,
                                    }}>
                                        Your IP ({helperIp}) will be allowlisted for server management.{' '}
                                        <span
                                            onClick={() => setEditingIp(true)}
                                            style={{ color: 'var(--gold)', cursor: 'pointer', textDecoration: 'underline' }}
                                        >
                                            Change
                                        </span>
                                    </div>
                                )}
                                <Button
                                    disabled={busy || !operatorId || !pin || detectingIp || !helperIp}
                                    onClick={async () => {
                                        if (!operatorId) return;
                                        setProvisionLog([]);
                                        if (live) {
                                            await run(() =>
                                                Wizard.provisionRun(
                                                    operatorId,
                                                    pin,
                                                    helperIp,
                                                    useExisting ?? undefined,
                                                ),
                                            );
                                        } else {
                                            await fakeProgress(
                                                'provision',
                                                setProvisionLog,
                                                [
                                                    ['create server', 10],
                                                    ['await SSH', 40],
                                                    ['toolbox bring-up', 80],
                                                    ['done', 100],
                                                ],
                                            );
                                        }
                                        mark('provision');
                                    }}
                                >
                                    {busy
                                        ? t('wiz.provision.running')
                                        : t('wiz.provision.run')}
                                </Button>
                                <EventList events={provisionLog} />
                                <div style={{ height: 14 }} />
                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={
                                        busy || !completed.provision
                                    }
                                    onNext={() => {
                                        mark('provision');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 6: SIGN ===== */}
                        {step.id === 'sign' && (
                            <div>
                                <div style={{ marginBottom: 14 }}>
                                    <p
                                        style={{
                                            margin: '0 0 10px',
                                            color: 'var(--muted)',
                                            fontSize: 14,
                                            lineHeight: 1.55,
                                        }}
                                    >
                                        {t('wiz.sign.simpleHelp')}
                                    </p>
                                    <div
                                        style={{
                                            border: '1px solid var(--border)',
                                            borderRadius: 14,
                                            padding: 12,
                                            color: 'var(--dim)',
                                            fontSize: 12,
                                            lineHeight: 1.45,
                                        }}
                                    >
                                        {t('wiz.sign.autoHelp')}
                                    </div>
                                </div>
                                <Label>{t('wiz.sign.pubname')}</Label>
                                <Input
                                    value={publisherName}
                                    onChange={(e) =>
                                        setPublisherName(e.target.value)
                                    }
                                    style={{ marginBottom: 12 }}
                                />
                                <Button
                                    disabled={busy || sharing || !operatorId || !pin}
                                    onClick={async () => {
                                        if (!operatorId) return;
                                        setSignLog([]);
                                        if (live) {
                                            const r = await run(() =>
                                                Wizard.signRelaypack(
                                                    operatorId,
                                                    pin,
                                                    'V1.6',
                                                    '',
                                                    publisherName,
                                                ),
                                            );
                                            // Sign failed — error already shown;
                                            // stay on Step 6, don't advance.
                                            if (!r) return;
                                            // Immediately produce the CONNECTABLE
                                            // shared `.sbp` (mints the shared r0
                                            // user + rewrites profiles, ~10-20s)
                                            // so Step 7 hands out a real,
                                            // importable file rather than the
                                            // dead raw signed bundle.
                                            setSharing(true);
                                            const shared = await run(() =>
                                                Wizard.produceSharedSbp(
                                                    operatorId,
                                                    pin,
                                                    helperIp,
                                                ),
                                            );
                                            setSharing(false);
                                            // Producing the shared pack failed —
                                            // keep the user on Step 6 (bindResult
                                            // stays null → Next disabled) so they
                                            // never advance with a dead file.
                                            if (!shared) return;
                                            sharedSbpReadyForRef.current =
                                                operatorId;
                                            setSbpPath(shared.sbp_path);
                                            setBindResult(r);
                                        } else {
                                            await fakeProgress(
                                                'sign',
                                                setSignLog,
                                                [
                                                    ['collect endpoints', 25],
                                                    ['canonicalize', 60],
                                                    ['sign', 90],
                                                    ['done', 100],
                                                ],
                                            );
                                            setBindResult({
                                                sbp_path: 'Daal app storage',
                                                fingerprint_hex: 'aa'.repeat(16),
                                                sbp_sha256: 'bb'.repeat(32),
                                            });
                                        }
                                        mark('sign');
                                    }}
                                >
                                    {sharing
                                        ? t('pub.share.working')
                                        : busy
                                            ? t('wiz.sign.running')
                                            : t('wiz.sign.run')}
                                </Button>
                                <EventList events={signLog} />
                                {bindResult && (
                                    <Card
                                        style={{
                                            marginTop: 10,
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
                                            {t('wiz.sign.result.eyebrow')}
                                        </div>
                                        <div
                                            style={{
                                                fontSize: 14,
                                                color: 'var(--fg)',
                                                marginTop: 4,
                                            }}
                                        >
                                            {t('wiz.sign.result.body')}
                                        </div>
                                    </Card>
                                )}
                                <div style={{ height: 14 }} />
                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={!bindResult}
                                    onNext={() => {
                                        mark('sign');
                                        setStepIdx((i) => i + 1);
                                    }}
                                />
                            </div>
                        )}

                        {/* ===== STEP 7: SEND ===== */}
                        {step.id === 'distribute' && (
                            <div>
                                <p
                                    style={{
                                        fontSize: 13,
                                        color: 'var(--muted)',
                                        margin: '0 0 14px',
                                        lineHeight: 1.5,
                                    }}
                                >
                                    {t('wiz.distribute.explain')}
                                </p>

                                {sbpPath && (
                                    <Card
                                        style={{
                                            background: 'var(--surface-2)',
                                            marginBottom: 12,
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
                                            {t('wiz.distribute.saved.eyebrow')}
                                        </div>
                                        <div
                                            style={{
                                                fontFamily: 'var(--font-mono)',
                                                fontSize: 11,
                                                color: 'var(--fg)',
                                                marginTop: 4,
                                                wordBreak: 'break-all',
                                            }}
                                        >
                                            {sbpPath}
                                        </div>
                                    </Card>
                                )}

                                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                    <Button
                                        disabled={busy || sharing || !operatorId || !sbpPath}
                                        onClick={async () => {
                                            if (!operatorId || !sbpPath) return;
                                            setSaveMsg(null);
                                            setSharing(true);
                                            try {
                                                if (live) {
                                                    await run(() =>
                                                        Wizard.shareInvite(
                                                            operatorId,
                                                            publisherName,
                                                        ),
                                                    );
                                                } else {
                                                    alert(
                                                        fmt(
                                                            t('wiz.distribute.alert.finalized'),
                                                            { path: sbpPath },
                                                        ),
                                                    );
                                                }
                                                mark('distribute');
                                            } finally {
                                                setSharing(false);
                                            }
                                        }}
                                    >
                                        {sharing
                                            ? t('wiz.distribute.sharing')
                                            : t('wiz.distribute.send')}
                                    </Button>
                                    {/* Save the CONNECTABLE shared `.sbp` straight
                                        to the phone's Downloads — mirrors the
                                        recipients page. Uses the same shared file
                                        the Send button hands out. */}
                                    <Button
                                        variant="secondary"
                                        disabled={busy || sharing || !operatorId || !sbpPath}
                                        onClick={async () => {
                                            if (!operatorId || !sbpPath) return;
                                            setSaveMsg(null);
                                            if (live) {
                                                const ok = await run(() =>
                                                    Wizard.saveSharedSbpToDownloads(
                                                        operatorId,
                                                        'daal-connection.sbp',
                                                    ),
                                                );
                                                if (ok !== null) {
                                                    setSaveMsg(t('pub.share.saved'));
                                                    mark('distribute');
                                                }
                                            } else {
                                                setSaveMsg(t('pub.share.saved'));
                                                mark('distribute');
                                            }
                                        }}
                                    >
                                        {t('pub.share.save')}
                                    </Button>
                                </div>
                                {saveMsg && (
                                    <div
                                        style={{
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            marginTop: 8,
                                        }}
                                    >
                                        {saveMsg}
                                    </div>
                                )}

                                {/* QR fountain — placeholder until the
                                    canvas rendering is wired in V1.6. */}
                                <div style={{ marginTop: 14 }}>
                                    <Button
                                        variant="ghost"
                                        disabled
                                        onClick={() => {}}
                                    >
                                        {t('wiz.distribute.qr.soon')}
                                    </Button>
                                </div>

                                {qrFrame && (
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            marginTop: 8,
                                        }}
                                    >
                                        {fmt(t('wiz.distribute.frame'), {
                                            i: qrFrame.index,
                                            total: qrFrame.total_frames,
                                        })}
                                    </div>
                                )}

                                {/* FRP-14: per-recipient roster + Add sheet. */}
                                <div
                                    style={{
                                        marginTop: 22,
                                        paddingTop: 18,
                                        borderTop:
                                            '1px solid var(--surface-3)',
                                    }}
                                >
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 10,
                                            color: 'var(--dim)',
                                            letterSpacing: '0.18em',
                                            textTransform: 'uppercase',
                                            marginBottom: 8,
                                        }}
                                    >
                                        {t('wiz.recipients.eyebrow')}
                                    </div>
                                    <p
                                        style={{
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            margin: '0 0 12px',
                                            lineHeight: 1.5,
                                        }}
                                    >
                                        {t('wiz.recipients.explain')}
                                    </p>

                                    {/* Add row */}
                                    <div style={{ display: 'grid', gap: 8 }}>
                                        {/* FRP-14: on a fresh app launch (reinstall /
                                            relaunch / phone reboot) the React-state
                                            `pin` is empty because we never persist it.
                                            Show an inline PIN field here so the
                                            operator can unlock the per-recipient
                                            provision call from Step 7 without
                                            walking the whole wizard again. */}
                                        {recipientPinFieldOpen && (
                                            <Input
                                                type="password"
                                                placeholder={t(
                                                    'wiz.recipients.pin_placeholder',
                                                )}
                                                value={pin}
                                                onChange={(e) =>
                                                    setPin(e.target.value)
                                                }
                                            />
                                        )}
                                        {/* Same story for helperIp: auto-detect runs
                                            on step entry, but if detection failed
                                            (no internet / blocked) the operator
                                            needs a way in. */}
                                        {recipientHelperIpFieldOpen && (
                                            <Input
                                                placeholder={t(
                                                    'wiz.recipients.helper_ip_placeholder',
                                                )}
                                                value={helperIp}
                                                onChange={(e) =>
                                                    setHelperIp(e.target.value)
                                                }
                                            />
                                        )}
                                        <Input
                                            placeholder={t(
                                                'wiz.recipients.address_placeholder',
                                            )}
                                            value={recipientAddress}
                                            onChange={(e) =>
                                                setRecipientAddress(
                                                    e.target.value,
                                                )
                                            }
                                        />
                                        <Input
                                            placeholder={t(
                                                'wiz.recipients.display_placeholder',
                                            )}
                                            value={recipientDisplayName}
                                            onChange={(e) =>
                                                setRecipientDisplayName(
                                                    e.target.value,
                                                )
                                            }
                                        />
                                        {/* When the button is disabled, surface
                                            WHY so the operator isn't stuck staring
                                            at a dead button with no clue. */}
                                        {!recipientBusy &&
                                            operatorId &&
                                            recipientAddress.trim() !== '' &&
                                            (!pin || !helperIp) && (
                                                <div
                                                    style={{
                                                        fontSize: 11,
                                                        color: 'var(--muted)',
                                                        fontFamily:
                                                            'var(--font-mono)',
                                                    }}
                                                >
                                                    {!pin
                                                        ? t(
                                                              'wiz.recipients.need_pin',
                                                          )
                                                        : t(
                                                              'wiz.recipients.need_helper_ip',
                                                          )}
                                                </div>
                                            )}
                                        <Button
                                            disabled={
                                                recipientBusy ||
                                                !operatorId ||
                                                !pin ||
                                                !helperIp ||
                                                recipientAddress.trim() === ''
                                            }
                                            onClick={async () => {
                                                if (!operatorId) return;
                                                setRecipientBusy(true);
                                                setRecipientError(null);
                                                try {
                                                    const s =
                                                        await Wizard.recipientProvision(
                                                            operatorId,
                                                            pin,
                                                            helperIp,
                                                            recipientAddress.trim(),
                                                            recipientDisplayName.trim(),
                                                        );
                                                    setRecipients((prev) => [
                                                        s,
                                                        ...prev,
                                                    ]);
                                                    setRecipientAddress('');
                                                    setRecipientDisplayName('');
                                                } catch (e) {
                                                    setRecipientError(
                                                        String(e),
                                                    );
                                                } finally {
                                                    setRecipientBusy(false);
                                                }
                                            }}
                                        >
                                            {recipientBusy
                                                ? `${t('wiz.recipients.adding')} (${recipientElapsed}s)`
                                                : t('wiz.recipients.add')}
                                        </Button>
                                        {/* FRP-14 UX: while the add is in flight,
                                            spell out the steps so the user knows
                                            the app is alive and what stage of the
                                            ~30s round-trip it's in. */}
                                        {recipientBusy && (
                                            <div
                                                style={{
                                                    fontFamily:
                                                        'var(--font-mono)',
                                                    fontSize: 11,
                                                    color: 'var(--muted)',
                                                    lineHeight: 1.5,
                                                }}
                                            >
                                                {t(
                                                    'wiz.recipients.adding_detail',
                                                )}
                                            </div>
                                        )}
                                        {recipientError && (
                                            <>
                                                <div
                                                    style={{
                                                        fontFamily:
                                                            'var(--font-mono)',
                                                        fontSize: 11,
                                                        color: 'var(--danger)',
                                                    }}
                                                >
                                                    {recipientError}
                                                </div>
                                                {/* Surface a clear next step when
                                                    the server is unreachable on
                                                    the mgmt port. This happens on
                                                    relays provisioned before the
                                                    box-side ufw fix shipped — the
                                                    only recovery is to scrap +
                                                    redeploy with the new cloud-
                                                    init. */}
                                                {/(context deadline exceeded|connection refused|i\/o timeout|no route to host)/i.test(
                                                    recipientError,
                                                ) && (
                                                    <div
                                                        style={{
                                                            fontSize: 11,
                                                            color: 'var(--muted)',
                                                            lineHeight: 1.5,
                                                        }}
                                                    >
                                                        {t(
                                                            'wiz.recipients.err_unreachable',
                                                        )}
                                                    </div>
                                                )}
                                            </>
                                        )}
                                    </div>

                                    {/* Roster */}
                                    {recipients.length > 0 && (
                                        <div style={{ marginTop: 14 }}>
                                            {recipients.map((r) => (
                                                <Card
                                                    key={r.id}
                                                    style={{
                                                        background:
                                                            r.revoked_at_unix !==
                                                            0
                                                                ? 'var(--surface-1)'
                                                                : 'var(--surface-2)',
                                                        opacity:
                                                            r.revoked_at_unix !==
                                                            0
                                                                ? 0.55
                                                                : 1,
                                                        marginBottom: 8,
                                                    }}
                                                >
                                                    <div
                                                        style={{
                                                            display: 'flex',
                                                            justifyContent:
                                                                'space-between',
                                                            gap: 12,
                                                            alignItems:
                                                                'flex-start',
                                                        }}
                                                    >
                                                        <div style={{ minWidth: 0 }}>
                                                            <div
                                                                style={{
                                                                    fontSize:
                                                                        14,
                                                                    fontWeight: 600,
                                                                }}
                                                            >
                                                                {r.display_name ||
                                                                    r.name}
                                                            </div>
                                                            <div
                                                                style={{
                                                                    fontFamily:
                                                                        'var(--font-mono)',
                                                                    fontSize:
                                                                        11,
                                                                    color:
                                                                        'var(--dim)',
                                                                    wordBreak:
                                                                        'break-all',
                                                                    marginTop: 2,
                                                                }}
                                                            >
                                                                {r.address_str}
                                                            </div>
                                                            {r.revoked_at_unix ===
                                                                0 &&
                                                                r.sbpx_path && (
                                                                    <div
                                                                        style={{
                                                                            marginTop: 8,
                                                                        }}
                                                                    >
                                                                        <Button
                                                                            variant="ghost"
                                                                            onClick={async () => {
                                                                                try {
                                                                                    await Wizard.shareInviteSbpx(
                                                                                        r.sbpx_path,
                                                                                        r.display_name ||
                                                                                            r.name,
                                                                                    );
                                                                                } catch (e) {
                                                                                    setRecipientError(
                                                                                        String(
                                                                                            e,
                                                                                        ),
                                                                                    );
                                                                                }
                                                                            }}
                                                                        >
                                                                            {t(
                                                                                'wiz.recipients.share',
                                                                            )}
                                                                        </Button>
                                                                    </div>
                                                                )}
                                                        </div>
                                                        {r.revoked_at_unix ===
                                                            0 && (
                                                            <Button
                                                                variant="ghost"
                                                                disabled={
                                                                    recipientBusy ||
                                                                    !pin ||
                                                                    !helperIp
                                                                }
                                                                onClick={async () => {
                                                                    if (
                                                                        !operatorId
                                                                    )
                                                                        return;
                                                                    setRecipientBusy(
                                                                        true,
                                                                    );
                                                                    setRecipientError(
                                                                        null,
                                                                    );
                                                                    try {
                                                                        const u =
                                                                            await Wizard.recipientRevoke(
                                                                                operatorId,
                                                                                pin,
                                                                                helperIp,
                                                                                r.id,
                                                                            );
                                                                        setRecipients(
                                                                            (
                                                                                prev,
                                                                            ) =>
                                                                                prev.map(
                                                                                    (
                                                                                        x,
                                                                                    ) =>
                                                                                        x.id ===
                                                                                        u.id
                                                                                            ? u
                                                                                            : x,
                                                                                ),
                                                                        );
                                                                    } catch (e) {
                                                                        setRecipientError(
                                                                            String(
                                                                                e,
                                                                            ),
                                                                        );
                                                                    } finally {
                                                                        setRecipientBusy(
                                                                            false,
                                                                        );
                                                                    }
                                                                }}
                                                            >
                                                                {t(
                                                                    'wiz.recipients.revoke',
                                                                )}
                                                            </Button>
                                                        )}
                                                        {r.revoked_at_unix !==
                                                            0 && (
                                                            <div
                                                                style={{
                                                                    fontFamily:
                                                                        'var(--font-mono)',
                                                                    fontSize:
                                                                        10,
                                                                    color:
                                                                        'var(--dim)',
                                                                    textTransform:
                                                                        'uppercase',
                                                                    letterSpacing:
                                                                        '0.18em',
                                                                    paddingTop: 4,
                                                                }}
                                                            >
                                                                {t(
                                                                    'wiz.recipients.revoked',
                                                                )}
                                                            </div>
                                                        )}
                                                    </div>
                                                </Card>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                <div style={{ marginTop: 18 }}>
                                    <Button
                                        variant="ghost"
                                        onClick={() => {
                                            mark('distribute');
                                            setStepIdx(0);
                                            if (live) {
                                                Wizard.listOperators()
                                                    .then(setOperators)
                                                    .catch(() => {});
                                            }
                                        }}
                                    >
                                        {t('wiz.distribute.back_to_servers')}
                                    </Button>
                                </div>
                            </div>
                        )}
                    </Card>

                    {operatorId && (
                        <Button
                            variant="ghost"
                            onClick={async () => {
                                if (live) {
                                    await run(() =>
                                        Wizard.cancelAndCleanup(operatorId),
                                    );
                                } else {
                                    mock.operators = mock.operators.filter(
                                        (o) => o.id !== operatorId,
                                    );
                                }
                                setOperatorId(null);
                                setStepIdx(0);
                                setCompleted({
                                    operator: false,
                                    provider: false,
                                    pricing: false,
                                    keys: false,
                                    provision: false,
                                    sign: false,
                                    distribute: false,
                                });
                            }}
                        >
                            {t('wiz.cancel')}
                        </Button>
                    )}
                </div>
            </div>
        </div>
    );
}

// ---- Helpers ----

// PhoneStepPager — replacement for the side rail on phones.
// Renders as a compact horizontal card with:
//   * a back arrow that jumps to the previous step (disabled at idx 0)
//   * "Step N / M" mono-cased counter
//   * the current step's localised title (truncated with ellipsis)
//   * a forward arrow that jumps to the next step (only if the
//     current step is marked done — same gate as the desktop rail)
//   * a thin progress bar at the bottom showing N/M completion
//
// Total height < 56px so it doesn't crowd the wizard body on a phone.
function PhoneStepPager({
    steps,
    stepIdx,
    completed,
    onJump,
    t,
}: {
    steps: StepDef[];
    stepIdx: number;
    completed: Record<StepId, boolean>;
    onJump: (i: number) => void;
    t: (k: string) => string;
}) {
    const step = steps[stepIdx];
    const canBack = stepIdx > 0;
    const canForward =
        stepIdx < steps.length - 1 && completed[step.id];
    const pct = ((stepIdx + 1) / steps.length) * 100;
    const arrowBtn = (
        dir: 'back' | 'fwd',
        enabled: boolean,
        onClick: () => void,
    ) => (
        <button
            onClick={enabled ? onClick : undefined}
            disabled={!enabled}
            aria-label={dir === 'back' ? 'Previous step' : 'Next step'}
            style={{
                appearance: 'none',
                background: 'transparent',
                border: '1px solid var(--line)',
                color: enabled ? 'var(--gold-warm)' : 'var(--dim)',
                width: 36,
                height: 36,
                borderRadius: 10,
                cursor: enabled ? 'pointer' : 'not-allowed',
                fontFamily: 'var(--font-mono)',
                fontSize: 16,
                lineHeight: 1,
            }}
        >
            {dir === 'back' ? '‹' : '›'}
        </button>
    );
    return (
        <div
            style={{
                position: 'relative',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 10px 12px',
                background: 'var(--surface-2)',
                border: '1px solid var(--line-soft)',
                borderRadius: 12,
                marginBottom: 14,
            }}
        >
            {arrowBtn('back', canBack, () => onJump(stepIdx - 1))}
            <div style={{ flex: 1, minWidth: 0 }}>
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 9.5,
                        letterSpacing: '0.14em',
                        textTransform: 'uppercase',
                        color: 'var(--dim)',
                    }}
                >
                    {fmt(t('wiz.step.label'), {
                        n: stepIdx + 1,
                        total: steps.length,
                    })}
                </div>
                <div
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: 15,
                        color: 'var(--fg)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                    }}
                >
                    {t(step.titleKey)}
                </div>
            </div>
            {arrowBtn('fwd', !!canForward, () => onJump(stepIdx + 1))}
            <div
                aria-hidden
                style={{
                    position: 'absolute',
                    insetInlineStart: 0,
                    insetInlineEnd: 0,
                    bottom: 0,
                    height: 2,
                    background: 'var(--line-soft)',
                    borderBottomLeftRadius: 12,
                    borderBottomRightRadius: 12,
                    overflow: 'hidden',
                }}
            >
                <div
                    style={{
                        width: `${pct}%`,
                        height: '100%',
                        background: 'var(--gold-warm)',
                        transition: 'width var(--t-fast)',
                    }}
                />
            </div>
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
    canBack,
    onBack,
    nextDisabled,
    nextLabel,
    onNext,
}: {
    t: (k: string) => string;
    canBack: boolean;
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
            <Button
                variant="ghost"
                disabled={!canBack}
                onClick={onBack}
            >
                {t('wiz.nav.back')}
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
