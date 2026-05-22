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

import { useEffect, useMemo, useState } from 'react';
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
} from './wizardCommands';
import { isHarnessActive } from '../harness/scenarios';
import { isTauriRuntime } from '../backends';
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
        defaultServer: 'cx21',
        tokenHintKey: 'wiz.provider.hetzner.tokenHint',
    },
    {
        id: 'vultr',
        labelKey: 'wiz.provider.vultr.label',
        regionKey: 'wiz.provider.vultr.region',
        defaultServer: 'vc2-1c-1gb',
        tokenHintKey: 'wiz.provider.vultr.tokenHint',
    },
    {
        id: 'digitalocean',
        labelKey: 'wiz.provider.do.label',
        regionKey: 'wiz.provider.do.region',
        defaultServer: 's-1vcpu-1gb',
        tokenHintKey: 'wiz.provider.do.tokenHint',
    },
    {
        id: 'linode',
        labelKey: 'wiz.provider.linode.label',
        regionKey: 'wiz.provider.linode.region',
        defaultServer: 'g6-nanode-1',
        tokenHintKey: 'wiz.provider.linode.tokenHint',
    },
    {
        id: 'custom',
        labelKey: 'wiz.provider.custom.label',
        regionKey: 'wiz.provider.custom.region',
        defaultServer: 'custom',
        tokenHintKey: 'wiz.provider.custom.tokenHint',
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
    operator_id: number;
    label: string;
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
    const [region, setRegion] = useState('eu-central');
    const [serverType, setServerType] = useState<string>(providerDef.defaultServer);
    const [toolboxProfile, setToolboxProfile] = useState('default');
    const [enabledFamilies, setEnabledFamilies] = useState<string[]>([
        'pars',
        'wg',
    ]);
    const [pricing, setPricing] = useState<{
        monthly_usd: number;
        bandwidth_tib: number;
    } | null>(null);

    // Keys + provision + sign + distribute.
    const [fp, setFp] = useState<Fingerprint | null>(null);
    const [helperIp, setHelperIp] = useState('203.0.113.10');
    const [provisionLog, setProvisionLog] = useState<ProgressEvent[]>([]);
    const [signLog, setSignLog] = useState<ProgressEvent[]>([]);
    const [bindResult, setBindResult] = useState<BindResult | null>(null);
    const [qrFrame, setQrFrame] = useState<FountainFrame | null>(null);
    const [phase, setPhase] = useState('production');
    const [outputDir, setOutputDir] = useState('/tmp/daal-bundles');
    const [publisherName, setPublisherName] = useState('My Family Relay');

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
        return () => unsubs.forEach((u) => u());
    }, [live]);

    // Load operator list on entry.
    useEffect(() => {
        if (live) {
            Wizard.listOperators()
                .then((rows) => setOperators(rows))
                .catch((e) => setError(String(e)));
        } else {
            setOperators(
                mock.operators.map((o) => ({
                    operator_id: o.operator_id,
                    label: o.label,
                    region: o.region,
                    server_type: o.server_type,
                    created_unix: Math.floor(Date.now() / 1000),
                })),
            );
        }
    }, [live, creatingOperator]);

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
                { phase: phaseName, detail, pct },
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
                                <Label>{t('wiz.op.existing')}</Label>
                                {operators.length === 0 ? (
                                    <EmptyHint>{t('wiz.op.empty')}</EmptyHint>
                                ) : (
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
                                                operatorId === o.operator_id;
                                            return (
                                                <li key={o.operator_id}>
                                                    <button
                                                        onClick={() =>
                                                            setOperatorId(
                                                                o.operator_id,
                                                            )
                                                        }
                                                        style={{
                                                            width: '100%',
                                                            display: 'flex',
                                                            alignItems: 'center',
                                                            gap: 10,
                                                            padding:
                                                                '10px 12px',
                                                            background: sel
                                                                ? 'rgba(201,162,58,0.10)'
                                                                : 'var(--surface-2)',
                                                            border: `1px solid ${
                                                                sel
                                                                    ? 'var(--gold)'
                                                                    : 'var(--line-soft)'
                                                            }`,
                                                            borderRadius:
                                                                'var(--r-tile)',
                                                            cursor: 'pointer',
                                                            color: 'var(--fg)',
                                                            fontFamily:
                                                                'var(--font-body)',
                                                            textAlign: 'start',
                                                        }}
                                                    >
                                                        <span
                                                            style={{
                                                                fontFamily:
                                                                    'var(--font-mono)',
                                                                fontSize: 11,
                                                                color: 'var(--dim)',
                                                            }}
                                                        >
                                                            #{o.operator_id}
                                                        </span>
                                                        <span
                                                            style={{ flex: 1 }}
                                                        >
                                                            {o.label}
                                                        </span>
                                                        <span
                                                            style={{
                                                                fontFamily:
                                                                    'var(--font-mono)',
                                                                fontSize: 10,
                                                                color: 'var(--muted)',
                                                            }}
                                                        >
                                                            {o.region} ·{' '}
                                                            {o.server_type}
                                                        </span>
                                                    </button>
                                                </li>
                                            );
                                        })}
                                    </ul>
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
                                    <Button
                                        variant="secondary"
                                        disabled={busy || !newLabel}
                                        onClick={async () => {
                                            setCreatingOperator(true);
                                            try {
                                                if (!live) {
                                                    const id = mock.nextId++;
                                                    mock.operators.push({
                                                        operator_id: id,
                                                        label: newLabel,
                                                        provider,
                                                        region: 'eu-central',
                                                        server_type:
                                                            providerDef.defaultServer,
                                                    });
                                                    setOperatorId(id);
                                                    setNewLabel('');
                                                } else {
                                                    // Real engine creates
                                                    // operator on first
                                                    // pricing_lookup; the
                                                    // wizard treats nextId as
                                                    // the next slot.
                                                    setOperatorId(
                                                        operators.length + 1,
                                                    );
                                                }
                                            } finally {
                                                setCreatingOperator(false);
                                            }
                                        }}
                                    >
                                        {t('wiz.op.add')}
                                    </Button>
                                </div>

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() =>
                                        setStepIdx((i) => Math.max(0, i - 1))
                                    }
                                    nextDisabled={operatorId == null}
                                    onNext={() => {
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
                                        return (
                                            <button
                                                key={p.id}
                                                onClick={() => {
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
                                                    color: 'var(--fg)',
                                                    padding: '10px 12px',
                                                    borderRadius:
                                                        'var(--r-tile)',
                                                    cursor: 'pointer',
                                                    textAlign: 'start',
                                                    fontFamily:
                                                        'var(--font-body)',
                                                }}
                                            >
                                                <div
                                                    style={{
                                                        fontSize: 13,
                                                        fontWeight: 600,
                                                    }}
                                                >
                                                    {t(p.labelKey)}
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
                                                    {t(p.regionKey)}
                                                </div>
                                            </button>
                                        );
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
                                    style={{ marginBottom: 10 }}
                                />

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

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={
                                        busy || !pin || !token || pin.length < 6
                                    }
                                    onNext={async () => {
                                        if (!operatorId) return;
                                        if (live) {
                                            await run(() =>
                                                Wizard.storeCloudToken(
                                                    provider,
                                                    token,
                                                    pin,
                                                ),
                                            );
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
                                <div
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: isPhone
                                            ? '1fr'
                                            : '1fr 1fr',
                                        gap: 10,
                                        marginBottom: 10,
                                    }}
                                >
                                    <div>
                                        <Label>{t('wiz.pricing.region')}</Label>
                                        <Input
                                            placeholder={
                                                t(providerDef.regionKey).split(
                                                    ' · ',
                                                )[0]
                                            }
                                            value={region}
                                            onChange={(e) =>
                                                setRegion(e.target.value)
                                            }
                                        />
                                    </div>
                                    <div>
                                        <Label>{t('wiz.pricing.server')}</Label>
                                        <Input
                                            value={serverType}
                                            onChange={(e) =>
                                                setServerType(e.target.value)
                                            }
                                        />
                                    </div>
                                </div>
                                <Label>{t('wiz.pricing.toolbox')}</Label>
                                <Input
                                    value={toolboxProfile}
                                    onChange={(e) =>
                                        setToolboxProfile(e.target.value)
                                    }
                                    style={{ marginBottom: 10 }}
                                />
                                <Label>{t('wiz.pricing.families')}</Label>
                                <div
                                    style={{
                                        display: 'flex',
                                        gap: 6,
                                        flexWrap: 'wrap',
                                        marginBottom: 14,
                                    }}
                                >
                                    {['pars', 'wg', 'masque', 'snowflake'].map(
                                        (f) => {
                                            const on =
                                                enabledFamilies.includes(f);
                                            return (
                                                <button
                                                    key={f}
                                                    onClick={() =>
                                                        setEnabledFamilies(
                                                            (cur) =>
                                                                on
                                                                    ? cur.filter(
                                                                          (
                                                                              x,
                                                                          ) =>
                                                                              x !==
                                                                              f,
                                                                      )
                                                                    : [
                                                                          ...cur,
                                                                          f,
                                                                      ],
                                                        )
                                                    }
                                                    style={{
                                                        background: on
                                                            ? 'var(--gold-warm)'
                                                            : 'var(--surface-2)',
                                                        color: on
                                                            ? 'oklch(20% 0.04 80)'
                                                            : 'var(--muted)',
                                                        border: 0,
                                                        padding: '6px 12px',
                                                        borderRadius:
                                                            'var(--r-pill)',
                                                        fontFamily:
                                                            'var(--font-mono)',
                                                        fontSize: 11,
                                                        cursor: 'pointer',
                                                    }}
                                                >
                                                    {f}
                                                </button>
                                            );
                                        },
                                    )}
                                </div>

                                {pricing && (
                                    <Card
                                        style={{
                                            marginBottom: 14,
                                            background: 'var(--surface-2)',
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
                                            {t('wiz.pricing.card.eyebrow')}
                                        </div>
                                        <div
                                            style={{
                                                fontFamily:
                                                    'var(--font-display)',
                                                fontSize: 22,
                                                color: 'var(--fg)',
                                                marginTop: 4,
                                            }}
                                        >
                                            {fmt(t('wiz.pricing.card.month'), {
                                                amount:
                                                    pricing.monthly_usd.toFixed(
                                                        2,
                                                    ),
                                            })}
                                        </div>
                                        <div
                                            style={{
                                                fontSize: 12,
                                                color: 'var(--muted)',
                                            }}
                                        >
                                            {fmt(t('wiz.pricing.card.sub'), {
                                                tib: pricing.bandwidth_tib,
                                            })}
                                        </div>
                                    </Card>
                                )}

                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextDisabled={
                                        busy ||
                                        !operatorId ||
                                        !region ||
                                        !serverType ||
                                        enabledFamilies.length === 0
                                    }
                                    nextLabel={
                                        pricing
                                            ? t('wiz.pricing.next.continue')
                                            : t('wiz.pricing.next.lookup')
                                    }
                                    onNext={async () => {
                                        if (!operatorId) return;
                                        if (live) {
                                            const p = await run(() =>
                                                Wizard.pricingLookup(
                                                    operatorId,
                                                    region,
                                                    serverType,
                                                    pin,
                                                ),
                                            );
                                            if (p) setPricing(p);
                                            await run(() =>
                                                Wizard.selectProfile(
                                                    operatorId,
                                                    region,
                                                    serverType,
                                                    toolboxProfile,
                                                    enabledFamilies,
                                                ),
                                            );
                                        } else {
                                            setPricing({
                                                monthly_usd: 5.49,
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
                                                words: fp.en?.join(' ') ?? '',
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
                                                words: fp.fa?.join(' ') ?? '',
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
                                                    en: 'phoenix rescue may sky honest stone river hill'.split(
                                                        ' ',
                                                    ),
                                                    fa: 'ققنوس نجات اردیبهشت آسمان درست سنگ رود تپه'.split(
                                                        ' ',
                                                    ),
                                                    visual_data_uri: '',
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
                                <Label>{t('wiz.provision.helperIp')}</Label>
                                <Input
                                    value={helperIp}
                                    onChange={(e) =>
                                        setHelperIp(e.target.value)
                                    }
                                    style={{ marginBottom: 12 }}
                                />
                                <Button
                                    disabled={busy || !operatorId || !pin}
                                    onClick={async () => {
                                        if (!operatorId) return;
                                        setProvisionLog([]);
                                        if (live) {
                                            await run(() =>
                                                Wizard.provisionRun(
                                                    operatorId,
                                                    pin,
                                                    helperIp,
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
                                        !completed.provision && provisionLog.length === 0
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
                                <div
                                    style={{
                                        display: 'grid',
                                        gridTemplateColumns: isPhone
                                            ? '1fr'
                                            : '1fr 1fr',
                                        gap: 10,
                                    }}
                                >
                                    <div>
                                        <Label>{t('wiz.sign.phase')}</Label>
                                        <Input
                                            value={phase}
                                            onChange={(e) =>
                                                setPhase(e.target.value)
                                            }
                                        />
                                    </div>
                                    <div>
                                        <Label>{t('wiz.sign.outdir')}</Label>
                                        <Input
                                            value={outputDir}
                                            onChange={(e) =>
                                                setOutputDir(e.target.value)
                                            }
                                        />
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
                                    disabled={busy || !operatorId || !pin}
                                    onClick={async () => {
                                        if (!operatorId) return;
                                        setSignLog([]);
                                        if (live) {
                                            const r = await run(() =>
                                                Wizard.signRelaypack(
                                                    operatorId,
                                                    pin,
                                                    phase,
                                                    outputDir,
                                                    publisherName,
                                                ),
                                            );
                                            if (r) setBindResult(r);
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
                                                fingerprint_hex: 'aa'.repeat(16),
                                                output_path:
                                                    `${outputDir}/${publisherName.replace(
                                                        / /g,
                                                        '-',
                                                    )}-${phase}.sbp`,
                                            });
                                        }
                                        mark('sign');
                                    }}
                                >
                                    {busy
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
                                                fontFamily:
                                                    'var(--font-mono)',
                                                fontSize: 12,
                                                color: 'var(--fg)',
                                                marginTop: 4,
                                                wordBreak: 'break-all',
                                            }}
                                        >
                                            {bindResult.output_path}
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

                        {/* ===== STEP 7: DISTRIBUTE ===== */}
                        {step.id === 'distribute' && (
                            <div>
                                <div
                                    style={{
                                        display: 'flex',
                                        gap: 8,
                                        flexWrap: 'wrap',
                                        marginBottom: 12,
                                    }}
                                >
                                    <Button
                                        disabled={busy || !operatorId}
                                        onClick={async () => {
                                            if (!operatorId) return;
                                            if (live) {
                                                await run(() =>
                                                    Wizard.qrRender(
                                                        operatorId,
                                                        256,
                                                        64,
                                                        0,
                                                    ),
                                                );
                                            } else {
                                                setQrFrame({
                                                    index: 1,
                                                    total_frames: 64,
                                                    frame_b64: '',
                                                });
                                            }
                                        }}
                                    >
                                        {t('wiz.distribute.qr')}
                                    </Button>
                                    <Button
                                        variant="secondary"
                                        disabled={busy || !operatorId}
                                        onClick={async () => {
                                            if (!operatorId) return;
                                            if (live) {
                                                const p = await run(() =>
                                                    Wizard.finalizePreProvision(
                                                        operatorId,
                                                    ),
                                                );
                                                if (p)
                                                    alert(
                                                        fmt(
                                                            t(
                                                                'wiz.distribute.alert.finalized',
                                                            ),
                                                            { path: p },
                                                        ),
                                                    );
                                            } else {
                                                alert(
                                                    fmt(
                                                        t(
                                                            'wiz.distribute.alert.finalized',
                                                        ),
                                                        {
                                                            path: `${outputDir}/preprovision-${operatorId}.json`,
                                                        },
                                                    ),
                                                );
                                            }
                                            mark('distribute');
                                        }}
                                    >
                                        {t('wiz.distribute.save')}
                                    </Button>
                                </div>
                                {qrFrame && (
                                    <div
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            marginBottom: 8,
                                        }}
                                    >
                                        {fmt(t('wiz.distribute.frame'), {
                                            i: qrFrame.index,
                                            total: qrFrame.total_frames,
                                        })}
                                    </div>
                                )}
                                <NavRow
                                    t={t}
                                    canBack={canBack}
                                    onBack={() => setStepIdx((i) => i - 1)}
                                    nextLabel={t('wiz.nav.finish')}
                                    nextDisabled={false}
                                    onNext={() => {
                                        mark('distribute');
                                    }}
                                />
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
                                        (o) => o.operator_id !== operatorId,
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
    if (events.length === 0) return null;
    return (
        <ul
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
                <li key={i}>
                    [{ev.phase}] {ev.detail}
                    {ev.pct !== undefined && ` · ${ev.pct}%`}
                </li>
            ))}
        </ul>
    );
}
