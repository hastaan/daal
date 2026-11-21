// Onboarding.tsx — first run (spec C1), the renderer of the shared
// onboarding state machine (client-shared/onboarding/onboarding-spec-v1.md).
//
//   W  Welcome: the mark, the name, one line, and the language, offered
//      in both scripts. Choosing one IS "continue".
//   B  "Who is this for?": two cards.
//        I want to connect          → Home, which asks for the file
//        I'm helping family connect → the Publisher tab, where the
//                                     relay wizard's first step says
//                                     what it costs
// The intro page a helper used to read first, and "I'm not sure yet"
// (which did exactly what "I want to connect" does), are gone.

import { useState } from 'react';
import { applyDir, type Locale } from '../lib/i18n';
import { Prefs } from '../lib/prefs';
import { useDensity } from '../design/DensityProvider';
import { Icon, IconButton } from '../design/primitives';
import type { IconName } from '../design/primitives';
import daalLogoSvg from '@branding/sources/daal-eagle.svg?url';
import { scenarioFromUrl } from '../harness/scenarios';

type Screen = 'W' | 'B';

/** The languages offered on the first screen, each named in itself. */
export const WELCOME_LANGUAGES: { locale: Locale; label: string }[] = [
    { locale: 'fa', label: 'فارسی' },
    { locale: 'en', label: 'English' },
];

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    onComplete: () => void;
    t: (k: string) => string;
}

// Maps ?step=N harness URLs to the screens (step 3 and above, the old
// helper intro, land on "Who is this for?").
const STEP_ORDER: Screen[] = ['W', 'B'];

function initialScreenFromUrl(): Screen {
    try {
        const params = new URLSearchParams(window.location.search);
        // The harness scenario's own route (`/onboarding?step=5`) when the
        // page URL does not say.
        const route = scenarioFromUrl()?.initialRoute ?? '';
        const fromRoute = route.includes('?') ? new URLSearchParams(route.slice(route.indexOf('?'))).get('step') : null;
        const stepRaw = params.get('step') ?? fromRoute;
        if (!stepRaw) return 'W';
        const step = parseInt(stepRaw, 10);
        if (!Number.isFinite(step)) return 'W';
        const idx = Math.max(1, Math.min(STEP_ORDER.length, step)) - 1;
        return STEP_ORDER[idx];
    } catch {
        return 'W';
    }
}

/** What each answer to "Who is this for?" does, without React. */
export function chooseLane(lane: 'recipient' | 'publisher'): void {
    Prefs.setLane(lane);
    if (lane === 'publisher') {
        Prefs.setPublisherEnabled(true);
        // The Publisher tab opens first, once; the wizard is its empty state.
        Prefs.setFirstSection('publisher');
    }
    Prefs.setOnboardingCompleted(true);
}

export default function Onboarding({ locale, onLocaleChange, onComplete, t }: Props) {
    // M0 detection is not wired in the dev shell; we go straight to
    // Welcome. A future migration probe (D-2 §7.2) will check the legacy
    // data path and swap to M0 when relevant.
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const [screen, setScreen] = useState<Screen>(initialScreenFromUrl());

    const setLocale = (l: Locale) => {
        onLocaleChange(l);
        applyDir(l);
    };
    const pick = (lane: 'recipient' | 'publisher') => {
        chooseLane(lane);
        onComplete();
    };

    return (
        <div
            style={{
                height: '100%',
                background: 'var(--bg)',
                color: 'var(--fg)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: isPhone ? '24px 16px' : 32,
                overflow: 'auto',
            }}
        >
            <div style={{ maxWidth: 480, width: '100%' }}>
                {screen === 'W' && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
                        <img
                            src={daalLogoSvg}
                            alt=""
                            aria-hidden
                            width={96}
                            height={96}
                            style={{ display: 'block', objectFit: 'contain' }}
                        />
                        <div
                            style={{
                                display: 'flex',
                                alignItems: 'baseline',
                                gap: 10,
                                marginBlockStart: 14,
                                fontFamily: 'var(--font-display)',
                            }}
                        >
                            <span style={{ fontSize: 30, color: 'var(--gold-warm)', fontWeight: 600 }}>دال</span>
                            {/* In Persian the name IS the mark: said once. */}
                            {t('app.title') !== 'دال' && (
                                <span style={{ fontSize: 22, color: 'var(--fg)' }}>{t('app.title')}</span>
                            )}
                        </div>
                        <h1
                            style={{
                                fontFamily: 'var(--font-display)',
                                fontSize: 'var(--fs-xl)',
                                fontWeight: 600,
                                lineHeight: 1.3,
                                margin: '12px 0 32px',
                                color: 'var(--fg)',
                            }}
                        >
                            {t('app.tagline')}
                        </h1>
                        {/* The first choice is the language, offered in
                            both, each in its own script: a person who
                            reads only Farsi must not have to find a small
                            toggle on an English screen. */}
                        <div
                            style={{
                                display: 'flex',
                                flexDirection: isPhone ? 'column' : 'row',
                                gap: 12,
                                width: '100%',
                            }}
                        >
                            {WELCOME_LANGUAGES.map((l) => (
                                <button
                                    key={l.locale}
                                    type="button"
                                    lang={l.locale}
                                    data-button={`lang-${l.locale}`}
                                    onClick={() => {
                                        setLocale(l.locale);
                                        setScreen('B');
                                    }}
                                    className="daal-hover"
                                    style={{
                                        flex: 1,
                                        minHeight: 56,
                                        background: 'var(--surface)',
                                        border: '1px solid var(--line)',
                                        color: 'var(--fg)',
                                        borderRadius: 'var(--radius-md)',
                                        fontFamily: l.locale === 'fa' ? 'var(--font-fa)' : 'var(--font-body)',
                                        fontSize: 18,
                                        fontWeight: 600,
                                        cursor: 'pointer',
                                    }}
                                >
                                    {l.label}
                                </button>
                            ))}
                        </div>
                    </div>
                )}

                {screen === 'B' && (
                    <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBlockEnd: 20 }}>
                            <h1
                                style={{
                                    flex: 1,
                                    fontFamily: 'var(--font-display)',
                                    fontSize: 'var(--fs-xl)',
                                    fontWeight: 600,
                                    margin: 0,
                                    color: 'var(--fg)',
                                }}
                            >
                                {t('onboarding.branch.title')}
                            </h1>
                            <IconButton
                                icon="globe"
                                label={t('lang.toggle.aria')}
                                onClick={() => setLocale(locale === 'en' ? 'fa' : 'en')}
                                dataButton="lang-toggle"
                            />
                        </div>
                        <div style={{ display: 'grid', gap: 12 }}>
                            <LaneCard
                                icon="person"
                                title={t('onboarding.branch.recipient')}
                                detail={t('onboarding.branch.recipient.detail')}
                                onClick={() => pick('recipient')}
                                dataButton="lane-recipient"
                            />
                            <LaneCard
                                icon="people"
                                title={t('onboarding.branch.publisher')}
                                detail={t('onboarding.branch.publisher.detail')}
                                onClick={() => pick('publisher')}
                                dataButton="lane-publisher"
                            />
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

function LaneCard({
    icon,
    title,
    detail,
    onClick,
    dataButton,
}: {
    icon: IconName;
    title: string;
    detail: string;
    onClick: () => void;
    dataButton: string;
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            data-button={dataButton}
            className="daal-hover"
            style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                background: 'var(--surface)',
                border: '1px solid var(--line)',
                color: 'var(--fg)',
                padding: 16,
                minHeight: 88,
                borderRadius: 'var(--r-card)',
                cursor: 'pointer',
                textAlign: 'start',
                fontFamily: 'var(--font-body)',
            }}
        >
            <span
                aria-hidden
                style={{
                    width: 48,
                    height: 48,
                    borderRadius: '50%',
                    flexShrink: 0,
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'var(--surface-2)',
                    color: 'var(--gold-warm)',
                }}
            >
                <Icon name={icon} size={24} />
            </span>
            <span style={{ flex: 1, minWidth: 0 }}>
                <span style={{ display: 'block', fontFamily: 'var(--font-display)', fontSize: 18, fontWeight: 600 }}>
                    {title}
                </span>
                <span style={{ display: 'block', fontSize: 14, color: 'var(--muted)', marginBlockStart: 2 }}>{detail}</span>
            </span>
            <span aria-hidden style={{ color: 'var(--muted)', display: 'inline-flex' }}>
                <Icon name="chevron" size={20} />
            </span>
        </button>
    );
}
