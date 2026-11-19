// Onboarding.tsx — desktop renderer of the shared onboarding state
// machine (client-shared/onboarding/onboarding-spec-v1.md).

import { useState } from 'react';
import { applyDir, type Locale } from '../lib/i18n';
import { Prefs, type Lane } from '../lib/prefs';
import { useDensity } from '../design/DensityProvider';
import daalLogoSvg from '@branding/sources/daal-eagle.svg?url';

type Screen = 'W' | 'B' | 'P2';

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

// Maps ?step=N harness URLs to the internal Screen tokens.
const STEP_ORDER: Screen[] = ['W', 'B', 'P2'];

function initialScreenFromUrl(): Screen {
    try {
        const params = new URLSearchParams(window.location.search);
        const stepRaw = params.get('step');
        if (!stepRaw) return 'W';
        const step = parseInt(stepRaw, 10);
        if (!Number.isFinite(step)) return 'W';
        const idx = Math.max(1, Math.min(STEP_ORDER.length, step)) - 1;
        return STEP_ORDER[idx];
    } catch {
        return 'W';
    }
}

export default function Onboarding({
    locale,
    onLocaleChange,
    onComplete,
    t,
}: Props) {
    // M0 detection is not wired in the dev shell; we go straight to
    // Welcome. A future migration probe (D-2 §7.2) will check the
    // legacy data path and swap to M0 when relevant.
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const [screen, setScreen] = useState<Screen>(initialScreenFromUrl());
    const [lane, setLaneState] = useState<Lane | null>(null);

    const setLane = (l: Lane) => {
        Prefs.setLane(l);
        setLaneState(l);
    };

    const finish = () => {
        Prefs.setOnboardingCompleted(true);
        onComplete();
    };

    return (
        <div
            style={{
                height: '100%',
                background: 'var(--bg)',
                color: 'var(--paper)',
                display: 'flex',
                alignItems: isPhone ? 'flex-start' : 'center',
                justifyContent: 'center',
                padding: isPhone ? '20px 14px' : 32,
                overflow: 'auto',
            }}
        >
            <div style={{ maxWidth: isPhone ? 480 : 720, width: '100%' }}>
                <Header
                    t={t}
                    locale={locale}
                    onLocaleChange={(l) => {
                        onLocaleChange(l);
                        applyDir(l);
                    }}
                />

                {screen === 'W' && (
                    <Card>
                        <img
                            src={daalLogoSvg}
                            alt={t('app.title')}
                            width={128}
                            height={128}
                            style={{
                                display: 'block',
                                margin: '0 auto 16px',
                                objectFit: 'contain',
                            }}
                        />
                        <Kicker>{t('onboarding.welcome.title')}</Kicker>
                        <H1>{t('app.tagline')}</H1>
                        {/* The first choice is the language, offered in
                            both, each in its own script: a person who
                            reads only Farsi must not have to find a
                            small toggle on an English screen. */}
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            {WELCOME_LANGUAGES.map((l) => (
                                <Primary
                                    key={l.locale}
                                    onClick={() => {
                                        onLocaleChange(l.locale);
                                        applyDir(l.locale);
                                        setScreen('B');
                                    }}
                                >
                                    {l.label}
                                </Primary>
                            ))}
                        </div>
                    </Card>
                )}

                {screen === 'B' && (
                    <Card>
                        <Kicker>{t('onboarding.branch.title')}</Kicker>
                        <Lane
                            primary
                            title={t('onboarding.branch.recipient')}
                            detail={t('onboarding.branch.recipient.detail')}
                            onClick={() => {
                                setLane('recipient');
                                finish();
                            }}
                        />
                        <Lane
                            title={t('onboarding.branch.publisher')}
                            detail={t('onboarding.branch.publisher.detail')}
                            onClick={() => {
                                setLane('publisher');
                                Prefs.setPublisherEnabled(true);
                                setScreen('P2');
                            }}
                        />
                        <Lane
                            tertiary
                            title={t('onboarding.branch.unsure')}
                            detail={t('onboarding.branch.unsure.banner')}
                            onClick={() => {
                                setLane('unsure');
                                finish();
                            }}
                        />
                    </Card>
                )}

                {/* What used to follow here (a permissions page, "paste a
                    source URL", a trust question whose three buttons all
                    did the same thing, "read these four words" with no
                    words) described an older design. The main screen
                    asks for the file and the system asks for the
                    permission when it is needed. */}
                {screen === 'P2' && (
                    <Card>
                        <Kicker>{t('onboarding.p2.title')}</Kicker>
                        <Body>{t('onboarding.p2.body')}</Body>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                            <Primary
                                onClick={() => {
                                    Prefs.setFirstSection('publisher');
                                    finish();
                                }}
                            >
                                {t('common.continue')}
                            </Primary>
                            <Secondary onClick={() => setScreen('B')}>
                                {t('common.back')}
                            </Secondary>
                        </div>
                    </Card>
                )}

                {/* The lane variable is consumed by the migration
                    branch on real installs; we acknowledge it here
                    for completeness so React-strict-mode warnings
                    don't fire on the dev shell. */}
                <span style={{ display: 'none' }}>{lane}</span>
            </div>
        </div>
    );
}

function Header({
    t,
    locale,
    onLocaleChange,
}: {
    t: (k: string) => string;
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
}) {
    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 12,
                marginBottom: 32,
                fontFamily: 'var(--font-display)',
            }}
        >
            <span
                style={{
                    fontSize: 30,
                    color: 'var(--gold-soft)',
                    fontWeight: 600,
                }}
            >
                دال
            </span>
            <span style={{ fontSize: 18, letterSpacing: '0.04em' }}>
                {t('app.title')}
            </span>
            <span style={{ flex: 1 }} />
            <button
                onClick={() => onLocaleChange(locale === 'en' ? 'fa' : 'en')}
                style={{
                    background: 'transparent',
                    color: 'var(--paper-dim)',
                    border: '1px solid var(--teal-border)',
                    borderRadius: 'var(--radius-md)',
                    padding: '4px 10px',
                    cursor: 'pointer',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                }}
                aria-label={t('lang.toggle.aria')}
            >
                {locale === 'en' ? t('lang.fa') : t('lang.en')}
            </button>
        </div>
    );
}

function Card({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                background: 'var(--teal-surface)',
                border: '1px solid var(--teal-border)',
                borderRadius: 'var(--radius-lg)',
                padding: 28,
                boxShadow: '0 30px 60px rgba(0,0,0,0.35)',
            }}
        >
            {children}
        </div>
    );
}
function Kicker({ children }: { children: React.ReactNode }) {
    return (
        <div
            style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                letterSpacing: '0.18em',
                textTransform: 'uppercase',
                color: 'var(--gold-soft)',
                marginBottom: 12,
            }}
        >
            {children}
        </div>
    );
}
function H1({ children }: { children: React.ReactNode }) {
    return (
        <h1
            style={{
                fontFamily: 'var(--font-display)',
                fontSize: 36,
                color: 'var(--paper)',
                margin: 0,
                marginBottom: 18,
                lineHeight: 1.15,
            }}
        >
            {children}
        </h1>
    );
}
function Body({ children }: { children: React.ReactNode }) {
    return (
        <p
            style={{
                color: 'var(--paper-dim)',
                fontSize: 14,
                marginTop: 0,
                marginBottom: 16,
            }}
        >
            {children}
        </p>
    );
}
function Primary({
    onClick,
    children,
}: {
    onClick: () => void;
    children: React.ReactNode;
}) {
    return (
        <button
            onClick={onClick}
            style={{
                background: 'var(--gold)',
                border: 0,
                color: '#1A1208',
                padding: '12px 18px',
                borderRadius: 'var(--radius-md)',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                fontWeight: 600,
                cursor: 'pointer',
            }}
        >
            {children}
        </button>
    );
}
function Secondary({
    onClick,
    children,
}: {
    onClick: () => void;
    children: React.ReactNode;
}) {
    return (
        <button
            onClick={onClick}
            style={{
                background: 'var(--teal-raised)',
                border: '1px solid var(--teal-border)',
                color: 'var(--paper)',
                padding: '10px 16px',
                borderRadius: 'var(--radius-md)',
                fontFamily: 'var(--font-body)',
                fontSize: 14,
                cursor: 'pointer',
            }}
        >
            {children}
        </button>
    );
}

function Lane({
    title,
    detail,
    onClick,
    primary,
    tertiary,
}: {
    title: string;
    detail: string;
    onClick: () => void;
    primary?: boolean;
    tertiary?: boolean;
}) {
    return (
        <button
            onClick={onClick}
            style={{
                width: '100%',
                background: primary
                    ? 'rgba(201,162,58,0.10)'
                    : 'var(--teal-raised)',
                border: `1px solid ${
                    primary ? 'var(--gold)' : 'var(--teal-border)'
                }`,
                color: 'var(--paper)',
                padding: 18,
                borderRadius: 'var(--radius-md)',
                marginBottom: 10,
                cursor: 'pointer',
                textAlign: 'start',
                opacity: tertiary ? 0.85 : 1,
                fontFamily: 'var(--font-body)',
            }}
        >
            <div
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 18,
                    color: primary ? 'var(--gold-soft)' : 'var(--paper)',
                    marginBottom: 4,
                }}
            >
                {title}
            </div>
            <div style={{ fontSize: 13, color: 'var(--paper-dim)' }}>
                {detail}
            </div>
        </button>
    );
}
