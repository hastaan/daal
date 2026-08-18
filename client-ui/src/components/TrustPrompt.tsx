// TrustPrompt.tsx — modal trust prompt with EN+FA word grid.
// Used by AddEntryModal and the onboarding R4 step.

import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle, TrustDecision } from '../contract/D2Contract';
import { useDensity } from '../design/DensityProvider';
import { Button } from '../design/primitives';
import { parseVerdict, type TrustResolution } from '../lib/importVerdict';

interface Props {
    t: (k: string) => string;
    preview: PreviewedBundle;
    /** Receives what the ENGINE said, not merely what the user tapped.
     *  Callers must not report success without checking it — see
     *  `trustFailure` in lib/importVerdict. */
    onResolve: (r: TrustResolution) => void;
}

export default function TrustPrompt({ t, preview, onResolve }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const choose = async (decision: TrustDecision) => {
        // resolveTrustPrompt is the call that COMMITS the routes, and it
        // re-verifies the pending bundle first, so it can legitimately
        // refuse here — a revocation that landed while the word grid was
        // on screen, an expiry, or a failed save. Both its return value
        // and its exception are load-bearing; this used to discard both
        // and report success either way.
        let verdict = null;
        let error: string | null = null;
        try {
            const raw = await contract.resolveTrustPrompt(preview.fingerprintHex, decision);
            verdict = parseVerdict(raw ?? '');
        } catch (e) {
            error = e instanceof Error ? e.message : String(e);
        }
        onResolve({ decision, verdict, error });
    };

    const enWords = preview.fingerprintEN.split(/\s+/);
    const faWords = preview.fingerprintFA.split(/\s+/);

    return (
        <div
            style={{
                background: 'var(--teal-deep)',
                border: '1px solid var(--teal-border)',
                borderRadius: 'var(--radius-md)',
                padding: 16,
                marginTop: 18,
            }}
            role="region"
            aria-label={t('trust.title')}
        >
            <h3
                style={{
                    fontFamily: 'var(--font-display)',
                    fontSize: 16,
                    color: 'var(--paper)',
                    margin: 0,
                    marginBottom: 4,
                }}
            >
                {t('trust.title')}
            </h3>
            <p
                style={{
                    color: 'var(--paper-dim)',
                    fontSize: 13,
                    margin: 0,
                    marginBottom: 12,
                }}
            >
                {t('trust.body')}
            </p>
            <div
                style={{
                    display: 'grid',
                    gridTemplateColumns: isPhone ? '1fr' : '1fr 1fr',
                    gap: 12,
                    marginBottom: 14,
                }}
            >
                <WordGrid title={t('trust.fingerprint.en')} words={enWords} />
                <WordGrid
                    title={t('trust.fingerprint.fa')}
                    words={faWords}
                    rtl
                />
            </div>
            <div
                style={{
                    display: 'flex',
                    gap: 8,
                    justifyContent: isPhone ? 'stretch' : 'flex-end',
                    flexDirection: isPhone ? 'column-reverse' : 'row',
                }}
            >
                <Button variant="ghost" onClick={() => choose(2)} block={isPhone}>
                    {t('trust.cancel')}
                </Button>
                <Button
                    variant="secondary"
                    onClick={() => choose(1)}
                    block={isPhone}
                >
                    {t('trust.once')}
                </Button>
                <Button onClick={() => choose(0)} block={isPhone}>
                    {t('trust.trust')}
                </Button>
            </div>
        </div>
    );
}

function WordGrid({
    title,
    words,
    rtl,
}: {
    title: string;
    words: string[];
    rtl?: boolean;
}) {
    return (
        <div style={{ direction: rtl ? 'rtl' : 'ltr' }}>
            <div
                style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    letterSpacing: '0.16em',
                    textTransform: 'uppercase',
                    color: 'var(--ink-mute)',
                    marginBottom: 6,
                }}
            >
                {title}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {words.map((w, i) => (
                    <span
                        key={i}
                        style={{
                            background: 'var(--teal-raised)',
                            border: '1px solid var(--teal-border)',
                            borderRadius: 'var(--radius-sm)',
                            padding: '4px 10px',
                            fontFamily: rtl ? 'var(--font-fa)' : 'var(--font-mono)',
                            fontSize: 13,
                            color: 'var(--paper)',
                        }}
                    >
                        {w}
                    </span>
                ))}
            </div>
        </div>
    );
}


