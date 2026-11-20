// TrustPrompt.tsx — "Is this file from {name}?" (spec C3.3a).
//
// A file from a publisher this phone has never met is not added until
// the person answers. The check words come from the engine's verdict:
// four English words and four Persian words, from DIFFERENT bytes of the
// key (one set is not a translation of the other), so both stay on
// screen — the set in the page's language first and large.
//
// Two answers: "Yes, I know them" (trust) and "No". "Use this file only"
// (trust this bundle, not the publisher) is behind "Other choices".
// Used by the add sheet for pasted, chosen, opened and scanned files.

import { useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { PreviewedBundle, TrustDecision } from '../contract/D2Contract';
import { useDensity } from '../design/DensityProvider';
import { Button, Disclosure, FingerprintThumb, Icon } from '../design/primitives';
import { effectiveLocale } from '../lib/i18n';
import { parseVerdict, type TrustResolution } from '../lib/importVerdict';

interface Props {
    t: (k: string) => string;
    preview: PreviewedBundle;
    /** Receives what the ENGINE said, not merely what the user tapped.
     *  Callers must not report success without checking it — see
     *  `trustFailure` in lib/importVerdict. */
    onResolve: (r: TrustResolution) => void;
    /** The page language; read from the app when absent. */
    locale?: 'en' | 'fa';
}

export function trustTitle(t: (k: string) => string, name: string): string {
    return name.trim() ? t('trust.title').replace('{name}', name.trim()) : t('trust.title_anon');
}

export default function TrustPrompt({ t, preview, onResolve, locale }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const [busy, setBusy] = useState(false);
    const lang = locale ?? effectiveLocale();
    const choose = async (decision: TrustDecision) => {
        if (busy) return;
        setBusy(true);
        // resolveTrustPrompt is the call that COMMITS the routes, and it
        // re-verifies the pending bundle first, so it can legitimately
        // refuse here — a revocation that landed while the words were on
        // screen, an expiry, or a failed save. Both its return value and
        // its exception are load-bearing.
        let verdict = null;
        let error: string | null = null;
        try {
            const raw = await contract.resolveTrustPrompt(preview.fingerprintHex, decision);
            verdict = parseVerdict(raw ?? '');
        } catch (e) {
            error = e instanceof Error ? e.message : String(e);
        } finally {
            setBusy(false);
        }
        onResolve({ decision, verdict, error });
    };

    const enWords = preview.fingerprintEN.split(/\s+/).filter(Boolean);
    const faWords = preview.fingerprintFA.split(/\s+/).filter(Boolean);
    const sets = [
        { lang: 'fa' as const, words: faWords, label: t('trust.words.fa') },
        { lang: 'en' as const, words: enWords, label: t('trust.words.en') },
    ];
    if (lang === 'en') sets.reverse();
    const title = trustTitle(t, preview.publisherName);

    return (
        <div role="region" aria-label={title} data-testid="trust-prompt" style={{ display: 'grid', gap: 16 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                <h2
                    style={{
                        flex: 1,
                        minWidth: 0,
                        fontFamily: 'var(--font-display)',
                        fontSize: 'var(--fs-xl)',
                        lineHeight: 1.25,
                        fontWeight: 600,
                        color: 'var(--fg)',
                        margin: 0,
                    }}
                >
                    <bdi>{title}</bdi>
                </h2>
                {preview.fingerprintHex && <FingerprintThumb fingerprint={preview.fingerprintHex} size={48} />}
            </div>
            <p style={{ color: 'var(--muted)', fontSize: 14, margin: 0 }}>{t('trust.body')}</p>
            <div style={{ display: 'grid', gap: 12 }}>
                {sets.map((s, i) => (
                    <WordSet key={s.lang} words={s.words} rtl={s.lang === 'fa'} large={i === 0} label={s.label} cols={isPhone ? 2 : 4} />
                ))}
            </div>
            <div
                style={{
                    display: 'flex',
                    gap: 8,
                    flexDirection: isPhone ? 'column' : 'row-reverse',
                    justifyContent: isPhone ? undefined : 'flex-start',
                }}
            >
                <Button onClick={() => void choose(0)} block={isPhone} disabled={busy} dataButton="trust-yes">
                    {t('trust.trust')}
                </Button>
                <Button
                    variant="secondary"
                    onClick={() => void choose(2)}
                    block={isPhone}
                    disabled={busy}
                    dataButton="trust-no"
                >
                    {t('trust.cancel')}
                </Button>
            </div>
            <Disclosure summary={t('trust.more')} dataButton="trust-more">
                <Button variant="secondary" block onClick={() => void choose(1)} disabled={busy} dataButton="trust-once">
                    {t('trust.once')}
                </Button>
            </Disclosure>
        </div>
    );
}

/** A set of check words in even rows (4 across, 2 on a phone), so no
 *  word is ever left alone on a line of its own. The language sits in a
 *  small header row above its words (the globe; its name is the
 *  group's label for screen readers), and both sets share the same
 *  column edges and the same cells — only the text size differs. */
function WordSet({
    words,
    rtl,
    large,
    label,
    cols,
}: {
    words: string[];
    rtl: boolean;
    large: boolean;
    label: string;
    cols: number;
}) {
    return (
        <div role="group" aria-label={label} style={{ display: 'grid', gap: 6 }}>
            <span aria-hidden style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--muted)', fontSize: 12 }}>
                <Icon name="globe" size={14} />
            </span>
            <span dir={rtl ? 'rtl' : 'ltr'} style={{ display: 'grid', gridTemplateColumns: `repeat(${cols}, minmax(0, 1fr))`, gap: 6 }}>
            {words.map((w, i) => (
                <span
                    key={i}
                    style={{
                        textAlign: 'center',
                        // A check word is never broken inside.
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--line-soft)',
                        borderRadius: 'var(--radius-sm)',
                        padding: large ? '7px 4px' : '5px 4px',
                        fontFamily: rtl ? 'var(--font-fa)' : 'var(--font-body)',
                        fontSize: large ? 18 : 14,
                        lineHeight: 1.4,
                        color: large ? 'var(--fg)' : 'var(--muted)',
                    }}
                >
                    {w}
                </span>
            ))}
            </span>
        </div>
    );
}
