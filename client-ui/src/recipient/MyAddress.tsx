// MyAddress.tsx — FRP-14 Layer 3c "My Daal address" screen.
//
// First entry: shows a PIN field + "Create my Daal address" CTA.
// On success (or if an identity already exists), shows the
// monospace `daal1…` address + a Copy button + footer note.
//
// Reached from the Add-entry modal as a fifth tab so the surface
// stays small. See `specs/recipient-identity-v1.md` §7.

import { useEffect, useState } from 'react';
import { RecipientIdentity, type RecipientIdentitySummary } from './recipientCommands';
import { Button, Input } from '../design/primitives';

interface Props {
    t: (k: string) => string;
}

export default function MyAddress({ t }: Props) {
    const [summary, setSummary] = useState<RecipientIdentitySummary | null | undefined>(
        undefined,
    );
    const [pin, setPin] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    // Initial fetch.
    useEffect(() => {
        RecipientIdentity.get()
            .then((s) => setSummary(s))
            .catch(() => setSummary(null));
    }, []);

    const onCreate = async () => {
        setBusy(true);
        setError(null);
        try {
            const s = await RecipientIdentity.getOrCreate(pin);
            setSummary(s);
            setPin('');
        } catch (e) {
            setError(String(e));
        } finally {
            setBusy(false);
        }
    };

    const onCopy = async () => {
        if (!summary) return;
        try {
            await navigator.clipboard.writeText(summary.address);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        } catch {
            // best-effort; older webviews may not expose Clipboard API
        }
    };

    // 4-char groups for the monospace display so it wraps cleanly
    // on narrow phones without breaking mid-token.
    const groupedAddress = (addr: string): string =>
        addr.replace(/(.{4})/g, '$1 ').trim();

    return (
        <div style={{ padding: '8px 0' }}>
            <div
                style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 10,
                    color: 'var(--dim)',
                    letterSpacing: '0.18em',
                    textTransform: 'uppercase',
                    marginBottom: 6,
                }}
            >
                {t('recipient.address.eyebrow')}
            </div>
            <h2
                style={{
                    fontSize: 20,
                    fontWeight: 600,
                    margin: '0 0 8px',
                }}
            >
                {t('recipient.address.title')}
            </h2>
            <p
                style={{
                    fontSize: 13,
                    color: 'var(--muted)',
                    lineHeight: 1.5,
                    margin: '0 0 18px',
                }}
            >
                {t('recipient.address.explain')}
            </p>

            {summary === undefined && (
                <div style={{ color: 'var(--muted)', fontSize: 12 }}>…</div>
            )}

            {summary === null && (
                <div style={{ display: 'grid', gap: 10 }}>
                    <Input
                        type="password"
                        placeholder="PIN"
                        value={pin}
                        onChange={(e) => setPin(e.target.value)}
                        autoFocus
                    />
                    <Button
                        disabled={busy || pin.length < 6}
                        onClick={onCreate}
                    >
                        {busy
                            ? t('recipient.address.creating')
                            : t('recipient.address.create_cta')}
                    </Button>
                    {error && (
                        <div
                            style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: 11,
                                color: 'var(--danger)',
                            }}
                        >
                            {error}
                        </div>
                    )}
                </div>
            )}

            {summary && (
                <div>
                    <div
                        style={{
                            background: 'var(--surface-2)',
                            border: '1px solid var(--surface-3)',
                            borderRadius: 8,
                            padding: 14,
                            fontFamily: 'var(--font-mono)',
                            fontSize: 13,
                            wordBreak: 'break-all',
                            lineHeight: 1.5,
                            marginBottom: 10,
                        }}
                    >
                        {groupedAddress(summary.address)}
                    </div>
                    <Button onClick={onCopy}>
                        {copied
                            ? t('recipient.address.copied')
                            : t('recipient.address.copy')}
                    </Button>
                </div>
            )}

            <p
                style={{
                    fontSize: 11,
                    color: 'var(--dim)',
                    lineHeight: 1.45,
                    marginTop: 20,
                }}
            >
                {t('recipient.address.footer')}
            </p>
        </div>
    );
}
