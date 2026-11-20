// VaultUnlock.tsx — full-screen PIN entry for high-risk-class devices.

import { useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import { Button, Icon, Input } from '../design/primitives';
import { useDensity } from '../design/DensityProvider';

interface Props {
    t: (k: string) => string;
    onUnlocked: () => void;
}

export default function VaultUnlock({ t, onUnlocked }: Props) {
    const contract = useContract();
    const { density } = useDensity();
    const isPhone = density === 'phone';
    const [pin, setPin] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const submit = async (e?: React.FormEvent) => {
        e?.preventDefault();
        if (!pin) return;
        setBusy(true);
        setError(null);
        try {
            const r = await contract.unlockSecrets(pin);
            if (r === 'unlocked' || r === 'not_required') {
                onUnlocked();
            } else {
                setError(t('vault.wrong_pin'));
                setPin('');
            }
        } catch (err) {
            setError(String(err));
        } finally {
            setBusy(false);
        }
    };

    return (
        <div
            style={{
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'var(--bg)',
                color: 'var(--fg)',
                padding: isPhone ? 18 : 32,
            }}
        >
            <form
                onSubmit={submit}
                style={{
                    width: '100%',
                    maxWidth: 380,
                    background: 'var(--surface)',
                    borderRadius: 'var(--r-card)',
                    padding: isPhone ? '28px 20px' : '32px 28px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'stretch',
                    textAlign: 'center',
                }}
            >
                <span
                    aria-hidden
                    style={{
                        alignSelf: 'center',
                        width: 64,
                        height: 64,
                        borderRadius: '50%',
                        background: 'var(--surface-2)',
                        color: 'var(--gold-warm)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        marginBottom: 16,
                    }}
                >
                    <Icon name="lock" size={28} />
                </span>
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: isPhone ? 22 : 26,
                        fontWeight: 600,
                        margin: 0,
                        marginBottom: 6,
                    }}
                >
                    {t('vault.title')}
                </h1>
                <p style={{ margin: 0, marginBottom: 20, fontSize: 14, color: 'var(--muted)' }}>{t('vault.prompt')}</p>
                <Input
                    type="password"
                    autoFocus
                    value={pin}
                    onChange={(e) => setPin(e.target.value)}
                    placeholder={t('vault.placeholder')}
                    aria-label={t('vault.placeholder')}
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 16,
                        letterSpacing: '0.18em',
                        marginBottom: 12,
                    }}
                />
                {error && (
                    <div
                        style={{
                            color: 'var(--red)',
                            fontSize: 13,
                            marginBottom: 10,
                        }}
                    >
                        {error}
                    </div>
                )}
                <Button type="submit" disabled={busy || !pin} block dataButton="unlock">
                    {busy ? '…' : t('vault.unlock')}
                </Button>
            </form>
        </div>
    );
}
