// VaultUnlock.tsx — full-screen PIN entry for high-risk-class devices.

import { useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import { Button, Input } from '../design/primitives';
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
            <form onSubmit={submit} style={{ width: '100%', maxWidth: 360 }}>
                <div
                    style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        letterSpacing: '0.2em',
                        textTransform: 'uppercase',
                        color: 'var(--dim)',
                        marginBottom: 12,
                    }}
                >
                    {t('vault.title')}
                </div>
                <h1
                    style={{
                        fontFamily: 'var(--font-display)',
                        fontSize: isPhone ? 22 : 28,
                        margin: 0,
                        marginBottom: 22,
                    }}
                >
                    {t('vault.prompt')}
                </h1>
                <Input
                    type="password"
                    autoFocus
                    value={pin}
                    onChange={(e) => setPin(e.target.value)}
                    placeholder={t('vault.placeholder')}
                    aria-label="PIN"
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
                <Button type="submit" disabled={busy || !pin} block>
                    {busy ? '…' : t('vault.unlock')}
                </Button>
            </form>
        </div>
    );
}
