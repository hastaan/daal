// RouteBudgetModal.tsx — per-route data cap (engine_set_route_budget).

import { useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { RouteDisplayRow } from '../contract/D2Contract';

interface Props {
    t: (k: string) => string;
    route: RouteDisplayRow;
    onClose: () => void;
    onSaved: () => void;
}

const TAGS = ['lifeline', 'normal', 'bulk', 'unmetered'] as const;

export default function RouteBudgetModal({ t, route, onClose, onSaved }: Props) {
    const contract = useContract();
    const [tag, setTag] = useState<(typeof TAGS)[number]>('normal');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const save = async () => {
        setBusy(true);
        setError(null);
        try {
            await contract.setRouteBudget(route.routeId, tag);
            onSaved();
        } catch (e) {
            setError((e as Error).message || 'unknown');
        } finally {
            setBusy(false);
        }
    };

    return (
        <div
            onClick={onClose}
            style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0,0,0,0.55)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 100,
            }}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                style={{
                    width: 400,
                    background: 'var(--bg)',
                    border: '1px solid var(--teal-border)',
                    borderRadius: 'var(--radius-lg)',
                    padding: 22,
                    color: 'var(--paper)',
                }}
            >
                <h2 style={{ marginTop: 0, fontFamily: 'var(--font-display)' }}>
                    {t('routes.budget.title') || 'Data cap'}
                </h2>
                <div style={{ color: 'var(--paper-dim)', fontSize: 13, marginBottom: 14 }}>
                    {route.publisherName} · {route.routeNickname}
                </div>
                <label style={{ display: 'block', marginBottom: 14 }}>
                    <div style={{ fontSize: 11, color: 'var(--ink-mute)', marginBottom: 4 }}>
                        Budget tag
                    </div>
                    <select
                        value={tag}
                        onChange={(e) => setTag(e.target.value as (typeof TAGS)[number])}
                        style={{
                            background: 'var(--teal-deep)',
                            color: 'var(--paper)',
                            border: '1px solid var(--teal-border)',
                            borderRadius: 'var(--radius-md)',
                            padding: '6px 10px',
                            fontFamily: 'var(--font-body)',
                            fontSize: 13,
                            width: '100%',
                        }}
                    >
                        {TAGS.map((x) => (
                            <option key={x} value={x}>
                                {x}
                            </option>
                        ))}
                    </select>
                </label>
                {error && (
                    <div
                        style={{
                            color: 'var(--danger)',
                            fontSize: 12,
                            marginBottom: 10,
                        }}
                    >
                        {error}
                    </div>
                )}
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <button
                        onClick={onClose}
                        disabled={busy}
                        style={{
                            background: 'transparent',
                            color: 'var(--paper)',
                            border: '1px solid var(--teal-border)',
                            padding: '6px 14px',
                            borderRadius: 'var(--radius-md)',
                            cursor: 'pointer',
                        }}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={save}
                        disabled={busy}
                        style={{
                            background: 'var(--gold)',
                            color: '#1A1208',
                            border: 0,
                            padding: '6px 14px',
                            borderRadius: 'var(--radius-md)',
                            fontWeight: 600,
                            cursor: 'pointer',
                        }}
                    >
                        Save
                    </button>
                </div>
            </div>
        </div>
    );
}
