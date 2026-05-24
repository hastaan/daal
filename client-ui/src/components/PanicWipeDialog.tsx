// PanicWipeDialog.tsx — three-step confirm: type a word + 5-second
// hold + Cancel. The actual engine wipe call is wired by the host;
// the dialog closes itself once the user has typed the word and
// held the button.

import { useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';

const WORD = 'erase';
const HOLD_MS = 5000;

interface Props {
    t: (k: string) => string;
    onClose: () => void;
}

export default function PanicWipeDialog({ t, onClose }: Props) {
    const contract = useContract();
    const [typed, setTyped] = useState('');
    const [holdSince, setHoldSince] = useState<number | null>(null);
    const [progress, setProgress] = useState(0);
    const [done, setDone] = useState(false);

    useEffect(() => {
        if (holdSince == null) {
            setProgress(0);
            return;
        }
        const id = setInterval(() => {
            const elapsed = Date.now() - holdSince;
            const p = Math.min(1, elapsed / HOLD_MS);
            setProgress(p);
            if (p >= 1) {
                clearInterval(id);
                setDone(true);
                // Fire the engine wipe; close once it returns. The
                // engine handles the actual key/route shred.
                contract.panicWipe()
                    .catch(() => { /* already wiped or engine gone */ })
                    .finally(() => setTimeout(onClose, 250));
            }
        }, 50);
        return () => clearInterval(id);
    }, [holdSince, onClose, contract]);

    const wordOk = typed.toLowerCase() === WORD;

    return (
        <div
            role="dialog"
            aria-modal="true"
            style={modalShade()}
            onClick={onClose}
        >
            <div onClick={(e) => e.stopPropagation()} style={modal()}>
                <h2 style={title()}>{t('settings.panic_wipe.confirm.title')}</h2>
                <p style={body()}>{t('settings.panic_wipe.confirm.body')}</p>
                <label style={mono()}>
                    {t('settings.panic_wipe.type_word').replace('{word}', WORD)}
                </label>
                <input
                    value={typed}
                    onChange={(e) => setTyped(e.target.value)}
                    style={inputStyle()}
                    aria-label={t('settings.panic_wipe.type_word')}
                />
                <button
                    disabled={!wordOk || done}
                    onPointerDown={() => setHoldSince(Date.now())}
                    onPointerUp={() => setHoldSince(null)}
                    onPointerLeave={() => setHoldSince(null)}
                    style={{
                        ...holdBtn(progress, !wordOk),
                        marginTop: 14,
                        width: '100%',
                    }}
                >
                    {t('settings.panic_wipe.delay')}
                </button>
                <div style={{ marginTop: 12, textAlign: 'end' }}>
                    <button onClick={onClose} style={ghostBtn()}>
                        {t('settings.panic_wipe.cancel')}
                    </button>
                </div>
            </div>
        </div>
    );
}

function modalShade() {
    return {
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
    } as const;
}
function modal() {
    return {
        background: 'var(--teal-surface)',
        border: '1px solid var(--teal-border)',
        borderRadius: 'var(--radius-lg)',
        padding: 28,
        width: 480,
        boxShadow: '0 30px 60px rgba(0,0,0,0.45)',
    } as const;
}
function title() {
    return {
        fontFamily: 'var(--font-display)',
        fontSize: 22,
        color: 'var(--paper)',
        margin: 0,
        marginBottom: 6,
    } as const;
}
function body() {
    return {
        color: 'var(--paper-dim)',
        fontSize: 14,
        margin: 0,
        marginBottom: 14,
    } as const;
}
function mono() {
    return {
        fontFamily: 'var(--font-mono)',
        fontSize: 11,
        letterSpacing: '0.16em',
        textTransform: 'uppercase',
        color: 'var(--ink-mute)',
        display: 'block',
        marginBottom: 6,
    } as const;
}
function inputStyle() {
    return {
        width: '100%',
        background: 'var(--teal-deep)',
        border: '1px solid var(--teal-border)',
        color: 'var(--paper)',
        padding: 10,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-mono)',
        fontSize: 14,
        outline: 'none',
    } as const;
}
function holdBtn(progress: number, dim: boolean) {
    return {
        background: dim
            ? 'var(--teal-raised)'
            : `linear-gradient(90deg, var(--danger) ${progress * 100}%, var(--teal-raised) ${progress * 100}%)`,
        color: dim ? 'var(--ink-mute)' : 'var(--paper)',
        border: '1px solid var(--teal-border)',
        padding: '12px 14px',
        borderRadius: 'var(--radius-md)',
        fontFamily: 'var(--font-body)',
        fontSize: 14,
        cursor: dim ? 'not-allowed' : 'pointer',
        opacity: dim ? 0.6 : 1,
    } as const;
}
function ghostBtn() {
    return {
        background: 'transparent',
        border: 0,
        color: 'var(--ink-soft)',
        padding: '8px 14px',
        fontFamily: 'var(--font-body)',
        fontSize: 13,
        cursor: 'pointer',
    } as const;
}
