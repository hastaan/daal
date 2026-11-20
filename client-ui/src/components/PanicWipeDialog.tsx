// PanicWipeDialog.tsx — the erase confirm (spec C5.4): type a word, then
// press and hold the red Erase button for five seconds. Cancel, Back,
// Escape or a tap outside close it, until the erase has fired.
//
// A Sheet: a bottom sheet on a phone, a centred Modal on a computer.

import { useEffect, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { useContract } from '../contract/ContractProvider';
import { useDensity } from '../design/DensityProvider';
import { Button, Disclosure, Input, Sheet } from '../design/primitives';
import { mix } from '../design/mix';

/** The word typed to confirm. Every language accepts it, so a person
 *  who knows it never has to look it up. */
export const ERASE_WORD = 'erase';
export const HOLD_MS = 5000;

/** The word this language asks for (`settings.panic_wipe.word`: «پاک» in
 *  Farsi, so nobody under stress has to switch keyboards), and whether
 *  `typed` matches it or the English word. */
export function eraseWord(t: (k: string) => string): string {
    const w = t('settings.panic_wipe.word');
    return w && w !== 'settings.panic_wipe.word' ? w : ERASE_WORD;
}
export function eraseWordMatches(t: (k: string) => string, typed: string): boolean {
    const v = typed.trim().toLowerCase();
    return v === ERASE_WORD || v === eraseWord(t).toLowerCase();
}

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    /** How long the button is held. Tests shorten it. */
    holdMs?: number;
}

/** True when the words should say "this phone" (a phone layout or an
 *  Android device); false on a computer, where they say "this computer". */
export function useEraseWording(): boolean {
    const { density } = useDensity();
    if (density === 'phone') return true;
    try {
        return /Android/i.test(navigator.userAgent || '');
    } catch {
        return false;
    }
}

export default function PanicWipeDialog({ t, onClose, holdMs = HOLD_MS }: Props) {
    const contract = useContract();
    const { isRTL } = useDensity();
    const onPhone = useEraseWording();
    const [typed, setTyped] = useState('');
    const [holdSince, setHoldSince] = useState<number | null>(null);
    const [progress, setProgress] = useState(0);
    const [done, setDone] = useState(false);
    // The wipe fires once. The callers pass a new onClose arrow on every
    // render, which re-runs the hold effect with the same holdSince; without
    // this a re-render after the hold would call panicWipe() again.
    const firedRef = useRef(false);
    const onCloseRef = useRef(onClose);
    onCloseRef.current = onClose;

    useEffect(() => {
        if (holdSince == null) {
            setProgress(0);
            return;
        }
        const id = setInterval(() => {
            if (firedRef.current) {
                clearInterval(id);
                return;
            }
            const elapsed = Date.now() - holdSince;
            const p = Math.min(1, elapsed / holdMs);
            setProgress(p);
            if (p >= 1) {
                clearInterval(id);
                firedRef.current = true;
                setDone(true);
                // Fire the engine wipe; close once it returns. The
                // engine handles the actual key/route shred. A rejection
                // most often means the engine is already gone with the
                // data it held, so the dialog closes either way.
                contract.panicWipe()
                    .catch(() => { /* already wiped or engine gone */ })
                    .finally(() => setTimeout(() => onCloseRef.current(), 250));
            }
        }, 50);
        return () => clearInterval(id);
    }, [holdSince, holdMs, contract]);

    // Back, Escape and a tap outside are Cancel; once the wipe has fired
    // there is nothing to cancel.
    const close = () => {
        if (!done) onClose();
    };

    const word = eraseWord(t);
    const wordOk = eraseWordMatches(t, typed);
    const start = () => {
        if (wordOk && !done) setHoldSince(Date.now());
    };
    const stop = () => {
        if (!done) setHoldSince(null);
    };
    const onKey = (e: ReactKeyboardEvent<HTMLButtonElement>) => {
        if (e.key !== ' ' && e.key !== 'Enter') return;
        e.preventDefault();
        if (e.type === 'keydown' && !e.repeat && holdSince == null) start();
        if (e.type === 'keyup') stop();
    };

    const [before, after] = t('settings.panic_wipe.type_word').split('{word}');
    const fill = `${Math.round(progress * 100)}%`;

    return (
        <Sheet
            title={t(onPhone ? 'settings.panic_wipe.confirm.title' : 'settings.panic_wipe.confirm.title_desktop')}
            onClose={close}
            width={460}
        >
            <div data-panic-dialog style={{ display: 'grid', gap: 14, marginBlockStart: 8 }}>
                <p style={{ margin: 0, fontSize: 15, lineHeight: 1.5, color: 'var(--fg)' }}>
                    {t(onPhone ? 'settings.panic_wipe.confirm.body' : 'settings.panic_wipe.confirm.body_desktop')}
                </p>

                <label style={{ display: 'grid', gap: 6 }}>
                    <span style={{ fontSize: 13, color: 'var(--muted)' }}>
                        {before}
                        <bdi style={{ fontWeight: 700, color: 'var(--fg)' }}>{word}</bdi>
                        {after ?? ''}
                    </span>
                    <Input
                        value={typed}
                        onChange={(e) => setTyped(e.target.value)}
                        aria-label={t('settings.panic_wipe.type_word').replace('{word}', word)}
                        data-button="erase-word"
                        dir="auto"
                        autoCapitalize="off"
                        autoCorrect="off"
                        autoComplete="off"
                        spellCheck={false}
                        disabled={done}
                        style={{ fontSize: 15 }}
                    />
                </label>

                <div>
                    <button
                        type="button"
                        data-button="erase-hold"
                        disabled={!wordOk || done}
                        onPointerDown={start}
                        onPointerUp={stop}
                        onPointerLeave={stop}
                        onPointerCancel={stop}
                        onKeyDown={onKey}
                        onKeyUp={onKey}
                        onContextMenu={(e) => e.preventDefault()}
                        style={{
                            width: '100%',
                            minHeight: 52,
                            border: 0,
                            borderRadius: 'var(--r-tile)',
                            background: !wordOk
                                ? 'var(--surface-3)'
                                : `linear-gradient(${isRTL ? 'to left' : 'to right'}, ${mix('var(--red)', 55, 'var(--bg-deep)')} ${fill}, var(--red) ${fill})`,
                            color: !wordOk ? 'var(--muted)' : '#fff',
                            fontFamily: 'var(--font-body)',
                            fontSize: 16,
                            fontWeight: 700,
                            cursor: !wordOk ? 'not-allowed' : 'pointer',
                            opacity: !wordOk ? 0.7 : 1,
                            userSelect: 'none',
                            WebkitUserSelect: 'none',
                            touchAction: 'none',
                        }}
                    >
                        {done ? t('settings.panic_wipe.erasing') : t('settings.panic_wipe.erase')}
                    </button>
                    <div
                        aria-live="polite"
                        style={{ fontSize: 13, color: 'var(--muted)', textAlign: 'center', marginBlockStart: 6 }}
                    >
                        {t('settings.panic_wipe.delay')}
                    </div>
                </div>

                <Disclosure summary={t('settings.erase.locked_q')} icon="help" dataButton="erase-locked-q">
                    <p style={{ margin: 0, fontSize: 13, lineHeight: 1.5, color: 'var(--muted)' }}>
                        {t('settings.emergency.body')}
                    </p>
                </Disclosure>

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button variant="ghost" dataButton="erase-cancel" onClick={close} disabled={done}>
                        {t('settings.panic_wipe.cancel')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}
