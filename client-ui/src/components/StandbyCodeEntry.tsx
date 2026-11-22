// StandbyCodeEntry — the recipient's "I was sent a code" field
// (optional add-ons, standby address; docs/optional-addons-plan.md §1.5,
// S8).
//
// The person who gave someone their file switched their relay to its
// standby address and sent a 26-character code by message or call. The
// engine checks it against the signed commitment in the held files and
// keeps it only where it matches (lib/standbyKey.ts). A wrong code
// cannot steer anyone anywhere, so the field says what happened and no
// more. The code is never logged or echoed back. The code may be the
// plain key or the key wrapped for this person's own file
// (specs/update-ladder-v2.md §3); the person cannot tell and need not.

import { useState } from 'react';
import { Button, Input } from '../design/primitives';
import { enterStandbyKey } from '../lib/standbyKey';
import type { StandbyKeyOutcome } from '../lib/standbyKey';

/** Spaces, dashes and case do not matter; the engine reads the rest. */
export function normaliseCode(s: string): string {
    return s.toUpperCase().replace(/[\s-]+/g, ' ').trim();
}

export function StandbyCodeEntry({
    t,
    onAccepted,
    enter = enterStandbyKey,
}: {
    t: (k: string) => string;
    onAccepted?: () => void;
    /** The engine call; a parameter for tests. */
    enter?: (key: string) => Promise<StandbyKeyOutcome>;
}) {
    const [code, setCode] = useState('');
    const [busy, setBusy] = useState(false);
    const [outcome, setOutcome] = useState<StandbyKeyOutcome | null>(null);

    const submit = async () => {
        const c = normaliseCode(code);
        if (!c) return;
        setBusy(true);
        setOutcome(null);
        try {
            const o = await enter(c);
            setOutcome(o);
            if (o === 'accepted') {
                setCode('');
                onAccepted?.();
            }
        } finally {
            setBusy(false);
        }
    };

    return (
        <form
            data-testid="standby-code"
            onSubmit={(e) => {
                e.preventDefault();
                void submit();
            }}
            style={{ display: 'grid', gap: 10 }}
        >
            <p style={{ margin: 0, fontSize: 14, color: 'var(--muted)', lineHeight: 1.55 }}>{t('add.code.help')}</p>
            {/* Either form of the code works here (plain, or wrapped
                for the person's own file); the engine tries both. */}
            <p data-testid="standby-code-file-note" style={{ margin: 0, fontSize: 13, color: 'var(--muted)', lineHeight: 1.55 }}>
                {t('standby.wrap.entry_note')}
            </p>
            <Input
                value={code}
                onChange={(e) => {
                    setOutcome(null);
                    setCode(e.target.value);
                }}
                dir="ltr"
                autoFocus
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                placeholder={t('add.code.placeholder')}
                aria-label={t('add.code.label')}
                data-button="standby-code-input"
                style={{ fontFamily: 'var(--font-mono)', letterSpacing: 1 }}
            />
            {outcome && (
                <p
                    role={outcome === 'accepted' ? 'status' : 'alert'}
                    data-outcome={outcome}
                    style={{
                        margin: 0,
                        fontSize: 14,
                        lineHeight: 1.55,
                        color: outcome === 'accepted' ? 'var(--green)' : 'var(--red)',
                    }}
                >
                    {t(`add.code.${outcome}`)}
                </p>
            )}
            <div>
                {/* Enter submits the form; the button calls the same
                    function, so one tap is one check. */}
                <Button type="button" onClick={() => void submit()} disabled={busy || normaliseCode(code) === ''} dataButton="standby-code-go">
                    {busy ? t('add.code.working') : t('add.code.go')}
                </Button>
            </div>
        </form>
    );
}
