// StatusPill — the older name for a state badge, kept so every existing
// call site works. It is a `Badge` now (body font, sentence case), so the
// mono capitals that broke words in two are gone everywhere at once.

import type { ReactNode } from 'react';
import { Badge } from './Badge';

type Tone = 'good' | 'warn' | 'bad' | 'neutral' | 'gold';

interface Props {
    tone: Tone;
    children: ReactNode;
    /** A breathing dot (connecting). */
    glow?: boolean;
    /** No icon at all. */
    dotless?: boolean;
}

export function StatusPill({ tone, children, glow, dotless }: Props) {
    return (
        <Badge tone={tone} icon={dotless ? false : undefined} pulse={glow}>
            {children}
        </Badge>
    );
}
