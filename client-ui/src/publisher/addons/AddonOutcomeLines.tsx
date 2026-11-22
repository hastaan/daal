// AddonOutcomeLines — the add-ons part of the relay delete report
// (DestroyReport.addons, specs/optional-addons-v1.md §2).
//
// One line per add-on: removed, goes with the relay (the standby
// address is released with the relay's addresses), could not be removed
// yet (the relay is kept for the retry), or left running (a local-only
// removal never asks a provider). Provider text under Details.

import { WhatIsThis } from '../Disclosure';
import type { AddonOutcome } from './addonTypes';
import { ADDON_COPY } from './addonText';

const LINE: React.CSSProperties = { fontSize: 13, lineHeight: 1.55, margin: 0 };
const KNOWN = new Set(['removed', 'with_relay', 'failed', 'left', 'not_built']);

export function addonOutcomeLine(t: (k: string) => string, o: AddonOutcome): string {
    const copy = ADDON_COPY.find((c) => c.kind === o.kind);
    const name = copy ? t(copy.titleKey) : String(o.kind);
    const code = KNOWN.has(o.code) ? o.code : o.keeps_relay ? 'failed' : 'left';
    return t(`pub.addons.outcome.${code}`).replace('{name}', name);
}

export function AddonOutcomeLines({ t, outcomes }: { t: (k: string) => string; outcomes: AddonOutcome[] | undefined }) {
    const list = Array.isArray(outcomes) ? outcomes : [];
    if (list.length === 0) return null;
    const errors = list.filter((o) => o.error);
    return (
        <div data-testid="destroy-addons" style={{ display: 'grid', gap: 4 }}>
            <div style={{ fontSize: 13, fontWeight: 600 }}>{t('pub.addons.outcome.title')}</div>
            {list.map((o) => (
                <p
                    key={o.addon_id}
                    data-code={o.code}
                    style={{
                        ...LINE,
                        color: o.keeps_relay || o.code === 'left' ? 'var(--amber)' : 'var(--fg)',
                    }}
                >
                    {addonOutcomeLine(t, o)}
                </p>
            ))}
            {errors.length > 0 && (
                <WhatIsThis label={t('pub.addons.details')}>
                    {errors.map((o) => (
                        <div key={o.addon_id} style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} dir="ltr">
                            {o.error}
                        </div>
                    ))}
                </WhatIsThis>
            )}
        </div>
    );
}
