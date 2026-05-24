// PublisherPage.tsx — D-2 §3.5 publisher surface.
//
// Mounts the full PublisherWizard (Phase C of the v0.2.x plumbing pass)
// which exercises all 22 wizard_* Tauri commands.

import type { Locale } from '../lib/i18n';
import PublisherWizard from '../publisher/PublisherWizard';

interface Props {
    t: (k: string) => string;
    locale?: Locale;
}

export default function PublisherPage({ t, locale: _locale = 'en' }: Props) {
    return (
        <div
            style={{
                // Cyan accent surface treatment per brief §10.1: a faint
                // colored hairline + accent on links/CTAs marks
                // "advanced" so users always know they're in the
                // publisher surface.
                borderTop: '2px solid var(--cyan)',
                minHeight: '100%',
            }}
        >
            <PublisherWizard t={t} />
        </div>
    );
}
