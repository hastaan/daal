// PublisherPage.tsx — D-2 §3.5 publisher surface.
//
// Two tabs:
//   - Setup: the full PublisherWizard (provisioning, signing,
//     freshness, distribution). Used the first time and whenever
//     the operator needs to revisit setup state.
//   - Recipients: Gap 1 standalone dashboard for adding /
//     revoking / resending / syncing recipients without paging
//     through the wizard's 7 steps.

import { useState } from 'react';
import type { Locale } from '../lib/i18n';
import PublisherWizard from '../publisher/PublisherWizard';
import PublisherRecipientsPage from '../publisher/PublisherRecipientsPage';
import { Segmented } from '../design/primitives';

type Tab = 'setup' | 'recipients';

interface Props {
    t: (k: string) => string;
    locale?: Locale;
}

export default function PublisherPage({ t, locale: _locale = 'en' }: Props) {
    const [tab, setTab] = useState<Tab>('setup');
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
            <div style={{ padding: '12px 16px 0 16px' }}>
                <Segmented<Tab>
                    value={tab}
                    items={[
                        { value: 'setup', label: t('pub.tab.setup') },
                        { value: 'recipients', label: t('pub.tab.recipients') },
                    ]}
                    onChange={setTab}
                />
            </div>
            {tab === 'setup' ? (
                <PublisherWizard t={t} />
            ) : (
                <PublisherRecipientsPage t={t} />
            )}
        </div>
    );
}
