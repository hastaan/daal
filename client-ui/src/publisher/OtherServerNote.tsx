// OtherServerNote — PA-3: a delete found that the server id Daal had is
// gone, but the hosting account still has a Daal-labelled server with
// this relay's name and another id. Daal did not delete it (it cannot
// prove it is the same relay) and kept the relay and its key. Say so,
// and offer the account check, which shows that server and lets the
// person decide. The id is for a helper: Details only.

import { useState } from 'react';
import { Button } from '../design/primitives';
import type { DestroyReport } from './wizardCommands';
import { WhatIsThis } from './Disclosure';
import { AccountCheckSheet } from './AccountCheckSheet';

/** The other server's id, or "" when the report names none. */
export function otherServerId(report: DestroyReport | null | undefined): string {
    return (report?.other_server_id ?? '').trim();
}

export function OtherServerNote({
    t,
    report,
    onOpenRelay,
}: {
    t: (k: string) => string;
    report: DestroyReport;
    onOpenRelay?: (relayId: number) => void;
}) {
    const [checking, setChecking] = useState(false);
    const id = otherServerId(report);
    if (!id) return null;
    return (
        <div
            data-testid="other-server"
            style={{
                border: '1px solid var(--gold)',
                borderRadius: 'var(--radius-md)',
                padding: '10px 12px',
                display: 'grid',
                gap: 8,
            }}
        >
            <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--fg)' }}>
                {t('pub.relays.destroy.other_server')}
            </div>
            <div>
                <Button variant="secondary" size="sm" onClick={() => setChecking(true)} data-button="check-account">
                    {t('pub.account.open')}
                </Button>
            </div>
            <WhatIsThis label={t('pub.fb.details')}>
                <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {report.other_server_name ? `${report.other_server_name} · ` : ''}
                    {id}
                </div>
            </WhatIsThis>
            {checking && (
                <AccountCheckSheet
                    t={t}
                    onOpenRelay={onOpenRelay}
                    onClose={() => setChecking(false)}
                />
            )}
        </div>
    );
}
