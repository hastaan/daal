// UnavailableRoutes.tsx — "some ways to connect are not in this file".
//
// The engine never stores a route it cannot connect on, so a pack whose
// publisher dropped a route (or whose relay changed under one) simply
// yields fewer routes — and until this component existed no screen said
// so: the import read "Imported." either way (end-to-end rig finding
// F-003, remainder; backlog TW-6).
//
// Every word shown comes from our own string table, chosen by a closed
// reason code (lib/importVerdict.ts, unavailableLines). Nothing from
// the file is rendered.

import type { ImportVerdict } from '../lib/importVerdict';
import { unavailableLines } from '../lib/importVerdict';

interface Props {
    t: (k: string) => string;
    verdict: ImportVerdict | null;
}

export default function UnavailableRoutes({ t, verdict }: Props) {
    const lines = unavailableLines(t, verdict);
    if (lines.length === 0) return null;
    return (
        <div
            data-testid="unavailable-routes"
            style={{
                marginTop: 14,
                padding: '12px 14px',
                borderRadius: 'var(--radius-md, 10px)',
                border: '1px solid var(--line-soft, rgba(128,128,128,0.35))',
                fontSize: 13,
                textAlign: 'start',
            }}
        >
            <strong style={{ display: 'block', marginBlockEnd: 6 }}>
                {t('add.unavailable.title')}
            </strong>
            <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                {lines.map((line, i) => (
                    <li key={i} style={{ marginBlockEnd: 4 }}>
                        {line}
                    </li>
                ))}
            </ul>
        </div>
    );
}
