// StatusStrip — what the desktop and tablet title bar says (spec C9).
//
//   inline-start: one Badge for the connection — "Connected · 01:02:03"
//                 (live), "Connecting…" or "Not connected"; it opens
//                 Connection.
//   inline-end:   nothing while the engine answers. When it stops
//                 answering: "Daal stopped working", which opens Status.

import { sep } from '../lib/format';
import { useEffect, useState } from 'react';
import { useContract } from '../contract/ContractProvider';
import type { ConnState } from '../contract/D2Contract';
import { Badge, TitleBar } from '../design/primitives';
import { toFaDigits } from '../lib/i18n';
import type { Locale } from '../lib/i18n';

interface Props {
    t: (k: string) => string;
    locale: Locale;
    engineHealthy: boolean;
    onOpenConnection: () => void;
    onOpenStatus: () => void;
}

/** "01:02:03" — hours, minutes, seconds since `sinceMs`. */
export function formatElapsed(sinceMs: number | null, nowMs: number): string {
    if (sinceMs == null) return '00:00:00';
    const sec = Math.max(0, Math.floor((nowMs - sinceMs) / 1000));
    const pad = (n: number) => String(n).padStart(2, '0');
    return `${pad(Math.floor(sec / 3600))}:${pad(Math.floor((sec % 3600) / 60))}:${pad(sec % 60)}`;
}

export default function StatusStrip({ t, locale, engineHealthy, onOpenConnection, onOpenStatus }: Props) {
    const contract = useContract();
    const [state, setState] = useState<ConnState>('disconnected');
    const [since, setSince] = useState<number | null>(null);
    const [now, setNow] = useState(() => Date.now());

    useEffect(() => {
        let cancelled = false;
        const tick = async () => {
            try {
                const c = await contract.connectionSummary();
                if (cancelled) return;
                setState(c.state);
                // No made-up start time: when the engine does not say when
                // the connection began, the badge says "Connected" alone.
                setSince((prev) => (c.state === 'connected' ? c.connectedSinceUnixMs ?? prev ?? null : null));
            } catch {
                /* the badge keeps the last state it knew */
            }
        };
        void tick();
        const id = setInterval(tick, 2000);
        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [contract]);

    // The elapsed time counts every second, only while connected.
    useEffect(() => {
        if (state !== 'connected') return;
        const id = setInterval(() => setNow(Date.now()), 1000);
        return () => clearInterval(id);
    }, [state]);

    const elapsed = formatElapsed(since, now);
    const left =
        state === 'connected' ? (
            <Badge tone="good" size="sm" onClick={onOpenConnection} dataButton="title-connection">
                {t('connection.connected')}
                {since != null && (
                    <>
                        {sep()}
                        <bdi dir="ltr">{locale === 'fa' ? toFaDigits(elapsed) : elapsed}</bdi>
                    </>
                )}
            </Badge>
        ) : state === 'connecting' ? (
            <Badge tone="gold" size="sm" pulse onClick={onOpenConnection} dataButton="title-connection">
                {t('status.badge.connecting')}
            </Badge>
        ) : (
            <Badge tone="neutral" size="sm" onClick={onOpenConnection} dataButton="title-connection">
                {t('connection.disconnected')}
            </Badge>
        );

    return (
        <TitleBar
            left={left}
            right={
                engineHealthy ? null : (
                    <Badge tone="warn" size="sm" onClick={onOpenStatus} dataButton="title-engine">
                        {t('engine.degraded')}
                    </Badge>
                )
            }
        />
    );
}
