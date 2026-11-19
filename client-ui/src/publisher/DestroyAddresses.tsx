// DestroyAddresses — after a delete, what happened to each address Daal
// reserved for the relay (D4).
//
// A reserved address is billed on its own, whether or not a server uses
// it. Deleting the server used to leave it reserved and print a command
// line as a "warning". Now the shell releases every one Daal reserved
// and reports each; this says, per address, whether it still costs
// money and — when a release failed — offers the same delete again.
// Never a command line: provider text stays under Details.

import { Button } from '../design/primitives';
import type { AddressOutcome } from './wizardCommands';

export function addressLineKey(code: AddressOutcome['code']): string {
    switch (code) {
        case 'released':
            return 'pub.relays.destroy.addr.released';
        case 'not_daal':
            return 'pub.relays.destroy.addr.not_daal';
        case 'still_attached':
            return 'pub.relays.destroy.addr.still_attached';
        case 'in_use':
            return 'pub.relays.destroy.addr.in_use';
        default:
            return 'pub.relays.destroy.addr.release_failed';
    }
}

export { retryNeeded, stillBills } from './destroyReport';

const LINE: React.CSSProperties = { fontSize: 12, lineHeight: 1.55 };

/** One address line. A failed release with neither an address nor an
 *  id is the helper saying it could not read the account's address
 *  list at all: say that, instead of "Address  is still reserved". */
export function addressLineText(t: (k: string) => string, code: AddressOutcome['code'], label: string): string {
    if (label === '' && code === 'release_failed') return t('pub.relays.destroy.addr.list_unreadable');
    return t(addressLineKey(code)).replace('{ip}', label);
}

export function AddressLines({
    t,
    addresses,
    onRetry,
    retryBusy,
}: {
    t: (k: string) => string;
    addresses: AddressOutcome[];
    onRetry?: () => void;
    retryBusy?: boolean;
}) {
    if (addresses.length === 0) return null;
    const failed = addresses.some((a) => a.code === 'release_failed');
    return (
        <div style={{ display: 'grid', gap: 6 }} data-testid="destroy-addresses">
            {addresses.map((a) => {
                const bad = a.code === 'release_failed' || a.code === 'still_attached';
                return (
                    <div
                        key={a.id || a.ip || a.code}
                        style={{
                            ...LINE,
                            color: bad ? 'var(--red)' : a.code === 'released' ? 'var(--fg)' : 'var(--muted)',
                        }}
                    >
                        {addressLineText(t, a.code, a.ip || a.id)}
                    </div>
                );
            })}
            {failed && onRetry && (
                <div>
                    <Button variant="danger" size="sm" disabled={retryBusy} onClick={onRetry}>
                        {retryBusy ? t('pub.relays.destroy.addr.retrying') : t('pub.relays.destroy.addr.retry')}
                    </Button>
                </div>
            )}
        </div>
    );
}

/** A relay card whose delete left addresses reserved: name them. */
export function UnreleasedAddresses({
    t,
    ips,
    onRetry,
    retryBusy,
    live,
}: {
    t: (k: string) => string;
    ips: string[];
    /** Absent when there is nothing safe to retry. */
    onRetry?: () => void;
    retryBusy?: boolean;
    /** A working relay (PA-1): Try again gives back only the address,
     *  never the server. */
    live?: boolean;
}) {
    if (ips.length === 0) return null;
    return (
        <div style={{ display: 'grid', gap: 6 }} data-testid="unreleased-addresses">
            {ips.map((ip, i) => (
                <div key={ip || i} style={{ ...LINE, color: 'var(--red)' }}>
                    {addressLineText(t, 'release_failed', ip)}
                </div>
            ))}
            {live && <div style={{ ...LINE, color: 'var(--muted)' }}>{t('pub.relays.release.intro')}</div>}
            {onRetry ? (
                <div>
                    <Button
                        variant="danger"
                        size="sm"
                        disabled={retryBusy}
                        onClick={(e) => {
                            e.stopPropagation();
                            onRetry();
                        }}
                    >
                        {retryBusy ? t('pub.relays.destroy.addr.retrying') : t('pub.relays.destroy.addr.retry')}
                    </Button>
                </div>
            ) : (
                <div style={{ ...LINE, color: 'var(--muted)' }}>{t('pub.relays.destroy.addr.earlier_try')}</div>
            )}
        </div>
    );
}
