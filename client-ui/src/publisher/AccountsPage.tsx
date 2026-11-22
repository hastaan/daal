// AccountsPage — «حساب‌ها»: the outside services Daal works with, each
// connected once from here, the way the wizard connects Hetzner.
//
//   Hetzner    — HetznerSheet: the wizard's three steps, paste the key,
//                "✓ Connected". Kept for every new relay, with no relay
//                needed (accounts come before relays). Also connected
//                when a relay already holds a key (older phones).
//   Cloudflare — CloudflareSheet: three steps, paste the key, "✓ Connected".
//   Google     — GoogleSheet: the account's one update script, added by
//                hand (copy, paste in Apps Script, deploy, paste the
//                address back), checked through Google, "✓ Connected".
//   The other hosting companies the wizard lists as «در دست ساخت».
//
// A relay's «More protection» switch opens the same sheets when the
// account it needs is not connected yet.

import { useState } from 'react';
import { Badge, Button, Card, GroupLabel, Icon, ListRow, PageHeader } from '../design/primitives';
import type { IconName } from '../design/primitives/icons';
import { useBack } from '../lib/useBack';
import { PageColumn } from './ui';
import { CloudflareSheet, GoogleSheet, HetznerSheet } from './addons/AccountSheets';
import { useAccounts } from './addons/accounts';
import type { ServiceId } from './addons/accounts';

/** The hosting companies still being built (PublisherWizard's
 *  CLOUD_PROVIDERS with `available: false`), by their wizard labels. */
export const SOON_SERVICES = [
    { id: 'vultr', labelKey: 'wiz.provider.vultr.label' },
    { id: 'digitalocean', labelKey: 'wiz.provider.do.label' },
    { id: 'linode', labelKey: 'wiz.host.linode' },
    { id: 'custom', labelKey: 'wiz.host.own' },
] as const;

const GROUP_LINE = { margin: '-4px 0 0', fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 } as const;

const ICON: Record<ServiceId, IconName> = { hetzner: 'server', cloudflare: 'shield', google: 'refresh' };

export default function AccountsPage({
    t,
    onBack,
    backLabel,
}: {
    t: (k: string) => string;
    onBack: () => void;
    /** The page Back returns to ("Relays", the relay's name). */
    backLabel: string;
}) {
    const { accounts, loaded, reload } = useAccounts();
    const [open, setOpen] = useState<ServiceId | null>(null);
    useBack(true, onBack, 'page');

    const connected: Record<ServiceId, boolean> = {
        hetzner: accounts.hetzner,
        cloudflare: accounts.cloudflare.connected,
        google: accounts.google.connected,
    };
    const subtitle = (s: ServiceId): string => {
        if (!connected[s]) return t(`pub.accounts.${s}.line`);
        if (s === 'cloudflare' && accounts.cloudflare.zone) {
            return t('pub.accounts.connected_to').replace('{name}', accounts.cloudflare.zone);
        }
        return t('pub.accounts.connected');
    };
    const onRow = (s: ServiceId) => setOpen(s);

    const labelOf: Record<ServiceId, string> = {
        hetzner: t('wiz.provider.hetzner.label'),
        cloudflare: 'Cloudflare',
        google: 'Google',
    };
    const serviceRow = (s: { id: ServiceId; label: string }, last: boolean) => {
                    const on = connected[s.id];
                    const green = on;
                    return (
                        <div key={s.id} data-account={s.id} data-connected={loaded ? String(on) : 'unknown'}>
                            <ListRow
                                leading={
                                    <span
                                        aria-hidden
                                        style={{
                                            inlineSize: 36,
                                            blockSize: 36,
                                            borderRadius: '50%',
                                            display: 'grid',
                                            placeItems: 'center',
                                            background: 'var(--surface-3)',
                                            color: green ? 'var(--green)' : 'var(--muted)',
                                        }}
                                    >
                                        <Icon name={ICON[s.id]} size={18} />
                                    </span>
                                }
                                title={<span dir="auto">{s.label}</span>}
                                subtitle={
                                    <span style={{ color: green ? 'var(--green)' : undefined }} data-testid={`account-${s.id}-state`}>
                                        {subtitle(s.id)}
                                    </span>
                                }
                                trailing={
                                    !on ? (
                                        <Button size="compact" variant="secondary" onClick={() => onRow(s.id)} dataButton={`account-${s.id}-connect`}>
                                            {t('pub.accounts.connect')}
                                        </Button>
                                    ) : undefined
                                }
                                chevron={on}
                                onClick={() => onRow(s.id)}
                                stack={false}
                                dataButton={`account-${s.id}`}
                                last={last}
                            />
                        </div>
                    );
    };

    return (
        <PageColumn gap={12}>
            <PageHeader title={t('pub.accounts.title')} back={{ label: backLabel, onClick: onBack }} />

            {/* The hosting company: needed, and one is enough. The others
                are the same kind of thing, still being built. */}
            <GroupLabel>{t('pub.accounts.group.hosting')}</GroupLabel>
            <p style={GROUP_LINE}>{t('pub.accounts.group.hosting.line')}</p>
            <Card style={{ padding: '0 16px' }}>
                {serviceRow({ id: 'hetzner', label: labelOf.hetzner }, false)}
                {SOON_SERVICES.map((s, i) => (
                    <div key={s.id} data-account={s.id} data-connected="soon" style={{ opacity: 0.6 }}>
                        <ListRow
                            title={<span dir="auto">{t(s.labelKey)}</span>}
                            badge={
                                <Badge tone="neutral" size="sm" icon="clock">
                                    {t('wiz.host.soon')}
                                </Badge>
                            }
                            stack={false}
                            last={i === SOON_SERVICES.length - 1}
                        />
                    </div>
                ))}
            </Card>


            {/* Extras: not needed to run a relay. */}
            <GroupLabel>{t('pub.accounts.group.extra')}</GroupLabel>
            <p style={GROUP_LINE}>{t('pub.accounts.group.extra.line')}</p>
            <Card style={{ padding: '0 16px' }}>
                {serviceRow({ id: 'cloudflare', label: labelOf.cloudflare }, false)}
                {serviceRow({ id: 'google', label: labelOf.google }, true)}
            </Card>

            {open === 'hetzner' && (
                <HetznerSheet
                    t={t}
                    connected={accounts.hetzner}
                    account={accounts.hetznerAccount}
                    onClose={() => {
                        setOpen(null);
                        reload();
                    }}
                    onConnected={() => reload()}
                    onDisconnected={() => {
                        setOpen(null);
                        reload();
                    }}
                />
            )}
            {open === 'cloudflare' && (
                <CloudflareSheet
                    t={t}
                    zone={accounts.cloudflare.connected ? accounts.cloudflare.zone : null}
                    onClose={() => {
                        setOpen(null);
                        reload();
                    }}
                    onConnected={() => reload()}
                    onDisconnected={() => {
                        setOpen(null);
                        reload();
                    }}
                />
            )}
            {open === 'google' && (
                <GoogleSheet
                    t={t}
                    google={accounts.google}
                    onClose={() => {
                        setOpen(null);
                        reload();
                    }}
                    onConnected={() => reload()}
                    onDisconnected={() => {
                        setOpen(null);
                        reload();
                    }}
                />
            )}
        </PageColumn>
    );
}
