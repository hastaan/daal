// AccountsPage — «حساب‌ها»: the outside services Daal works with, each
// connected once from here, the way the wizard connects Hetzner.
//
//   Hetzner    — connected when a relay holds a hosting key. Connecting
//                is the wizard's first screen (a new relay).
//   Cloudflare — CloudflareSheet: three steps, paste the key, "✓ Connected".
//   Google     — GoogleSheet: one step, "Sign in with Google".
//   The other hosting companies the wizard lists as «در دست ساخت».
//
// A relay's «More protection» switch opens the same sheets when the
// account it needs is not connected yet.

import { useState } from 'react';
import { Badge, Button, Card, GroupLabel, Icon, ListRow, PageHeader } from '../design/primitives';
import type { IconName } from '../design/primitives/icons';
import { useBack } from '../lib/useBack';
import { PageColumn } from './ui';
import { CloudflareSheet, GoogleSheet } from './addons/AccountSheets';
import { setGoogleChoice, useAccounts } from './addons/accounts';
import type { ServiceId } from './addons/accounts';

/** The hosting companies still being built (PublisherWizard's
 *  CLOUD_PROVIDERS with `available: false`), by their wizard labels. */
export const SOON_SERVICES = [
    { id: 'vultr', labelKey: 'wiz.provider.vultr.label' },
    { id: 'digitalocean', labelKey: 'wiz.provider.do.label' },
    { id: 'linode', labelKey: 'wiz.host.linode' },
    { id: 'custom', labelKey: 'wiz.host.own' },
] as const;

const ICON: Record<ServiceId, IconName> = { hetzner: 'server', cloudflare: 'shield', google: 'refresh' };

export default function AccountsPage({
    t,
    onBack,
    backLabel,
    onConnectHetzner,
}: {
    t: (k: string) => string;
    onBack: () => void;
    /** The page Back returns to ("Relays", the relay's name). */
    backLabel: string;
    /** Hetzner connects in the wizard: a new relay. */
    onConnectHetzner?: () => void;
}) {
    const { accounts, loaded, reload } = useAccounts();
    const [open, setOpen] = useState<'cloudflare' | 'google' | null>(null);
    useBack(true, onBack, 'page');

    const connected: Record<ServiceId, boolean> = {
        hetzner: accounts.hetzner,
        cloudflare: accounts.cloudflare.connected,
        google: accounts.google != null,
    };
    const subtitle = (s: ServiceId): string => {
        if (!connected[s]) return t(`pub.accounts.${s}.line`);
        if (s === 'cloudflare' && accounts.cloudflare.zone) {
            return t('pub.accounts.connected_to').replace('{name}', accounts.cloudflare.zone);
        }
        if (s === 'google') {
            return t(accounts.google === 'manual' ? 'pub.accounts.google.chosen.manual' : 'pub.accounts.google.chosen.signin');
        }
        return t('pub.accounts.connected');
    };
    const onRow = (s: ServiceId) => {
        if (s === 'hetzner') {
            if (!connected.hetzner) onConnectHetzner?.();
            return;
        }
        setOpen(s);
    };

    const services: { id: ServiceId; label: string }[] = [
        { id: 'hetzner', label: t('wiz.provider.hetzner.label') },
        { id: 'cloudflare', label: 'Cloudflare' },
        { id: 'google', label: 'Google' },
    ];

    return (
        <PageColumn gap={12}>
            <PageHeader title={t('pub.accounts.title')} back={{ label: backLabel, onClick: onBack }} />
            <Card style={{ padding: '0 16px' }}>
                {services.map((s, i) => {
                    const on = connected[s.id];
                    const tappable = s.id !== 'hetzner' || (!on && !!onConnectHetzner);
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
                                            color: on ? 'var(--green)' : 'var(--muted)',
                                        }}
                                    >
                                        <Icon name={ICON[s.id]} size={18} />
                                    </span>
                                }
                                title={<span dir="auto">{s.label}</span>}
                                subtitle={
                                    <span style={{ color: on ? 'var(--green)' : undefined }} data-testid={`account-${s.id}-state`}>
                                        {subtitle(s.id)}
                                    </span>
                                }
                                trailing={
                                    !on && tappable ? (
                                        <Button size="compact" variant="secondary" onClick={() => onRow(s.id)} dataButton={`account-${s.id}-connect`}>
                                            {t('pub.accounts.connect')}
                                        </Button>
                                    ) : undefined
                                }
                                chevron={on && s.id !== 'hetzner'}
                                onClick={tappable ? () => onRow(s.id) : undefined}
                                stack={false}
                                dataButton={`account-${s.id}`}
                                last={i === services.length - 1}
                            />
                        </div>
                    );
                })}
            </Card>

            <GroupLabel>{t('pub.accounts.others')}</GroupLabel>
            <Card style={{ padding: '0 16px' }}>
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
                    choice={accounts.google}
                    onClose={() => setOpen(null)}
                    onChoose={(c) => {
                        setGoogleChoice(c);
                        setOpen(null);
                        reload();
                    }}
                />
            )}
        </PageColumn>
    );
}
