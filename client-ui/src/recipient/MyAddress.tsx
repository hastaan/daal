// MyAddress.tsx — "My Daal address" (spec C4.4).
//
// The address is made as the sheet opens (Device Custody v1 mints the
// keypair under this phone's secure storage) — no "Create" tap — except
// where custody is a session passphrase that has not been entered yet:
// then the passphrase field and "Create" stay.
//
// Shown grouped (`daal1 qm3n 8v2k …`) so it can be read out, and
// selectable. On Android the first button sends it with another app
// (the shell's share_text); Copy is the second. Elsewhere — and on an
// older shell without share_text — Copy is the one button.

import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
    DeviceCustody,
    RecipientIdentity,
    type CustodyLevel,
    type RecipientIdentitySummary,
} from './recipientCommands';
import { Button, Disclosure, Icon, Input, StateIcon, useToast } from '../design/primitives';
import { writeClipboardText } from '../lib/clipboard';

interface Props {
    t: (k: string) => string;
}

/** `daal1qm3n8v2k…` → `daal1 qm3n 8v2k …`: the prefix, then groups of 4. */
export function groupAddress(addr: string): string {
    const a = addr.replace(/\s+/g, '');
    const m = a.match(/^(daal1)(.*)$/i);
    const head = m ? m[1] : '';
    const rest = m ? m[2] : a;
    const groups = rest.match(/.{1,4}/g) ?? [];
    return [head, ...groups].filter(Boolean).join(' ');
}

/** Android has a share sheet; the desktop shell's share_text only
 *  copies, which the Copy button already does. */
export function canShareText(): boolean {
    try {
        return /Android/i.test(navigator.userAgent);
    } catch {
        return false;
    }
}

/** Opens the share sheet with the address. Resolves false when the shell
 *  has no share_text (an older build), so the caller copies instead. */
export async function shareText(text: string, title: string): Promise<boolean> {
    try {
        await invoke('share_text', { text, title });
        return true;
    } catch {
        return false;
    }
}

export default function MyAddress({ t }: Props) {
    const [summary, setSummary] = useState<RecipientIdentitySummary | null | undefined>(undefined);
    const [level, setLevel] = useState<CustodyLevel | null>(null);
    const [needsUnlock, setNeedsUnlock] = useState(false);
    const [passphrase, setPassphrase] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const toast = useToast();
    const share = canShareText();
    const tried = useRef(false);

    const create = async (unlockWith?: string) => {
        setBusy(true);
        setError(null);
        try {
            if (unlockWith !== undefined) {
                if (unlockWith.length < 6) {
                    setError(t('recipient.address.passphrase_required'));
                    return;
                }
                await DeviceCustody.unlock(unlockWith);
                setNeedsUnlock(false);
                setPassphrase('');
            }
            setSummary(await RecipientIdentity.getOrCreate());
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
            setSummary(null);
        } finally {
            setBusy(false);
        }
    };

    useEffect(() => {
        Promise.all([
            RecipientIdentity.get().catch(() => null),
            DeviceCustody.level().catch(() => null),
            DeviceCustody.isUnlocked().catch(() => true),
        ]).then(([s, lvl, unlocked]) => {
            setLevel((lvl as CustodyLevel) ?? null);
            const locked = lvl === 'session_passphrase' && !unlocked;
            setNeedsUnlock(locked);
            if (s) {
                setSummary(s);
                return;
            }
            // Made on open, unless a passphrase is needed first.
            if (!locked && !tried.current) {
                tried.current = true;
                void create();
                return;
            }
            setSummary(null);
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const onCopy = async () => {
        if (!summary) return;
        try {
            await writeClipboardText(summary.address);
            toast.show('good', t('ui.copied'));
        } catch {
            toast.show('bad', t('recipient.address.copy_failed'));
        }
    };

    const onShare = async () => {
        if (!summary) return;
        // A share-sheet success says nothing (principle 8); an older
        // shell without the command copies, and says that.
        const ok = await shareText(summary.address, t('recipient.address.title'));
        if (!ok) await onCopy();
    };

    const custody = level ? t(`recipient.address.custody.${level}`) : undefined;

    return (
        <div style={{ display: 'grid', gap: 14, padding: '2px 0 4px' }}>
            <p style={{ fontSize: 14, color: 'var(--muted)', lineHeight: 1.5, margin: 0 }}>
                {t('recipient.address.explain')}
            </p>

            {(summary === undefined || (busy && !summary)) && (
                <div role="status" style={{ display: 'flex', justifyContent: 'center', padding: 16 }}>
                    <StateIcon state="busy" size={24} />
                </div>
            )}

            {summary === null && !busy && (
                <div style={{ display: 'grid', gap: 10 }}>
                    {needsUnlock && (
                        <Input
                            type="password"
                            placeholder={t('recipient.address.passphrase_placeholder')}
                            aria-label={t('recipient.address.passphrase_placeholder')}
                            value={passphrase}
                            onChange={(e) => setPassphrase(e.target.value)}
                            autoFocus
                        />
                    )}
                    <Button
                        block
                        disabled={busy || (needsUnlock && passphrase.length < 6)}
                        onClick={() => void create(needsUnlock ? passphrase : undefined)}
                        dataButton="create-address"
                    >
                        {busy ? t('recipient.address.creating') : t('recipient.address.create_cta')}
                    </Button>
                </div>
            )}
            {error && (
                <div role="alert" style={{ fontSize: 13, color: 'var(--red)', overflowWrap: 'anywhere' }}>
                    {error}
                </div>
            )}

            {summary && (
                <>
                    <div
                        style={{
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: 10,
                            background: 'var(--surface-2)',
                            border: '1px solid var(--line-soft)',
                            borderRadius: 'var(--r-tile)',
                            padding: '12px 14px',
                        }}
                    >
                        <span
                            dir="ltr"
                            data-testid="my-address"
                            style={{
                                flex: 1,
                                minWidth: 0,
                                fontFamily: 'var(--font-mono)',
                                fontSize: 15,
                                lineHeight: 1.6,
                                wordSpacing: 2,
                                userSelect: 'text',
                                WebkitUserSelect: 'text',
                                unicodeBidi: 'isolate',
                                textAlign: 'start',
                            }}
                        >
                            {groupAddress(summary.address)}
                        </span>
                        <span
                            role="img"
                            aria-label={custody ?? t('recipient.address.protected')}
                            title={t('recipient.address.protected')}
                            style={{ color: 'var(--muted)', display: 'inline-flex', paddingBlockStart: 3 }}
                        >
                            <Icon name="lock" size={18} />
                        </span>
                    </div>
                    <div style={{ display: 'grid', gap: 8 }}>
                        {share && (
                            <Button block leading="share" onClick={() => void onShare()} dataButton="send-address">
                                {t('recipient.address.send')}
                            </Button>
                        )}
                        <Button
                            block
                            variant={share ? 'secondary' : 'primary'}
                            leading="copy"
                            onClick={() => void onCopy()}
                            dataButton="copy-address"
                        >
                            {t('recipient.address.copy')}
                        </Button>
                    </div>
                </>
            )}

            <Disclosure summary={t('recipient.address.reinstall_q')} dataButton="address-reinstall">
                <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>{t('recipient.address.footer')}</div>
            </Disclosure>
            {toast.node}
        </div>
    );
}
