// ui — small pieces every publisher screen shares after the redesign
// (spec C7): the reader's locale, an app confirm sheet in place of
// window.confirm, the one relay badge, the send sheet, and the column
// that keeps a desktop page at a readable width.

import { useCallback, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useDensity } from '../design/DensityProvider';
import { Badge, Button, Disclosure, MenuSheet, Sheet, StateIcon } from '../design/primitives';
import type { MenuItem } from '../design/primitives';
import type { Locale } from '../lib/i18n';
import { toFaDigits } from '../lib/i18n';

/** The language the page is drawn in: Persian when it runs right to left. */
export function useLocale(): Locale {
    const { isRTL } = useDensity();
    return isRTL ? 'fa' : 'en';
}

/** `t` that says "this computer" on a computer: for a key with a
 *  `<key>_desktop` variant, that variant is used unless the layout is a
 *  phone or the device is Android (the same rule as the erase row,
 *  `settings.erase.row`). Keys without a variant are unchanged. */
export function useDeviceT(t: (k: string) => string): (k: string) => string {
    const { density } = useDensity();
    let onPhone = density === 'phone';
    if (!onPhone) {
        try {
            onPhone = /Android/i.test(navigator.userAgent || '');
        } catch {
            onPhone = false;
        }
    }
    return useCallback(
        (k: string) => {
            if (onPhone) return t(k);
            const alt = `${k}_desktop`;
            const v = t(alt);
            return v && v !== alt ? v : t(k);
        },
        [t, onPhone],
    );
}

/** A count in the reader's digits (Persian digits in Persian prose). */
export function num(locale: Locale, n: number): string {
    return locale === 'fa' ? toFaDigits(String(n)) : String(n);
}

/** A page column: full width on a phone, ≤ --content-max on desktop. */
export function PageColumn({ children, gap = 16 }: { children: ReactNode; gap?: number }) {
    const { density } = useDensity();
    const phone = density === 'phone';
    return (
        <div
            style={{
                // On a phone the shell's own gutter is the side margin.
                padding: phone ? '0 0 24px' : '16px 32px 32px',
                // The same column as Settings and Files: --content-max of
                // text plus the 32 px padding on each side.
                maxWidth: phone ? undefined : 'calc(var(--content-max) + 64px)',
                width: '100%',
                boxSizing: 'border-box',
                display: 'grid',
                gap,
                minWidth: 0,
            }}
        >
            {children}
        </div>
    );
}

// ---------------------------------------------------------------------
// Confirm sheet (H-29): the app's own sheet, styled and translated, in
// place of the web view's window.confirm.
// ---------------------------------------------------------------------

export interface ConfirmAsk {
    title: string;
    /** The consequence, visible. */
    body: ReactNode;
    confirmLabel: string;
    cancelLabel: string;
    danger?: boolean;
}

export function ConfirmSheet({
    ask,
    onAnswer,
}: {
    ask: ConfirmAsk;
    onAnswer: (yes: boolean) => void;
}) {
    return (
        <Sheet
            title={ask.title}
            width={480}
            onClose={() => onAnswer(false)}
            footer={
                <span style={{ display: 'inline-flex', gap: 8, flexWrap: 'wrap' }}>
                    <Button variant="ghost" onClick={() => onAnswer(false)} dataButton="confirm-cancel">
                        {ask.cancelLabel}
                    </Button>
                    <Button
                        variant={ask.danger ? 'danger' : 'primary'}
                        onClick={() => onAnswer(true)}
                        dataButton="confirm-yes"
                    >
                        {ask.confirmLabel}
                    </Button>
                </span>
            }
        >
            <div
                data-testid="confirm-body"
                style={{ fontSize: 14, lineHeight: 1.55, color: 'var(--fg)', whiteSpace: 'pre-line' }}
            >
                {ask.body}
            </div>
        </Sheet>
    );
}

/** `const c = useConfirm(); if (!(await c.ask({...}))) return; … {c.node}` */
export function useConfirm(): { ask: (a: ConfirmAsk) => Promise<boolean>; node: ReactNode } {
    const [open, setOpen] = useState<ConfirmAsk | null>(null);
    const resolver = useRef<((yes: boolean) => void) | null>(null);
    const ask = useCallback(
        (a: ConfirmAsk) =>
            new Promise<boolean>((resolve) => {
                // A second ask answers the first one "no".
                resolver.current?.(false);
                resolver.current = resolve;
                setOpen(a);
            }),
        [],
    );
    const answer = useCallback((yes: boolean) => {
        const r = resolver.current;
        resolver.current = null;
        setOpen(null);
        r?.(yes);
    }, []);
    return { ask, node: open ? <ConfirmSheet ask={open} onAnswer={answer} /> : null };
}

// ---------------------------------------------------------------------
// The one relay badge (C7.1 table). The list and the relay page draw it
// from the same function, so they cannot disagree.
// ---------------------------------------------------------------------

export { relayLook, relayUnfinished } from './relayStatus';
export type { RelayLook, RelayStateIcon } from './relayStatus';
import type { RelayLook } from './relayStatus';

export function RelayBadge({
    t,
    look,
    size,
    pulse,
}: {
    t: (k: string) => string;
    look: RelayLook;
    size?: 'sm' | 'md';
    pulse?: boolean;
}) {
    return (
        <Badge tone={look.tone} size={size} wrap={look.wrap} pulse={pulse}>
            {t(look.labelKey)}
        </Badge>
    );
}

// ---------------------------------------------------------------------
// The send sheet (C7.2a): a file's four ways out, for one person or for
// everyone. One label per action across both (H-24).
// ---------------------------------------------------------------------

export interface SendWays {
    share: () => void;
    qr: () => void;
    copy: () => void;
    save: () => void;
}

export function sendItems(t: (k: string) => string, ways: SendWays, disabled = false): MenuItem[] {
    return [
        { id: 'share', label: t('pub.send.share'), icon: 'share', onSelect: ways.share, disabled },
        { id: 'qr', label: t('pub.send.qr'), icon: 'qr', onSelect: ways.qr, disabled },
        { id: 'copy', label: t('pub.send.copy'), icon: 'copy', onSelect: ways.copy, disabled },
        { id: 'save', label: t('pub.send.save'), icon: 'download', onSelect: ways.save, disabled },
    ];
}

export function SendSheet({
    t,
    name,
    everyone,
    ways,
    onClose,
}: {
    t: (k: string) => string;
    /** The person's name; ignored for the everyone file. */
    name: string;
    everyone?: boolean;
    ways: SendWays;
    onClose: () => void;
}) {
    const fill = (s: string) => s.replace(/\{name\}/g, name);
    return (
        <MenuSheet
            title={everyone ? t('pub.send.title.everyone') : fill(t('pub.send.title'))}
            // MUST KEEP 17 / 9: who can open what they are about to send.
            subtitle={everyone ? t('pub.send.everyone_line') : fill(t('pub.send.only'))}
            primaryId="share"
            items={sendItems(t, ways)}
            onClose={onClose}
        />
    );
}

// ---------------------------------------------------------------------
// A notice: one bordered row — state icon, a title, at most one line,
// and its action(s). Longer text goes behind `details`.
// ---------------------------------------------------------------------

export function Notice({
    tone,
    title,
    line,
    action,
    details,
    detailsLabel,
    testId,
}: {
    tone: 'warn' | 'bad' | 'ok';
    title: ReactNode;
    line?: ReactNode;
    action?: ReactNode;
    details?: ReactNode;
    detailsLabel?: string;
    testId?: string;
}) {
    const color = tone === 'bad' ? 'var(--red)' : tone === 'ok' ? 'var(--green)' : 'var(--amber)';
    return (
        <div
            data-testid={testId}
            data-notice={tone}
            style={{
                border: `1px solid ${color}`,
                borderRadius: 'var(--r-card)',
                background: 'var(--surface)',
                padding: '12px 14px',
                display: 'grid',
                gap: 8,
            }}
        >
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span style={{ display: 'inline-flex', paddingBlockStart: 2, flexShrink: 0 }}>
                    <StateIcon state={tone} size={20} />
                </span>
                <div style={{ minWidth: 0, display: 'grid', gap: 4 }}>
                    <div style={{ fontSize: 15, fontWeight: 600, lineHeight: 1.4, color: 'var(--fg)' }}>{title}</div>
                    {line && <div style={{ fontSize: 13, lineHeight: 1.5, color: 'var(--muted)' }}>{line}</div>}
                </div>
            </div>
            {action && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>{action}</div>}
            {details && detailsLabel && (
                <Disclosure summary={detailsLabel} dataButton="notice-details">
                    <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--muted)', display: 'grid', gap: 8 }}>{details}</div>
                </Disclosure>
            )}
        </div>
    );
}
