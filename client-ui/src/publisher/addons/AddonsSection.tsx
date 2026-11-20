// AddonsSection — "Add-ons" on the relay page and at the end of the
// build wizard (docs/optional-addons-plan.md, X3).
//
// Three optional extras — a standby address, a way in through
// Cloudflare, an update channel through Google — each as one quiet
// block: what it rescues, what it costs, what it ties to the publisher.
// Off unless the publisher turns it on. Folded away by default: the
// relay works without any of them, and the page's one job per section
// rule holds.
//
// An add-on this build cannot turn on (ADDON_BUILT false) says "In
// development" and its switch is off and disabled. One it can opens its
// sheet (StandbyCard, CdnCard, GoogleCard) from the switch or from "Set
// up" / "Manage"; the sheet does the setup, the status and the removal.
// Nothing here starts an operation on its own.

import { useCallback, useEffect, useState } from 'react';
import { Badge, Button, Disclosure, Toggle } from '../../design/primitives';
import { Addons } from '../wizardCommands';
import { StandbySheet } from './StandbyCard';
import { CdnSheet } from './CdnCard';
import { GoogleSheet } from './GoogleCard';
import type { AddonKind, AddonRow } from './addonTypes';
import { ADDON_BUILT, ADDON_COPY, liveRow, stateKey, summaryOf } from './addonText';
import type { AddonCopy } from './addonText';

export interface AddonsSectionProps {
    t: (key: string) => string;
    /** The relay; absent while it does not exist yet. */
    operatorId?: number | null;
    /** `relay`: the relay page. `wizard`: the end of the build wizard,
     *  which adds that the relay works without them. */
    variant?: 'relay' | 'wizard';
    /** Which add-ons this build can turn on. A parameter for tests. */
    built?: Readonly<Record<AddonKind, boolean>>;
    /** Open on first render. */
    defaultOpen?: boolean;
}

export function AddonsSection({
    t,
    operatorId,
    variant = 'relay',
    built = ADDON_BUILT,
    defaultOpen = false,
}: AddonsSectionProps) {
    const [rows, setRows] = useState<AddonRow[]>([]);
    const [openKind, setOpenKind] = useState<AddonKind | null>(null);
    const [generation, setGeneration] = useState(0);
    const reload = useCallback(() => setGeneration((g) => g + 1), []);

    useEffect(() => {
        let gone = false;
        if (operatorId == null) {
            setRows([]);
            return;
        }
        // A shell that predates the ledger, or a relay that went: no
        // add-ons, said as "off". Never an error on a page about extras.
        Addons.list(operatorId)
            .then((r) => {
                if (!gone) setRows(Array.isArray(r) ? r : []);
            })
            .catch(() => {
                if (!gone) setRows([]);
            });
        return () => {
            gone = true;
        };
    }, [operatorId, generation]);

    const sheetProps =
        operatorId != null && openKind != null
            ? { t, operatorId, rows, onClose: () => setOpenKind(null), onChanged: reload }
            : null;

    const summary = summaryOf(rows, built);
    return (
        <div data-testid={`addons-${variant}`} style={{ width: '100%', textAlign: 'start' }}>
            <Disclosure
                variant="card"
                summary={
                    <span style={{ display: 'grid', gap: 2 }}>
                        <span>{t('pub.addons.title')}</span>
                        <span
                            data-testid="addons-summary"
                            style={{ fontSize: 12, fontWeight: 400, color: 'var(--muted)', lineHeight: 1.5 }}
                        >
                            {t(summary.key).replace('{n}', String(summary.n))}
                        </span>
                    </span>
                }
                defaultOpen={defaultOpen}
                dataButton={`addons-${variant}`}
            >
                <div style={{ display: 'grid', gap: 0 }}>
                    <p style={INTRO}>{t(variant === 'wizard' ? 'pub.addons.wizard.intro' : 'pub.addons.intro')}</p>
                    {ADDON_COPY.map((c, i) => (
                        <AddonBlock
                            key={c.kind}
                            t={t}
                            copy={c}
                            row={liveRow(rows, c.kind)}
                            built={built[c.kind]}
                            first={i === 0}
                            onOpen={operatorId != null && built[c.kind] ? () => setOpenKind(c.kind) : undefined}
                        />
                    ))}
                </div>
            </Disclosure>
            {sheetProps && openKind === 'standby' && <StandbySheet {...sheetProps} />}
            {sheetProps && openKind === 'cdn' && <CdnSheet {...sheetProps} />}
            {sheetProps && openKind === 'google' && <GoogleSheet {...sheetProps} />}
        </div>
    );
}

function AddonBlock({
    t,
    copy,
    row,
    built,
    first,
    onOpen,
}: {
    t: (key: string) => string;
    copy: AddonCopy;
    row: AddonRow | null;
    built: boolean;
    first: boolean;
    /** Opens the add-on's sheet; absent when it cannot be turned on. */
    onOpen?: () => void;
}) {
    const titleId = `addon-${copy.kind}-title`;
    const badge = row ? (
        <Badge tone={row.state === 'ready' ? 'good' : 'neutral'} size="sm">
            {t(stateKey(row.state))}
        </Badge>
    ) : !built ? (
        <Badge tone="neutral" size="sm" icon={false}>
            {t('pub.addons.soon')}
        </Badge>
    ) : null;
    return (
        <section
            data-testid={`addon-${copy.kind}`}
            data-state={row ? row.state : built ? 'off' : 'soon'}
            aria-labelledby={titleId}
            style={{
                display: 'grid',
                gap: 8,
                padding: '14px 0',
                borderTop: first ? 'none' : '1px solid var(--line)',
            }}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ flex: 1, minWidth: 0, display: 'grid', gap: 2 }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span id={titleId} style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg)' }}>
                            {t(copy.titleKey)}
                        </span>
                        {badge}
                    </span>
                    <span style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>{t(copy.lineKey)}</span>
                </span>
                <Toggle
                    checked={row != null}
                    // Turning one on or off happens in its sheet: the
                    // switch only opens it.
                    onChange={() => onOpen?.()}
                    disabled={!onOpen}
                    ariaLabel={`${t('pub.addons.turn_on')}: ${t(copy.titleKey)}`}
                    dataButton={`addon-${copy.kind}-toggle`}
                />
            </div>
            <dl style={{ margin: 0, display: 'grid', gap: 6 }}>
                <Fact label={t('pub.addons.label.rescues')} text={t(copy.rescuesKey)} />
                <Fact label={t('pub.addons.label.cost')} text={t(copy.costKey)} testId={`addon-${copy.kind}-cost`} />
                <Fact label={t('pub.addons.label.ties')} text={t(copy.tiesKey)} testId={`addon-${copy.kind}-ties`} />
            </dl>
            {!built && !row && (
                <p data-testid={`addon-${copy.kind}-soon`} style={{ ...INTRO, margin: 0 }}>
                    {t('pub.addons.soon.line')}
                </p>
            )}
            {onOpen && (
                <div>
                    <Button size="sm" variant="secondary" onClick={onOpen} dataButton={`addon-${copy.kind}-open`}>
                        {t(row ? 'pub.addons.manage' : 'pub.addons.set_up')}
                    </Button>
                </div>
            )}
        </section>
    );
}

function Fact({ label, text, testId }: { label: string; text: string; testId?: string }) {
    return (
        <div data-testid={testId} style={{ display: 'grid', gap: 1 }}>
            <dt style={{ fontSize: 12, fontWeight: 600, color: 'var(--muted)' }}>{label}</dt>
            <dd style={{ margin: 0, fontSize: 13, color: 'var(--fg)', lineHeight: 1.6 }}>{text}</dd>
        </div>
    );
}

const INTRO = {
    fontSize: 12,
    color: 'var(--muted)',
    lineHeight: 1.6,
    margin: '0 0 4px',
} as const;
