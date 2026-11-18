// The "More ways to connect" section of the build wizard's plan screen.
// Collapsed by default; every option off by default; each says what it
// costs. The decisions live in extraFamilies.ts — this file only draws
// them.
//
// While the relay software a new server downloads cannot serve these
// (RELEASED_RELAY_SERVES_EXTRA_FAMILIES false — see extraFamilies.ts and
// the pin in publisher/deploy/cloudinit/artifacts.go) the section stays
// visible, every switch is disabled and unticked, and one line says why.
import {
    RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
    extraFamilyOptions,
    selectionForcesNewFileFormat,
} from './extraFamilies';

export interface MoreWaysToConnectProps {
    t: (key: string) => string;
    profileSlug: string;
    /** Whether the section is expanded. */
    open: boolean;
    onToggleOpen: () => void;
    /** The opt-in families currently ticked. */
    selected: readonly string[];
    onChange: (family: string, on: boolean) => void;
    disabled?: boolean;
    /** Whether the released relay software can serve these at all.
     *  Defaults to the build constant; a parameter only for tests. */
    available?: boolean;
}

export function MoreWaysToConnect({
    t,
    profileSlug,
    open,
    onToggleOpen,
    selected,
    onChange,
    disabled,
    available = RELEASED_RELAY_SERVES_EXTRA_FAMILIES,
}: MoreWaysToConnectProps) {
    const options = extraFamilyOptions(profileSlug);
    if (options.length === 0) return null;
    // Unavailable means nothing is on, whatever the caller remembered.
    const count = available ? options.filter((o) => selected.includes(o.family)).length : 0;
    const locked = disabled || !available;
    const summary = !available
        ? t('wiz.more.summary.unavailable')
        : count === 0
          ? t('wiz.more.summary.off')
          : t('wiz.more.summary.on').replace('{n}', String(count));
    return (
        <div
            data-testid="more-ways"
            style={{
                border: '1px solid var(--line)',
                borderRadius: 'var(--r-tile)',
                marginBottom: 14,
                background: 'var(--surface-2)',
            }}
        >
            <button
                type="button"
                aria-expanded={open}
                aria-controls="more-ways-body"
                onClick={onToggleOpen}
                style={{
                    display: 'flex',
                    width: '100%',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    padding: '12px 14px',
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--fg)',
                    cursor: 'pointer',
                    textAlign: 'start',
                    font: 'inherit',
                }}
            >
                <span style={{ fontSize: 13, fontWeight: 600 }}>
                    <span aria-hidden="true">{open ? '▾ ' : '▸ '}</span>
                    {t('wiz.more.title')}
                </span>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>{summary}</span>
            </button>
            {open && (
                <div id="more-ways-body" style={{ padding: '0 14px 12px' }}>
                    <p
                        style={{
                            fontSize: 12,
                            color: 'var(--muted)',
                            lineHeight: 1.6,
                            margin: '0 0 8px',
                        }}
                    >
                        {t('wiz.more.intro')}
                    </p>
                    <p
                        style={{
                            fontSize: 12,
                            color: 'var(--muted)',
                            lineHeight: 1.6,
                            margin: '0 0 10px',
                        }}
                    >
                        {t('wiz.more.newer')}
                    </p>
                    {!available && (
                        <p
                            id="more-ways-unavailable"
                            data-testid="more-ways-unavailable"
                            style={{
                                fontSize: 12,
                                color: 'var(--fg)',
                                lineHeight: 1.6,
                                margin: '0 0 10px',
                                padding: '8px 10px',
                                borderRadius: 'var(--r-tile)',
                                border: '1px solid var(--line)',
                            }}
                        >
                            {t('wiz.more.unavailable')}
                        </p>
                    )}
                    {options.map((o) => {
                        const on = available && selected.includes(o.family);
                        const id = `more-ways-${o.family}`;
                        return (
                            <label
                                key={o.family}
                                htmlFor={id}
                                style={{
                                    display: 'flex',
                                    gap: 10,
                                    alignItems: 'flex-start',
                                    padding: '8px 0',
                                    borderTop: '1px solid var(--line)',
                                    cursor: locked ? 'default' : 'pointer',
                                    opacity: available ? 1 : 0.6,
                                }}
                            >
                                <input
                                    id={id}
                                    type="checkbox"
                                    checked={on}
                                    disabled={locked}
                                    aria-describedby={available ? undefined : 'more-ways-unavailable'}
                                    onChange={(e) => {
                                        if (!locked) onChange(o.family, e.target.checked);
                                    }}
                                    style={{ marginTop: 3 }}
                                />
                                <span>
                                    <span
                                        style={{
                                            display: 'block',
                                            fontSize: 13,
                                            fontWeight: 600,
                                            color: 'var(--fg)',
                                        }}
                                    >
                                        {t(o.titleKey)}
                                    </span>
                                    <span
                                        style={{
                                            display: 'block',
                                            fontSize: 12,
                                            color: 'var(--muted)',
                                            lineHeight: 1.6,
                                        }}
                                    >
                                        {t(o.bodyKey)}
                                    </span>
                                </span>
                            </label>
                        );
                    })}
                    {selectionForcesNewFileFormat(profileSlug, selected, available) && (
                        <div
                            role="alert"
                            style={{
                                marginTop: 8,
                                padding: '8px 10px',
                                borderRadius: 'var(--r-tile)',
                                border: '1px solid var(--warn, var(--line))',
                                fontSize: 12,
                                lineHeight: 1.6,
                                color: 'var(--fg)',
                            }}
                        >
                            {t('wiz.more.anytls.warn')}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
