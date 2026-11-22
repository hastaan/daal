// AccountSheets — connecting an outside account, in the Hetzner
// wizard's shape (PublisherWizard, screen 1b): a few numbered steps,
// each with the link that opens the right page, then one thing to paste
// or one button. Opened from the Accounts page, and from a relay's
// «More protection» switch when its account is not connected yet.
//
//   HetznerSheet — account, project, access key with Read & Write (the
//     wizard's own guide); paste → one read-only check → "✓ Connected".
//     The key is kept by hosting_account::connect, for every new relay;
//     Disconnect forgets it and the relays keep their own copies.
//   CloudflareSheet — account, domain, access key (the pre-filled token
//     page); paste → check → the one domain it sees → "✓ Connected".
//     The key is kept by addon_cdn::connect, for every relay.
//   GoogleSheet — one step (an account only for this), then "Sign in
//     with Google"; the by-hand script is a small link under it. Google
//     signs in per relay, so this records the choice; the relay switch
//     does the sign-in.
//   GoogleByHandSheet — the script by hand, for one relay.

import { useState } from 'react';
import { Button, Input, Sheet, Textarea } from '../../design/primitives';
import { useDeviceT } from '../ui';
import { useSecureScreen } from '../useSecureScreen';
import { Addons, Wizard } from '../wizardCommands';
import type { AddonRow, CdnTokenCheck } from './addonTypes';
import type { GoogleChoice } from './accounts';
import { BODY, ErrorNote, MONO, MUTED, NumberedSteps, copyText, useRun } from './addonUi';

/** The wizard's sign-up link (PublisherWizard CLOUD_PROVIDERS). */
export const HETZNER_SIGNUP_URL = 'https://console.hetzner.cloud/register';
/** The console's project list: make a project, then its API token. */
export const HETZNER_CONSOLE_URL = 'https://console.hetzner.cloud/projects';
export const CLOUDFLARE_SIGNUP_URL = 'https://dash.cloudflare.com/sign-up';
export const CLOUDFLARE_REGISTRAR_URL = 'https://dash.cloudflare.com/?to=/:account/domains/register';
export const GOOGLE_SIGNUP_URL = 'https://accounts.google.com/signup';
export const APPS_SCRIPT_SETTINGS_URL = 'https://script.google.com/home/usersettings';
export const APPS_SCRIPT_NEW_URL = 'https://script.google.com/home/projects/create';

/** The pre-filled token page (plan §2.5): exactly the five zone
 *  permissions Daal needs. It cannot pre-pick one zone; the owner picks
 *  the domain they bought, and a key that sees more is refused. */
export function cloudflareTokenUrl(): string {
    const groups = JSON.stringify([
        { key: 'zone', type: 'read' },
        { key: 'dns', type: 'edit' },
        { key: 'ssl_and_certificates', type: 'edit' },
        { key: 'zone_settings', type: 'edit' },
        { key: 'origin_rules', type: 'edit' },
    ]);
    return (
        'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
        encodeURIComponent(groups) +
        '&accountId=*&zoneId=all&name=daal'
    );
}

const VERDICTS = new Set(['invalid', 'no_zone', 'too_broad', 'missing_permission', 'refused']);

/** The line for a key that was not kept. */
export function verdictKey(v: string): string {
    return `pub.accounts.cf.verdict.${VERDICTS.has(v) ? v : 'refused'}`;
}

function Connected({ text, testId }: { text: string; testId: string }) {
    return (
        <p data-testid={testId} style={{ ...BODY, color: 'var(--green)', fontWeight: 600 }}>
            {text}
        </p>
    );
}

/** True when the hosting company itself refused the key (as opposed to
 *  the phone being offline or the store locked). The same words
 *  setup_recovery.rs classifies as `token_rejected`. */
export function hostingKeyRefused(e: unknown): boolean {
    const s = typeof e === 'string' ? e : e instanceof Error ? e.message : String(e ?? '');
    return /\b(401|403)\b|unauthori[sz]ed|forbidden/i.test(s);
}

export function HetznerSheet({
    t,
    connected,
    account,
    onClose,
    onConnected,
    onDisconnected,
}: {
    t: (k: string) => string;
    /** A key Daal can use is on this phone (the account's or a relay's). */
    connected: boolean;
    /** That key is the account's own: Disconnect can forget it. */
    account: boolean;
    onClose: () => void;
    onConnected: () => void;
    onDisconnected?: () => void;
}) {
    const [token, setToken] = useState('');
    const [done, setDone] = useState(false);
    const [refused, setRefused] = useState(false);
    const [pasteFailed, setPasteFailed] = useState(false);
    const { busy, error, setError, run } = useRun();
    const dt = useDeviceT(t);

    const connect = async () => {
        const typed = token;
        setRefused(false);
        let rejected: unknown = null;
        const r = await run(() =>
            Wizard.hostingAccountConnect('hetzner', typed).catch((e: unknown) => {
                rejected = e;
                throw e;
            }),
        );
        // The key leaves the page once it is checked, kept or not.
        setToken('');
        if (r) {
            setDone(true);
            onConnected();
        } else if (rejected != null && hostingKeyRefused(rejected)) {
            setRefused(true);
            setError(null);
        }
    };
    const paste = async () => {
        try {
            const s = await navigator.clipboard.readText();
            if (s && s.trim()) {
                setToken(s.trim());
                setPasteFailed(false);
                return;
            }
        } catch {
            /* the web view would not read it */
        }
        setPasteFailed(true);
    };
    const disconnect = async () => {
        const r = await run(async () => {
            await Wizard.hostingAccountDisconnect('hetzner');
            return true;
        });
        if (r) onDisconnected?.();
    };

    const label = t('wiz.provider.hetzner.label');
    return (
        <Sheet title={label} onClose={onClose} width={480}>
            <div data-testid="hetzner-sheet" style={{ display: 'grid', gap: 14 }}>
                {done || connected ? (
                    <>
                        <Connected testId="hetzner-connected" text={t('pub.accounts.connected')} />
                        <p style={MUTED}>
                            {t(done || account ? 'pub.accounts.hz.kept' : 'pub.accounts.hz.relay_only')}
                        </p>
                        {!done && account && onDisconnected && (
                            <p data-testid="hetzner-disconnect-line" style={MUTED}>
                                {t('pub.accounts.hz.disconnect.line')}
                            </p>
                        )}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
                            {!done && account && onDisconnected ? (
                                <Button variant="ghost" onClick={() => void disconnect()} disabled={busy} dataButton="hetzner-disconnect">
                                    {t('pub.accounts.disconnect')}
                                </Button>
                            ) : (
                                <span />
                            )}
                            <Button onClick={onClose} dataButton="hetzner-done">
                                {t('pub.accounts.done')}
                            </Button>
                        </div>
                        {error != null && <ErrorNote t={t} error={error} />}
                    </>
                ) : (
                    <>
                        <NumberedSteps
                            testId="hetzner-steps"
                            items={[
                                {
                                    text: t('wiz.guide.1'),
                                    action: {
                                        label: t('wiz.provider.signup'),
                                        url: HETZNER_SIGNUP_URL,
                                        dataButton: 'hetzner-signup',
                                    },
                                },
                                {
                                    text: t('pub.accounts.hz.step.2'),
                                    action: {
                                        label: t('pub.accounts.hz.console'),
                                        url: HETZNER_CONSOLE_URL,
                                        dataButton: 'hetzner-project',
                                    },
                                },
                                {
                                    text: t('wiz.guide.2'),
                                    action: {
                                        label: t('pub.accounts.hz.console'),
                                        url: HETZNER_CONSOLE_URL,
                                        dataButton: 'hetzner-token-page',
                                    },
                                },
                            ]}
                        />
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{t('wiz.provider.token')}</div>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <Input
                                    type="password"
                                    autoComplete="off"
                                    autoCapitalize="off"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    dir="ltr"
                                    value={token}
                                    onChange={(e) => setToken(e.target.value)}
                                    placeholder={t('wiz.provider.token.placeholder')}
                                    aria-label={t('wiz.provider.token')}
                                    data-button="hetzner-token"
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <Button variant="secondary" leading="paste" onClick={() => void paste()} dataButton="hetzner-paste">
                                    {t('ui.paste')}
                                </Button>
                            </div>
                            {pasteFailed && <p style={{ ...MUTED, color: 'var(--red)' }}>{t('wiz.provider.token.paste_failed')}</p>}
                            <p style={MUTED}>{dt('wiz.provider.token.kept')}</p>
                        </div>
                        {refused && (
                            <p data-testid="hetzner-refused" style={{ ...MUTED, color: 'var(--red)' }}>
                                {t('pub.accounts.hz.refused')}
                            </p>
                        )}
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button onClick={() => void connect()} disabled={busy || token.trim() === ''} dataButton="hetzner-connect">
                                {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}

export function CloudflareSheet({
    t,
    zone,
    onClose,
    onConnected,
    onDisconnected,
}: {
    t: (k: string) => string;
    /** The connected zone; '' or null when not connected. */
    zone: string | null;
    onClose: () => void;
    onConnected: (zone: string) => void;
    onDisconnected?: () => void;
}) {
    const [token, setToken] = useState('');
    const [check, setCheck] = useState<CdnTokenCheck | null>(null);
    const [pasteFailed, setPasteFailed] = useState(false);
    const { busy, error, run } = useRun();
    const done = check?.stored ? check.zones[0] ?? '' : null;
    const shown = done ?? (zone || null);

    const connect = async () => {
        const typed = token;
        const c = await run(() => Addons.cdnConnect({ token: typed }));
        // The key leaves the page once it is checked, kept or not.
        setToken('');
        if (c) {
            setCheck(c);
            if (c.stored) onConnected(c.zones[0] ?? '');
        }
    };
    const paste = async () => {
        try {
            const s = await navigator.clipboard.readText();
            if (s && s.trim()) {
                setToken(s.trim());
                setPasteFailed(false);
                return;
            }
        } catch {
            /* the web view would not read it */
        }
        setPasteFailed(true);
    };
    const disconnect = async () => {
        const r = await run(async () => {
            await Addons.cdnDisconnect();
            return true;
        });
        if (r) onDisconnected?.();
    };

    return (
        <Sheet title="Cloudflare" onClose={onClose} width={480}>
            <div data-testid="cloudflare-sheet" style={{ display: 'grid', gap: 14 }}>
                {shown != null ? (
                    <>
                        <Connected testId="cloudflare-connected" text={t('pub.accounts.connected_to').replace('{name}', shown)} />
                        <p style={MUTED}>{t('pub.accounts.cf.sees')}</p>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
                            {done == null && onDisconnected ? (
                                <Button variant="ghost" onClick={() => void disconnect()} disabled={busy} dataButton="cloudflare-disconnect">
                                    {t('pub.accounts.disconnect')}
                                </Button>
                            ) : (
                                <span />
                            )}
                            <Button onClick={onClose} dataButton="cloudflare-done">
                                {t('pub.accounts.done')}
                            </Button>
                        </div>
                        {error != null && <ErrorNote t={t} error={error} />}
                    </>
                ) : (
                    <>
                        <NumberedSteps
                            testId="cloudflare-steps"
                            items={[
                                {
                                    text: t('pub.accounts.cf.step.1'),
                                    action: {
                                        label: t('pub.accounts.cf.step.1.action'),
                                        url: CLOUDFLARE_SIGNUP_URL,
                                        dataButton: 'cloudflare-signup',
                                    },
                                },
                                {
                                    text: t('pub.accounts.cf.step.2'),
                                    action: {
                                        label: t('pub.accounts.cf.step.2.action'),
                                        url: CLOUDFLARE_REGISTRAR_URL,
                                        dataButton: 'cloudflare-domain',
                                    },
                                },
                                {
                                    text: t('pub.accounts.cf.step.3'),
                                    action: {
                                        label: t('pub.accounts.cf.step.3.action'),
                                        url: cloudflareTokenUrl(),
                                        dataButton: 'cloudflare-token-page',
                                    },
                                },
                            ]}
                        />
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{t('pub.accounts.cf.key')}</div>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <Input
                                    type="password"
                                    autoComplete="off"
                                    autoCapitalize="off"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    dir="ltr"
                                    value={token}
                                    onChange={(e) => setToken(e.target.value)}
                                    placeholder={t('wiz.provider.token.placeholder')}
                                    aria-label={t('pub.accounts.cf.key')}
                                    data-button="cloudflare-token"
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <Button variant="secondary" leading="paste" onClick={() => void paste()} dataButton="cloudflare-paste">
                                    {t('ui.paste')}
                                </Button>
                            </div>
                            {pasteFailed && <p style={{ ...MUTED, color: 'var(--red)' }}>{t('wiz.provider.token.paste_failed')}</p>}
                        </div>
                        {check && !check.stored && (
                            <p data-testid="cloudflare-verdict" data-verdict={check.verdict} style={{ ...MUTED, color: 'var(--red)' }}>
                                {t(verdictKey(check.verdict))}
                            </p>
                        )}
                        {error != null && <ErrorNote t={t} error={error} />}
                        <p style={MUTED}>{t('pub.accounts.cf.sees')}</p>
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button onClick={() => void connect()} disabled={busy || token.trim() === ''} dataButton="cloudflare-connect">
                                {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}

export function GoogleSheet({
    t,
    choice,
    onClose,
    onChoose,
}: {
    t: (k: string) => string;
    /** What was chosen before; null when Google is not connected. */
    choice: GoogleChoice | null;
    onClose: () => void;
    /** The owner chose a way (null: disconnect). The caller records it
     *  and, from a relay switch, goes on to turn the switch on. */
    onChoose: (c: GoogleChoice | null) => void;
}) {
    return (
        <Sheet title="Google" onClose={onClose} width={480}>
            <div data-testid="google-sheet" style={{ display: 'grid', gap: 14 }}>
                {choice ? (
                    <>
                        <Connected
                            testId="google-connected"
                            text={t(choice === 'signin' ? 'pub.accounts.google.chosen.signin' : 'pub.accounts.google.chosen.manual')}
                        />
                        <p style={MUTED}>{t('pub.accounts.google.later')}</p>
                        <p style={{ ...MUTED, color: 'var(--amber)' }}>{t('pub.accounts.google.warn')}</p>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
                            <Button variant="ghost" onClick={() => onChoose(null)} dataButton="google-disconnect">
                                {t('pub.accounts.disconnect')}
                            </Button>
                            <Button onClick={onClose} dataButton="google-done">
                                {t('pub.accounts.done')}
                            </Button>
                        </div>
                    </>
                ) : (
                    <>
                        <NumberedSteps
                            testId="google-steps"
                            items={[
                                {
                                    text: t('pub.accounts.google.step'),
                                    action: {
                                        label: t('pub.accounts.google.step.action'),
                                        url: GOOGLE_SIGNUP_URL,
                                        dataButton: 'google-signup',
                                    },
                                },
                            ]}
                        />
                        <p data-testid="google-warn" style={{ ...MUTED, color: 'var(--amber)' }}>
                            {t('pub.accounts.google.warn')}
                        </p>
                        <div style={{ display: 'grid', gap: 6, justifyItems: 'center' }}>
                            <Button onClick={() => onChoose('signin')} dataButton="google-sign-in">
                                {t('pub.accounts.google.sign_in')}
                            </Button>
                            <p style={{ ...MUTED, textAlign: 'center' }}>{t('pub.accounts.google.unverified')}</p>
                            <Button variant="link" onClick={() => onChoose('manual')} dataButton="google-by-hand">
                                {t('pub.accounts.google.by_hand')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}

/** The script by hand, for one relay: copy, paste in Apps Script,
 *  deploy, paste the address back. Ends in the same check as sign-in. */
export function GoogleByHandSheet({
    t,
    operatorId,
    onClose,
    onDone,
}: {
    t: (k: string) => string;
    operatorId: number;
    onClose: () => void;
    onDone: (row: AddonRow) => void;
}) {
    const [script, setScript] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [url, setUrl] = useState('');
    const { busy, error, run } = useRun();
    // The script carries the write key: no screenshots while it shows.
    useSecureScreen(script != null);

    const copy = async () => {
        let s = script;
        if (s == null) {
            const got = await run(() => Addons.googleScript({ operator_id: operatorId }));
            if (!got) return;
            s = got.code_gs;
            setScript(s);
        }
        setCopied(await copyText(s));
    };
    const attach = async () => {
        const r = await run(() => Addons.googleAttach({ operator_id: operatorId, url: url.trim() }));
        if (r) onDone(r);
    };

    return (
        <Sheet title={t('pub.accounts.google.by_hand')} onClose={onClose} width={520}>
            <div data-testid="google-hand-sheet" style={{ display: 'grid', gap: 14 }}>
                <NumberedSteps
                    items={[
                        {
                            text: t('pub.addons.google.hand.1'),
                            extra: (
                                <div style={{ marginTop: 6 }}>
                                    <Button size="sm" variant="secondary" leading="copy" onClick={() => void copy()} disabled={busy} dataButton="google-copy-script">
                                        {copied ? t('pub.addons.copied') : t('pub.addons.google.hand.1.action')}
                                    </Button>
                                </div>
                            ),
                        },
                        {
                            text: t('pub.addons.google.hand.2'),
                            action: { label: t('pub.addons.google.hand.2.action'), url: APPS_SCRIPT_NEW_URL, dataButton: 'google-open-editor' },
                        },
                        { text: t('pub.addons.google.hand.3') },
                        { text: t('pub.addons.google.hand.4') },
                    ]}
                />
                {script != null && (
                    <>
                        <p style={{ ...MUTED, color: 'var(--amber)' }}>{t('pub.addons.google.hand.secret')}</p>
                        <Textarea
                            readOnly
                            value={script}
                            rows={4}
                            dir="ltr"
                            spellCheck={false}
                            aria-label={t('pub.addons.google.hand.1.action')}
                            data-testid="google-script"
                            style={{ ...MONO, fontSize: 11 }}
                        />
                    </>
                )}
                <Input
                    dir="ltr"
                    inputMode="url"
                    autoComplete="off"
                    spellCheck={false}
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://script.google.com/macros/s/…/exec"
                    aria-label={t('pub.addons.google.hand.url')}
                    data-button="google-url"
                />
                {error != null && <ErrorNote t={t} error={error} />}
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <Button onClick={() => void attach()} disabled={busy || url.trim() === ''} dataButton="google-attach">
                        {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                    </Button>
                </div>
            </div>
        </Sheet>
    );
}
