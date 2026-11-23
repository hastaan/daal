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
//     page); paste → check → "✓ Connected: <domain>". A key that sees
//     several domains asks which one, then is checked again on it. A key
//     that can do more than Daal needs is kept, with one line naming
//     what more (also on the connected state, later). Only a key that
//     cannot do the job is refused, and what it lacks is named. The key
//     is kept by addon_cdn::connect, for every relay.
//   GoogleSheet — the account's one update script, added by hand: an
//     account only for this, copy the script (its key is already in it),
//     paste it in Apps Script, deploy it as a web app, paste the address
//     back → Daal writes and reads back through Google → "✓ Connected".
//     Every relay's switch then takes a place in that script; nothing
//     per relay is done in Google. "Sign in with Google" is the same step
//     done for the owner, and shows only in a build that has the OAuth
//     clients. Disconnect forgets the key; the script stays in Google.
//   GithubSheet — an account only for this, the key page (fine-grained,
//     all repositories, Administration and Contents: read and write);
//     paste → one call to GitHub → "✓ Connected as <name>". A key GitHub
//     refuses, or a classic key without the repository scope, is never
//     kept, and the sheet says what is wrong. A fine-grained key's
//     permissions cannot be proven by that call: it is kept, and if it
//     lacks one, the relay switch's first write names what GitHub said
//     is missing and opens this sheet in its «Use a new key» mode. The
//     connected sheet always offers «Use a new key» (an expired or
//     revoked key is replaced without disconnecting). The key is kept
//     by addon_notes::github_connect; a relay's «Updates through GitHub»
//     makes its own repository under the account.

import { useState } from 'react';
import { useDensity } from '../../design/DensityProvider';
import { Button, Input, Sheet, Textarea } from '../../design/primitives';
import { useDeviceT } from '../ui';
import { useSecureScreen } from '../useSecureScreen';
import { Addons, Wizard } from '../wizardCommands';
import type { CdnTokenCheck, GithubCheck } from './addonTypes';
import type { GithubState, GoogleState } from './accounts';
import { classifyAddonError } from './addonErrors';
import { BODY, ErrorNote, MONO, MUTED, NumberedSteps, copyText, openExternal, useRun } from './addonUi';
import { readClipboardText } from '../../lib/clipboard';

/** The wizard's sign-up link (PublisherWizard CLOUD_PROVIDERS). */
export const HETZNER_SIGNUP_URL = 'https://console.hetzner.cloud/register';
/** The console's project list: make a project, then its API token. */
export const HETZNER_CONSOLE_URL = 'https://console.hetzner.cloud/projects';
export const CLOUDFLARE_SIGNUP_URL = 'https://dash.cloudflare.com/sign-up';
export const CLOUDFLARE_REGISTRAR_URL = 'https://dash.cloudflare.com/?to=/:account/domains/register';
export const GOOGLE_SIGNUP_URL = 'https://accounts.google.com/signup';
export const APPS_SCRIPT_SETTINGS_URL = 'https://script.google.com/home/usersettings';
export const APPS_SCRIPT_NEW_URL = 'https://script.google.com/home/projects/create';
export const GITHUB_SIGNUP_URL = 'https://github.com/signup';

/** GitHub's page for a new fine-grained key, filled in as far as GitHub
 *  lets a link fill it: a plain name, and the two permissions Daal needs
 *  (Administration, to make the relay's repository; Contents, to write
 *  to it). GitHub ignores a field it does not read, so the steps still
 *  name both, and "All repositories". */
export function githubTokenUrl(): string {
    return 'https://github.com/settings/personal-access-tokens/new?name=notes&administration=write&contents=write';
}

const GITHUB_VERDICTS = new Set(['invalid', 'missing_permission', 'owner_mismatch', 'rate_limited']);

/** The line for a GitHub key that was not kept. */
export function githubVerdictKey(v: string): string {
    return `pub.accounts.github.verdict.${GITHUB_VERDICTS.has(v) ? v : 'invalid'}`;
}

/** GitHub's permission names (note-gittag's `missing` and `extra`) as
 *  the publisher sees them on the key's page. */
export function githubPermissionList(t: (k: string) => string, names: string[] | undefined, rtl: boolean): string {
    const words: string[] = [];
    for (const n of names ?? []) {
        const name = n.trim();
        const w = name === 'public_repo' ? t('pub.accounts.github.perm.public_repo') : name.replace(/\s*\(.*\)$/, '');
        if (w && !words.includes(w)) words.push(w);
    }
    return words.join(rtl ? '، ' : ', ');
}

/** "2027-11-22T…" in the reader's calendar, or '' when unreadable. */
function dateOf(iso: string | undefined, rtl: boolean): string {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    try {
        return d.toLocaleDateString(rtl ? 'fa-IR' : 'en-GB', { year: 'numeric', month: 'long', day: 'numeric' });
    } catch {
        return iso.slice(0, 10);
    }
}

/** The pre-filled token page (plan §2.5): exactly the five zone
 *  permissions Daal needs. It cannot pre-pick one zone; the owner picks
 *  the domain they bought (a key that sees more asks which one). */
export function cloudflareTokenUrl(): string {
    const groups = JSON.stringify([
        { key: 'zone', type: 'read' },
        { key: 'dns', type: 'edit' },
        { key: 'ssl_and_certificates', type: 'edit' },
        { key: 'zone_settings', type: 'edit' },
        // `origin`, not `origin_rules`: the key is the permission group's
        // name ("Origin Write", shown as "Origin Rules") without its
        // read/write ending, and Cloudflare silently drops a key that
        // matches no group, which is how Origin Rules arrived unticked.
        { key: 'origin', type: 'edit' },
    ]);
    return (
        'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=' +
        encodeURIComponent(groups) +
        '&accountId=*&zoneId=all&name=daal'
    );
}

const VERDICTS = new Set(['invalid', 'no_zone', 'zone_not_visible', 'missing_permission', 'refused']);

/** The line for a key that was not kept. */
export function verdictKey(v: string): string {
    return `pub.accounts.cf.verdict.${VERDICTS.has(v) ? v : 'refused'}`;
}

/** Cloudflare's permission names (cdn-token-check's `missing` and
 *  `extra`, publisher/deploy/cloudflare/token_check.go) in plain words.
 *  The five Daal needs keep Cloudflare's own label, which is what the
 *  publisher looks for on the key's page. */
const CF_PERMISSION_WORDS: Record<string, string> = {
    'zone — zone': 'pub.accounts.cf.perm.zone',
    'zone — dns': 'pub.accounts.cf.perm.dns',
    'zone — ssl and certificates': 'pub.accounts.cf.perm.ssl',
    'zone — zone settings': 'pub.accounts.cf.perm.zone_settings',
    'zone — origin rules': 'pub.accounts.cf.perm.origin_rules',
    'user — user details': 'pub.accounts.cf.perm.user_details',
    'user — api tokens': 'pub.accounts.cf.perm.api_tokens',
    'zone — workers routes': 'pub.accounts.cf.perm.workers_routes',
    'zone — firewall services': 'pub.accounts.cf.perm.firewall',
    'zone — page rules': 'pub.accounts.cf.perm.page_rules',
    'account — workers scripts': 'pub.accounts.cf.perm.workers_scripts',
    'account — registrar': 'pub.accounts.cf.perm.registrar',
    'account — billing': 'pub.accounts.cf.perm.billing',
    'account — members': 'pub.accounts.cf.perm.members',
};

/** The i18n key for one of Cloudflare's permission names, or null for a
 *  name this build does not know (it is then shown as Cloudflare says
 *  it). A trailing access level ("— Edit") is not part of the name. */
export function cfPermissionKey(name: string): string | null {
    const n = name
        .trim()
        .toLowerCase()
        .replace(/\s*[—-]\s*(read|edit)$/, '');
    return CF_PERMISSION_WORDS[n] ?? null;
}

/** Permission names as one list in plain words, each once. */
export function cfPermissionList(t: (k: string) => string, names: string[] | undefined, rtl: boolean): string {
    const words: string[] = [];
    for (const name of names ?? []) {
        const k = cfPermissionKey(name);
        const w = k ? t(k) : name.trim();
        if (w && !words.includes(w)) words.push(w);
    }
    return words.join(rtl ? '، ' : ', ');
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
        // '' when nothing could be read: the field takes it by hand.
        const s = (await readClipboardText()).trim();
        if (s) setToken(s);
        setPasteFailed(!s);
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
    extra,
    onClose,
    onConnected,
    onDisconnected,
}: {
    t: (k: string) => string;
    /** The connected zone; '' or null when not connected. */
    zone: string | null;
    /** What the kept key can do beyond the five (Cloudflare's names). */
    extra?: string[];
    onClose: () => void;
    onConnected: (zone: string) => void;
    onDisconnected?: () => void;
}) {
    const { isRTL } = useDensity();
    const [token, setToken] = useState('');
    const [check, setCheck] = useState<CdnTokenCheck | null>(null);
    const [picked, setPicked] = useState('');
    const [pasteFailed, setPasteFailed] = useState(false);
    const { busy, error, run } = useRun();
    const done = check?.stored ? check.zone || check.zones[0] || '' : null;
    const shown = done ?? (zone || null);
    const picking = check?.verdict === 'pick_zone' && check.zones.length > 1;
    const broad = cfPermissionList(t, done != null ? check?.extra : extra, isRTL);

    const connect = async () => {
        const typed = token;
        const want = picking ? picked : '';
        const c = await run(() => Addons.cdnConnect(want ? { token: typed, zone: want } : { token: typed }));
        if (!c) return;
        setCheck(c);
        setPicked('');
        // The key leaves the page once it is checked, kept or not; only a
        // key that sees several domains stays until one is picked.
        if (c.verdict !== 'pick_zone') setToken('');
        if (c.stored) onConnected(c.zone || c.zones[0] || '');
    };
    const typeToken = (v: string) => {
        setToken(v);
        // A different key: the domains it was asked about are not its.
        if (picking) setCheck(null);
    };
    const paste = async () => {
        // '' when nothing could be read: the field takes it by hand.
        const s = (await readClipboardText()).trim();
        if (s) typeToken(s);
        setPasteFailed(!s);
    };
    const disconnect = async () => {
        const r = await run(async () => {
            await Addons.cdnDisconnect();
            return true;
        });
        if (r) onDisconnected?.();
    };
    const refusal = (c: CdnTokenCheck): string => {
        const line = t(verdictKey(c.verdict));
        if (c.verdict !== 'missing_permission') return line;
        // Name what is missing, so the key can be fixed; "a permission"
        // when the helper did not say.
        return line.replace('{list}', cfPermissionList(t, c.missing, isRTL) || t('pub.accounts.cf.perm.some'));
    };

    return (
        <Sheet title="Cloudflare" onClose={onClose} width={480}>
            <div data-testid="cloudflare-sheet" style={{ display: 'grid', gap: 14 }}>
                {shown != null ? (
                    <>
                        <Connected testId="cloudflare-connected" text={t('pub.accounts.connected_to').replace('{name}', shown)} />
                        {broad && (
                            <p data-testid="cloudflare-broad" style={MUTED}>
                                {t('pub.accounts.cf.broad').replace('{list}', broad)}
                            </p>
                        )}
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
                                    onChange={(e) => typeToken(e.target.value)}
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
                        {picking && check && (
                            <div data-testid="cloudflare-pick" style={{ display: 'grid', gap: 8 }}>
                                <p style={BODY}>{t('pub.accounts.cf.pick')}</p>
                                <div role="radiogroup" aria-label={t('pub.accounts.cf.pick')} style={{ display: 'grid', gap: 6 }}>
                                    {check.zones.map((z) => (
                                        <ZoneChoice key={z} name={z} selected={picked === z} onSelect={() => setPicked(z)} />
                                    ))}
                                </div>
                            </div>
                        )}
                        {check && !check.stored && !picking && (
                            <p data-testid="cloudflare-verdict" data-verdict={check.verdict} style={{ ...MUTED, color: 'var(--red)' }}>
                                {refusal(check)}
                            </p>
                        )}
                        {error != null && <ErrorNote t={t} error={error} />}
                        <p style={MUTED}>{t('pub.accounts.cf.sees')}</p>
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button
                                onClick={() => void connect()}
                                disabled={busy || token.trim() === '' || (picking && picked === '')}
                                dataButton="cloudflare-connect"
                            >
                                {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}

/** One domain to pick, as a radio row. */
function ZoneChoice({ name, selected, onSelect }: { name: string; selected: boolean; onSelect: () => void }) {
    return (
        <button
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={onSelect}
            data-button={`cloudflare-zone-${name}`}
            dir="ltr"
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                width: '100%',
                minHeight: 44,
                padding: '8px 12px',
                font: 'inherit',
                fontSize: 14,
                color: 'var(--fg)',
                textAlign: 'start',
                background: 'var(--surface-2)',
                border: `1px solid ${selected ? 'var(--gold)' : 'var(--line)'}`,
                borderRadius: 'var(--radius-md)',
                cursor: 'pointer',
            }}
        >
            <span
                aria-hidden
                style={{
                    width: 18,
                    height: 18,
                    flexShrink: 0,
                    borderRadius: '50%',
                    border: `2px solid ${selected ? 'var(--gold)' : 'var(--muted)'}`,
                    background: selected ? 'var(--gold)' : 'transparent',
                    boxShadow: selected ? 'inset 0 0 0 3px var(--surface-2)' : 'none',
                }}
            />
            <span style={{ ...MONO, overflowWrap: 'anywhere' }}>{name}</span>
        </button>
    );
}

export function GoogleSheet({
    t,
    google,
    onClose,
    onConnected,
    onDisconnected,
}: {
    t: (k: string) => string;
    google: GoogleState;
    onClose: () => void;
    /** The script was added and checked. From a relay switch, the caller
     *  goes on to turn the switch on. */
    onConnected: () => void;
    onDisconnected?: () => void;
}) {
    const [script, setScript] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);
    const [url, setUrl] = useState('');
    const [done, setDone] = useState(false);
    const [pasteFailed, setPasteFailed] = useState(false);
    const { busy, error, run } = useRun();
    // The script carries the account's write key: no screenshots while
    // it shows.
    useSecureScreen(script != null);
    const connected = done || google.connected;

    const copy = async () => {
        let s = script;
        if (s == null) {
            const got = await run(() => Addons.googleAccountScript());
            if (!got) return;
            s = got.code_gs;
            setScript(s);
        }
        setCopied(await copyText(s));
    };
    const paste = async () => {
        // '' when nothing could be read: the field takes it by hand.
        const s = (await readClipboardText()).trim();
        if (s) setUrl(s);
        setPasteFailed(!s);
    };
    const finished = () => {
        setDone(true);
        setScript(null);
        setUrl('');
        onConnected();
    };
    const connect = async () => {
        const r = await run(() => Addons.googleAccountAttach({ url: url.trim() }));
        if (r?.connected) finished();
    };
    const signIn = async () => {
        const r = await run(() => Addons.googleAccountSignIn());
        if (r?.connected) finished();
    };
    const disconnect = async () => {
        const r = await run(async () => {
            await Addons.googleAccountDisconnect();
            return true;
        });
        if (r) onDisconnected?.();
    };
    const failure =
        error != null ? (
            <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
                <ErrorNote t={t} error={error} />
                {classifyAddonError(error) === 'E_GOOGLE_API_NOT_ENABLED' && (
                    <Button size="sm" variant="link" leading="external" onClick={() => void openExternal(APPS_SCRIPT_SETTINGS_URL)} dataButton="google-api-open">
                        {t('pub.accounts.google.api.open')}
                    </Button>
                )}
            </div>
        ) : null;

    return (
        <Sheet title="Google" onClose={onClose} width={520}>
            <div data-testid="google-sheet" style={{ display: 'grid', gap: 14 }}>
                {connected ? (
                    <>
                        <Connected testId="google-connected" text={t('pub.accounts.connected')} />
                        <p style={MUTED}>{t('pub.accounts.google.kept')}</p>
                        <p style={{ ...MUTED, color: 'var(--amber)' }}>{t('pub.accounts.google.warn')}</p>
                        {!done && onDisconnected && (
                            <p data-testid="google-disconnect-line" style={MUTED}>
                                {t('pub.accounts.google.disconnect.line')}
                            </p>
                        )}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
                            {!done && onDisconnected ? (
                                <Button variant="ghost" onClick={() => void disconnect()} disabled={busy} dataButton="google-disconnect">
                                    {t('pub.accounts.disconnect')}
                                </Button>
                            ) : (
                                <span />
                            )}
                            <Button onClick={onClose} dataButton="google-done">
                                {t('pub.accounts.done')}
                            </Button>
                        </div>
                        {failure}
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
                                {
                                    text: t('pub.accounts.google.hand.1'),
                                    extra: (
                                        <div style={{ marginTop: 6 }}>
                                            <Button size="sm" variant="secondary" leading="copy" onClick={() => void copy()} disabled={busy} dataButton="google-copy-script">
                                                {copied ? t('pub.addons.copied') : t('pub.accounts.google.hand.1.action')}
                                            </Button>
                                        </div>
                                    ),
                                },
                                {
                                    text: t('pub.accounts.google.hand.2'),
                                    action: { label: t('pub.accounts.google.hand.2.action'), url: APPS_SCRIPT_NEW_URL, dataButton: 'google-open-editor' },
                                },
                                { text: t('pub.accounts.google.hand.3') },
                                { text: t('pub.accounts.google.hand.4') },
                            ]}
                        />
                        {script != null && (
                            <>
                                <p style={{ ...MUTED, color: 'var(--amber)' }}>{t('pub.accounts.google.hand.secret')}</p>
                                <Textarea
                                    readOnly
                                    value={script}
                                    rows={4}
                                    dir="ltr"
                                    spellCheck={false}
                                    aria-label={t('pub.accounts.google.hand.1.action')}
                                    data-testid="google-script"
                                    style={{ ...MONO, fontSize: 11 }}
                                />
                            </>
                        )}
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{t('pub.accounts.google.hand.url')}</div>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <Input
                                    dir="ltr"
                                    inputMode="url"
                                    autoComplete="off"
                                    autoCapitalize="off"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    placeholder="https://script.google.com/macros/s/…/exec"
                                    aria-label={t('pub.accounts.google.hand.url')}
                                    data-button="google-url"
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <Button variant="secondary" leading="paste" onClick={() => void paste()} dataButton="google-paste">
                                    {t('ui.paste')}
                                </Button>
                            </div>
                            {pasteFailed && <p style={{ ...MUTED, color: 'var(--red)' }}>{t('wiz.provider.token.paste_failed')}</p>}
                        </div>
                        <p data-testid="google-warn" style={{ ...MUTED, color: 'var(--amber)' }}>
                            {t('pub.accounts.google.warn')}
                        </p>
                        {failure}
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button onClick={() => void connect()} disabled={busy || url.trim() === ''} dataButton="google-connect">
                                {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                            </Button>
                        </div>
                        {/* Only a build with the OAuth clients can sign in;
                            any other build shows no trace of it. */}
                        {google.signIn && (
                            <div data-testid="google-sign-in-block" style={{ display: 'grid', gap: 6, justifyItems: 'center', borderTop: '1px solid var(--line)', paddingTop: 12 }}>
                                <Button variant="secondary" onClick={() => void signIn()} disabled={busy} dataButton="google-sign-in">
                                    {t('pub.accounts.google.sign_in')}
                                </Button>
                                <p style={{ ...MUTED, textAlign: 'center' }}>{t('pub.accounts.google.unverified')}</p>
                            </div>
                        )}
                    </>
                )}
            </div>
        </Sheet>
    );
}

export function GithubSheet({
    t,
    github,
    onClose,
    onConnected,
    onDisconnected,
    newKey = false,
}: {
    t: (k: string) => string;
    /** Open on «Use a new key»: steps 2 and 3 and the key field. */
    newKey?: boolean;
    /** The account as kept now; absent or not connected: the steps. */
    github?: GithubState;
    onClose: () => void;
    /** The key was checked and kept: the account's name on GitHub. From a
     *  relay switch, the caller goes on to turn the switch on. */
    onConnected: (login: string) => void;
    onDisconnected?: () => void;
}) {
    const { isRTL } = useDensity();
    const [token, setToken] = useState('');
    const [check, setCheck] = useState<GithubCheck | null>(null);
    const [pasteFailed, setPasteFailed] = useState(false);
    const { busy, error, run } = useRun();
    // «Use a new key»: the key steps again, without the account step.
    const [replacing, setReplacing] = useState(newKey);
    const done = check?.stored ? check : null;
    const login = done ? (done.login ?? '') : github?.connected ? github.login : null;
    const extra = done ? done.extra : github?.extra;
    const expires = done ? done.expires_at : github?.expiresAt;
    const broad = githubPermissionList(t, extra, isRTL);
    const until = dateOf(expires, isRTL);

    const connect = async () => {
        const typed = token;
        const c = await run(() => Addons.githubConnect({ token: typed }));
        // The key leaves the page once it is checked, kept or not.
        setToken('');
        if (!c) return;
        setCheck(c);
        if (c.stored) {
            setReplacing(false);
            onConnected(c.login ?? '');
        }
    };
    const paste = async () => {
        // '' when nothing could be read: the field takes it by hand.
        const s = (await readClipboardText()).trim();
        if (s) {
            setToken(s);
            setCheck(null);
        }
        setPasteFailed(!s);
    };
    const disconnect = async () => {
        const r = await run(async () => {
            await Addons.githubDisconnect();
            return true;
        });
        if (r) onDisconnected?.();
    };
    const refusal = (c: GithubCheck): string => {
        const line = t(githubVerdictKey(c.verdict));
        if (c.verdict !== 'missing_permission') return line;
        return line.replace('{list}', githubPermissionList(t, c.missing, isRTL) || t('pub.accounts.cf.perm.some'));
    };

    return (
        <Sheet title="GitHub" onClose={onClose} width={480}>
            <div data-testid="github-sheet" style={{ display: 'grid', gap: 14 }}>
                {login != null && !(replacing && done == null) ? (
                    <>
                        <Connected
                            testId="github-connected"
                            text={login ? t('pub.accounts.github.connected_as').replace('{name}', login) : t('pub.accounts.connected')}
                        />
                        <p style={MUTED}>{t('pub.accounts.github.kept')}</p>
                        {broad && (
                            <p data-testid="github-broad" style={MUTED}>
                                {t('pub.accounts.github.broad').replace('{list}', broad)}
                            </p>
                        )}
                        {until && (
                            <p data-testid="github-expires" style={{ ...MUTED, color: 'var(--amber)' }}>
                                {t('pub.accounts.github.expires').replace('{date}', until)}
                            </p>
                        )}
                        {done == null && onDisconnected && (
                            <p data-testid="github-disconnect-line" style={MUTED}>
                                {t('pub.accounts.github.disconnect.line')}
                            </p>
                        )}
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', flexWrap: 'wrap' }}>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                {done == null && onDisconnected && (
                                    <Button variant="ghost" onClick={() => void disconnect()} disabled={busy} dataButton="github-disconnect">
                                        {t('pub.accounts.disconnect')}
                                    </Button>
                                )}
                                <Button
                                    variant="secondary"
                                    onClick={() => {
                                        setCheck(null);
                                        setReplacing(true);
                                    }}
                                    disabled={busy}
                                    dataButton="github-new-key"
                                >
                                    {t('pub.accounts.github.new_key')}
                                </Button>
                            </div>
                            <Button onClick={onClose} dataButton="github-done">
                                {t('pub.accounts.done')}
                            </Button>
                        </div>
                        {error != null && <ErrorNote t={t} error={error} />}
                    </>
                ) : (
                    <>
                        <NumberedSteps
                            testId="github-steps"
                            items={[
                                ...(replacing && login != null
                                    ? []
                                    : [
                                          {
                                              text: t('pub.accounts.github.step.1'),
                                              action: {
                                                  label: t('pub.accounts.github.step.1.action'),
                                                  url: GITHUB_SIGNUP_URL,
                                                  dataButton: 'github-signup',
                                              },
                                          },
                                      ]),
                                {
                                    text: t('pub.accounts.github.step.2'),
                                    action: {
                                        label: t('pub.accounts.github.step.2.action'),
                                        url: githubTokenUrl(),
                                        dataButton: 'github-token-page',
                                    },
                                },
                                { text: t('pub.accounts.github.step.3') },
                            ]}
                        />
                        <div style={{ display: 'grid', gap: 6 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{t('pub.accounts.github.key')}</div>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                <Input
                                    type="password"
                                    autoComplete="off"
                                    autoCapitalize="off"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    dir="ltr"
                                    value={token}
                                    onChange={(e) => {
                                        setToken(e.target.value);
                                        setCheck(null);
                                    }}
                                    placeholder={t('wiz.provider.token.placeholder')}
                                    aria-label={t('pub.accounts.github.key')}
                                    data-button="github-token"
                                    style={{ flex: 1, minWidth: 0 }}
                                />
                                <Button variant="secondary" leading="paste" onClick={() => void paste()} dataButton="github-paste">
                                    {t('ui.paste')}
                                </Button>
                            </div>
                            {pasteFailed && <p style={{ ...MUTED, color: 'var(--red)' }}>{t('wiz.provider.token.paste_failed')}</p>}
                        </div>
                        {check && !check.stored && (
                            <p data-testid="github-verdict" data-verdict={check.verdict} style={{ ...MUTED, color: 'var(--red)' }}>
                                {refusal(check)}
                            </p>
                        )}
                        {error != null && <ErrorNote t={t} error={error} />}
                        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                            <Button onClick={() => void connect()} disabled={busy || token.trim() === ''} dataButton="github-connect">
                                {busy ? t('pub.accounts.checking') : t('pub.accounts.connect')}
                            </Button>
                        </div>
                    </>
                )}
            </div>
        </Sheet>
    );
}
