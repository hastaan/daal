// RestoreNotice — after a restore, the truth about the old phone (D2).
//
// A restore copies the keys; it does not take them away from the phone
// they came from. Until the person acts, that phone can still manage the
// relays and make files the family's phones trust. What this wave can
// change is the hosting key: a new one at the hosting company shuts the
// old phone out of the account and of the relays' management. The
// signing key cannot be changed yet, and the notice says so rather than
// promising it.

import { useState } from 'react';
import { Button, Card, Input, Sheet } from '../design/primitives';
import { Backup, classifyPublisherError } from './wizardCommands';
import type { RelayHealth, RelayLine, RestoreNotice } from './wizardCommands';
import { checkHealth } from './relayHealth';
import { explainFailure, rawErrorText } from './failureText';
import type { Failure } from './failureText';
import { WhatIsThis } from './Disclosure';
import { dayLabel, fill, providersOf, relayLineName, relayNames } from './backup';

const BODY: React.CSSProperties = { fontSize: 13, lineHeight: 1.6, color: 'var(--fg)' };

export function RestoreNoticeCard({
    t,
    notice,
    busy,
    onEnterKey,
    onDismiss,
}: {
    t: (k: string) => string;
    notice: RestoreNotice;
    busy?: boolean;
    onEnterKey: () => void;
    onDismiss: () => void;
}) {
    return (
        <Card>
            <div style={{ display: 'grid', gap: 10 }} data-testid="restore-notice">
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 17, color: 'var(--fg)' }}>
                    {t('pub.restore.oldphone.title')}
                </div>
                <div style={BODY}>{t('pub.restore.oldphone.body1')}</div>
                <div style={BODY}>{t('pub.restore.oldphone.body2')}</div>
                <div>
                    <Button variant="secondary" disabled={busy} onClick={onEnterKey} data-button="new-key">
                        {t('pub.restore.oldphone.newkey')}
                    </Button>
                </div>
                <div style={BODY}>{t('pub.restore.oldphone.body3')}</div>
                {notice.has_refresh_keys && <div style={BODY}>{t('pub.restore.oldphone.body4')}</div>}
                {notice.backup_made_at_unix > 0 && (
                    <div style={BODY} data-testid="restore-later">
                        {fill(t('pub.restore.oldphone.later'), { date: dayLabel(notice.backup_made_at_unix) })}
                    </div>
                )}
                <div>
                    <Button disabled={busy} onClick={onDismiss} data-button="understand">
                        {t('pub.restore.oldphone.ok')}
                    </Button>
                </div>
            </div>
        </Card>
    );
}

export interface KeyDeps {
    /** Test the key with one read-only account call, then store it for
     *  these relays; rejects (storing nothing) when it does not work or
     *  opens another account. */
    replaceKey: (provider: string, token: string, operatorIds: number[]) => Promise<number[]>;
    check: (operatorId: number) => Promise<RelayHealth>;
}

const LIVE_KEY_DEPS: KeyDeps = {
    replaceKey: (p, tok, ids) => Backup.replaceHostingKey(p, tok, ids),
    check: (id) => checkHealth(id, true),
};

export interface KeyLine {
    relayId: number;
    name: string;
    /** null: the key is in use but the check failed. */
    health: RelayHealth | null;
    failure: Failure | null;
}

export interface KeyResult {
    /** One line per relay whose key was replaced. */
    lines: KeyLine[];
    /** Per provider whose key was NOT taken: why, in one sentence. The
     *  key this phone had is still the one in use there. */
    refused: Record<string, Failure>;
}

function refusal(t: (k: string) => string, e: unknown, relays: RelayLine[]): Failure {
    const detail = rawErrorText(e);
    switch (classifyPublisherError(e)) {
        case 'E_HOSTING_KEY_REJECTED':
            return { message: t('pub.restore.newkey.rejected'), detail };
        case 'E_HOSTING_KEY_WRONG_ACCOUNT':
            return { message: fill(t('pub.restore.newkey.wrong_account'), { names: relayNames(relays) }), detail };
        default:
            return { ...explainFailure(t, e), message: t('pub.restore.newkey.failed') };
    }
}

/**
 * For each provider with a key typed: the shell tests the key against
 * the hosting company and only then replaces the stored one for every
 * relay there; a refused key changes nothing and the sheet says so in
 * plain words. Each relay whose key was replaced is then checked.
 */
export async function saveNewKeys(
    t: (k: string) => string,
    notice: RestoreNotice,
    tokens: Record<string, string>,
    deps: KeyDeps = LIVE_KEY_DEPS,
): Promise<KeyResult> {
    const out: KeyResult = { lines: [], refused: {} };
    for (const { provider, relays } of providersOf(notice)) {
        const token = (tokens[provider] ?? '').trim();
        if (!token) continue;
        try {
            await deps.replaceKey(
                provider,
                token,
                relays.map((r) => r.id),
            );
        } catch (e) {
            out.refused[provider] = refusal(t, e, relays);
            continue;
        }
        for (const r of relays) {
            const line: KeyLine = { relayId: r.id, name: relayLineName(r), health: null, failure: null };
            try {
                line.health = await deps.check(r.id);
            } catch (e) {
                line.failure = explainFailure(t, e);
            }
            out.lines.push(line);
        }
    }
    return out;
}

export function keyLineText(t: (k: string) => string, l: KeyLine): string {
    if (l.health === null) return fill(t('pub.restore.newkey.line.unknown'), { name: l.name });
    const k = l.health.overall;
    const key =
        k === 'working' || k === 'partly' || k === 'not_working'
            ? `pub.restore.newkey.line.${k}`
            : 'pub.restore.newkey.line.unknown';
    return fill(t(key), { name: l.name });
}

export function NewHostingKeySheet({
    t,
    notice,
    onClose,
    deps = LIVE_KEY_DEPS,
}: {
    t: (k: string) => string;
    notice: RestoreNotice;
    onClose: () => void;
    deps?: KeyDeps;
}) {
    const groups = providersOf(notice);
    const [tokens, setTokens] = useState<Record<string, string>>({});
    const [busy, setBusy] = useState(false);
    const [lines, setLines] = useState<KeyLine[]>([]);
    const [saved, setSaved] = useState<Set<string>>(new Set());
    const [refused, setRefused] = useState<Record<string, Failure>>({});
    const open = groups.filter((g) => !saved.has(g.provider));
    const ready = open.some((g) => (tokens[g.provider] ?? '').trim() !== '');
    const finished = open.length === 0;
    return (
        <Sheet
            title={t('pub.restore.newkey.title')}
            width={520}
            onClose={() => {
                if (!busy) onClose();
            }}
            footer={
                <span style={{ display: 'inline-flex', gap: 8 }}>
                    <Button variant="ghost" disabled={busy} onClick={onClose}>
                        {finished || lines.length > 0 ? t('pub.backup.done') : t('common.cancel')}
                    </Button>
                    {!finished && (
                        <Button
                            disabled={busy || !ready}
                            data-button="save-key"
                            onClick={async () => {
                                setBusy(true);
                                try {
                                    const r = await saveNewKeys(t, notice, tokens, deps);
                                    const took = new Set(saved);
                                    for (const g of open) {
                                        if ((tokens[g.provider] ?? '').trim() && !r.refused[g.provider]) took.add(g.provider);
                                    }
                                    setSaved(took);
                                    setLines((l) => [...l, ...r.lines]);
                                    setRefused(r.refused);
                                } finally {
                                    // The keys leave state as soon as they were tried.
                                    setTokens({});
                                    setBusy(false);
                                }
                            }}
                        >
                            {busy ? t('pub.restore.newkey.saving') : t('pub.restore.newkey.save')}
                        </Button>
                    )}
                </span>
            }
        >
            <div style={{ display: 'grid', gap: 10 }}>
                <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.55 }}>
                    {t('pub.restore.newkey.body')}
                </div>
                {open.map((g) => (
                    <label key={g.provider} style={{ display: 'grid', gap: 4 }}>
                        <span style={{ fontSize: 12, color: 'var(--muted)' }}>
                            {fill(t('pub.restore.newkey.label'), {
                                provider: g.provider,
                                names: relayNames(g.relays),
                            })}
                        </span>
                        <Input
                            type="password"
                            autoComplete="off"
                            value={tokens[g.provider] ?? ''}
                            onChange={(e) => setTokens((m) => ({ ...m, [g.provider]: e.target.value }))}
                        />
                        {refused[g.provider] && (
                            <div role="alert" style={{ display: 'grid', gap: 4 }} data-testid="key-refused">
                                <div style={{ ...BODY, color: 'var(--red)' }}>{refused[g.provider].message}</div>
                                {refused[g.provider].detail && (
                                    <WhatIsThis label={t('pub.fb.details')}>
                                        <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                            {refused[g.provider].detail}
                                        </div>
                                    </WhatIsThis>
                                )}
                            </div>
                        )}
                    </label>
                ))}
                {lines.map((l) => (
                    <div key={l.relayId} style={{ display: 'grid', gap: 4 }} data-testid="key-line">
                        <div style={BODY}>{keyLineText(t, l)}</div>
                        {l.failure?.detail && (
                            <WhatIsThis label={t('pub.fb.details')}>
                                <div dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                                    {l.failure.detail}
                                </div>
                            </WhatIsThis>
                        )}
                    </div>
                ))}
            </div>
        </Sheet>
    );
}
