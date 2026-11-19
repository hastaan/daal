// PeopleSection — who has access, and each person's own file.
//
// This used to be two lists. "Files to share" had one row per person
// (Resend, Save) and, further down, "Recipients" had one row per person
// again (New key, Revoke). The same human appeared twice under two
// different nouns, and the owner could not tell which list was "the
// people" — so now there is one row per person and everything you can
// do for that person is on it.
//
// One primary action for the section: "Add a person". The one file
// that works for everyone is the NEXT section, not a row in this one.

import type { ReactNode } from 'react';
import type { ArtifactInfo, RecipientSummary } from './wizardCommands';
import { Button, Card } from '../design/primitives';
import { ActionButton } from './useAction';
import type { ActionState } from './useAction';
import { WhatIsThis } from './Disclosure';

export interface PersonRow {
    /** Stable React key. */
    key: string;
    label: string;
    /** Null only for a file whose roster row is gone. */
    recipient: RecipientSummary | null;
    /** Null when the roster has no file entry for them at all. */
    file: ArtifactInfo | null;
    revoked: boolean;
}

/** What to call a person on screen: the name the owner gave them, else
 *  the relay-side name, else the row number. Never empty — confirms
 *  interpolate it into a sentence that has to name one person. */
export function personLabel(r: RecipientSummary): string {
    return r.display_name || r.name || `#${r.id}`;
}

/** One row per person: the roster joined to its files. People first,
 *  in roster order; a file with no roster row (should not happen, but
 *  the file is still a working credential and must stay reachable)
 *  goes last. */
export function joinPeople(
    recipients: RecipientSummary[],
    files: ArtifactInfo[],
): PersonRow[] {
    const byId = new Map<number, ArtifactInfo>();
    for (const f of files) {
        if (f.kind === 'sbpx' && f.recipient_id != null) byId.set(f.recipient_id, f);
    }
    const seen = new Set<number>();
    const rows: PersonRow[] = recipients.map((r) => {
        seen.add(r.id);
        return {
            key: `p${r.id}`,
            label: personLabel(r),
            recipient: r,
            file: byId.get(r.id) ?? null,
            revoked: r.revoked_at_unix > 0,
        };
    });
    for (const f of files) {
        if (f.kind !== 'sbpx') continue;
        if (f.recipient_id != null && seen.has(f.recipient_id)) continue;
        // Nothing to do with a file that is neither on disk nor on the
        // roster.
        if (!f.exists) continue;
        rows.push({
            key: `f${f.path}`,
            label: f.recipient_label || `#${f.recipient_id ?? '?'}`,
            recipient: null,
            file: f,
            revoked: false,
        });
    }
    return rows;
}

function dayLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 10);
    } catch {
        return '';
    }
}

const ROW_BUTTONS: React.CSSProperties = {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 6,
};
const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 };

interface Props {
    t: (k: string) => string;
    action: ActionState;
    loading: boolean;
    people: PersonRow[];
    onAdd: () => void;
    onSend: (path: string, label: string) => void;
    onSave: (path: string, label: string) => void;
    /** Their file is missing on this device: make it again. */
    onRemake: (r: RecipientSummary) => void;
    /** Give them a new file and cancel the old one. */
    onReplace: (r: RecipientSummary) => void;
    onRemoveAccess: (r: RecipientSummary) => void;
    onRemoveFromList: (r: RecipientSummary) => void;
}

export function PeopleSection({
    t,
    action,
    loading,
    people,
    onAdd,
    onSend,
    onSave,
    onRemake,
    onReplace,
    onRemoveAccess,
    onRemoveFromList,
}: Props) {
    return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <header
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 12,
                }}
            >
                <h2 style={H2}>{t('pub.people.title')}</h2>
                <Button onClick={onAdd}>{t('pub.people.add')}</Button>
            </header>
            <div style={SUB}>{t('pub.people.line')}</div>

            {people.length === 0 && !loading && (
                <Card>
                    <div style={SUB}>{t('pub.people.empty')}</div>
                </Card>
            )}

            {people.length > 0 && (
                <Card>
                    {people.map((p, i) => (
                        <div
                            key={p.key}
                            style={{
                                display: 'grid',
                                gap: 8,
                                padding: '11px 0',
                                borderBottom:
                                    i === people.length - 1
                                        ? 'none'
                                        : '1px solid var(--line-soft)',
                            }}
                        >
                            <div>
                                <div
                                    style={{
                                        fontWeight: 600,
                                        fontSize: 14,
                                        color: 'var(--fg)',
                                        lineHeight: 1.3,
                                    }}
                                >
                                    {p.label}
                                </div>
                                <div style={SUB}>{personState(t, p)}</div>
                            </div>
                            <div style={ROW_BUTTONS}>{personButtons(p)}</div>
                            {/* The one per-person action that is not
                                routine. Behind a tap, with its
                                consequence, because on the row it was a
                                button called "New key" next to one
                                called "Resend" and nothing said which
                                one cuts the person off. */}
                            {p.recipient && !p.revoked && p.file?.exists && (
                                <WhatIsThis label={t('pub.people.more')}>
                                    <div>
                                        {t('pub.people.replace.line').replace(
                                            /\{name\}/g,
                                            p.label,
                                        )}
                                    </div>
                                    {/* Which person this is, for when
                                        two share a name. An identifier,
                                        not a sentence, so it stays
                                        left-to-right in any language. */}
                                    <div
                                        dir="ltr"
                                        style={{
                                            fontFamily: 'var(--font-mono)',
                                            fontSize: 11,
                                            wordBreak: 'break-all',
                                            textAlign: 'start',
                                        }}
                                    >
                                        {p.recipient.address_str}
                                    </div>
                                    <div>
                                        <Button
                                            variant="secondary"
                                            size="sm"
                                            disabled={action.busy !== null}
                                            onClick={() => onReplace(p.recipient!)}
                                        >
                                            {t('pub.people.replace')}
                                        </Button>
                                    </div>
                                </WhatIsThis>
                            )}
                        </div>
                    ))}
                </Card>
            )}
        </section>
    );

    function personButtons(p: PersonRow): ReactNode {
        const r = p.recipient;
        if (p.revoked && r) {
            return (
                <Button
                    variant="secondary"
                    size="sm"
                    disabled={action.busy !== null}
                    onClick={() => onRemoveFromList(r)}
                >
                    {t('pub.people.remove_from_list')}
                </Button>
            );
        }
        const f = p.file;
        return (
            <>
                {f?.exists ? (
                    <>
                        <ActionButton
                            action={action}
                            k={`send:${f.path}`}
                            busyLabel={t('pub.fb.opening')}
                            size="sm"
                            onClick={() => onSend(f.path, p.label)}
                        >
                            {t('pub.people.send')}
                        </ActionButton>
                        <ActionButton
                            action={action}
                            k={`save:${f.path}`}
                            busyLabel={t('pub.fb.saving')}
                            variant="secondary"
                            size="sm"
                            onClick={() => onSave(f.path, p.label)}
                        >
                            {t('pub.people.save')}
                        </ActionButton>
                    </>
                ) : (
                    r && (
                        <ActionButton
                            action={action}
                            k={`remake:${r.id}`}
                            busyLabel={t('pub.fb.making')}
                            size="sm"
                            onClick={() => onRemake(r)}
                        >
                            {t('pub.people.remake')}
                        </ActionButton>
                    )
                )}
                {r && (
                    <Button
                        variant="danger"
                        size="sm"
                        disabled={action.busy !== null}
                        onClick={() => onRemoveAccess(r)}
                    >
                        {t('pub.people.remove_access')}
                    </Button>
                )}
            </>
        );
    }
}

/** The one line under a person's name: where they stand. */
export function personState(t: (k: string) => string, p: PersonRow): string {
    if (p.revoked) return t('pub.people.state.removed');
    if (!p.file?.exists) return t('pub.people.state.no_file');
    const day = dayLabel(p.recipient?.provisioned_at_unix ?? 0);
    return day
        ? t('pub.people.state.added').replace('{date}', day)
        : t('pub.people.state.has_file');
}

const H2: React.CSSProperties = {
    fontFamily: 'var(--font-display)',
    fontSize: 22,
    fontWeight: 500,
    lineHeight: 1.15,
    letterSpacing: '-0.01em',
    margin: '4px 0',
    color: 'var(--fg)',
};
