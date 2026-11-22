// PeopleSection — who has access, and each person's own file.
//
// One row per person (spec C7.2 §4): their initial, their name, one
// badge, ONE send button and a ⋯. The four ways a file can leave the
// phone (an app, a QR code, text, a saved file) are in the send sheet
// the button and the row open, not five buttons on every row (H-14).
// "Give a new file" and "Remove access" are in the person's ⋯.
//
// One primary action for the section: "Add". It is gold only while
// nobody is on the list; after that the send buttons carry the weight.

import type { ArtifactInfo, RecipientSummary } from './wizardCommands';
import {
    Avatar,
    Badge,
    Button,
    Card,
    Disclosure,
    Icon,
    IconButton,
    ListRow,
    OverflowMenu,
} from '../design/primitives';
import type { MenuItem } from '../design/primitives';
import type { ActionState } from './useAction';
import { num, useLocale } from './ui';

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

/** Where a person stands: what their one badge says, and what a tap on
 *  their row does. */
export type PersonState = 'ready' | 'no_file' | 'waiting' | 'removed';

export function personStateOf(p: PersonRow, waiting = false): PersonState {
    if (p.revoked) return 'removed';
    if (waiting) return 'waiting';
    if (!p.file?.exists) return 'no_file';
    return 'ready';
}

const STATE_BADGE: Record<PersonState, { tone: 'good' | 'warn' | 'neutral'; key: string }> = {
    ready: { tone: 'good', key: 'pub.people.badge.ready' },
    no_file: { tone: 'warn', key: 'pub.people.badge.no_file' },
    waiting: { tone: 'warn', key: 'pub.people.badge.needs_answer' },
    removed: { tone: 'neutral', key: 'pub.people.badge.removed' },
};

/** The one line about a person, for screen readers and older callers. */
export function personState(t: (k: string) => string, p: PersonRow, waiting = false): string {
    const s = personStateOf(p, waiting);
    if (s === 'removed') return t('pub.people.state.removed');
    if (s === 'waiting') return t('pub.people.state.needs_answer');
    if (s === 'no_file') return t('pub.people.state.no_file');
    return t('pub.people.state.has_file');
}

interface Props {
    t: (k: string) => string;
    action: ActionState;
    loading: boolean;
    people: PersonRow[];
    onAdd: () => void;
    /** Open the send sheet for this person (their row, their button). */
    onSend: (p: PersonRow) => void;
    /** Their file is missing on this device: make it again. */
    onRemake: (r: RecipientSummary) => void;
    /** Give them a new file and cancel the old one. */
    onReplace: (r: RecipientSummary) => void;
    onRemoveAccess: (r: RecipientSummary) => void;
    onRemoveFromList: (r: RecipientSummary) => void;
    /** PB-1: people waiting for an answer after a restore. Their row
     *  says so and offers nothing: the question card is where they are
     *  settled, and a tap on the row goes there. */
    waiting?: ReadonlySet<number>;
    onWaitingTap?: () => void;
    /** PB-2: relay user names the relay lets in that this phone's list
     *  has no row for (added on the other phone after the backup). */
    relayOnly?: string[];
    onRemoveRelayOnly?: (relayUser: string) => void;
    /** The file for everyone, when this relay has one: one more row. */
    everyone?: { onSend: () => void; onAbout: () => void } | null;
}

export function PeopleSection({
    t,
    action,
    loading,
    people,
    onAdd,
    onSend,
    onRemake,
    onReplace,
    onRemoveAccess,
    onRemoveFromList,
    waiting,
    onWaitingTap,
    relayOnly = [],
    onRemoveRelayOnly,
    everyone,
}: Props) {
    const locale = useLocale();
    const busy = action.busy !== null;
    const isWaiting = (p: PersonRow) => !p.revoked && p.recipient != null && (waiting?.has(p.recipient.id) ?? false);
    const current = people.filter((p) => !p.revoked);
    const removed = people.filter((p) => p.revoked);
    const nobody = current.length === 0 && relayOnly.length === 0;
    const rows = current.length + relayOnly.length + (everyone ? 1 : 0);
    let n = 0;
    const isLast = () => ++n === rows;

    const personRow = (p: PersonRow) => {
        const state = personStateOf(p, isWaiting(p));
        const r = p.recipient;
        const b = STATE_BADGE[state];
        const fill = (k: string) => t(k).replace(/\{name\}/g, p.label);
        const tap =
            state === 'ready'
                ? () => onSend(p)
                : state === 'no_file' && r
                  ? () => onRemake(r)
                  : state === 'waiting'
                    ? onWaitingTap
                    : undefined;
        const items: MenuItem[] = [];
        if (r && state !== 'waiting') {
            items.push({
                id: 'replace',
                label: t('pub.people.replace'),
                icon: 'refresh',
                hint: t('pub.people.replace.hint'),
                disabled: busy,
                onSelect: () => onReplace(r),
            });
            items.push({
                id: 'remove',
                label: t('pub.people.remove_access'),
                icon: 'trash',
                tone: 'danger',
                disabled: busy,
                onSelect: () => onRemoveAccess(r),
            });
        }
        const trailing = (
            <>
                {state === 'ready' && (
                    <IconButton
                        label={fill('pub.people.send_to')}
                        dataButton="person-send"
                        disabled={busy}
                        onClick={() => onSend(p)}
                        style={{ color: 'var(--gold-warm)' }}
                    >
                        <Icon name="share" size={20} />
                    </IconButton>
                )}
                {state === 'no_file' && r && (
                    <IconButton
                        label={t('pub.people.remake')}
                        dataButton="person-remake"
                        disabled={busy}
                        onClick={() => onRemake(r)}
                        style={{ color: 'var(--gold-warm)' }}
                    >
                        <Icon name="refresh" size={20} />
                    </IconButton>
                )}
                <OverflowMenu label={t('ui.more')} title={p.label} items={items} dataButton="person-more" />
            </>
        );
        return (
            <div key={p.key} data-person={p.label} data-person-state={state}>
                <ListRow
                    leading={<Avatar name={p.label} />}
                    title={p.label}
                    badge={
                        <Badge tone={b.tone} size="sm">
                            {t(b.key)}
                        </Badge>
                    }
                    trailing={trailing}
                    stack={false}
                    onClick={busy ? undefined : tap}
                    last={isLast()}
                />
            </div>
        );
    };

    return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8 }} data-testid="people">
            <header
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 12,
                    minHeight: 44,
                }}
            >
                <h2 style={H2}>{t('pub.people.title')}</h2>
                <Button
                    variant={nobody ? 'primary' : 'secondary'}
                    size="compact"
                    leading="plus"
                    onClick={onAdd}
                    aria-label={t('pub.people.add')}
                    dataButton="add-person"
                >
                    {t('pub.people.add_short')}
                </Button>
            </header>

            {nobody && !everyone && !loading && <div style={SUB}>{t('pub.people.empty')}</div>}

            {rows > 0 && (
                <Card>
                    {current.map(personRow)}
                    {/* PB-2: someone the relay lets in that this phone has
                        no name for. The relay's name is the only handle. */}
                    {relayOnly.length > 0 && (
                        <div data-testid="relay-only">
                            {relayOnly.map((u) => (
                                <div key={u} data-relay-user={u}>
                                    <ListRow
                                        leading={<Avatar name="?" />}
                                        title={t('pub.people.unknown')}
                                        subtitle={
                                            <span dir="ltr" style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                                                {u}
                                            </span>
                                        }
                                        stack={false}
                                        trailing={
                                            onRemoveRelayOnly ? (
                                                <OverflowMenu
                                                    label={t('ui.more')}
                                                    title={t('pub.people.unknown')}
                                                    dataButton={`relay-only-more-${u}`}
                                                    items={[
                                                        {
                                                            id: `relay-only-remove-${u}`,
                                                            label: t('pub.people.remove_access'),
                                                            icon: 'trash',
                                                            tone: 'danger',
                                                            disabled: busy,
                                                            onSelect: () => onRemoveRelayOnly(u),
                                                        },
                                                    ]}
                                                />
                                            ) : undefined
                                        }
                                        last={isLast()}
                                    />
                                </div>
                            ))}
                        </div>
                    )}
                    {everyone && (
                        <div data-testid="everyone-row">
                            <ListRow
                                leading={
                                    <span
                                        aria-hidden
                                        style={{
                                            width: 36,
                                            height: 36,
                                            borderRadius: '50%',
                                            background: 'var(--surface-3)',
                                            color: 'var(--fg)',
                                            display: 'inline-flex',
                                            alignItems: 'center',
                                            justifyContent: 'center',
                                        }}
                                    >
                                        <Icon name="people" size={20} />
                                    </span>
                                }
                                title={t('pub.everyone.row')}
                                // The kind of file, as its one quiet line: a
                                // badge here squeezes "Everyone" in two.
                                subtitle={t('pub.everyone.badge')}
                                stack={false}
                                onClick={busy ? undefined : everyone.onSend}
                                trailing={
                                    <>
                                        <IconButton
                                            label={t('pub.send.title.everyone')}
                                            dataButton="everyone-send"
                                            disabled={busy}
                                            onClick={everyone.onSend}
                                            style={{ color: 'var(--gold-warm)' }}
                                        >
                                            <Icon name="share" size={20} />
                                        </IconButton>
                                        <OverflowMenu
                                            label={t('ui.more')}
                                            title={t('pub.everyone.row')}
                                            dataButton="everyone-more"
                                            items={[
                                                {
                                                    id: 'everyone',
                                                    label: t('pub.more.everyone_about'),
                                                    icon: 'info',
                                                    onSelect: everyone.onAbout,
                                                },
                                            ]}
                                        />
                                    </>
                                }
                                last={isLast()}
                            />
                        </div>
                    )}
                </Card>
            )}

            {/* People whose access is gone are history, not something to
                do: folded, at the end (H-17). */}
            {removed.length > 0 && (
                <Disclosure
                    summary={t('pub.people.removed').replace('{n}', num(locale, removed.length))}
                    dataButton="people-removed"
                >
                    <Card>
                        {removed.map((p, i) => (
                            <ListRow
                                key={p.key}
                                leading={<Avatar name={p.label} />}
                                title={p.label}
                                subtitle={t('pub.people.state.removed')}
                                stack={false}
                                trailing={
                                    p.recipient ? (
                                        <OverflowMenu
                                            label={t('ui.more')}
                                            title={p.label}
                                            dataButton="person-more"
                                            items={[
                                                {
                                                    id: 'remove-from-list',
                                                    label: t('pub.people.remove_from_list'),
                                                    icon: 'trash',
                                                    disabled: busy,
                                                    onSelect: () => onRemoveFromList(p.recipient!),
                                                },
                                            ]}
                                        />
                                    ) : undefined
                                }
                                last={i === removed.length - 1}
                            />
                        ))}
                    </Card>
                </Disclosure>
            )}
        </section>
    );
}

const SUB: React.CSSProperties = { fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 };

const H2: React.CSSProperties = {
    fontFamily: 'var(--font-display)',
    fontSize: 20,
    fontWeight: 500,
    lineHeight: 1.2,
    margin: 0,
    color: 'var(--fg)',
};
