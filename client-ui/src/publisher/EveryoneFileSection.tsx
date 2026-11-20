// EveryoneFileSheet — the one file that works for anybody (spec C7.4).
//
// It used to be a whole section of the relay page, a second answer to
// "how do I give my family access?" right under People, with its own
// four buttons (H-23). A non-technical publisher could not choose
// between the two. People is now the one path; this file is opened from
// the relay's ⋯ ("File for everyone…") or from its own row in People
// once it exists, and it says its cost (MUST KEEP 9) before anything.

import type { ArtifactInfo } from './wizardCommands';
import { Badge, Button, Disclosure, Sheet } from '../design/primitives';
import { formatDate } from '../lib/format';
import { ActionButton } from './useAction';
import type { ActionState } from './useAction';
import { useLocale } from './ui';

interface Props {
    t: (k: string) => string;
    action: ActionState;
    /** The everyone file, or null while the list has not loaded. */
    file: ArtifactInfo | null;
    /** Open the send sheet for the everyone file. */
    onSend: () => void;
    /** Opens the "make it" confirm. Making it cancels any copy already
     *  handed out, so it is never a one-tap action. */
    onMake: () => void;
    /** Opens the "replace it" confirm. */
    onReplace: () => void;
    onClose: () => void;
}

const SUB: React.CSSProperties = { fontSize: 13, color: 'var(--muted)', lineHeight: 1.55 };

export function EveryoneFileSheet({ t, action, file, onSend, onMake, onReplace, onClose }: Props) {
    const locale = useLocale();
    const exists = file?.exists === true;
    const busy = action.busy !== null;
    return (
        <Sheet title={t('pub.everyone.title')} width={480} onClose={onClose}>
            <div style={{ display: 'grid', gap: 14 }} data-testid="everyone-sheet">
                {/* MUST KEEP 9: one shared key; nobody can be cut off alone. */}
                <div style={{ fontSize: 14, lineHeight: 1.55, color: 'var(--fg)' }}>{t('pub.everyone.line')}</div>
                {exists ? (
                    <>
                        {file!.modified_at_unix > 0 && (
                            <div>
                                <Badge tone="neutral" icon="check">
                                    {t('pub.everyone.made').replace('{date}', formatDate(locale, file!.modified_at_unix))}
                                </Badge>
                            </div>
                        )}
                        <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
                            <Button leading="share" disabled={busy} onClick={onSend} dataButton="everyone-send">
                                {t('pub.everyone.send_open')}
                            </Button>
                            <Button variant="link" disabled={busy} onClick={onReplace} dataButton="everyone-replace">
                                {t('pub.everyone.replace')}
                            </Button>
                        </div>
                    </>
                ) : (
                    <div>
                        <ActionButton
                            action={action}
                            k="everyone:make"
                            busyLabel={t('pub.artifacts.building')}
                            onClick={onMake}
                            dataButton="everyone-make"
                        >
                            {t('pub.everyone.make')}
                        </ActionButton>
                    </div>
                )}
                <Disclosure summary={t('pub.what')} icon="help" dataButton="everyone-what">
                    <div style={{ display: 'grid', gap: 8 }}>
                        <div style={SUB}>{t('pub.everyone.what')}</div>
                        <div style={SUB}>{t('pub.everyone.what.ways')}</div>
                        {exists && <div style={SUB}>{t('pub.everyone.replace.line')}</div>}
                    </div>
                </Disclosure>
            </div>
        </Sheet>
    );
}
