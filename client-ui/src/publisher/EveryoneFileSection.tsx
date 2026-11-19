// EveryoneFileSection — the one file that works for anybody.
//
// It used to be the first row of a list that also held every person's
// own file and an internal build artefact, under the title "Files to
// share". Nothing said which of those you would hand to whom. It is its
// own section now, with one line that says when to reach for it instead
// of a person's file.

import type { ArtifactInfo } from './wizardCommands';
import { Button, Card } from '../design/primitives';
import { ActionButton } from './useAction';
import type { ActionState } from './useAction';
import { WhatIsThis } from './Disclosure';

interface Props {
    t: (k: string) => string;
    action: ActionState;
    /** The everyone file, or null while the list has not loaded. */
    file: ArtifactInfo | null;
    onSend: () => void;
    onSave: () => void;
    onQr: () => void;
    onCopy: () => void;
    /** Opens the "make it" confirm. Making it cancels any copy already
     *  handed out, so it is never a one-tap action. */
    onMake: () => void;
    /** Opens the "replace it" confirm. */
    onReplace: () => void;
}

const SUB: React.CSSProperties = { fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 };
const H2: React.CSSProperties = {
    fontFamily: 'var(--font-display)',
    fontSize: 22,
    fontWeight: 500,
    lineHeight: 1.15,
    letterSpacing: '-0.01em',
    margin: '4px 0',
    color: 'var(--fg)',
};

function dayLabel(unix: number): string {
    if (!unix) return '';
    try {
        return new Date(unix * 1000).toISOString().slice(0, 10);
    } catch {
        return '';
    }
}

export function EveryoneFileSection({
    t,
    action,
    file,
    onSend,
    onSave,
    onQr,
    onCopy,
    onMake,
    onReplace,
}: Props) {
    const exists = file?.exists === true;
    const day = exists ? dayLabel(file!.modified_at_unix) : '';
    return (
        <section style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <h2 style={H2}>{t('pub.everyone.title')}</h2>
            <div style={SUB}>{t('pub.everyone.line')}</div>
            <Card>
                <div style={{ display: 'grid', gap: 8 }}>
                    {exists ? (
                        <>
                            {day && (
                                <div style={SUB}>
                                    {t('pub.everyone.made').replace('{date}', day)}
                                </div>
                            )}
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                <ActionButton
                                    action={action}
                                    k="everyone:send"
                                    busyLabel={t('pub.fb.opening')}
                                    size="sm"
                                    onClick={onSend}
                                >
                                    {t('pub.people.send')}
                                </ActionButton>
                                <ActionButton
                                    action={action}
                                    k="everyone:save"
                                    busyLabel={t('pub.fb.saving')}
                                    variant="secondary"
                                    size="sm"
                                    onClick={onSave}
                                >
                                    {t('pub.people.save')}
                                </ActionButton>
                                <Button
                                    variant="secondary"
                                    size="sm"
                                    disabled={action.busy !== null}
                                    onClick={onQr}
                                >
                                    {t('pub.everyone.qr')}
                                </Button>
                                <ActionButton
                                    action={action}
                                    k="everyone:copy"
                                    busyLabel={t('pub.artifacts.copying')}
                                    variant="secondary"
                                    size="sm"
                                    onClick={onCopy}
                                >
                                    {t('pub.everyone.copy')}
                                </ActionButton>
                            </div>
                        </>
                    ) : (
                        <>
                            <div style={SUB}>{t('pub.everyone.none')}</div>
                            <div>
                                <Button
                                    size="sm"
                                    disabled={action.busy !== null}
                                    onClick={onMake}
                                >
                                    {t('pub.everyone.make')}
                                </Button>
                            </div>
                        </>
                    )}
                    <WhatIsThis label={t('pub.what')}>
                        <div>{t('pub.everyone.what')}</div>
                        <div>{t('pub.everyone.what.ways')}</div>
                        {exists && (
                            <>
                                <div>{t('pub.everyone.replace.line')}</div>
                                <div>
                                    <Button
                                        variant="secondary"
                                        size="sm"
                                        disabled={action.busy !== null}
                                        onClick={onReplace}
                                    >
                                        {t('pub.everyone.replace')}
                                    </Button>
                                </div>
                            </>
                        )}
                    </WhatIsThis>
                </div>
            </Card>
        </section>
    );
}
