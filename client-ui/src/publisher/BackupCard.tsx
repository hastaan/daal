// BackupCard — on the relay list (and on a relay page after a change):
// has a backup been made, and is it still current? (D1)

import { Button, Card } from '../design/primitives';
import type { BackupStatus } from './wizardCommands';
import { backupCard, backupCardButtonKey, backupCardKey, dayLabel, fill } from './backup';

export function BackupCard({
    t,
    status,
    onBackup,
    onlyWhenStale,
}: {
    t: (k: string) => string;
    status: BackupStatus | null;
    onBackup?: () => void;
    /** The relay page shows the card only when the backup is out of date. */
    onlyWhenStale?: boolean;
}) {
    const c = backupCard(status);
    if (c === 'hidden' || !status) return null;
    if (onlyWhenStale && c !== 'stale') return null;
    const button = backupCardButtonKey(c);
    return (
        <Card>
            <div
                data-testid="backup-card"
                data-card={c}
                style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
            >
                <div
                    style={{
                        flex: 1,
                        minWidth: 180,
                        fontSize: 13,
                        lineHeight: 1.55,
                        color: c === 'last' ? 'var(--muted)' : 'var(--fg)',
                    }}
                >
                    {fill(t(backupCardKey(c)), { date: dayLabel(status.last_backup_at_unix) })}
                </div>
                {button && onBackup && (
                    <Button size="sm" onClick={onBackup} data-button="backup">
                        {t(button)}
                    </Button>
                )}
                {!button && onBackup && (
                    <Button size="sm" variant="ghost" onClick={onBackup} data-button="backup">
                        {t('pub.backup.card.open')}
                    </Button>
                )}
            </div>
        </Card>
    );
}
