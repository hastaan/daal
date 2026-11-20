// BackupBadge — on the relay list header: has a backup been made, and is
// it still current? (D1, spec C7.1). One badge instead of a three-line
// banner above the relays (H-01, H-42); nothing at all when the backup
// is current. A tap opens Backup.

import { Badge } from '../design/primitives';
import type { BackupStatus } from './wizardCommands';
import { backupCard } from './backup';

/** The badge's i18n key, or null when there is nothing to say. */
export function backupBadgeKey(status: BackupStatus | null): string | null {
    const c = backupCard(status);
    if (c === 'never') return 'pub.backup.badge.never';
    if (c === 'stale' || c === 'words') return 'pub.backup.badge.stale';
    return null;
}

export function BackupBadge({
    t,
    status,
    onBackup,
}: {
    t: (k: string) => string;
    status: BackupStatus | null;
    onBackup?: () => void;
}) {
    const key = backupBadgeKey(status);
    if (!key) return null;
    return (
        <span data-testid="backup-card" data-card={backupCard(status)} style={{ display: 'inline-flex', minWidth: 0 }}>
            <Badge tone="warn" onClick={onBackup} dataButton="backup" title={t(key)}>
                {t(key)}
            </Badge>
        </span>
    );
}
