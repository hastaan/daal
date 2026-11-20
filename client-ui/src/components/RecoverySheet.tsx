// RecoverySheet.tsx — "Try something else" after a connect that did not
// work (spec C2). A MenuSheet: Daal choosing is the first and gold
// choice; then the person's files, a new file, Lifeline, and a report
// for whoever helps them. "Try another route" and "Refresh sources" did
// the same thing (open the files) and are one item now.

import { MenuSheet } from '../design/primitives';
import type { MenuItem } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    /** Let Daal choose: back to automatic, and connect. */
    onAuto: () => void;
    /** Open the Files page. */
    onFiles: () => void;
    /** Open the add sheet. */
    onAdd: () => void;
    onLifeline: () => void;
    /** Copy the diagnostics report. */
    onExportDiag: () => void;
}

export default function RecoverySheet({ t, onClose, onAuto, onFiles, onAdd, onLifeline, onExportDiag }: Props) {
    const items: MenuItem[] = [
        { id: 'auto', label: t('auto.let_daal_choose'), icon: 'refresh', onSelect: onAuto },
        { id: 'files', label: t('conn.recovery.files'), icon: 'files', onSelect: onFiles },
        { id: 'add', label: t('conn.recovery.add'), icon: 'plus', onSelect: onAdd },
        { id: 'lifeline', label: t('conn.recovery.lifeline'), icon: 'shield', onSelect: onLifeline },
        { id: 'report', label: t('conn.recovery.report'), icon: 'copy', onSelect: onExportDiag },
    ];
    return <MenuSheet title={t('conn.recovery.title')} items={items} primaryId="auto" onClose={onClose} />;
}
