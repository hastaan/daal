// OpenedFileToast — "A file is waiting to be added. [Open]": shown by
// every shell when a file is handed to Daal while the person is busy on
// Publisher or Settings (shell/useShellNav.ts). It stays until opened or
// closed; nothing in progress is taken away.

import { Button, Toast } from '../design/primitives';

export default function OpenedFileToast({
    t,
    onOpen,
    onDismiss,
}: {
    t: (k: string) => string;
    onOpen: () => void;
    onDismiss: () => void;
}) {
    return (
        <Toast tone="neutral" autoHideMs={0} onDismiss={onDismiss}>
            <span data-opened-waiting style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span>{t('nav.file_waiting')}</span>
                <Button variant="link" onClick={onOpen} dataButton="opened-file-open">
                    {t('nav.file_waiting.open')}
                </Button>
            </span>
        </Toast>
    );
}
