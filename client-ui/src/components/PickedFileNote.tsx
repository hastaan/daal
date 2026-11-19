// PickedFileNote — the one line under "Choose the file you were sent"
// once a file is chosen.
//
// For a sealed file this used to print two sentences at once: "enter
// the PIN you created with your Daal address" and "It will open
// automatically using your device's key" (backlog PH-27; no PIN was
// ever asked for). Which one is true is known: a sealed file is opened
// with this phone's own key, held by device custody
// (recipient/recipientCommands.ts DeviceCustody). On a phone whose
// custody is unlocked — every phone with a hardware or OS keystore,
// from boot — it opens by itself. Only where custody is a passphrase
// the person has not entered this session is something needed first.
// So exactly one sentence is shown, chosen by what `isUnlocked` said:
//
//   'ready'    opens by itself with this phone's key
//   'locked'   Daal is locked: unlock first
//   'unknown'  custody could not be asked — say only that it is sealed,
//              and promise nothing either way
export type SealedCustody = 'ready' | 'locked' | 'unknown';

/** From `DeviceCustody.isUnlocked()`: its answer, or `undefined` when
 *  the call failed. */
export function sealedCustody(isUnlocked: boolean | undefined): SealedCustody {
    if (isUnlocked === true) return 'ready';
    if (isUnlocked === false) return 'locked';
    return 'unknown';
}

/** i18n key of the single line for a chosen file. */
export function pickedFileNoteKey(sealed: boolean, custody: SealedCustody): string {
    if (!sealed) return 'add.file.picked';
    if (custody === 'ready') return 'add.file.sealed_auto';
    if (custody === 'locked') return 'add.file.sealed_locked';
    return 'add.file.sealed';
}

export default function PickedFileNote({
    t,
    sealed,
    custody,
}: {
    t: (k: string) => string;
    sealed: boolean;
    custody: SealedCustody;
}) {
    return (
        <div style={{ fontSize: 12, color: 'var(--paper-dim)' }}>
            {t(pickedFileNoteKey(sealed, custody))}
        </div>
    );
}
