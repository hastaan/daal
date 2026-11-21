// ScanSheet.tsx — the scanner on its own: the add sheet opened on "Scan
// a code" (spec C3.4).
//
// Scanning used to be a second sheet with its own reading of the
// verdict; it is now one of the add sheet's three ways in, so a file
// that arrives over the camera gets exactly the same trust question and
// the same result screen as a pasted or chosen one (components/
// AddSheet.tsx, ImportResult.tsx). In particular a first-seen publisher
// — the normal case for an animated QR, which is offline distribution
// by construction — is never imported without the question, and a
// refusal is never shown as a silent success.

import AddSheet from './AddSheet';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
    /** Called once routes have actually committed. */
    onImported?: () => void;
    onConnect?: () => void;
}

export default function ScanSheet({ t, onClose, onImported, onConnect }: Props) {
    return <AddSheet t={t} initialStep="scan" onClose={onClose} onImported={onImported} onConnect={onConnect} />;
}
