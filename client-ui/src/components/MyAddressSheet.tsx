// MyAddressSheet.tsx — "My Daal address" in a sheet (spec C4.4). The
// title is said once, by the sheet; there is no Continue: the address is
// made as it opens, and the drag handle, the backdrop, Escape and Back
// close it.

import MyAddress from '../recipient/MyAddress';
import { Sheet } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
}

export default function MyAddressSheet({ t, onClose }: Props) {
    return (
        <Sheet title={t('recipient.address.title')} onClose={onClose} width={480}>
            <MyAddress t={t} />
        </Sheet>
    );
}
