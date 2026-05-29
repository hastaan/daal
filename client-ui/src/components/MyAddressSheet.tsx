// MyAddressSheet.tsx — wraps the existing MyAddress flow in a Sheet
// so it can be reached from a dedicated header action on the Network
// page (separate from "Add", per D-2 redesign).

import MyAddress from '../recipient/MyAddress';
import { Sheet, Button } from '../design/primitives';

interface Props {
    t: (k: string) => string;
    onClose: () => void;
}

export default function MyAddressSheet({ t, onClose }: Props) {
    return (
        <Sheet
            title={t('recipient.address.title')}
            onClose={onClose}
            width={520}
            footer={<Button onClick={onClose}>{t('common.continue')}</Button>}
        >
            <MyAddress t={t} />
        </Sheet>
    );
}
