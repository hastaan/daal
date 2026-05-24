// Sheet — density-aware container. On phone it renders a BottomSheet
// and on tablet/desktop a centered Modal. Use this everywhere a modal
// is wanted; the layout will follow the form factor automatically.

import type { ReactNode } from 'react';
import { useDensity } from '../DensityProvider';
import { BottomSheet } from './BottomSheet';
import { Modal } from './Modal';

interface Props {
    title?: ReactNode;
    children: ReactNode;
    onClose: () => void;
    footer?: ReactNode;
    /** Desktop-only override; ignored on phone. */
    width?: number;
}

export function Sheet({ title, children, onClose, footer, width }: Props) {
    const { density } = useDensity();
    if (density === 'phone') {
        return (
            <BottomSheet title={title} onClose={onClose} footer={footer}>
                {children}
            </BottomSheet>
        );
    }
    return (
        <Modal title={title} onClose={onClose} footer={footer} width={width}>
            {children}
        </Modal>
    );
}
