// ModePickerSheet — the four connection modes as a MenuSheet (spec C10).
// The current one carries a check; choosing one calls setMode and the
// sheet closes (MenuSheet closes first, then runs the item).
import type { ConnMode } from '../../contract/D2Contract';
import { MenuSheet } from '../../design/primitives';
import type { MenuItem } from '../../design/primitives';

interface Props {
    t: (k: string) => string;
    current: ConnMode;
    onPick: (m: ConnMode) => void;
    onClose: () => void;
}

const ORDER: ConnMode[] = ['normal', 'lifeline', 'lifeline-strict', 'bulk'];

const LABEL_KEY: Record<ConnMode, string> = {
    'lifeline': 'mode_picker.lifeline',
    'lifeline-strict': 'mode_picker.lifeline_strict',
    'normal': 'mode_picker.normal',
    'bulk': 'mode_picker.bulk',
};

const DESC_KEY: Record<ConnMode, string> = {
    'lifeline': 'mode_picker_lifeline_desc',
    'lifeline-strict': 'mode_picker_lifeline_strict_desc',
    'normal': 'mode_picker_normal_desc',
    'bulk': 'mode_picker_bulk_desc',
};

export function modeItems(t: (k: string) => string, current: ConnMode, onPick: (m: ConnMode) => void): MenuItem[] {
    return ORDER.map((m) => ({
        id: `mode-${m}`,
        label: t(LABEL_KEY[m]),
        hint: t(DESC_KEY[m]),
        icon: m === current ? 'check' : 'dot',
        onSelect: () => onPick(m),
    }));
}

export default function ModePickerSheet({ t, current, onPick, onClose }: Props) {
    return (
        <MenuSheet
            title={t('mode_picker_title')}
            items={modeItems(t, current, onPick)}
            primaryId={`mode-${current}`}
            onClose={onClose}
        />
    );
}
