// ModeChip — current mode pill; click opens mode picker.
import type { ConnMode } from '../../contract/D2Contract';

interface Props {
    mode: ConnMode;
    t: (k: string) => string;
    onClick: () => void;
}

const MODE_LABEL_KEY: Record<ConnMode, string> = {
    'lifeline': 'mode_lifeline',
    'lifeline-strict': 'mode_lifeline_strict',
    'normal': 'mode_normal',
    'bulk': 'mode_bulk',
};

export default function ModeChip({ mode, t, onClick }: Props) {
    const label = t(MODE_LABEL_KEY[mode]) || `● ${mode}`;
    return (
        <button
            type="button"
            className={`d2-mode-chip ${mode}`}
            onClick={onClick}
        >
            {label}
        </button>
    );
}
