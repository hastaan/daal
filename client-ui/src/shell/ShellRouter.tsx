// ShellRouter.tsx — picks the active shell based on density.
//
// Phase 1 wires the router with placeholder shells so we can verify
// hot-swap on browser resize. Phases 3 & 5 replace the bodies with
// real shells; this file does not need further changes.

import { useDensity } from '../design/DensityProvider';
import type { Locale } from '../lib/i18n';
import MobileShell from './MobileShell';
import TabletShell from './TabletShell';
import DesktopShell from './DesktopShell';

interface Props {
    locale: Locale;
    onLocaleChange: (l: Locale) => void;
    engineHealthy: boolean;
    appVersion: string;
    t: (k: string) => string;
}

export default function ShellRouter(props: Props) {
    const { density } = useDensity();
    if (density === 'phone') return <MobileShell {...props} />;
    if (density === 'tablet') return <TabletShell {...props} />;
    return <DesktopShell {...props} />;
}
