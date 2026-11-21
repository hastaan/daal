// harnessStart — where a browser-harness scenario opens.
//
// The plain scenarios (no fake shell to drive) name their screen
// (`screen: 'settings'`, `'status'`, `'network'`) but nothing opened it,
// so `settings-default` and every `status-*` capture showed Home. The
// shells read this once at mount. Outside the harness it is null and
// changes nothing.

import { scenarioFromUrl } from '../harness/scenarios';
import type { SettingsSubPage } from '../d2pages/SettingsPage';

export interface ShellStart {
    section: 'connection' | 'network' | 'settings';
    settingsPage: SettingsSubPage;
    /** Open the erase confirm (scenario `panic-wipe-confirm`). */
    erase: boolean;
}

export function harnessStart(): ShellStart | null {
    const s = scenarioFromUrl();
    // A scenario with a fake shell opens its screen by tapping (driver.ts).
    if (!s || s.fake) return null;
    if (s.id === 'panic-wipe-confirm') return { section: 'settings', settingsPage: 'main', erase: true };
    // "Publisher · off": the switch that turns it on, in Settings.
    if (s.id === 'publisher-off') return { section: 'settings', settingsPage: 'main', erase: false };
    switch (s.screen) {
        case 'status':
            return { section: 'settings', settingsPage: 'status', erase: false };
        case 'settings':
            return {
                section: 'settings',
                // The engine-internals scenarios show the Advanced page (its
                // developer card needs ?dev=1 in the URL).
                settingsPage: s.id.startsWith('settings-advanced') || s.id === 'settings-wasm-loaded' ? 'advanced' : 'main',
                erase: false,
            };
        case 'network':
            return { section: 'network', settingsPage: 'main', erase: false };
        default:
            return null;
    }
}
