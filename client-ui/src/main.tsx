import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { ContractProvider } from './contract/ContractProvider';
import { DevPicker } from './harness/DevPicker';
import { isHarnessActive, scenarioFromUrl } from './harness/scenarios';
import { DensityProvider } from './design/DensityProvider';
import { secureScreenClearAtStart } from './publisher/useSecureScreen';
import './design/tokens.css';
import './styles.css';

// Theme bootstrap. The design DNA assumes dark theme; tokens have a
// `prefers-color-scheme: light` override that we only want to honor
// when the user explicitly chose "system" *and* the OS is light.
// Default is dark to match the design.
function bootstrapTheme() {
    try {
        const saved = localStorage.getItem('daal.theme_pref'); // 'system'|'dark'|'light'
        let resolved: 'dark' | 'light' = 'dark';
        if (saved === 'light') {
            resolved = 'light';
        } else if (saved === 'system') {
            const mq = window.matchMedia?.('(prefers-color-scheme: light)');
            resolved = mq?.matches ? 'light' : 'dark';
        }
        document.documentElement.setAttribute('data-theme', resolved);
    } catch {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
}
bootstrapTheme();
// PB-20: a page that reloads in the same window starts with the
// screenshot block off; screens showing the recovery words turn it on.
secureScreenClearAtStart();

function render() {
    const rootEl = document.getElementById('root');
    if (!rootEl) throw new Error('root element missing');
    createRoot(rootEl).render(
        <React.StrictMode>
            <ContractProvider>
                <DensityProvider>
                    <App />
                    <DevPicker />
                </DensityProvider>
            </ContractProvider>
        </React.StrictMode>,
    );
}

// Browser harness only: on ?harness=<id> for a scenario with a `fake`
// block, a pretend Tauri shell answers the publisher/recipient commands
// (harness/publisherFake.ts) before the first render. Without ?harness=
// the fake is never loaded (its own chunk) and the app renders exactly
// as before; inside the real app it also refuses to shadow the shell.
// A plain scenario that needs taps (a sheet, a fold) is walked by the
// same driver once the page has drawn.
if (isHarnessActive()) {
    import('./harness/driver')
        .then((d) => d.prepareScenario(scenarioFromUrl()))
        .catch(() => undefined)
        .then(() => import('./harness/publisherFake'))
        .then((m) => m.installPublisherFake())
        .catch(() => false)
        .finally(() => {
            render();
            void import('./harness/driver')
                .then((d) => d.runPlainDrive(scenarioFromUrl()))
                .catch(() => undefined);
        });
} else {
    render();
}
