import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { ContractProvider } from './contract/ContractProvider';
import { DevPicker } from './harness/DevPicker';
import { DensityProvider } from './design/DensityProvider';
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
