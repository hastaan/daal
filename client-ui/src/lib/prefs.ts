// prefs.ts — platform-side preferences for D-2 onboarding & UI flags.
//
// We deliberately keep these out of the engine (per onboarding-spec
// §Persistence). For now the dev shell uses localStorage; a future
// Tauri command surface (`set_pref` / `get_pref`) can be wired in
// without changing call sites.

const NS = 'daal.d2.';

export type Lane = 'recipient' | 'publisher' | 'unsure';

export const Prefs = {
    onboardingCompleted(): boolean {
        return localStorage.getItem(NS + 'onboarding.completed') === '1';
    },
    setOnboardingCompleted(v: boolean): void {
        localStorage.setItem(NS + 'onboarding.completed', v ? '1' : '0');
    },
    lane(): Lane | null {
        const v = localStorage.getItem(NS + 'onboarding.lane');
        return (v === 'recipient' || v === 'publisher' || v === 'unsure') ? v : null;
    },
    setLane(v: Lane): void {
        localStorage.setItem(NS + 'onboarding.lane', v);
    },
    publisherEnabled(): boolean {
        return localStorage.getItem(NS + 'publisher.enabled') === '1';
    },
    setPublisherEnabled(v: boolean): void {
        localStorage.setItem(NS + 'publisher.enabled', v ? '1' : '0');
    },
    deepLinkBuffer(): string | null {
        return localStorage.getItem(NS + 'deeplink.buffer');
    },
    setDeepLinkBuffer(url: string | null): void {
        if (url == null) localStorage.removeItem(NS + 'deeplink.buffer');
        else localStorage.setItem(NS + 'deeplink.buffer', url);
    },
    theme(): 'system' | 'light' | 'dark' {
        const v = localStorage.getItem(NS + 'theme');
        return (v === 'light' || v === 'dark') ? v : 'system';
    },
    setTheme(v: 'system' | 'light' | 'dark'): void {
        localStorage.setItem(NS + 'theme', v);
    },
    closeToTrayExplained(): boolean {
        return localStorage.getItem(NS + 'tray.first_close_explained') === '1';
    },
    setCloseToTrayExplained(v: boolean): void {
        localStorage.setItem(NS + 'tray.first_close_explained', v ? '1' : '0');
    },
};
