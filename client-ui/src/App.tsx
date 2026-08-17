import { useEffect, useMemo, useState } from 'react';
import { applyDir, detectLocale, setLocalePref, translate, type Locale } from './lib/i18n';
import { useContract } from './contract/ContractProvider';
import { Prefs } from './lib/prefs';
import { isHarnessActive } from './harness/scenarios';
import { isTauriRuntime } from './backends';
import ShellRouter from './shell/ShellRouter';
import Onboarding from './onboarding/Onboarding';
import VaultUnlock from './components/VaultUnlock';

export default function App() {
    const contract = useContract();
    const [locale, setLocale] = useState<Locale>('en');
    const [engineHealthy, setEngineHealthy] = useState(true);
    const [engineVersion, setEngineVersion] = useState('');
    const [versionMismatch, setVersionMismatch] = useState(false);
    // The vault PIN gate is only relevant when a real engine is
    // present. In the harness or in a plain dev browser we treat
    // it as unlocked so the GUI stays interactive.
    const engineLive = isTauriRuntime() && !isHarnessActive();
    const [vaultUnlocked, setVaultUnlocked] = useState<boolean>(!engineLive);
    const [needsUnlock, setNeedsUnlock] = useState<boolean>(false);
    const [onboardingDone, setOnboardingDone] = useState<boolean>(() => {
        // Harness / plain-browser dev mode jumps straight to the shell
        // so screens are visible without going through onboarding —
        // EXCEPT when the scenario explicitly targets an onboarding step.
        if (isHarnessActive()) {
            try {
                const params = new URLSearchParams(window.location.search);
                const scenario = params.get('harness') ?? '';
                if (scenario.startsWith('onboarding-')) return false;
            } catch { /* ignore */ }
            return true;
        }
        if (!isTauriRuntime()) return true;
        return Prefs.onboardingCompleted();
    });

    useEffect(() => {
        const detected = detectLocale();
        setLocale(detected);
        applyDir(detected);
    }, []);

    useEffect(() => {
        if (!engineLive) return; // harness or plain-browser dev: skip
        let cancelled = false;
        contract.versionInfo()
            .then((v) => {
                if (cancelled) return;
                setEngineVersion(v.engineVersion);
                // Keep this prefix in lockstep with REQUIRED_VERSION_PREFIX
                // in client-shell/tauri/daal-desktop-core/src/engine.rs and
                // the engine_version pin in core/abi/abi.go.
                if (!v.engineVersion.startsWith('daal-core 0.9')) {
                    setVersionMismatch(true);
                }
            })
            .catch(() => setVersionMismatch(true));
        return () => {
            cancelled = true;
        };
    }, [contract, engineLive]);

    useEffect(() => {
        if (!engineLive) return;
        const id = setInterval(async () => {
            try {
                const ok = await contract.heartbeatTick();
                setEngineHealthy(ok);
            } catch {
                setEngineHealthy(false);
            }
        }, 2000);
        return () => clearInterval(id);
    }, [contract, engineLive]);

    // Probe unlock state on first boot — try with an empty PIN which
    // returns 'not_required' on non-high-risk devices; the high-risk
    // case returns 'wrong_pin' which is exactly the signal we need.
    useEffect(() => {
        if (!engineLive) return;
        let cancelled = false;
        contract.unlockSecrets('')
            .then((r) => {
                if (cancelled) return;
                if (r === 'not_required' || r === 'unlocked') {
                    setVaultUnlocked(true);
                } else {
                    setNeedsUnlock(true);
                }
            })
            .catch(() => {
                if (!cancelled) setVaultUnlocked(true);
            });
        return () => { cancelled = true; };
    }, [contract, engineLive]);

    // Lifecycle event emitter — wake/sleep + memory pressure hints.
    useEffect(() => {
        if (!engineLive) return;
        const onVisibility = () => {
            const token = document.hidden ? 'will_sleep' : 'did_wake';
            contract.lifecycleEvent(token).catch(() => {});
        };
        document.addEventListener('visibilitychange', onVisibility);
        return () => document.removeEventListener('visibilitychange', onVisibility);
    }, [contract, engineLive]);

    // Device Custody B6 — lock-on-background for session-passphrase
    // devices. We only attach the listener if custody is currently
    // session-passphrase (the only level where `lock()` is more
    // than a no-op). The OS-keystore and hardware paths re-fetch
    // the DWK per call, so a forced lock there gains nothing and
    // would spam the audit log.
    useEffect(() => {
        if (!engineLive) return;
        let cancelled = false;
        let cleanup: (() => void) | null = null;
        (async () => {
            try {
                const { DeviceCustody } = await import('./recipient/recipientCommands');
                const lvl = await DeviceCustody.level();
                if (cancelled || lvl !== 'session_passphrase') return;
                const onHide = () => {
                    if (!document.hidden) return;
                    DeviceCustody.lock().catch(() => { /* best-effort */ });
                };
                document.addEventListener('visibilitychange', onHide);
                cleanup = () => document.removeEventListener('visibilitychange', onHide);
            } catch {
                /* custody not available — harness or pre-init */
            }
        })();
        return () => {
            cancelled = true;
            if (cleanup) cleanup();
        };
    }, [engineLive]);

    // Network change emitter — basic browser online/offline as a
    // best-effort signal. Real Wi-Fi/cell discrimination requires a
    // platform-side observer (Tauri OS info plugin); deferred.
    useEffect(() => {
        if (!engineLive) return;
        const fire = (kind: string) => () =>
            contract.networkChanged(kind, '', '').catch(() => {});
        const on = fire('unknown');
        const off = fire('unknown');
        window.addEventListener('online', on);
        window.addEventListener('offline', off);
        return () => {
            window.removeEventListener('online', on);
            window.removeEventListener('offline', off);
        };
    }, [contract, engineLive]);

    const t = useMemo(() => (k: string) => translate(locale, k), [locale]);

    const handleLocaleChange = (next: Locale) => {
        setLocale(next);
        applyDir(next);
        // Persist the choice; effectiveLocale() reads it back on the
        // next launch. Without this the selection is lost on restart.
        setLocalePref(next);
    };

    if (versionMismatch) {
        // Engine version mismatch is a full-screen blocker per the
        // brief's hard-state inventory.
        return (
            <div
                style={{
                    height: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'var(--bg)',
                    color: 'var(--paper)',
                    padding: 32,
                    textAlign: 'center',
                }}
            >
                <div>
                    <div
                        style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 11,
                            letterSpacing: '0.2em',
                            textTransform: 'uppercase',
                            color: 'var(--danger)',
                            marginBottom: 14,
                        }}
                    >
                        {t('common.error')}
                    </div>
                    <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 32 }}>
                        {t('engine.mismatch')}
                    </h1>
                    <p style={{ color: 'var(--paper-dim)' }}>
                        {engineVersion || '?'}
                    </p>
                </div>
            </div>
        );
    }

    if (needsUnlock && !vaultUnlocked) {
        return (
            <VaultUnlock
                t={t}
                onUnlocked={() => {
                    setVaultUnlocked(true);
                    setNeedsUnlock(false);
                }}
            />
        );
    }

    if (!onboardingDone) {
        return (
            <Onboarding
                locale={locale}
                onLocaleChange={handleLocaleChange}
                onComplete={() => {
                    Prefs.setOnboardingCompleted(true);
                    setOnboardingDone(true);
                }}
                t={t}
            />
        );
    }

    return (
        <ShellRouter
            locale={locale}
            onLocaleChange={handleLocaleChange}
            engineHealthy={engineHealthy}
            appVersion={APP_VERSION}
            t={t}
        />
    );
}

// Injected by Vite at build time from the repo-root VERSION file
// (see vite.config.ts `define: { __APP_VERSION__ }`).
declare const __APP_VERSION__: string;
const APP_VERSION = __APP_VERSION__;
