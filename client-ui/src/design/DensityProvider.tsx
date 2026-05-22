// DensityProvider.tsx — single source of truth for which shell is
// rendered and how dense the screens are packed.
//
// Breakpoints (web responsive defaults):
//   width ≤ 640px               → phone   (MobileShell)
//   641px ≤ width ≤ 1023px      → tablet  (TabletShell)
//   width ≥ 1024px              → desktop (DesktopShell)
//
// We listen for matchMedia changes so the swap is instant when the
// user resizes the browser. The HTML element gets a data-density
// attribute so tokens.css can fork gutter/sizing without a re-render.
//
// `?density=phone|tablet|desktop` URL override is honored for the
// screenshot harness so we can capture all three densities from one
// dev server.

import {
    createContext,
    useContext,
    useEffect,
    useMemo,
    useState,
    type ReactNode,
} from 'react';

export type Density = 'phone' | 'tablet' | 'desktop';

export interface DensityState {
    density: Density;
    isCoarse: boolean;
    isRTL: boolean;
}

const DensityContext = createContext<DensityState | null>(null);

function readOverride(): Density | null {
    if (typeof window === 'undefined') return null;
    try {
        const v = new URLSearchParams(window.location.search).get('density');
        if (v === 'phone' || v === 'tablet' || v === 'desktop') return v;
    } catch {
        /* ignore */
    }
    return null;
}

function detect(): Density {
    if (typeof window === 'undefined') return 'desktop';
    const w = window.innerWidth;
    if (w <= 640) return 'phone';
    if (w <= 1023) return 'tablet';
    return 'desktop';
}

export function DensityProvider({ children }: { children: ReactNode }) {
    const override = useMemo(() => readOverride(), []);
    const [density, setDensity] = useState<Density>(() => override ?? detect());
    const [isCoarse, setIsCoarse] = useState<boolean>(() =>
        typeof window === 'undefined'
            ? false
            : window.matchMedia('(pointer: coarse)').matches,
    );
    const [isRTL, setIsRTL] = useState<boolean>(() =>
        typeof document === 'undefined'
            ? false
            : document.documentElement.getAttribute('dir') === 'rtl',
    );

    useEffect(() => {
        if (override) return; // pinned by URL flag
        const onResize = () => setDensity(detect());
        window.addEventListener('resize', onResize);
        return () => window.removeEventListener('resize', onResize);
    }, [override]);

    useEffect(() => {
        const mq = window.matchMedia('(pointer: coarse)');
        const on = () => setIsCoarse(mq.matches);
        mq.addEventListener?.('change', on);
        return () => mq.removeEventListener?.('change', on);
    }, []);

    useEffect(() => {
        const obs = new MutationObserver(() => {
            setIsRTL(document.documentElement.getAttribute('dir') === 'rtl');
        });
        obs.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['dir'],
        });
        return () => obs.disconnect();
    }, []);

    useEffect(() => {
        document.documentElement.setAttribute('data-density', density);
    }, [density]);

    const value = useMemo<DensityState>(
        () => ({ density, isCoarse, isRTL }),
        [density, isCoarse, isRTL],
    );

    return (
        <DensityContext.Provider value={value}>
            {children}
        </DensityContext.Provider>
    );
}

export function useDensity(): DensityState {
    const v = useContext(DensityContext);
    if (!v)
        throw new Error(
            'useDensity must be called inside <DensityProvider>.',
        );
    return v;
}
