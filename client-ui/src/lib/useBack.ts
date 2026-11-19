// useBack — register a Back handler with the app's one back stack
// (lib/backStack.ts) while `active`.
//
// The handler is kept in a ref, so a new closure on every render neither
// re-registers nor moves this entry in the stack. A handler that does
// nothing refuses Back (its entry stays on top).

import { useEffect, useRef } from 'react';
import { appBackStack } from './backStack';
import type { BackLayer } from './backStack';

export function useBack(active: boolean, onBack: () => void, layer: BackLayer = 'sheet'): void {
    const ref = useRef(onBack);
    ref.current = onBack;
    useEffect(() => {
        if (!active) return;
        const stack = appBackStack();
        if (!stack) return;
        return stack.register(layer, () => ref.current());
    }, [active, layer]);
}
