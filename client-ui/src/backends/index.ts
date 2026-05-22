// backends/index.ts — picks the active D2Contract implementation at
// boot. Decision tree:
//
//   ?harness=<scenario-id>  → HarnessContract (explicit override)
//   running inside Tauri    → TauriContract  (real, invokes commands)
//   plain browser           → HarnessContract (dev shell, no engine)
//
// The plain-browser fall-back used to be impossible — invoke() simply
// threw and we treated the resulting empty version as an engine
// mismatch. v0.2.x flips this so opening http://localhost:1420 in a
// regular browser renders a friendly mocked UI instead of the
// "reinstall" error banner.

import type { D2Contract } from '../contract/D2Contract';
import { isHarnessActive } from '../harness/scenarios';
import { HarnessContract } from './harness';
import { TauriContract } from './tauri';

/** True when the runtime exposes the Tauri 2 invoke bridge. */
export function isTauriRuntime(): boolean {
    if (typeof window === 'undefined') return false;
    // Tauri 2 injects __TAURI_INTERNALS__ into every renderer process.
    return Boolean((window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);
}

function pickBackend(): D2Contract {
    if (isHarnessActive()) return new HarnessContract();
    if (isTauriRuntime()) return new TauriContract();
    return new HarnessContract();
}

export const activeContract: D2Contract = pickBackend();

export { isHarnessActive };
