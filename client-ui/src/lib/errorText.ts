// Any rejected value, as text.
//
// A Tauri command that fails rejects with a plain STRING, not an Error.
// The pages used to read `(e as Error).message || 'unknown'`, which for
// a string is `undefined || 'unknown'`: the first phone pass showed a
// red banner holding the single word "unknown" while the real reason
// was thrown away one line earlier.
//
// What this returns is the RAW text — the host's own words ("engine call
// returned -1"). It belongs in a details area and in a diagnostics
// export. It is never the sentence the person reads: that is one of our
// own, translated, next to a Try again button.
export function errorText(e: unknown): string {
    if (typeof e === 'string') return e.trim() || 'empty error';
    if (e instanceof Error) {
        return e.message.trim() || e.name || 'error with no message';
    }
    if (e === null || e === undefined) return 'no error value';
    if (typeof e === 'object') {
        const o = e as Record<string, unknown>;
        for (const k of ['message', 'error', 'reason', 'code']) {
            const v = o[k];
            if (typeof v === 'string' && v.trim()) return v.trim();
            if (typeof v === 'number') return `${k} ${v}`;
        }
        try {
            const j = JSON.stringify(e);
            if (j && j !== '{}') return j;
        } catch {
            /* circular: fall through */
        }
        return 'error with no details';
    }
    return String(e);
}
