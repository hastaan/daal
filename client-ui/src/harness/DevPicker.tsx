// DevPicker.tsx — floating scenario chooser, visible only when the
// page is loaded with ?harness=… The picker jumps between any
// declared Scenario by setting the location to ?harness=<id>.
//
// Keep this UI ultra-minimal — it is a *developer* tool. It must not
// look pretty enough to be confused with the real app.

import { useState } from 'react';
import { SCENARIOS, isHarnessActive, activeScenario, type Scenario } from './scenarios';

export function DevPicker() {
    if (!isHarnessActive()) return null;
    const [open, setOpen] = useState(false);
    const current = activeScenario();

    const groups = groupByScreen(SCENARIOS);

    return (
        <div
            style={{
                position: 'fixed',
                right: 12,
                bottom: 12,
                zIndex: 9999,
                fontFamily: 'ui-sans-serif, system-ui, sans-serif',
                fontSize: 12,
                color: '#fff',
            }}
        >
            {open && (
                <div
                    style={{
                        marginBottom: 6,
                        background: 'rgba(10, 14, 22, 0.96)',
                        border: '1px solid rgba(255,255,255,0.12)',
                        borderRadius: 8,
                        padding: 10,
                        width: 280,
                        maxHeight: '70vh',
                        overflow: 'auto',
                        boxShadow: '0 10px 30px rgba(0,0,0,0.4)',
                    }}
                >
                    <div style={{ opacity: 0.6, marginBottom: 8 }}>
                        harness scenario · current: <strong>{current.id}</strong>
                    </div>
                    {Object.entries(groups).map(([screen, list]) => (
                        <div key={screen} style={{ marginBottom: 8 }}>
                            <div
                                style={{
                                    opacity: 0.55,
                                    fontSize: 10,
                                    textTransform: 'uppercase',
                                    letterSpacing: 0.5,
                                    marginBottom: 4,
                                }}
                            >
                                {screen}
                            </div>
                            {list.map((s) => (
                                <button
                                    key={s.id}
                                    onClick={() => jumpTo(s)}
                                    style={{
                                        display: 'block',
                                        width: '100%',
                                        textAlign: 'left',
                                        background:
                                            s.id === current.id
                                                ? 'rgba(255, 215, 100, 0.18)'
                                                : 'transparent',
                                        color: '#fff',
                                        border: 'none',
                                        padding: '4px 6px',
                                        borderRadius: 4,
                                        cursor: 'pointer',
                                        font: 'inherit',
                                    }}
                                >
                                    {s.title}
                                </button>
                            ))}
                        </div>
                    ))}
                </div>
            )}
            <button
                onClick={() => setOpen((x) => !x)}
                style={{
                    background: 'rgba(255, 215, 100, 0.9)',
                    color: '#0a0e16',
                    border: 'none',
                    borderRadius: 999,
                    padding: '6px 12px',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                }}
            >
                {open ? '×  close' : '◧  ' + current.id}
            </button>
        </div>
    );
}

function jumpTo(s: Scenario) {
    const url = new URL(window.location.href);
    url.searchParams.set('harness', s.id);
    if (s.initialRoute) {
        // initialRoute may be "/sources" or "/onboarding?step=5".
        const [path, query] = s.initialRoute.split('?');
        url.pathname = path;
        if (query) {
            const qp = new URLSearchParams(query);
            qp.forEach((v, k) => url.searchParams.set(k, v));
        }
    }
    window.location.href = url.toString();
}

function groupByScreen(list: Scenario[]): Record<string, Scenario[]> {
    const out: Record<string, Scenario[]> = {};
    for (const s of list) {
        const k = s.screen;
        if (!out[k]) out[k] = [];
        out[k].push(s);
    }
    return out;
}
