---
name: diagnostics-explain-v1
phase: 1.5A
status: draft
---

# diagnostics-explain-v1 — "Why this route?"

## Status

Draft, Phase 1.5A.

## Purpose

The Phase 1B path manager already tracks per-route + per-family
cooldown, last-failure category, and the FSM state. Phase 1.5A adds a
**deterministic transcription** so the user can answer the question
"why is the app using this route, and not those other routes?".

There is no scoring, no ML, no learned model. The "why" is a one-liner
projection of the FSM at decision time.

## ABI

```c
int engine_diagnostics_explain(char* out, int out_len);
```

Returns:

```json
{
  "bucket": "2026-04-26T20:00:00Z",
  "state": "Connected",
  "active_route": "Provider-Reality-7",
  "why_chose_route": "Tunnel up on Provider-Reality-7.",
  "skipped_families": [
    {"family": "hysteria2",     "reason": "cooldown until 2026-04-26T20:30:00Z"},
    {"family": "vless-reality", "reason": "cooldown until 2026-04-26T20:00:00Z"}
  ],
  "last_failure": null
}
```

`bucket` is hour-truncated (per the global hour-bucketing rule).

## State → why_chose_route mapping

| FSM state    | `why_chose_route` |
|---|---|
| `Connected`  | `Tunnel up on <route>.` |
| `Connecting` | `Attempting <route>.` |
| `Cooldown`   | `Last attempt failed; cooling down. Reason: <FSM reason>.` |
| `Failed`     | `Last attempt failed without cooldown. Reason: <FSM reason>.` |
| `NoRoute`    | `No route is active.` |

`<FSM reason>` is exactly `Manager.LastReason()` — the same string the
existing diagnostics export already exposes.

## Persistence

Each call to `engine_diagnostics_explain` upserts the projection into
the `diagnostics_explain` table keyed by hour bucket. This lets the next
boot's UI show a "last hour explanation" even if the app was killed.

## OPSEC invariants

- Route IDs are NOT user destinations; they are local labels assigned
  at import time. Logging them is allowed.
- Failure categories are V0.3 enums; the raw error string is NOT
  surfaced to the UI.
- Hour bucketing is preserved everywhere.
