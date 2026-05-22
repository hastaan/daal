# Mode Budgets v1

## Status

**Frozen at the end of Phase 2B.** Three modes (`lifeline`, `normal`,
`bulk`) ride on top of the per-route + per-session caps frozen by
2A and 2A-Polish. The 2D mode `lifeline-strict` shares the
`lifeline` multiplier and is otherwise a path-manager-side
behavioural overlay; it is NOT a separate multiplier here.

## Roadmap coverage

V2.2 ("Mode budget UI — three explicit modes; lifeline tightens
caps, bulk unlocks bulk-capable routes; mode is a UI-level toggle
that translates to engine-level budget adjustment"). Builds on
V2.1 (route budgets) and V2.5 (lifeline mode local policy).

## Modes

| Mode | Multiplier | Visible routes | Note |
|---|---|---|---|
| `lifeline` | 0.33× | every route whose `modes_allowed` contains `lifeline` | `bulk-capable` ranks last; recommended for messaging / news / search |
| `normal` | 1.0× | every route whose `modes_allowed` contains `normal` | `bulk-capable` ranks last; default for ordinary use |
| `bulk` | 1.0× | `bulk-capable` only (per V2.2 explicit-opt-in) | required for video / large downloads |
| `lifeline-strict` (2D) | 0.33× | `lifeline` set MINUS `bulk-capable` (unless per-session opt-in) | stability-biased ranker; permanent banner; see `lifeline-mode-v1.md` |

The roadmap V2.5 prose says lifeline tightens caps "by ~3×"; the
canonical multiplier is **0.33** (rounded toward zero on uint64
multiply). This applies to both the hourly and per-session axes;
unlimited (cap=0) stays unlimited.

## `bulk` is a filter, not a preference

V2.2 verbatim: *"Bulk — explicit opt-in, only on bulk-capable
routes."* The path-manager's mode-aware ranker (`pathmanager.Rank`)
filters by `modes_allowed`; in `bulk` mode the only tag whose
`modes_allowed` includes `"bulk"` is `bulk-capable`, so the V2.2
"bulk on bulk-capable only" semantics fall directly out of the
filter.

In `lifeline` and `normal` modes, `bulk-capable` routes survive the
filter (their `modes_allowed` includes `lifeline` and `normal`) but
are deprefer-sorted to rank LAST. The user opted into a
budget-conscious mode; burning a paid bulk route on chat-class
traffic is the wrong default.

## V2.1 rate-limit prompt copy

When any `budgets[]` row's
`consumed_bytes / hourly_cap_bytes >= 0.9` AND the active mode is
not `bulk`, the desktop UI renders the V2.1 canonical prompt
verbatim:

> *"This route is rate-limited. Switch to bulk mode? (uses a paid
> subscription if available)"*

The prompt is dismissible per session and re-arms when a *different*
route crosses the 90% threshold. Persian translation is in
`tauri/src/i18n/fa.json` under `prompt.rate_limit`.

## ABI

**No new release function.** `engine_set_mode` already exists (1B);
its accepted set at 2B is `{lifeline, normal, bulk}`. The 2D mode
`lifeline-strict` is intentionally rejected by `engine_set_mode` at
2B — 2D widens the validation set.

`engine_set_mode` threads the mode into the budget engine
(`budget.Engine.SetMode`) and into the V2.3 posture FSM
(`pathmanager.Manager.SetPosture`):
- `SetMode("lifeline")` flips ImportedActive/SharedActive →
  PostureLifeline.
- `SetMode("normal")` or `SetMode("bulk")` flips PostureLifeline
  back to ImportedActive.
- Mode change MUST NOT bump the budget session epoch (2A-Polish
  rule); the boundary is `engine_init`.

`engine_export_diagnostics` widens additively — every `budgets[]`
row's `hourly_cap_bytes` and `session_cap_bytes` reflect the
*effective* (post-multiplier) cap so the desktop's RouteBudgetTable
can render the actually-enforced ceiling.

## Files

- `core/budget/effective.go` — `ModeFactor`, `applyFactor`,
  `Engine.EffectiveCap`, `Engine.SetMode`, `Engine.Mode`.
- `core/budget/effective_test.go` — table tests over every
  (tag × mode) pair; lifeline-multiplier exhaustion test.
- `core/budget/engine.go` — `Add` and `Snapshot` consult
  `ModeFactor(e.mode)`.
- `core/abi/abi.go::SetMode` — threads mode into budget engine +
  posture; rejects `lifeline-strict` at 2B.
- `core/abi/abi.go::ExportDiagnostics` — widened with `posture`,
  `route_health[]`, `skipped_families[]` fields.
- `client-desktop/tauri/src/pages/components/{ModePicker,
  RouteBudgetTable, RouteHealthTable, RateLimitPrompt}.tsx`.
- `client-desktop/tauri/src/i18n/{en,fa}.json` — V2.2 + V0.3 keys.

## Stability

- The cap-multiplier table (`modeFactor`) is part of the V2 entry-
  criterion parity contract.
- `engine_set_mode`'s accepted set at 2B is locked. 2D widens it
  with `lifeline-strict`.
- The diagnostics widening is additive only.

## Phase 2D amendment

`lifeline-strict` is a fourth mode token. It shares lifeline's
0.33× cap multiplier — no new arithmetic — and adds a behavioural
overlay (stability-biased ranker, bulk-capable filter, refresh
gate). See `lifeline-mode-v1.md` for the full overlay contract
and `key-vault-v1.md` for the companion PIN-vault primitive.

The cap-multiplier table is now:

| Mode             | Multiplier |
| ---------------- | ---------- |
| `lifeline`       | 0.33×      |
| `lifeline-strict`| 0.33×      |
| `normal`         | 1.0×       |
| `bulk`           | 1.0×       |
