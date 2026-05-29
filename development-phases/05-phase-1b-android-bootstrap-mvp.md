# Phase 1B — Android Bootstrap MVP

## Roadmap Coverage

Addresses V1.1, V1.2, V1.3, and the Android portions of Modules 1–5.

## Goal

Ship the first Android MVP that can import a signed route bundle, show publisher trust, store routes, and connect through the embedded engine.

## Scope

- Android project setup.
- sing-box engine binding.
- Core engine packaging and stable ABI surface.
- Local route database.
- `.sbp` import.
- Trust prompt.
- Basic connect/disconnect flow.
- Initial diagnostics screen.
- File and clipboard import.
- Security-level onboarding with different defaults.
- Subscription metadata handling.

## Implementation Details

Android stack:

- Kotlin.
- Jetpack Compose.
- Coroutines/Flow.
- SQLDelight or Room.
- Android `VpnService`.
- Go engine via `gomobile bind` or controlled JNI layer.

Engine ABI expectations:

- Start/stop engine.
- Set active route.
- Register event callback.
- Query redacted stats.
- Set mode.
- Apply route cooldown.
- Export local diagnostics.
- Report structured failures using the V0 taxonomy.

The ABI can be extended later, but V1B must avoid UI-driven churn in the engine boundary.

Core screens:

- Onboarding with four app-facing security levels: Standard, Elevated, Strict, and Maximum Protection.
- Home.
- Routes.
- Add Route.
- Diagnostics.
- Settings.

Trust behavior:

- Unknown publisher triggers visible fingerprint confirmation.
- Expired route cannot connect.
- Revoked route is disabled.
- Trust badge is always visible.
- Network score never overrides trust state silently.

Security-level behavior:

- Maximum Protection requires stronger local protection and prepares for PIN-locked storage.
- Strict Protection prefers safer defaults and stronger warnings on unknown/shared publishers.
- Elevated Protection biases toward low-bandwidth survival UX and degraded-network resilience.
- Standard Protection keeps the UX simple but never weakens trust prompts.
- Do not use app-facing labels based on identity, occupation, politics, or social group.

Network behavior:

- UDP-based route families are disabled until local UDP probing succeeds.
- DoH/DoT must not be assumed reachable; once a tunnel exists, DNS/subscription refresh should prefer tunneled paths where applicable.
- NaiveProxy and VLESS/REALITY should be represented as first-class supported route families if the engine supports them.

## Testing Requirements

- Unit tests for import logic.
- Instrumented tests for trust prompts where practical.
- Censor-lab scenarios for DNS/SNI/UDP failures.
- Engine ABI smoke tests.
- Onboarding default tests for all four security levels.
- UDP-gating tests.
- Subscription metadata parsing tests.
- Manual device test on at least one Android phone.
- Verify no telemetry endpoints exist.

## Exit Criteria

- User can import a valid signed bundle.
- User can reject or trust a new publisher.
- User can connect to a route when the engine accepts the config.
- Invalid bundles are rejected.
- Diagnostics classify basic failures.
- Engine boundary is stable enough for desktop/iOS reuse.
- Security-level defaults are visible and testable.

## Handover to Phase 1C

Phase 1C receives:

- Working route database.
- Import pipeline.
- Trust UI.
- Engine bridge.
- Signed test bundles.

Offline sharing must reuse the same import/trust path, not create a parallel trust path.
