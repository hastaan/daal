# Phase 00 — Master Execution Plan

## Roadmap Coverage

Addresses the whole roadmap at coordination level. It does not implement product features; it defines how the project stays aligned across V0–V3.

## Goal

Maintain a disciplined execution system where each phase has a bounded spec, measurable exit criteria, and a handover package for the next phase.

## Implementation Approach

- Treat `daal-roadmap-v3.md` as the strategic source of truth.
- Treat the current phase document as the tactical source of truth.
- Create a detailed implementation spec only for the active phase.
- Keep future phases outlined but not over-specified.
- Track zero-trust assumptions explicitly.
- Prefer small, verifiable deliverables over broad partial implementation.

## Phase Cadence

Each phase should follow this loop:

1. Read roadmap and phase document.
2. Write or update the current phase implementation spec.
3. Build only the phase scope.
4. Add fixtures and tests as part of the deliverable.
5. Run validators.
6. Produce handover notes.
7. Decide whether the next phase is unblocked.

## Cross-Phase Testing Model

- Lab simulation proves client behavior under hostile network classes.
- Field probes inform current reachability but are never trusted blindly.
- CI replay fixtures preserve known failure modes.
- Platform-specific behavior must be isolated behind clear interfaces.

## Platform Strategy

- Linux: core libraries, publisher tooling, censor lab, CI baseline.
- Android: first full user client and fastest device feedback loop.
- Windows: desktop/tooling validation and later user client.
- macOS/iOS: required project targets, implemented through macOS CI, external Apple hardware, TestFlight partners, or a trusted maintainer.

## Handover Template

Every phase must end with:

- Completed deliverables.
- Files/modules created.
- Test commands and results.
- Fixtures/artifacts produced.
- Known limitations.
- Security/privacy notes.
- Next-phase prerequisites.
- Open decisions.
