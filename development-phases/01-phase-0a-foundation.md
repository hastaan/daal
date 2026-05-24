# Phase 0A — Foundation, Repository, Toolchain, and Project Discipline

## Roadmap Coverage

Addresses V0.1, V0.4, V0.5, V0.6, and the operational parts of V0.7: threat-model skeleton, engine-control boundary audit, build-vs-contribute decision, repository layout, reproducible build direction, CI shape, platform strategy, and testing discipline.

## Goal

Create the project foundation before feature work begins. The output should make future phases predictable, testable, and hard to derail.

## Scope

- Repository layout.
- Language/toolchain choices.
- CI skeleton.
- Test fixture directories.
- Security baseline.
- Documentation conventions for specs and handovers.
- Initial threat-model skeleton.
- Engine-control boundary audit plan.
- Build-vs-contribute decision record.
- Persian fingerprint wordlist commissioning plan.

## Implementation Details

Create the monorepo structure:

```text
core/
bundle/
publisher/
client-android/
client-ios/
client-desktop/
specs/
specs/test-vectors/
test-rigs/
docs/
```

Define initial toolchains:

- Go for core engine, publisher CLI, and reference bundle implementation.
- Kotlin/Compose for Android.
- Swift/SwiftUI + Network Extension for iOS/macOS.
- Rust + Tauri + React/TypeScript for desktop.
- Ed25519 as the first signing primitive.

Create project-wide rules:

- No telemetry code path.
- No unsigned route import as trusted.
- No permanent route without expiry.
- No hardcoded clean IP assumption.
- No protocol marked as globally working.
- All field measurements are untrusted input.

Create the first threat-model skeleton with the four roadmap risk profiles, but do not use group-of-people labels as app-facing mode names:

- Standard protection.
- Elevated protection.
- Strict protection.
- Maximum protection.

Map these internally to the roadmap's risk assumptions without exposing identity-, occupation-, politics-, or social-group-based labels in the app UI.

Record the initial adversary list:

- DNS poisoning.
- SNI reset.
- protocol whitelisting.
- UDP suppression.
- service-class shutdown.
- endpoint enumeration.
- app-store/channel blocking.
- device seizure.

Create the engine-control audit checklist before engine work starts:

- Can the engine start/stop a specific outbound by ID?
- Can route metadata round-trip through stats without destination leakage?
- Can structured failure reasons be emitted?
- Can routes be soft-paused?
- Can byte budgets be enforced?
- Can mode-specific routing rules be generated?
- Can platform network changes be handled?
- Can probes run without starting a full route?

Record the V1 fork decision:

- Path A: greenfield client.
- Path B: upstream into existing clients.
- Path C: toolkit + reference client.

Default remains Path C unless explicitly changed.

Commission the Persian fingerprint work:

- Define requirements for a 2048-word Persian list.
- Require low homophone collision risk for voice relay.
- Require native-speaker and lexicographer review.
- Track visual checksum accessibility constraints.

## Testing Requirements

- CI must run basic format/unit checks once code exists.
- Specs must include fixture folders from day one.
- Every later phase must add tests or fixtures.

## Exit Criteria

- Repo layout exists.
- Toolchain decision is recorded.
- CI skeleton exists.
- Threat-model skeleton exists.
- Engine-control audit checklist exists.
- Build-vs-contribute decision record exists.
- Persian wordlist commissioning plan exists.
- Handover template is adopted.
- Phase 0B is unblocked.

## Handover to Phase 0B

Phase 0B receives:

- Repository structure.
- Spec directory.
- Test-vector directory.
- Security principles.
- Toolchain baseline.
- Threat-model skeleton.
- Engine-control audit checklist.
- Build-vs-contribute decision record.
- Persian wordlist requirements and review plan.

Phase 0B may not start bundle implementation until the zero-trust rules and fixture structure are in place.
