# Cross-Cutting Governance and V4+ Sustainability

## Roadmap Coverage

Addresses V4+ and CC.1–CC.8: security audits, reproducible builds, funding, operational security, localization, no telemetry, documentation, incident response, and long-term research/sustainability.

## Goal

Keep the project trustworthy and sustainable while feature phases move forward. This track runs beside every implementation phase and cannot be deferred to the end.

## Scope

- Security audits.
- Reproducible builds and SBOM.
- Funding and partnership planning.
- Team operational security.
- Localization and accessibility.
- No-telemetry enforcement.
- User/operator/developer documentation.
- Incident-response runbooks.
- V4 research and sustainability backlog.

## Implementation Details

Security:

- End-of-V1 bundle/parser/signing audit is a release gate.
- End-of-V2 full-client audit is a release gate for broad rollout.
- Public bug bounty starts at V1.5 readiness, not after maturity.
- Protect signing keys with hardware-backed procedures.
- Use two-person release verification where possible.

Build integrity:

- Pin toolchains.
- Produce reproducible build instructions.
- Publish hashes.
- Generate CycloneDX SBOM per release.
- Archive debug symbols privately.

Operations:

- Mirror repositories.
- Maintain release-signing runbook.
- Maintain key-compromise runbook.
- Maintain burned-bootstrap runbook.
- Maintain app-store-removal runbook.

Localization/accessibility:

- Persian and English are required for GA.
- RTL and readable Persian error messages are required.
- TalkBack, VoiceOver, NVDA/JAWS considerations must be tracked.

Measurement:

- No telemetry code path.
- No automatic crash-report upload.
- Third-party measurement sources such as OONI/Censored Planet inform threat-model updates.
- User-submitted field reports remain manual, local-reviewable, and untrusted by default.

V4+ backlog:

- Refraction/Conjure partnership.
- Publisher economics.
- Adversarial reverse-engineering watch.
- UPGen/WATER research.
- Mesh/Nearby/Multipeer sharing.
- Decoupled UI and engine updates.
- Localization expansion.
- Formal parser verification.
- Hardware-token integration.
- Policy/funding partnerships.

## Testing Requirements

- Release process dry run.
- Incident-response tabletop exercise.
- Reproducible build verification.
- No-telemetry static/runtime checks.
- Localization smoke tests.
- Accessibility smoke tests.
- Audit readiness checklist at V1 and V2 gates.
- Bug-bounty readiness checklist before V1.5 public expansion.

## Exit Criteria

This track never fully exits. For each release, it must produce:

- Current risk register.
- Current incident runbooks.
- Build integrity artifacts.
- Audit status.
- Bug bounty status once V1.5 begins.
- Localization status.
- Known security/privacy limitations.

## Handover Practice

Every feature phase must hand issues into this track when they affect:

- signing,
- privacy,
- distribution,
- audits,
- localization,
- accessibility,
- incident response,
- funding,
- partnerships,
- or long-term sustainability.
