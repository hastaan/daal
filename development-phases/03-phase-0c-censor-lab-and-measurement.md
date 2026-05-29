# Phase 0C — Censor Lab and Measurement

## Roadmap Coverage

Addresses V0.3, V0.4, V0.7, CC.6, and the testing concerns around working from outside Iran.

## Goal

Create a repeatable lab that mocks Iran-like and China-like failure classes, plus a privacy-preserving field probe format for optional reports from trusted users.

## Scope

- Local censor emulator.
- Network-condition simulator.
- Distribution-failure simulator.
- Failure taxonomy fixtures.
- Replayable field-probe report format.
- Zero-telemetry measurement rules.

## Implementation Details

Build a Linux-first test rig using containers and local network namespaces.

Simulate:

- DNS poisoning to `10.10.34.34`-style sinkholes.
- DNS timeout.
- HTTP blockpage injection.
- TLS SNI reset.
- TCP connection timeout.
- UDP fully blocked.
- UDP high packet loss.
- QUIC unavailable.
- Subscription URL unreachable.
- GitHub/Telegram/CDN unreachable.
- Engine crash.
- Bundle tampering.
- FET-style "random first packet" blocking.
- AmneziaWG/WireGuard fingerprint blocking.
- TLS-in-TLS burst-pattern detection fixture.
- Iran-style first-two-data-packet/stateless DPI behavior.
- Upgraded stateful TCP reassembly behavior that defeats stale-segment/desync tricks.
- DoH/DoT endpoint poisoning and SNI blocking.
- ECH bootstrap failure via blocked HTTPS/SVCB records.
- Network transitions between Wi-Fi/mobile-like profiles.

The rig should emit failure categories matching the roadmap taxonomy, not vague errors.

Field probe design:

- One-button Android app later.
- Single executable for Linux/Windows where possible.
- No automatic upload.
- User reviews report before sharing.
- No exact IP, exact location, browsing history, contact graph, or persistent ID.
- Use coarse time buckets.

Distribution-failure rig:

- Telegram unavailable.
- GitHub unavailable.
- primary project domain unavailable.
- app-store path unavailable.
- subscription URL unavailable.
- bootstrap-directory mirror unavailable.

The rig should verify that these channels fail independently and that the client does not rely on any single one.

Research fixtures:

- Include non-shipping fixtures for FakeSNI/stale-segment assumptions so the lab can detect when a stateless-DPI workaround would fail under upgraded reassembly.
- Include Snowflake feasibility fixtures because research indicates it remains important in Iran, even if product integration stays in V3.
- Include UDP-gating fixtures: Hysteria2, TUIC, WireGuard/AmneziaWG, QUIC, MASQUE/H3 must fail closed until local UDP probes succeed.

## Testing Requirements

- Every failure category has at least one fixture.
- Path-manager tests can replay lab failures.
- Field reports can be loaded as fixtures without trusting them.
- Distribution failure scenarios are replayable.
- DoH/DoT/ECH bootstrap failure scenarios are replayable.
- Stateless and stateful DPI variants are both represented.

## Exit Criteria

- Censor lab runs locally.
- Failure taxonomy has executable fixtures.
- Field report JSON schema exists.
- Privacy review confirms no telemetry behavior.
- Distribution-failure rig exists.
- UDP-gating and encrypted-DNS failure fixtures exist.
- Phase 1B can use lab failures for Android behavior testing.

## Handover to Next Phase

Phase 1A receives fixture bundles for publisher-tool validation.

Phase 1B receives network scenarios for client diagnostics and route-selection tests.
