# Project Security Principles

## Constitutional Rules

- No telemetry code path.
- No automatic analytics.
- No automatic crash uploads.
- No browsing destinations collected.
- No exact IP, exact location, contact graph, or persistent user identifier collected.
- No unsigned route is trusted.
- No route is permanent; routes and directories expire.
- No hardcoded clean IP, CDN, protocol, or country-specific reachability assumption.
- Field reports are untrusted input.
- Route trust and network success are separate concepts.

## Signed Supply Chain

The following must be signed where applicable:

- route bundles,
- publisher keys and sub-keys,
- bootstrap directories,
- directory pointers,
- revocation lists,
- transport modules,
- kill-switch configuration.

## App-Facing Protection Labels

Use neutral security-level language:

- Standard Protection
- Elevated Protection
- Strict Protection
- Maximum Protection

Do not use app-facing labels based on identity, occupation, politics, social group, or suspicion level.

## Local-First Learning

Network diagnosis, route scoring, cooldowns, and per-network memory happen locally. Any field probe or user-submitted report must be manually reviewed by the user before sharing.

## Engineering Bias

Be boring where boring is safer. Innovate specifically around:

- bootstrap,
- trust,
- sharing,
- scarcity,
- survivability.
