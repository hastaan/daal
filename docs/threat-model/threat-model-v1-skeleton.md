# Threat Model v1 Skeleton

## Purpose

This skeleton anchors the V0 threat model. It is intentionally incomplete; later V0 work expands it into the reviewed threat-model document.

## App-Facing Protection Levels

Daal uses neutral app-facing protection levels:

- Standard Protection
- Elevated Protection
- Strict Protection
- Maximum Protection

These levels map internally to different risk assumptions and defaults, but the UI must not label people by identity, occupation, politics, or social group.

## Initial Adversary Capabilities

- DNS poisoning to RFC1918 or sinkhole addresses.
- SNI-based reset or teardown during TLS ClientHello.
- TIC-level protocol whitelisting.
- UDP and QUIC suppression.
- Service-class shutdown.
- TLS-in-TLS burst-pattern detection.
- Active probing of suspected proxy endpoints.
- Endpoint enumeration of public or popular route pools.
- App/update-channel blocking.
- App-store removal or geo-blocking.
- Device seizure.
- Provincial/operator divergence.
- AmneziaWG/WireGuard fingerprinting.
- CDN or hosting-provider pressure.

## Privacy Invariants

- The control plane never collects browsing destinations.
- The control plane never collects exact user IP.
- The control plane never collects exact location.
- The control plane never collects a contact graph.
- The control plane never creates a persistent user identifier.
- All learning is local-first.
- There is no telemetry.
- Unknown publishers require TOFU confirmation.
- Stolen-device exposure must be explicitly tracked and reduced over time.

## Risk Areas To Expand

- Route import and trust.
- Publisher compromise.
- Signing-key compromise.
- Bootstrap-directory blocking.
- Emergency-route burn.
- Subscription URL leakage.
- Field-probe privacy.
- Local database forensic exposure.
- DNS, IPv6, and WebRTC leakage.
- Apple and Google distribution failure.
