# Phase 0B — Bundle and Trust Core

## Roadmap Coverage

Addresses V0.2, V0.3 trust-related pieces, and the Module 2 foundation: `.sbp`, publisher keys, route object, publisher object, fingerprints, trust transitions, and test vectors.

## Goal

Build the signed route-supply core. By the end of this phase, a route bundle can be signed, verified, rejected, trusted, expired, revoked, and represented consistently.

## Scope

- `.sbp` archive specification.
- Canonical manifest format.
- Ed25519 signing and verification.
- Publisher root key and optional sub-key model.
- Route and Publisher runtime objects.
- Trust-state transitions.
- Multi-format fingerprints.
- Valid and invalid test vectors.
- Failure taxonomy data model references where trust/import failures intersect route selection.
- Five normative V0 specs: `.sbp`, publisher keys, internal route representation, `Route`, and `Publisher`.
- Persian fingerprint wordlist integration.

## Implementation Details

Define `.sbp` as a signed ZIP archive:

```text
manifest.json
manifest.sig
publisher.pub
profiles/
trust/
revocation.json
```

Freeze five separate normative specs before client implementation:

```text
specs/sbp-v1.md
specs/publisher-keys-v1.md
specs/route-internal-v1.md
specs/route-object-v1.md
specs/publisher-object-v1.md
```

Implement the reference library first in Go:

- Parse bundle.
- Canonicalize manifest.
- Verify signature.
- Extract profiles.
- Validate expiry.
- Validate route metadata.
- Reject malformed archives safely.

Define parser coverage targets from the roadmap:

- sing-box outbound JSON.
- Clash/mihomo YAML.
- `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`, `tuic://`.
- base64 multiline subscriptions.
- SIP008.
- WireGuard `.conf`.
- OpenVPN `.ovpn` where supported by engine/import policy.
- AmneziaWG extensions.
- Tor bridge lines.
- Subscription metadata headers: `subscription-userinfo`, `profile-update-interval`, `profile-title`, `support-url`, and Hiddify-style `moved-permanently-to`.

Full parser implementation may span later phases, but the normalized internal route object must be able to represent all of them.

Then define portability targets:

- Rust for desktop and future web/admin use.
- Kotlin for Android.
- Swift for Apple platforms.

Trust model:

- First-seen publishers become TOFU, not trusted.
- Changed publisher keys require explicit user action unless rotation chain verifies.
- Revoked publishers invalidate their routes.
- Route trust and network performance are separate fields.

Fingerprint model:

- English four-word fingerprint.
- Persian four-word fingerprint from the curated list.
- Deterministic visual checksum.
- Full hex only in details.

Transport-family modeling must include first-class entries for:

- VLESS/REALITY/Vision.
- NaiveProxy.
- Hysteria2 and TUIC as UDP-gated families.
- AmneziaWG as distinct from vanilla WireGuard.
- Snowflake/WebTunnel/Psiphon/Conjure as future route families.

## Testing Requirements

Create test vectors:

- Valid bundle.
- Invalid signature.
- Corrupt ZIP.
- Missing manifest.
- Expired route.
- Changed publisher key.
- Valid key rotation.
- Revoked publisher.
- Wrong canonical JSON.
- Unknown route family.
- Parser lifecycle cases for every supported import class.
- Persian/English/visual fingerprint rendering vectors.

## Exit Criteria

- Go bundle library passes all vectors.
- `.sbp` spec is frozen for V1 unless a breaking issue is found.
- Route and Publisher object schemas are documented.
- Trust transitions are covered by tests.
- Normalized route representation is broad enough for all roadmap import formats.
- Five normative specs are frozen or explicitly marked as pre-freeze blockers.
- Persian and visual fingerprint rendering is covered by vectors.
- Phase 0C and 1A are unblocked.

## Handover to Next Phase

Phase 0C receives bundle fixtures for hostile-network import testing.

Phase 1A receives the library primitives needed for `daal-publish`.
