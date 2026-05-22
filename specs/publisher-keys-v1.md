# Publisher Keys v1

## Status

Draft for V0 freeze; extended in Phase 1.5A (`revocation_url`).

## Phase 1.5A addition: per-publisher revocation URL

A publisher MAY pin a `revocation_url` (and the corresponding signing
key as raw hex in `revocation_fingerprint_hex`) in their v2 manifest.
Phase 1.5A clients fetch the listed URL through the active tunnel every
6h, verify the body's signature against the pinned key, and apply the
result. The full distribution semantics live in `revocation-v1.md`.

## Purpose

Publisher keys identify who produced a signed route bundle. They are a user-facing trust primitive, not only a cryptographic implementation detail.

## Key Model

- Root key: Ed25519 long-term identity key.
- Bundle signing key: either the root key or a short-lived Ed25519 sub-key signed by the root.
- Recommended sub-key validity: 1–4 weeks.

## Trust Classes

Publisher-declared classes:

- `official`
- `provider`
- `community`
- `unknown`

These are declarations. Final local trust is determined by the user's device through TOFU, revocation, and recognized directories.

## Fingerprints

The publisher public key fingerprint is SHA-256 over the 32-byte Ed25519 public key.

Renderings:

- full hex in details,
- English four-word fingerprint,
- Persian four-word fingerprint,
- deterministic visual checksum.

## Trust Transitions

```text
unknown -> tofu
tofu -> trusted
tofu -> unknown
trusted -> changed_key
trusted -> revoked
trusted -> expired
changed_key -> trusted
expired -> trusted
```

Network success must never upgrade trust.

## Key Rotation

A root-key rotation is valid only when the new root key is signed by the old root key during a transition window. Unsigned key changes must be blocked and surfaced to the user.

## Revocation

Revocation sources may include:

- official directory,
- publisher revocation list,
- user action.

Revoked publishers invalidate all associated routes unless a later valid recovery process is explicitly defined.

## Rejection Conditions

Clients must reject or block trust escalation when:

- a publisher key changes without a valid rotation chain,
- a sub-key is expired,
- a revocation lists the key,
- a signature is invalid,
- publisher metadata fingerprint does not match `publisher.pub`.
