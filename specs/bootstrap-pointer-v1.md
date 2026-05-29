# Bootstrap Pointer Set v1

## Status

Locked at the end of Phase 1D. Pointer rotation (V1.5.5) extends this
spec; the schema and signature rules remain the same.

## Purpose

A pointer set is a small, signed JSON document baked into the client at
build time that names where the Tier-3 bootstrap directory `.sbp` may be
fetched. It is the bridge between the immutable embedded material and
the mutable directory; rotating the directory does not require rebuilding
the client, but rotating the pointer set does (until V1.5.5).

## Schema

```jsonc
{
  "v": 1,
  "kind": "bootstrap_pointers",
  "set": "primary",                  // or "fallback"
  "issued_at":  "RFC3339",
  "valid_until": "RFC3339",          // typically issued_at + 365d
  "pointers": [
    {
      "url": "https://bootstrap.example.org/dir.sbp",
      "expected_publisher_fingerprint_hex": "<64 hex>"
    },
    /* 2..10 entries; primary should be diverse across ASN/TLD/CDN */
  ],
  "signature_hex": "<ed25519 signature, hex>"
}
```

## Signature

The signature is computed over the canonical JSON of the document with
`signature_hex` elided and `pointers` sorted lexicographically by `url`.
Signing key is **the project root**, not a publisher. Verification is by
the pinned `project-root.pub` baked into `core/bootstrap/embedded`.

The canonical-JSON algorithm sorts object keys lexicographically at every
nesting level and emits no whitespace; this matches the algorithm used
by `bundle-go` for manifest signatures, so a Go and a Rust implementation
of the verifier produce byte-identical signing inputs.

## Trust rules

- A pointer set whose signature does not verify is rejected; the client
  falls through to the next set or surfaces "all bootstrap blocked" UX.
- A pointer set whose `valid_until` is in the past is rejected.
- A pointer entry whose `expected_publisher_fingerprint_hex` length is not
  64 is rejected at parse time.
- The fetched `.sbp` MUST have a publisher fingerprint matching the
  pointer's pin. A mismatch is treated as `bundle_signature_invalid` per
  `failure-taxonomy-v1.md`.

## Rotation (V1.5.5, deferred)

V1.5 ships static primary + fallback pointer sets. V1.5.5 introduces a
project-root-signed `pointer_rotation` envelope that the running client
consumes to replace its primary or fallback set without an app update.
This document will be amended at that time; the schema above remains the
canonical source for the rotated set itself.

## Security

- The project root key MUST be held with the operator process documented
  in `specs/publisher-keys-v1.md`. Compromise of the project root would
  let an adversary issue malicious pointer sets; defense-in-depth is the
  fingerprint pin on the directory `.sbp`.
- The pointer set is small (<2 KB typical) and fits comfortably alongside
  Tier-2 seeds in the embedded artifact.

## OPSEC tests

- `core/bootstrap/embedded` must contain at least one valid primary and
  one valid fallback set whose signature verifies under the embedded
  project-root pubkey.
- Lexicographic sort of `pointers` in the canonical-JSON input is unit
  tested for stability against input ordering.
