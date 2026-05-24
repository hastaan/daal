# Phase 1A — Publisher CLI

## Roadmap Coverage

Addresses V1.6 and supports V1.7. This phase turns the bundle/trust core into an operator-facing tool.

## Goal

Build `daal-publish`, the command-line tool used to generate publisher keys, sign bundles, verify bundles, rotate keys, and revoke routes.

## Scope

- Publisher key generation.
- Sub-key issuance.
- Bundle creation.
- Bundle verification.
- Revocation list signing.
- Key-rotation support.
- Operator-safe defaults.
- Operator linting for sensitive or fragile route metadata.

## Implementation Details

Commands:

```text
daal-publish keygen
daal-publish subkey
daal-publish bundle
daal-publish verify
daal-publish revoke
daal-publish rotate-key
```

Safety rules:

- Refuse unsigned production bundles.
- Require expiry.
- Warn on excessive route count.
- Require explicit development flag for unsafe outputs.
- Never print private keys to logs.
- Store generated keys with restrictive permissions.

Route/operator linting:

- Warn when REALITY cover SNI and server IP/ASN look implausible.
- Warn on public-key reuse across many endpoints.
- Warn when route expiry is too long for bootstrap/emergency use.
- Warn when UDP-only routes are published without TCP fallback.
- Mark Hysteria2/TUIC/WireGuard/AmneziaWG routes as UDP-gated.
- Preserve provider metadata and support URLs without leaking them into unsafe logs.

## Testing Requirements

- CLI round-trips all valid Phase 0B vectors.
- CLI rejects invalid manifests.
- Revocation output verifies with the bundle library.
- Key rotation test covers old-root-to-new-root transition.
- Lint tests cover implausible REALITY metadata and UDP-only route warnings.

## Exit Criteria

- `daal-publish` can create and verify `.sbp`.
- Revocation and rotation are supported at minimum viable level.
- CLI output is compatible with Android import work.
- Operator misuse cases are tested.
- Publisher warnings reflect research-known failure cliffs without assuming any route works.

## Handover to Phase 1B

Phase 1B receives:

- Signed sample bundles.
- Revoked sample bundles.
- Unknown-publisher sample bundles.
- Changed-key sample bundles.
- CLI usage notes for generating future test data.
