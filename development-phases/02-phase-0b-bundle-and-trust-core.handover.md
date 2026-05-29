# Handover — Phase 0B Bundle and Trust Core

## Phase

Phase 0B — Bundle and Trust Core

## Date

2026-04-26

## Roadmap Sections Addressed

- V0.2 — wire-format and runtime-object specifications.
- V0.3 — trust/import failure categories intersecting bundle validation.
- Module 2 — Config & Trust foundation.
- V0 gate requirements for `.sbp`, publisher keys, Route object, Publisher object, fingerprints, and test vectors.

## Completed Deliverables

- Created five roadmap-required normative specs:
  - `.sbp`
  - publisher keys
  - internal route representation
  - Route runtime object
  - Publisher runtime object
- Added fingerprint rendering spec.
- Created test-vector directory structure and initial fixture notes.
- Created initial lifecycle and fingerprint JSON fixtures.
- Implemented `bundle-go` reference library for `.sbp` parsing, signing, verification, canonical JSON, fingerprints, route/publisher types, revocation checks, expiry checks, and validation errors.
- Added Go tests for valid bundles, invalid signatures, missing manifest, expired routes, invalid transport family, revoked publisher, fingerprint mismatch, missing profiles, and fingerprint determinism.
- Ran Go tests successfully.

## Files/Modules Created

Specs:

```text
specs/sbp-v1.md
specs/publisher-keys-v1.md
specs/route-internal-v1.md
specs/route-object-v1.md
specs/publisher-object-v1.md
specs/fingerprint-rendering-v1.md
```

Test-vector notes/fixtures:

```text
specs/test-vectors/README.md
specs/test-vectors/bundles/README.md
specs/test-vectors/lifecycle/README.md
specs/test-vectors/lifecycle/publisher-transitions.json
specs/test-vectors/fingerprints/README.md
specs/test-vectors/fingerprints/test-rendering.json
```

Go reference library:

```text
bundle/go/go.mod
bundle/go/bundle/types.go
bundle/go/bundle/errors.go
bundle/go/bundle/canonical.go
bundle/go/bundle/sign.go
bundle/go/bundle/fingerprint.go
bundle/go/bundle/sbp.go
bundle/go/bundle/sbp_test.go
```

## Validation Commands

```text
go version
cd /home/daal/bundle/go && go test ./...
gofmt -w /home/daal/bundle/go/bundle/*.go
cd /home/daal/bundle/go && go test ./...
Grep \"No telemetry|no telemetry\" /home/daal docs/specs
Grep \"Standard Protection|Elevated Protection|Strict Protection|Maximum Protection\" /home/daal docs/specs
Grep \"ordinary user|activist|journalist|high-risk|device-seizure|user-class\" /home/daal specs/bundle
git -C /home/daal status --short --branch
```

## Validation Results

- Initial `go test` failed because Go was not installed.
- Installed Debian `golang-go` package to run validators.
- `go version`: `go1.19.8 linux/amd64`.
- `cd /home/daal/bundle/go && go test ./...`: passed.
- `gofmt` completed successfully.
- Re-ran Go tests after formatting: passed.
- No forbidden group-based app-facing wording was found in `specs/` or `bundle/`.
- No telemetry references remain except explicit no-telemetry requirements.

## Fixtures/Artifacts Produced

- Initial lifecycle fixture: `specs/test-vectors/lifecycle/publisher-transitions.json`.
- Initial fingerprint fixture: `specs/test-vectors/fingerprints/test-rendering.json`.
- Binary `.sbp` fixtures are generated dynamically in Go tests for now and can be promoted to static fixtures later.

## Security/Privacy Notes

- No telemetry or field-upload behavior was created.
- No real route secrets, endpoints, IPs, CDNs, or operational routes were added.
- Bundle verification rejects path traversal, invalid signatures, expired material, invalid enums, missing profiles, revoked publishers/routes, and fingerprint mismatch.
- Trust and network reachability remain separate concepts in specs and types.
- Persian fingerprint words remain test-only/planned until the curated 2048-word list is reviewed.

## Known Limitations

- The Go reference library is initial and intentionally narrow.
- Parser implementations for individual URI/subscription formats are not implemented yet; the internal route representation is broad enough to model them later.
- Canonical JSON implementation is minimal and should be audited before V1 freeze.
- Key rotation is specified and fixture-noted but not fully implemented.
- Static `.sbp` binary fixtures are not yet checked in.
- Environment Go version is 1.19.8 from Debian, while roadmap CI target remains Go 1.23+.

## Open Decisions

- Decide whether to vendor or generate the English BIP-39 list.
- Commission/review the Persian 2048-word list.
- Decide canonical JSON finalization approach before spec freeze.
- Decide how much key-rotation logic belongs in `bundle-go` versus publisher/client layers.
- Decide when to promote generated test bundles into static fixtures.

## Next-Phase Prerequisites

Phase 0C receives:

- bundle validation errors,
- initial trust/import fixtures,
- failure-related specs,
- and test-vector directories for hostile-network import scenarios.

Phase 1A receives:

- `bundle-go` signing/verifying primitives,
- `.sbp` spec,
- publisher-key spec,
- and validation behavior for `daal-publish`.

Before Phase 0C or 1A, use Spec Mode to approve that phase's implementation spec.

## Blocked Items

None. Phase 0C and Phase 1A are unblocked.
