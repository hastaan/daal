# Phase 0C — No-Telemetry Privacy Review

## Scope

This review confirms that Phase 0C deliverables (censor lab, distribution-failure rig, field-probe schema, failure taxonomy) introduce no telemetry, no auto-upload, and no automatic data flows that would violate `docs/security/project-security-principles.md`.

## What Phase 0C Adds

- `specs/censor-lab-v1.md`, `specs/failure-taxonomy-v1.md`, `specs/field-probe-v1.md`.
- `test-rigs/censor-lab/lab-driver/` Go module.
- Scenario JSON files and replayable fixtures.
- Distribution-failure scenario JSON files and fixtures.
- Field-probe JSON Schema and sample report.

## Privacy Findings

- No code in `lab-driver` opens an outbound network socket. The replay path is filesystem-only.
- No scenario contains real CDN IPs, real publisher endpoints, or real route secrets. Scenarios use private address space (`10.0.0.0/8`) and example domains.
- Failure fixtures contain no exact timestamps; only RFC3339 hour buckets.
- The probe JSON Schema rejects exact IP, location, SSID/BSSID, IMSI/IMEI, persistent identifier, browsing destinations, and any URL field.
- A privacy-checker (`internal/probe`) walks any probe report and rejects forbidden field names at any nesting level. The sample report passes; an injected forbidden field is rejected by unit test.
- The privacy-rules and reviewer-checklist documents make the invariants explicit for human reviewers.

## What Phase 0C Does Not Change

- No client UI.
- No engine code.
- No publisher CLI.
- No bundle library logic.

## Outcome

Phase 0C complies with `project-security-principles.md`. No telemetry was introduced.
