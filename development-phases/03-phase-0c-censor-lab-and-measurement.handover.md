# Handover — Phase 0C Censor Lab and Measurement

## Phase

Phase 0C — Censor Lab and Measurement

## Date

2026-04-26

## Roadmap Sections Addressed

- V0.3 — failure taxonomy with executable fixtures.
- V0.4 — testbed for engine-control boundary audit (offline replay path).
- V0.7 — DPI emulation, network-condition, and distribution-failure rigs (skeleton; live-runner staged for incremental Linux delivery).
- CC.6 — privacy review confirms no telemetry; field-probe never auto-uploads.

## Completed Deliverables

- Specifications:
  - `specs/censor-lab-v1.md`
  - `specs/failure-taxonomy-v1.md`
  - `specs/field-probe-v1.md`
- Test-rig tree:
  - `test-rigs/README.md`
  - `test-rigs/censor-lab/README.md` and 16 scenario JSON files under `test-rigs/censor-lab/scenarios/`
  - `test-rigs/distribution-failure/README.md` and 8 scenario JSON files under `test-rigs/distribution-failure/scenarios/`
  - `test-rigs/field-probe/README.md`, schema, sample report, privacy rules, reviewer checklist
- Go module `daal/lab-driver` at `test-rigs/censor-lab/lab-driver/`:
  - `cmd/lab-driver` CLI (`validate` / `replay` / `run` subcommands)
  - `internal/scenarios` parser, validator, replay-fixture writer
  - `internal/probe` privacy checker
  - `internal/netns` and `internal/forgers` stubs for the staged live runner
- 31 censor-lab failure fixtures generated under `test-rigs/censor-lab/fixtures/failures/` and mirrored into `specs/test-vectors/failures/`, organized by V0.3 category.
- 8 distribution-failure fixtures under `test-rigs/distribution-failure/fixtures/`.
- Sample reviewed probe report under `test-rigs/censor-lab/fixtures/reports/sample-report.json`.
- Phase 0C privacy review at `docs/security/no-telemetry-review-phase-0c.md`.

## Validation Results

- `go build ./...` — clean.
- `go test ./...` — all tests pass:
  - scenario parser/validator
  - taxonomy enforcement
  - replay-fixture writer + hour-bucket determinism
  - sample probe report passes privacy checker; forbidden fields are rejected at any nesting level
  - required taxonomy categories all have at least one replayable fixture
- `lab-driver validate --scenarios test-rigs/censor-lab/scenarios` validates 16 scenarios.
- `lab-driver replay` produces 31 fixtures across 12 V0.3 categories.
- `rg` confirms only intentional "no telemetry" references in specs.
- `rg` confirms no forbidden group-based wording in test-rig or Phase 0C specs.

## Validation Commands

```bash
cd /home/daal/test-rigs/censor-lab/lab-driver
go build ./...
go test ./...

./lab-driver validate --scenarios /home/daal/test-rigs/censor-lab/scenarios
./lab-driver replay   --scenarios /home/daal/test-rigs/censor-lab/scenarios \
                      --out       /home/daal/test-rigs/censor-lab/fixtures/failures

rg -n "no telemetry|No telemetry" /home/daal/specs /home/daal/test-rigs
rg -n "ordinary user|activist|journalist|high-risk|device-seizure|user-class" \
   /home/daal/specs /home/daal/test-rigs || echo "NO MATCHES"
```

## Categories Covered (Censor-Lab Replay)

- `dns_poisoned`
- `dns_timeout`
- `tcp_connect_timeout`
- `tcp_reset`
- `tls_handshake_failed`
- `tls_sni_or_cert_block_suspected`
- `udp_unavailable`
- `quic_unavailable`
- `auth_failed`
- `route_expired`
- `bundle_signature_invalid`
- `bundle_corrupted`

Categories covered elsewhere:

- `subscription_unreachable` — distribution-failure rig (`subscription-url-unreachable`).
- `publisher_revoked`, `publisher_key_changed` — `bundle-go` tests in Phase 0B.
- `engine_crash`, `network_offline`, `unknown` — to be added in Phase 1B diagnostics work alongside the engine.

## Security/Privacy Notes

- The replay path is filesystem-only; no outbound sockets.
- Scenarios use private address space and example domains; no real CDN IPs or real route secrets.
- Probe report schema forbids exact IP, location, SSID/BSSID, IMSI/IMEI, persistent IDs, browsing destinations, and URLs. The privacy checker also rejects forbidden field names at any JSON nesting level.
- Probe is manually triggered, manually reviewed, and manually shared. There is no telemetry path.
- Fixture timestamps are bucketed at hour granularity.

## Known Limitations

- The live netns runner is staged. Phase 0C ships the offline replay path and refuses live runs without `CAP_NET_ADMIN`. Real-host live runs (DNS forging, SNI/IP RST injection, first-bytes whitelist, fingerprint dropping, stateful reassembly variant) land incrementally as scenarios are exercised on Linux hosts.
- WSL2 may have `tc netem` quirks; document fallbacks before promoting any single fixture to a "live-only" gate.
- TLS-in-TLS burst classifier in scenarios is a placeholder, not a trained model.
- AmneziaWG scenario is a placeholder; full junk-/H1-H4/S1-S4 coverage requires upstream protocol fixtures we should not embed without review.

## Open Decisions

- Whether to vendor `gopacket` for the eventual stateful-reassembly forger or implement a stdlib TCP assembler.
- Whether the field-probe binary lives under `client-desktop` (Tauri sidecar) or as a standalone Go CLI in V1.5.
- How to gate "live-only" scenarios in CI (require Linux runner with `CAP_NET_ADMIN`).
- Whether to promote distribution-failure fixtures into the V1.5 directory-fetch failure tests.

## Next-Phase Prerequisites

Phase 1A receives:

- failure fixtures and scenario schema for publisher-tool validation tests (e.g., `bundle-tampering`).

Phase 1B receives:

- network-failure scenarios for client diagnostics and route-selection tests.
- field-probe schema for the eventual one-button report.
- distribution-failure fixtures for Module 1 channel-independence tests.

Phase 2 receives:

- per-network and network-transition fixtures for cooldown FSM and per-network memory.

## Blocked Items

None. Phase 1A and the Phase 1B prep work are unblocked.
