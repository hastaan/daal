# Field Probe v1

## Status

Draft for V0 freeze.

## Purpose

`daal-probe` is a small, opt-in, manually-triggered tool that runs the V0.3 probe set on the user's device and produces a reviewable JSON report.

It is the **only** mechanism by which on-device observations may leave the device, and only after the user reviews and shares the file manually. There is no telemetry, no auto-upload, no background reporting.

## Non-Goals

- No automatic upload.
- No persistent identifier.
- No browsing destinations.
- No exact location.
- No exact IP.
- No SSID, IMSI, IMEI, or carrier numeric ID.
- No timestamps finer than the hour bucket.

## Probes

- `dns_resolves_default` — resolves a small fixed set of harmless probe names.
- `tcp_443_to_canary` — TCP/443 reachability to predeclared canary hosts.
- `udp_echo` — UDP probe to a predeclared echo target.
- `subscription_url_reachable` — only checks user-pasted URL on demand; URL is not stored in the report.
- `bootstrap_directory_reachable` — checks signed directory pointers.

The probe target list is bundled with the tool and visible to the user. Users do not paste arbitrary URLs into the report.

## Report Schema

`probe-report-v1.json` (JSON Schema): see `test-rigs/field-probe/schema/probe-report-v1.json`.

## Privacy Invariants

- No exact IP.
- No exact location.
- No SSID, no carrier numeric ID, no IMSI/IMEI.
- No browsing destinations.
- No persistent ID across runs.
- Free-text notes are opt-in, shown in the reviewer UI before sharing.

## Reviewer Workflow

The user opens the report, sees a banner explaining what is about to leave their device, and chooses to copy/share it manually. The CLI never opens a network socket to send the report.

Project-side ingestion treats every report as untrusted input and stores it as a fixture under `test-rigs/censor-lab/fixtures/reports/` only if the contributor has consented.
