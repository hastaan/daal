# Phase 1C — Offline Sharing

## Roadmap Coverage

Addresses V1.4 and the offline portions of Module 1.

## Goal

Make route transfer work when Telegram, GitHub, app stores, and subscription URLs are unavailable.

## Scope

- Static QR import/export.
- File import/export.
- LAN sharing over local Wi-Fi.
- Clipboard detection.
- Signed share bundles.
- Animated/fountain QR for medium signed bundles.

## Implementation Details

Sharing must always preserve provenance:

- Exported routes become signed `.sbp` bundles.
- Recipient sees original publisher trust where possible.
- Friend-shared bundles must not silently become trusted.
- Routes that publisher policy marks non-redistributable are not shared.

LAN sharing:

- Sender advertises local service only while sharing screen is open.
- Receiver enters short PIN.
- Receiver verifies bundle signature after download.
- Self-signed local TLS protects casual LAN interception but does not replace bundle signatures.

QR:

- Static QR for small payloads.
- Animated/fountain QR for medium payloads up to roughly 10 KB.
- Test animated QR on low-end/older Android cameras because frame rate and optics are expected failure points.

## Testing Requirements

- Share/import round trip.
- Tampered shared bundle rejected.
- Unknown publisher warning appears.
- LAN transfer interruption handled.
- QR scan failure does not corrupt route database.

## Exit Criteria

- Android-to-Android file share works.
- Static QR for a small signed bundle works.
- Animated/fountain QR works for a medium signed bundle or is explicitly blocked by a documented implementation issue.
- LAN share works on a local network.
- Trust prompt remains consistent across all share methods.

## Handover to Phase 1D

Phase 1D receives:

- Stable import/export pipeline.
- Shared bundle fixtures.
- User-facing trust flows.
- Distribution UI patterns.

Bootstrap directory routes must enter through the same validation model as shared bundles.
