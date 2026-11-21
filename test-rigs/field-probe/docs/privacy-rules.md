# Field-Probe Privacy Rules

The probe and any report file MUST NOT contain:

- exact public or private IP addresses,
- exact GPS or city-level location,
- SSID or BSSID,
- carrier numeric identifier, IMSI, IMEI, or hardware ID,
- browsing destinations or any user-pasted URL,
- timestamps finer than the hour bucket,
- a persistent identifier across runs,
- any field that would let an observer correlate two reports as the same user.

The probe MUST:

- run only when manually triggered,
- show the user the report before share,
- never open a socket to "send" the report.

If any future probe field would violate these rules, the schema must be revised first.

## v2 (network test) additions

- Targets appear by role only (`google`, `github`, `cf_edge`,
  `white_name`, `neutral_name`, `relay`, `known_zone`,
  `public_resolver`); `variant` cannot hold a dot or a colon.
- The resolver appears as its class only (`private`, `isp_public`,
  `well_known_public`, `unknown`).
- `report_id` is random, not a ULID (a ULID carries the millisecond).
- RTTs, byte counts and durations are buckets.
- The relay appears as `relay_ref` (8 hex of SHA-256 of the pack id).
- The file leaves the device only sealed (`specs/sealed-report-v1.md`)
  and only when the person taps Send or Save.
