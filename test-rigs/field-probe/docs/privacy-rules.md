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
