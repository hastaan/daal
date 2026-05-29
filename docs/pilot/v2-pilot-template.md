
**Status:** template (this file is committed; filled copies are
**NOT** committed — they are private operator records, see
`.gitignore`).

**Pilot scope:** two Family Relay Publishers (FRPs) running the
shipped V2 multi-provider + mgmt-plane surface for 14 consecutive
days, across at least two of the three providers (Hetzner / Vultr
/ Stark), with at least one designated recipient family per FRP.
The completed aggregate roll-up drives the `## Closure run
YYYY-MM-DD` section of `specs/v2-closure-v1.md`.

**Privacy:** this template captures operational measurements only.
Do not record real names, phone numbers, real IP addresses, real
domains, real ASNs, real provider account IDs, real provider tokens,
publisher private keys, or recipient device identifiers. Use
anonymous tokens such as `frp-1`, `recipient-1A`, `network-2X`,
`origin-1-public-ip-redacted`. Capture mgmt-plane fingerprints in
truncated form (first 8 hex chars + `…`) — that is enough for the
roll-up to confirm pinning held without exposing the full hash.

---

## Per-FRP entry — copy once per pilot FRP

### `frp-X` — pilot start: `YYYY-MM-DD UTC`

| Question | Anonymized answer |
|---|---|
| Pilot ID | `frp-X` |
| Operator OS | Linux \| Windows \| other |
| Cloud provider for primary deploy | hetzner \| vultr \| stark |
| Cloud provider for secondary deploy (if any) | hetzner \| vultr \| stark \| n/a |
| V2 toggle enabled at provision time | yes / no |
| Android publisher wizard used for primary deploy | yes / no |
| BYO domain used (CDN-fronted) | yes / no |
| Random mgmt port chosen at provision | `[10000–65000]` |
| Mgmt TLS fingerprint captured at bootstrap (first 8 hex + …) | `xxxxxxxx…` |

### V2 fast-path rotation log

For every L1 / L2 rotation attempted during the 14-day window,
record one row. (L3 / L4–L6 / L7–L9 use V1.5 / V1.6 surfaces and
are not the V2 metric — but operators should still track them
for cross-comparison.)

| Day | Op | Provider | Wall-clock (s) | Fingerprint mismatch? | Cloud-FW rule auto-expired? | Recipient sees `connected` post-rotation? |
|---|---|---|---|---|---|---|
| 1 | rotate-credentials | hetzner | 6 | no | yes | yes |
| 7 | rotate-tls | vultr | 19 | no | yes | yes |

A row with a non-`no` value in the "fingerprint mismatch?"
column is a **hard fail** that should be escalated immediately
(the fingerprint pin caught a box-swap or a MITM; the operator
should redeploy and discard the burned `OperatorRecord`).

### Cloud-firewall hygiene snapshot

For each provider used during the pilot, dump the cloud-provider-
native firewall audit log covering the 14-day window. Confirm:

* Every rule the wizard opened via `SetEphemeralFirewallRule` was
  removed within 600 s of opening (300 s wizard `defer` cleanup +
  300 s provider auto-expiry as belt-and-braces).
* No rule survived past the auto-expiry window.

Record: `provider`, `total rules opened`, `total rules removed`,
`mean lifetime (s)`, `max lifetime (s)`.

| Provider | Opened | Removed | Mean lifetime (s) | Max lifetime (s) |
|---|---|---|---|---|
| hetzner | … | … | … | … |
| vultr | … | … | … | … |

### Android publisher wizard log (if used)

| Question | Answer |
|---|---|
| Number of provisions completed phone-side end-to-end | … |
| Median wall-clock from "Begin" to QR rendered (s) | … |
| Were any rotations attempted from the phone? | **must be no** |
| Did the phone ever expose the desktop mgmt-plane signing key? | **must be no** |

### Closing roll-up — does the operator's pilot meet V2 closure criteria?

(Filled by project lead during the closure-run aggregation.
Cross-references back to `specs/v2-closure-v1.md`.)

| Criterion | Status |
|---|---|
| V2-P1 multi-provider provision green | yes / no |
| V2-P2 V2 fast-path rotation ≤ 20 s green | yes / no |
| V2-P3 Android provision green (if attempted) | yes / no / n/a |
| V2-S1 fingerprint pin held (zero unexpected mismatches) | yes / no |
| V2-S2 cloud-firewall hygiene clean | yes / no |
| FRP-10 invariant 26–30 unchanged at closure | yes / no |
| FRP-10 test surface green at closure-run head | yes / no |
