# FRP-9 Pilot Evidence Template (V1.6 CDN Alpha)

**Status:** template (this file is committed; filled copies are
**NOT** committed — they are private operator records, see
`.gitignore`).

**Pilot scope:** two Family Relay Publishers (FRPs) running the
shipped V1.6 `cdn_fronted` surface for 14 consecutive days with at
least one designated recipient family per FRP. The completed aggregate
roll-up drives the `## Closure run YYYY-MM-DD` section of
`specs/v1-6-closure-v1.md`.

**Privacy:** this template captures operational measurements only. Do
not record real names, phone numbers, IP addresses, domains, ASNs,
Cloudflare account IDs, provider tokens, publisher private keys, or
recipient device identifiers. Use anonymous tokens such as `frp-1`,
`recipient-1A`, and `network-2X`.

---

## Per-FRP entry — copy once per pilot FRP

### `frp-X` — pilot start: `YYYY-MM-DD UTC`

| Question | Anonymized answer |
|---|---|
| Pilot ID | `frp-X` |
| Operator OS | Linux \| Windows \| other |
| Origin cloud provider | hetzner |
| CDN provider | cloudflare |
| BYO domain used | yes / no |
| Freshness host | r2 \| github_pages \| manual_static_host |
| Pilot duration | 14 days |
| Number of recipients | N |

### V1.6 success-metric rows

| Metric | Budget | Observed | PASS / FAIL | Notes |
|---|---|---|---|---|
| V1.6-P1: recipient connected via `cdn_fronted` | ≤ 60 s after QR scan | NN s | | First attempt |
| V1.6-P2: hostname/path block recovered by freshness atomic swap | ≤ 5 min, no re-TOFU | NN min NN s | | Classification: `cdn_hostname_blocked` or `path_pattern_blocked` |
| V1.6-S1: uptime + cooldown + rotations | ≥99% uptime, ≥1 cdn cooldown, ≥1 public-surface rotation <30s, ≥1 origin-only rotation with zero family-visible event | NN.N%, details | | Public-surface ≠ origin-only |
| V1.6-S2: CDN posture + leak probe | Verify posture day 1 + day 14; no origin-IP leak | PASS / FAIL | | RP022/RP023 must not fire |
| V1.6-S3: RelayPack conformance | no drift from V1.6 phase contract | PASS / FAIL | | `freshness_url` FRP-controlled, `_cdn_attestation` conformant |

### Rotation log

| Day | Rotation kind | Trigger | Duration | Freshness republished | QR re-scan? | Family-visible event? |
|---|---|---|---|---|---|---|
| | L7 `cdn_path` \| L8 `cdn_hostname` \| L9 `cdn_origin` | | | yes / no | yes / no | yes / no |

### Open observations

- CDN posture or Cloudflare UX:
- Freshness delivery friction:
- Recipient explanation clarity:
- FA copy or consent copy issues:
- Packaging / OS issues:

---

## Aggregate roll-up

| Metric | FRPs PASSING | FRPs FAILING | Median observed |
|---|---|---|---|
| V1.6-P1: family online via `cdn_fronted` ≤ 60 s | /2 | /2 | NN s |
| V1.6-P2: block → freshness recovery ≤ 5 min, no re-TOFU | /2 | /2 | NN min |
| V1.6-S1: uptime ≥99%, cdn cooldown, public-surface rotation, origin-only rotation | /2 | /2 | NN.N% |
| V1.6-S2: posture day 1/day 14, no leak, RP022/RP023 clean | /2 | /2 | n/a |
| V1.6-S3: synthetic gate + real RelayPack conformance | /2 | /2 | n/a |
| V1.6-G1: synthetic `v1-6-superset` 7/7 PASS | n/a | n/a | PASS / FAIL |

**V1.6 closure verdict:** PASS only if every row above is green.
Otherwise `specs/v1-6-closure-v1.md` remains HOLD.

## How to fill this template

1. Copy this file into `docs/pilot/private/<frp-id>-frp9-filled.md`.
2. Fill one per-FRP block per pilot FRP.
3. Merge the two entries into `docs/pilot/private/frp9-aggregate-vN.md`.
4. Transcribe only the aggregate roll-up into
   `specs/v1-6-closure-v1.md`.

Signed consent forms are separate private artefacts; see
`docs/pilot/consent-template.md`.
