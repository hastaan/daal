# FRP-7 Pilot Evidence Template (V1.5)

**Status:** template (this file is committed; filled copies are
**NOT** committed — they are private operator records, see
`.gitignore`).

**Pilot scope:** five Family Relay Publishers (FRPs) running the
shipped FRP-0..FRP-7 surface for at least seven consecutive days
with at least one designated recipient family per FRP. The
operator drives the wizard end-to-end and records the results
below. The completed form drives the `## Pilot results` section
of `specs/v1-5-closure-v1.md`.

**Privacy:** this template is operational measurements only — no
real names, phone numbers, IPs, domains, ASNs, provider tokens,
publisher private keys, or recipient device identifiers. Use
anonymous tokens (`frp-1`, `frp-2`, `recipient-1A`, `network-2X`).

**Withdrawal:** any FRP may withdraw at any time without
explanation. Filling out this form does not create a contract or
ongoing obligation; the form exists to keep the project's V1.5
closure record honest, not to bind participants.

---

## Per-FRP entry — copy this block once per pilot FRP

### `frp-X` — pilot start: `YYYY-MM-DD UTC`

| Question | Anonymized answer |
|---|---|
| Pilot ID (anon) | `frp-X` |
| Operator OS | Linux \| Windows \| (other) |
| Cloud provider used | hetzner |
| Cloud region (anon if needed) | e.g. `region-A` (DE-class) |
| Server type | `cx22` \| `cpx21` \| (other) |
| Pilot duration (days) | NN |
| Number of recipients in family | N |

#### V1.5 success-metric rows (supplement §22.1)

| Metric | Budget | Observed | PASS / FAIL | Notes |
|---|---|---|---|---|
| Provisioning wall-clock (wizard.start → operator-record-persisted) | ≤ 10 min | NN min NN s | | First-time operator; no prior Hetzner account needed |
| First family member online (recipient.scan → tunnel up) | ≤ 60 s | NN s | | |
| 7-day stay-online (anonymized session uptime) | ≥ 99 % | NN.N % | | Tracked via local engine_diagnostics_explain.posture sampling |
| Rotations during 7 days | ≥ 1 | N | | Rotation level: L? — Recommender confidence: high \| medium \| low |
| Recipient sees plain-language Explanation on switch | yes | yes / no | | Was the Reason text useful? |
| Mode-aware schema end-to-end | inert at V1.5 | inert / drifted | | RP021 enforced? cdn:* rules not propagating? |
| L3 fast path wall-clock (if observed) | < 15 s | NN s | | Skipped if no L3 rotation observed |

#### Open observations / friction points

- Provisioning UX:
- Wizard copy or i18n issues:
- Recipient UX (FA copy clarity, banner timing, QR scan ease):
- Rotation UX (RotateModal flow, override usefulness, history view):
- OS / packaging issues (deb / AppImage / NSIS):

#### Anonymized failure log

| Day | Symptom | Selector classification | Action taken | Recovery time |
|---|---|---|---|---|
| | | | | |

---

## Aggregate roll-up

After the five FRP entries above are filled, summarise:

| Metric | FRPs PASSING | FRPs FAILING | Median observed |
|---|---|---|---|
| Provisioning ≤ 10 min | / 5 | / 5 | NN min |
| First family online ≤ 60 s | / 5 | / 5 | NN s |
| 7-day uptime ≥ 99 % | / 5 | / 5 | NN.N % |
| ≥ 1 rotation observed | / 5 | / 5 | N rotations |
| Plain-language Explanation present | / 5 | / 5 | n/a |
| Mode-aware schema inert at V1.5 | / 5 | / 5 | n/a |
| L3 wall-clock < 15 s | / N (if observed) | / N | NN s |

**V1.5 closure verdict:** PASS only if every metric row above is
≥ 4/5 PASSING (allowing one FRP-side failure per metric without
blocking closure). Lower scores keep `specs/v1-5-closure-v1.md`
in HOLD; the project iterates and re-pilots.

---

## How to fill this template

1. Copy this file into `docs/pilot/private/<frp-id>-filled.md`
   (the `.gitignore` rule keeps `*.filled.md` out of the repo).
2. Fill the per-FRP block; one block per pilot.
3. After all five FRPs complete, merge into a single
   `docs/pilot/private/aggregate-vN.md` (also gitignored).
4. The project lead transcribes the **aggregate roll-up table
   only** into `specs/v1-5-closure-v1.md` and flips the closure
   spec from HOLD to SHIPPED.

The signed consent form is a separate artefact; see
`docs/pilot/consent-template.md`.
