# Modifier review process — FRP-12

This document describes the process by which a per-candidate
modifier (e.g. `client_desync`, `tls_fragment`) progresses from a
PENDING reserved-slot doc at `specs/modifiers/<kind>.md` to a PASS
record that the publisher-side modifier registry advertises and the
relaypack validator's RP013 conditionally accepts.

**At FRP-12 ship zero modifiers carry a PASS record.** This document
is the contract for the post-track follow-on phase that ships the
first concrete PASS record.

## 1. Status lifecycle

```
        ┌────────┐
        │  none  │   no specs/modifiers/<kind>.md exists
        └───┬────┘
            │ author reserves the kind
            ▼
        ┌────────┐
        │ PENDING│   reserved-slot doc exists; validator hard-rejects
        └───┬────┘
            │ censor-lab review completes; reviewer signs off
            ▼
        ┌────────┐
        │  PASS  │   validator accepts at >= min_phase, on platforms[]
        └───┬────┘
            │ field evidence shows the kind is itself fingerprintable
            ▼
        ┌────────────┐
        │ DEPRECATED │   record retained; validator hard-rejects
        └────────────┘

A record never returns to PENDING after PASS or DEPRECATED. A record
may be REJECTED instead of PENDING when the censor-lab review
completes with a falsifying observation; REJECTED records are also
retained for the historical record.
```

## 2. Reviewer pool

The censor-lab reviewer pool consists of named operators who:

1. Have access to instrumented vantage points inside Iran (or a
   counterpart censor-network of equivalent severity).
2. Can run a censor-lab test plan against ≥3 distinct ISPs and ≥30
   trial connections per cohort.
3. Have signed the reviewer code of conduct (separate document; out
   of scope for FRP-12).

The pool composition is recorded in `docs/modifier-reviewers.md`
(NOT shipped at FRP-12; created in the first concrete-modifier
phase).

## 3. Methodology contract

A PASS record's `methodology` field MUST specify:

- **Target ASNs.** The ISPs whose DPI behaviour the modifier
  defeats. At minimum: one residential ASN, one mobile-carrier ASN,
  one corporate / institutional ASN.
- **Target services.** The transport families the modifier was
  tested against (e.g. vless-reality on TCP/443, naive on TCP/443,
  websocket-tls on TCP/443).
- **Trial count.** ≥30 connection attempts per (ASN × service ×
  cohort) cell. Cohorts: control (no modifier) and experiment
  (modifier active).
- **Instrumentation.** Per-flow capture (pcap or equivalent), DPI
  event timestamps from the censor-side observation if available,
  client-side success/failure outcomes.
- **Falsifying observation.** The specific observation that would
  have flipped the record to REJECTED. Naming this in advance is
  required so the reviewer cannot claim PASS by silently dropping
  inconvenient data.

## 4. Observed result contract

A PASS record's `observed` field MUST report:

- Date of the test run (`YYYY-MM-DD`).
- ASNs covered.
- Raw success rate per cohort.
- Negative-result note: any cohort where the modifier did NOT
  produce the expected outcome, with explanation.
- Self-fingerprintability check: whether the censor was able to
  identify the modifier itself as a Daal signature within the test
  window. A PASS record requires this answer to be a documented
  "no".

## 5. Sign-off

A PASS record's `reviewer` and `date` fields MUST be:

- A real (or pseudonymous but stable) reviewer identifier.
- The date of sign-off, not the date of test completion (these
  may differ when sign-off requires a multi-reviewer concurrence).

The `Meta.validate()` function at
`publisher/deploy/modifiers/frontmatter.go` rejects PASS records
whose reviewer or date is empty or `TBD`.

## 6. Refresh cadence

A PASS record is **revalidated every 6 months**. Revalidation:

- Re-runs the methodology against the current censor behaviour.
- If the modifier still produces the expected outcome and is still
  not self-fingerprintable, the record's `date` is bumped (the same
  reviewer or a successor signs off again).
- If the modifier no longer produces the expected outcome, the
  record is flipped to DEPRECATED.

The 6-month refresh interval is enforced operationally, not by
code. The post-track follow-on phase that ships the first PASS
record will add a small CI check that warns when a PASS record's
`date` is older than 6 months.

## 7. Codegen pipeline

After editing `specs/modifiers/<kind>.md`, run:

```
cd publisher && \
  go run ./deploy/modifiers/cmd/genregistry \
    --specs ../specs/modifiers \
    --out ./deploy/modifiers/registry_gen.go
```

The generator:

1. Reads every `*.md` file in the specs dir (excluding `_template.md`
   and `README.md`).
2. Parses front-matter via `modifiers.Parse`.
3. Validates each record via `Meta.ValidateExported`.
4. Refuses any PASS record unless `--allow-pass` is set (locked
   invariant 37 — FRP-12 ship MUST NOT use this flag).
5. Emits a deterministic Go literal map at the output path.

The output file (`registry_gen.go`) is committed. Reviewers see the
generated map in PR diffs alongside the `.md` source.

## 8. Promotion to PASS — checklist

A PR that promotes `specs/modifiers/<kind>.md` from PENDING to PASS
MUST include:

- [ ] Updated `pass_record.status` from PENDING to PASS.
- [ ] Non-empty `methodology`, `observed`, `reviewer`, `date`
      fields.
- [ ] Updated `platforms[]` list (no longer empty / no longer
      placeholder).
- [ ] Re-run of `genregistry --allow-pass` and committed
      `registry_gen.go`.
- [ ] Updated relaypack-v1.md test vectors to confirm the kind
      now passes RP013 at `min_phase`.
- [ ] Updated the FRP-12-ship empty-allow-list assertion test in
      `publisher/deploy/relaypack/binder_modifiers_test.go` (the
      one that asserts the allow-list is empty at every phase) to
      reflect the new non-empty allow-list at and above
      `min_phase`.
- [ ] Sign-off review by a second reviewer from the pool.

## 9. Out-of-band considerations

- **Multi-modifier interactions.** When two PASS modifiers are
  carried on the same candidate, the censor-lab MUST have tested
  the combination. The PR that adds the second PASS modifier MUST
  also re-validate against every existing PASS modifier; absent
  that, only one modifier per candidate is permitted (enforced
  operationally by the reviewer pool, not by code at FRP-12).
- **Cell-aware propagation.** Whether a modifier's PASS status
  propagates across cells in V3 is a separate question; not
  decided here. The cell-aware modifier propagation row is a V3
  candidate per FRP-12 phase doc §8.

## 10. References

- `specs/modifiers/_template.md` — the locked per-modifier doc
  template.
- `specs/relaypack-v1.md` — modifier framework section.
- `publisher/deploy/modifiers/` — registry + frontmatter parser.
- `core/internal/selection/candidate_platform.go` — engine platform-gate
  helper.
- `core/trust/state.go` — importer/store boundary that calls the
  platform gate before persisting modifier-bearing routes.
- `phases of development/42-phase-frp-12-modifier-framework.md` —
  FRP-12 phase doc.
- `daal-roadmap-v3-supplement-diaspora-helper.md` §11.6, §12.2.2.bis,
  §17.5 — reserved schema slots + FRP-12 implementation lock.
