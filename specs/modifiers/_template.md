# Modifier: <kind>

> **TEMPLATE.** Copy to `specs/modifiers/<kind>.md` and fill in. The
> registry codegen at `publisher/deploy/modifiers/cmd/genregistry`
> reads every `*.md` file in this directory **except** `_template.md`
> and `README.md`. The codegen rejects malformed front-matter at build
> time (per locked invariant 43).
>
> **Locked invariant 37:** zero `pass_record.status: PASS` records ship
> at FRP-12. The verification grep
> `rg "status.*PASS" specs/modifiers/*.md | grep -v _template.md` MUST
> return empty.

## Identity

- **kind**: `<kind>`
  Examples: `client_desync`, `tls_fragment`. The kind value is the
  string carried in `_relaypack.modifiers[].kind` per supplement
  §12.2.2.bis.
- **sing-box reference**: `<URL or "n/a">`
  Where applicable, link to the sing-box outbound modifier doc that
  the recipient implementation is built against. `n/a` for raw-socket
  modifiers that do not flow through sing-box.

## Description

Two-paragraph plain-language description of:

1. **What the recipient does to outgoing packets** — the mutation
   itself (e.g. "FakeSNI prepended before the ClientHello", "TLS
   record fragmentation at offset N", "TCP segment reordering on the
   first 4 segments").
2. **Why this modifier helps** — what specific Iranian DPI behaviour
   the mutation defeats, and the censor's expected reaction.

## Pass record

- **status**: `PENDING` | `PASS` | `REJECTED` | `DEPRECATED`
  - `PENDING` — slot is reserved but no censor-lab review has
    completed. Validator hard-rejects this kind.
  - `PASS` — censor-lab review completed; reviewer signed off;
    validator accepts at and above `min_phase`.
  - `REJECTED` — censor-lab review completed; the modifier failed
    safety review (e.g. itself fingerprintable). Validator hard-
    rejects; do **not** delete the file.
  - `DEPRECATED` — previously PASS; now superseded or known to be
    burned. Validator hard-rejects; the file remains as a record.
- **methodology**: `<test plan>`
  Describe the censor-lab test plan: target ASNs, target services,
  number of trials, control + experiment groups, instrumentation.
- **observed**: `<result>`
  Raw observation: date, ASN, what the censor did when the modifier
  was applied vs not applied. Include negative results.
- **reviewer**: `<name or pseudonym>`
  Who signed off on the result and the safety analysis.
- **date**: `<YYYY-MM-DD>`
  Date of sign-off.

## Phase gating

- **min_phase**: `V1.5` | `V1.6` | `PostV2`
  Earliest validator phase at which this modifier is accepted (when
  PASS). Even with `PASS` status, a modifier with `min_phase: PostV2`
  is rejected at V1.5 / V1.6 (locked invariant 39).
  Mirrors `relaypackvalidate.Phase` exactly.

## Platform gating

- **platforms**: `[<platform>, ...]`
  Allowed platforms as a JSON-style array. Permitted values:
  `linux-desktop`, `windows-desktop`, `macos-desktop`, `android`,
  `ios`. Empty array `[]` means "no platform yet enabled" — equivalent
  to a hard reject at the importer regardless of validator state.
  The engine importer reads `runtime.GOOS` (and on Linux also checks
  for the desktop UI presence) and rejects candidates whose modifier
  kind is not in the platforms list (locked invariant 40, error code
  `IMP_MODIFIER_PLATFORM`).

## Validator behavior

At each phase, what the validator does when this modifier appears in
`_relaypack.modifiers[]`:

- **V1.5**: `<accept|reject>` — `<reason>`
- **V1.6**: `<accept|reject>` — `<reason>`
- **PostV2**: `<accept|reject>` — `<reason>`

For PENDING records, all three rows are `reject — pass record PENDING`.

## Risk notes

Notes on what happens when the modifier mis-fires:

- Effect on `probing_risk_class` of the carrying candidate (see
  supplement §11.6: modifiers may bump the effective class upward).
- Cooldown attribution (see supplement §13.4: a modifier-bearing
  `direct_vps` candidate is still attributed as `direct_vps` for
  cooldown — the modifier does not change `exposure_mode`).
- Whether modifier failure burns sibling candidates in the same
  RelayPack (locked invariant 41: per-candidate scoping; siblings are
  NOT burned).

## References

- Supplement §11.6 — field-observed tactical modifiers table.
- Supplement §12.2.2.bis — `modifiers[]` schema slot.
- `specs/relaypack-v1.md` — modifier framework cross-reference.
- `docs/modifier-review-process.md` — censor-lab review methodology.
- FRP-12 phase doc: `phases of development/42-phase-frp-12-modifier-framework.md`.
