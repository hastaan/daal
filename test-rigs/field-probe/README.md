# Field Probe

Schema and supporting docs for `daal-probe`'s reviewable report format. See `specs/field-probe-v1.md`.

This directory does not implement the probe itself; the probe binary lives under `client-desktop/` (Linux/Windows) and `client-android/` later. This directory holds:

- `schema/probe-report-v1.json` — JSON Schema for the v1 report.
- `schema/probe-report-v2.json` — JSON Schema for the v2 report: the
  network test inside Daal (`specs/field-probe-v2.md`; Go twin
  `bundle/go/fieldreport`, held equal by `TestSchemaFileMatchesGoEnums`).
- `sample-report.json` / `sample-report-v2.json` — one valid report of
  each version (no real address, name or time).
- `docs/privacy-rules.md` — invariants the probe must enforce.
- `docs/reviewer-checklist.md` — checklist a reviewer applies before accepting a report as a fixture.
