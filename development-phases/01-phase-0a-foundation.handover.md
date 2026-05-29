# Handover — Phase 0A Foundation

## Phase

Phase 0A — Foundation, Repository, Toolchain, and Project Discipline

## Date

2026-04-26

## Roadmap Sections Addressed

- V0.1 — threat-model skeleton.
- V0.4 — engine-control boundary audit plan.
- V0.5 — build-vs-contribute decision.
- V0.6 — engineering infrastructure.
- V0.7 — initial fixture/test-rig directory structure.
- Cross-cutting zero-trust, no-telemetry, platform, and localization/security foundations.

## Completed Deliverables

- Created approved project directory structure.
- Created decision records for build-vs-contribute, toolchain baseline, and Persian fingerprint wordlist planning.
- Created project security principles.
- Created threat-model skeleton.
- Created engine-gap audit checklist.
- Created fixture directory structure.
- Added `.gitignore` for common build outputs, secrets, keys, and platform artifacts.
- Validated neutral protection-level language in new docs.
- Confirmed Phase 0B is unblocked.

## Files/Modules Created

Directories:

```text
core/
bundle/
publisher/
client-android/
client-ios/
client-desktop/
specs/
specs/test-vectors/
specs/test-vectors/failures/
test-rigs/
docs/
docs/decisions/
docs/handovers/
docs/security/
docs/threat-model/
```

Files:

```text
.gitignore
docs/decisions/0001-build-vs-contribute.md
docs/decisions/0002-toolchain-baseline.md
docs/decisions/0003-persian-fingerprint-wordlist-plan.md
docs/security/project-security-principles.md
docs/threat-model/threat-model-v1-skeleton.md
docs/engine-gap-analysis-v1-checklist.md
phases of development/01-phase-0a-foundation.handover.md
```

## Validation Commands

Validation was performed with:

```text
LS /home/daal
LS /home/daal/docs
LS /home/daal/specs/test-vectors
Grep "Path C|toolkit \\+ reference" /home/daal/docs/decisions
Grep "No telemetry|no telemetry|Standard Protection|Elevated Protection|Strict Protection|Maximum Protection" /home/daal/docs
Grep "ordinary user|activist|journalist|high-risk|device-seizure|user-class" /home/daal/docs
Grep "start/stop specific outbound|structured failure|byte-budget" /home/daal/docs/engine-gap-analysis-v1-checklist.md
git -C /home/daal status --short --branch
```

## Validation Results

- Required top-level directories exist.
- `docs/` subdirectories and files exist.
- `specs/test-vectors/failures/` exists.
- Build-vs-contribute decision records Path C.
- Security/threat docs include no-telemetry and neutral protection-level language.
- Forbidden group-based app-facing wording was not found in new `docs/`.
- Engine checklist includes route control, structured failure, and byte-budget audit items.
- Git repository is present on branch `main`; Phase 0A did not create a commit.

## Fixtures/Artifacts Produced

- No parser or network fixtures yet.
- Fixture directories were created for Phase 0B/0C:
  - `specs/test-vectors/`
  - `specs/test-vectors/failures/`

## Security/Privacy Notes

- No product code was created.
- No telemetry code path was created.
- No endpoints, IPs, routes, CDNs, or protocols were hardcoded.
- `.gitignore` excludes common secret/key formats and platform signing artifacts.
- App-facing protection language remains neutral:
  - Standard Protection
  - Elevated Protection
  - Strict Protection
  - Maximum Protection

## Known Limitations

- CI skeleton files were not created yet; this phase recorded baseline expectations only.
- Reproducible build tooling is not selected yet; Nix vs Bazel remains open.
- The threat model is only a skeleton and still needs full V0 expansion/review.
- The engine-gap checklist is not filled out yet; it is ready for the V0.4 audit.
- Persian wordlist is planned but not commissioned or produced.

## Open Decisions

- Choose reproducible-build system: Nix vs Bazel.
- Decide CI provider/matrix details.
- Decide decision-log naming and whether ADR style should be formalized further.
- Decide how handovers should be mirrored under `docs/handovers/` versus `phases of development/`.
- Decide whether to initialize additional package/workspace metadata once implementation begins.

## Next-Phase Prerequisites

Before Phase 0B:

1. Re-read `daal-roadmap-v3.md`.
2. Re-read `02-phase-0b-bundle-and-trust-core.md`.
3. Review Phase 0A artifacts listed above.
4. Use Spec Mode to approve the Phase 0B implementation spec.

## Blocked Items

None. Phase 0B is unblocked.
