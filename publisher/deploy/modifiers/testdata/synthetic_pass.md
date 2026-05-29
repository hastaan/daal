# Modifier: synthetic_pass

> TEST-ONLY FIXTURE. This file is loaded only by tests in the
> publisher/deploy/modifiers package and is NOT consumed by the
> genregistry binary. The locked-invariant-37 verification grep
> deliberately excludes the testdata/ subtree. The kind name
> `synthetic_pass` MUST NOT collide with any real reserved kind in
> specs/modifiers/.

## Identity
- **kind**: `synthetic_pass`
- **sing-box reference**: n/a

## Pass record
- **status**: PASS
- **methodology**: synthetic test fixture only
- **observed**: synthetic
- **reviewer**: test-only
- **date**: 2026-05-05

## Phase gating
- **min_phase**: PostV2

## Platform gating
- **platforms**: ["linux-desktop", "windows-desktop"]
