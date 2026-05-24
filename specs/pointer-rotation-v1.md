---
name: pointer-rotation-v1
phase: 1.5A
status: draft
---

# pointer-rotation-v1 — runtime replacement of embedded pointer sets

## Status

Draft, Phase 1.5A. Implements V1.5.5 from the roadmap.

## Purpose

The Phase 1D `core/bootstrap/embedded` package bakes a primary and
fallback pointer set into every build. A censor that learns those URLs
could block them all at once. **Pointer rotation** lets the project root
ship a fresh pointer set inside a Tier-3 directory bundle; the client
verifies, persists, and prefers it on the next boot — without an app
update.

## Envelope shape

```json
{
  "v": 1,
  "kind": "pointer_rotation",
  "primary":  { ... PointerSet ... },
  "fallback": { ... PointerSet ... }
}
```

The wrapper is unsigned; each inner `PointerSet` carries its own
project-root signature exactly as embedded sets do. The wrapper itself
adds no signed claim — it is a transport convenience.

## Distribution

The Tier-3 directory bundle (a `.sbp` of `bundle.type=directory`) MAY
embed the envelope as a member at the path named by
`bundle.pointer_rotation_ref.path` in the v2 manifest (typically
`trust/pointer-rotation.json`).

## Acceptance rules

For each inner set independently:

1. Verify the signature against the project root pubkey baked into the
   build.
2. Reject if `valid_until` is in the past.
3. Reject if `valid_until` is **not strictly later** than the higher of
   the persisted set's `valid_until` and the embedded set's
   `valid_until`.
4. Otherwise, persist under `secrets_kv:bootstrap-pointers:v1`.

A persisted set with a later `valid_until` than the embedded one
overlays the embedded set on the next `embedded.LoadManifest()` call;
the bootstrap orchestrator calls `OverlayPersistedOntoManifest` exactly
once per process start.

## Failure modes

- Tampered signature → silent drop. No error returned to the host.
- Older `valid_until` → silent drop.
- Empty rotation (both inner sets empty) → silent drop.
- A persisted set whose signature can no longer be verified (e.g.,
  project root rotated; this is V3 territory) → fall back to embedded.

There is no "active rollback" — a compromised project root is a CC.8
incident-response event, handled by shipping a new app build.

## Observability

`engine_pointer_rotation_status` returns:

```json
{
  "have_persisted": true,
  "primary_valid_until":   "2026-12-01T00:00:00Z",
  "fallback_valid_until":  "2026-12-01T00:00:00Z",
  "primary_source":   "persisted",
  "fallback_source":  "embedded",
  "embedded_primary_until":  "2026-08-01T00:00:00Z",
  "embedded_fallback_until": "2026-08-01T00:00:00Z"
}
```

The host UI shows this only inside Diagnostics; it is not surfaced on
the home screen.
