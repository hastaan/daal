# Bootstrap Directory v1

## Status

Locked at the end of Phase 1D.

## Purpose

The Tier-3 bootstrap directory is the steady-state mechanism by which a
fresh client learns about the current pool of emergency, experimental,
and (later) regular routes without needing an app update. It is the
direct counter to the V0.4 challenge: "embedded routes alone are
disposable; we need a route to *the rest*."

## Format

A directory is a `.sbp` archive — the **same** format `bundle-go`
already produces and verifies — distinguished only by:

| Field | Value | Reason |
|---|---|---|
| `bundle.type` | `"directory"` | Reuses the existing `bundle.type` enum (extended in Phase 1D); lints differ in a directory bundle. |
| `routes[].scarcity_class` | always `"emergency"` | Directory routes are part of the shared pool by definition until V2's per-publisher scarcity policy. |
| `bundle.expires_at` | typically `created_at + 24..72h` | Short-lived; the client refreshes well before expiry. |

Everything else — manifest schema, signature algorithm, fingerprint
rendering, sub-key cert embedding, revocation list embedding — is
identical to a regular bundle. The verifier code path is the same.

## Trust suppression

A directory `.sbp` whose publisher fingerprint matches a pinned Tier-1
publisher (see `embedded-material-v1.md`) is silently imported — no
trust prompt, no first-seen banner, no TOFU state. The mechanism is
**not** a new code path in `bundle-go/importer`: it is the existing
"publisher already at trust_level=official" branch, reached because the
embedded package pre-pins each Tier-1 publisher on first launch.

A directory `.sbp` whose publisher does not match any Tier-1 pin is
rejected outright. There is no TOFU on directory bundles.

## Lints (additive on top of `publisher-cli-v1`)

| Code | Level | Trigger |
|---|---|---|
| `DIRECTORY_TOO_LARGE` | warn | directory contains >150 routes |
| `DIRECTORY_EXPIRY_TOO_LONG` | block | `bundle.expires_at - created_at > 7d` |
| `DIRECTORY_EXPIRY_TOO_SHORT` | warn | `bundle.expires_at - created_at < 6h` |
| `DIRECTORY_NON_EMERGENCY_ROUTE` | warn | a route's `scarcity_class != "emergency"` |

`daal-publish bundle --bundle-type directory` enables these lints
automatically.

## Refresh cadence

- Best-effort daily, opportunistically when a tunnel is up.
- The client UI nags after 7 days without a successful refresh.
- If the directory's `expires_at` is past, the client falls back to
  Tier-2 seeds and surfaces the bootstrap-screen flow.

## Routes

Each route in the directory is a normal route entry per
`route-internal-v1.md`. The directory does NOT contain user-bound
metadata; it contains the publisher's signed shape only.

## Privacy

- The fetch is hostname-pinned and TLS+HTTP/1.1; the client sends no
  User-Agent, no cookie, no referrer.
- No record of which pointer URL was used is kept beyond the redacted
  diagnostics blob (which records "directory refreshed at HourBucket" but
  not the URL).
- The directory body is age-encrypted into the routestore as profiles,
  same as any other imported `.sbp`.
