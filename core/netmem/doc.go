// Package netmem implements V2.4 per-network memory: a small,
// privacy-preserving, encrypted-at-rest blob keyed by a hashed
// network identifier. Each blob captures the user's last-known
// good state on a network — mode, per-route health, family
// success/failure counts, network-diagnosis indicators, and the
// hourly-bucket budget consumption — so a roam restores rather
// than cold-starts.
//
// Privacy invariants (V0.1 + V0.6 telemetry-locked):
//
//   - Raw SSID, BSSID, and carrier strings NEVER cross the package
//     boundary in plaintext. The only entrypoint that accepts them
//     is HashID, which immediately derives an opaque 8-byte
//     network ID and forgets its inputs.
//   - Snapshots are serialised as canonical JSON (sorted keys) and
//     encrypted at rest by the caller via the routestore secrets
//     KV. This package operates only on plaintext bytes; the
//     encryption boundary is in the caller.
//   - The 30-day TTL on stale entries is enforced by Sweep, which
//     callers wire into the scheduler's hourly tick.
//
// The Snapshot shape is locked at v1; bumping the HashID derivation
// or the JSON shape invalidates every saved blob.
package netmem
