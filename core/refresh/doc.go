// Package refresh implements Phase 1.5A's reliability work:
//
//   - Subscription URL fetch through the active tunnel (or direct), parse
//     base64/SIP008/Clash bodies, wrap into a synthetic .sbp signed by
//     the device-local delegate key, and import via the existing
//     bundle-go importer with one-transaction atomic UPSERT.
//
//   - Per-publisher revocation list refresh (PublisherInfo.RevocationURL
//     in spec_version 2 manifests), verified against
//     PublisherInfo.RevocationFingerprintHex.
//
//   - A small audit writer that hour-buckets every refresh attempt into
//     `refresh_audit`.
//
// OPSEC invariants enforced by this package:
//   - subscription URLs are NEVER logged, NEVER written to refresh_audit
//     beyond the subscription_id, NEVER returned from any ABI call.
//   - This package MUST NOT import net/http; the fetcher reuses the raw
//     TLS/HTTP-1.1 primitive in core/bootstrap. The OPSEC test
//     TestNoNetHTTPInRefresh enforces this at build time.
//   - All on-disk timestamps go through routestore.HourBucket.
package refresh
