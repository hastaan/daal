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
//   - The relay-pack freshness walk (relaypack_refresh.go) and its two
//     unscheduled kinds (relaypack_recover.go), and after its mirrors the
//     update ladder (ladder.go): the note carriers of carrier.go, in the
//     order git tag → Google front → other readers → DNS, within one
//     walk's budget (8 TCP connections, 6 DNS questions, 120 s, one host
//     per class, one rung-4 reader per walk chosen per device and day,
//     two connections to Google's front counting the Apps Script door,
//     a class failing twice on a network held off for 6 h). For a pack
//     signed with no mirror the ladder is the whole walk.
//     The ladder runs only on the engine's failure walk and the person's
//     button while no route is up, does nothing for a file without an
//     update secret and a carriers member, and trusts nothing it finds:
//     a micro note must open the signed standby commitment, a full note's
//     document is verified exactly as a mirror's.
//
// OPSEC invariants enforced by this package:
//   - subscription URLs are NEVER logged, NEVER written to refresh_audit
//     beyond the subscription_id, NEVER returned from any ABI call.
//   - This package MUST NOT import net/http; the fetcher reuses the raw
//     TLS/HTTP-1.1 primitive in core/bootstrap. The OPSEC test
//     TestNoNetHTTPInRefresh enforces this at build time.
//   - All on-disk timestamps go through routestore.HourBucket.
package refresh
