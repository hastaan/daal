// Package freshness builds, signs and uploads the FRP-8 V1.6
// freshness documents (supplement §11.7) — the mechanism that
// lets a rotated relay reach its recipients without a courier.
//
// The freshness document is a small signed JSON file that
// recipients poll on selector-triggered events. It carries the
// current signed .sbp URL plus its SHA-256; recipients compare
// the digest to their on-disk pack, fetch current_signed_url when
// it differs, verify the signed bundle, and atomically swap.
//
// # Two documents, not one
//
//	trust/freshness-mirrors.json   (mirrors.go)  — inside the .sbp
//	    The endpoint SET: N URLs across N distinct providers,
//	    signed by the same key as the pack. This is what makes
//	    the freshness path survive one host being blocked.
//
//	the freshness document itself   (document.go) — at each mirror
//	    kind "daal/freshness-v2". What is current, when it stops
//	    being believable, and where to look next time.
//
// On-wire shape of the document (canonical JSON, same
// canonicalisation rules as the bundle SBP):
//
//	{
//	  "kind": "daal/freshness-v2",
//	  "relay_pack_id": "<stable id>",
//	  "sequence": 1755400000,
//	  "current_bundle_sha256": "<sha256 of signed .sbp bytes>",
//	  "current_signed_url": "https://<frp-host>/<bundle>.sbp",
//	  "last_modified": "<RFC3339>",
//	  "not_after": "<RFC3339>",
//	  "mirrors": [{"provider":"r2","url":"https://…"}, …],
//	  "publisher_pub_hex": "<publisher root pubkey hex>",
//	  "pad": "000…",
//	  "subkey_cert": { … } | omitted,
//	  "signature_hex": "<ed25519 over canonical body sans signature_hex>"
//	}
//
// # Authentication and anti-rollback
//
// Authentication is the publisher's Ed25519 key, directly or
// through an FRP-7.5 sub-key cert embedded in the document — the
// same trust root the pack itself was verified with, so no new
// key has to be distributed.
//
// A signature alone is NOT enough here, and this is the part
// worth being precise about. The attacker who matters is not
// forging documents; they are REPLAYING the publisher's own valid
// ones. Serving a captured copy of yesterday's document is
// indistinguishable from a signature check's point of view, and
// it buys two things:
//
//   - freeze: the recipient believes its dead pack is current;
//   - rollback: after a rotation, the stale document names the
//     PREVIOUS bundle, and a recipient that treats "digest
//     differs" as "install it" walks backwards onto credentials
//     the rotation just revoked.
//
// Three rules close that, all inside the signed body:
//
//  1. sequence — a strictly increasing counter per relay_pack_id.
//     The recipient persists the highest value it has accepted
//     and refuses anything below it, so a replayed document is
//     at best a no-op. Persistence is the load-bearing half: a
//     high-water mark held only in memory protects a process,
//     not a device.
//  2. not_after — a signed expiry (DefaultTTL, 72h). It bounds
//     how long a replay can freeze a recipient and, when it
//     lapses, converts a silent freeze into a visible failure the
//     recipient can escalate on (next mirror, then the bootstrap
//     pointer).
//  3. relay_pack_id — checked against the installed pack, so a
//     document cannot be spliced from one of the publisher's
//     packs onto another.
//
// All three are verified AFTER the signature, never before.
//
// # What the fetch leaks
//
// The document is small, unique per publisher, fetched by every
// recipient of that publisher on a cadence, and its URL is
// readable by anyone holding one copy of the pack. An observer
// therefore learns, without breaking TLS:
//
//   - CORRELATION: every device that fetches this host+path is a
//     recipient of the same publisher. This is the real leak and
//     it is inherent to a shared fixed endpoint — N mirrors in
//     randomised order divides the observation across providers
//     but does not remove it. What removes it is not polling from
//     the clear, which is the tunnel-required rule below.
//   - TIMING: a cadence is a fingerprint, and it is the leak an
//     observer gets for free. The cadence and its jitter are the
//     scheduler's to own (core/scheduler); this package
//     deliberately does not encode one. Two properties on that
//     side make the difference and neither was there when this
//     paragraph was first written: every due time carries a
//     per-device offset drawn from crypto/rand and persisted
//     beside the stamps, so devices holding the same pack are not
//     on one lattice; and the retry gap DOUBLES per consecutive
//     failure up to the staleness ceiling. Without the second, a
//     flat retry made a censored device poll THREE TIMES more
//     often than a healthy one — a fixed-period, zero-variance
//     burst from its real address, aimed at a small enumerable
//     set of hosts, in exactly the situation this mechanism
//     exists for.
//   - REQUEST SHAPE: the mitigation this design leans on is "host
//     the document where other traffic lives". That buys nothing
//     if Daal's requests are separable from that traffic in the
//     origin's access log — which they were, until
//     core/bootstrap/fetcher.go stopped sending no User-Agent, an
//     octet-stream Accept, and a Host header carrying the default
//     port. That triple enumerated a publisher's recipients by
//     source IP and timestamp, on the origin side, where the
//     camouflage was supposed to be doing the work.
//   - SIZE: without padding, the object's length moves when the
//     publisher rotates (URL and digest change, a mirror is
//     added, a sub-key cert appears). That would let an observer
//     detect a rotation in flight across the whole recipient set
//     and time an IP block to it. Every document is therefore
//     padded to a padBucket multiple, so length is constant
//     across all of those states.
//
// # Interaction with the tunnel-required rule
//
// core/refresh fails closed while a route is active: no scheduled
// refresh may hand out a direct dialer, because a beacon from the
// user's real address while the UI reads "connected" is worse
// than the feature being unavailable. Freshness inherits that,
// and the interaction is sharper than it looks:
//
//   - Tunnel UP — the poll rides the tunnel and the local
//     observer sees nothing but the tunnel. This is the common
//     case and it is the safe one.
//   - Tunnel DOWN — the guard permits a direct fetch (there is no
//     tunnel to betray, and recovery has to start somewhere).
//     But this is exactly the case freshness exists for: the
//     relay is burned and the recipient is fetching the recovery
//     document, in the clear, from their real address, at the
//     moment their traffic is most interesting. The mitigations
//     that matter are all in this window — mirrors on
//     high-traffic shared providers whose hostnames are not
//     unique to Daal, randomised order so a blocked provider
//     costs one attempt rather than the mechanism, constant
//     object size, and the bootstrap-pointer envelope underneath
//     when every mirror is gone.
//
// The caller-supplied-dialer shape of core/refresh's freshness
// entry point means that guard is NOT automatic there: whoever
// wires the scheduler must route the freshness fetch through the
// same dial() path the subscription and revocation refreshers
// use, or the guard is bypassed by construction.
//
// # Sub-key-aware signing (per phase doc §6 + invariant 18 lift)
//
//   - No active sub-key: the signature is by root. The recipient
//     verifies against the publisher root pubkey baked into the
//     bundle.
//   - Active sub-key: the cert is embedded as subkey_cert (the
//     same FRP-7.5 SubkeyCert format the SBP uses) and the
//     signature is by the sub-key. The recipient walks
//     pub→cert→sub before accepting the signature.
//
// # Backends (publisher/deploy/freshness/backends/)
//
//   - r2/      — Cloudflare R2 (S3-compatible PUT; primary).
//   - ghpages/ — GitHub Pages via repo-content commit (secondary).
//   - ipfs/    — reserved (IPFS pinning); ships disabled until a
//     maintained pinning surface stabilises.
//
// A publisher declares which of these they hold by passing one
// `provider=url` pair per account to `daal-deploy bind-and-sign
// --freshness-mirror`, and the matching credentials to
// `daal-deploy publish-freshness`. Network IO is confined to the
// backend implementations; the document builder is pure.
package freshness
