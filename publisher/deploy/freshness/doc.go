// Package freshness builds and uploads the FRP-8 V1.6
// freshness-endpoint document (supplement §11.7).
//
// The freshness document is a small signed JSON file that recipients
// poll on selector-triggered events. It carries the current signed
// .sbp URL plus its SHA-256; recipients compare the digest to their
// on-disk pack, fetch current_signed_url when it differs, verify the
// signed bundle, and atomically swap. The endpoint is FRP-controlled
// (R2, GitHub Pages, IPFS future) and identified by
// Manifest.RelayPack.FreshnessURL.
//
// On-wire shape (canonical JSON, same canonicalisation rules as
// the bundle SBP):
//
//	{
//	  "kind": "daal/freshness-v1",
//	  "relay_pack_id": "<stable id>",
//	  "current_bundle_sha256": "<sha256 of signed .sbp bytes>",
//	  "current_signed_url": "https://<frp-host>/<bundle>.sbp",
//	  "last_modified": "<RFC3339>",
//	  "publisher_pub_hex": "<publisher root pubkey hex>",
//	  "subkey_cert": { "...": "embedded SubkeyCert JSON, or omitted" },
//	  "signature_hex": "<ed25519 over canonical body sans signature_hex>"
//	}
//
// Sub-key-aware signing (per phase doc §6 + invariant 18 lift):
//
//   - When the FRP has no active sub-key, the signature is by root.
//     The recipient verifies against the publisher root pubkey
//     baked into the bundle.
//   - When the FRP has an active sub-key, the cert is embedded as
//     subkey_cert (the same FRP-7.5 SubkeyCert format the
//     SBP uses). The signature is by the sub-key. The recipient's
//     core/refresh/verify.go walks pub→cert→sub via the FRP-7.5
//     resolver before accepting the signature.
//
// Backends (publisher/deploy/freshness/backends/):
//
//   - r2/      — Cloudflare R2 (S3-compatible PUT; primary).
//   - ghpages/ — GitHub Pages via repo-content commit (secondary).
//   - ipfs/    — reserved (IPFS pinning); ships with phase doc
//     marked "reserved/disabled" until a maintained pinning surface
//     stabilises.
//
// Network IO is confined to the backend implementations; the
// document builder is pure.

package freshness
