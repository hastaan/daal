// Package relaypack implements the FRP-4b Helper-side binder.
//
// Lifecycle:
//
//	FRP-4a → FRP-5 → FRP-4b
//	   |        |       |
//	   |        |       └── this package: BindAndSign(rec, priv, opts) → BindResult
//	   |        └────────── desktop wizard: persists rec, custodies priv
//	   └─────────────────── deploy substrate: produces rec
//
// BindAndSign is a pure function over (OperatorRecord, ed25519 private
// key, BindOpts). It enriches every CandidateMeta with the FRP-1
// _relaypack sub-object (per supplement v2.3.7 §12.2.2), builds the
// bundle-level Manifest.relay_pack slot, computes the deterministic
// shared_risk_graph (§12.3), runs relaypackvalidate.Validate against
// the supplied phase BEFORE signing, and emits a deterministic .sbp
// via bundle.BuildSignedBundleDeterministic.
//
// Package boundaries:
//
//   - This package imports `bundle` (the on-disk format) and
//     `relaypackvalidate` (the neutral validator package). It does
//     NOT import `core` or `bundle/go/publisher`. The asymmetric guard
//     locked at FRP-1 stays in force: bundle/ + core/ never import
//     publisher/, and this package is the publisher-side of the bridge.
//
//   - This package has no I/O: BindAndSign returns the .sbp bytes;
//     callers (CLI, desktop wizard) handle file system writes.
//
//   - At V1.5, every candidate is direct_vps. cdn_fronted lands at
//     FRP-8 by widening the FRP-4a candidatesForProfile() generator;
//     this binder needs no change at V1.6 because it carries whatever
//     CandidateMeta.ExposureMode is set to.
//
// Position B: this package opens no network connections, spawns no
// subprocesses, and reads no environment variables. Verified by
// publisher/deploy/opsec_test.go (FRP-4a's regression).
package relaypack
