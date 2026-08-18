// Wave 5 (transport families). The two refraction-family
// compile-in flags, and the record of why they are constants.
//
// WHAT THESE FLAGS CLAIM. `psiphon_compiled_in` and
// `conjure_compiled_in` are surfaced verbatim in
// `ExportDiagnostics`. Their documented meaning is "the running
// binary links the vendored tree for this family" —
// psiphon-tunnel-core for the first, gotapdance for the second.
// That is a claim about `core/go.mod`, and it is checkable.
//
// WHAT WAS ACTUALLY TRUE. Neither tree has ever been in the
// module graph. `core/go.mod` requires bundle-go, age, sing-box,
// wazero, x/crypto and modernc sqlite; there is no
// psiphon-tunnel-core and no gotapdance, direct or indirect.
// Phase 3D nonetheless shipped `psiphonCompiledIn = true` behind
// a `!no_psiphon` build tag and `conjureCompiledIn = true`
// unconditionally, so every diagnostics blob a user could export
// asserted that two vendor trees were linked into a binary that
// did not contain a single line of either. The `-tags no_psiphon`
// build that was supposed to flip the first flag is not passed by
// `tools/build-engine-android.sh` or `tools/build-engine-ios.sh`
// — no shipped build has ever set it — so the false branch was
// unreachable in practice as well as untrue in principle.
//
// WHY THEY ARE NOW CONSTANT false, AND NOT A BUILD-TAG PAIR.
// Neither tree is arriving, and the reason is a property of the
// protocol rather than a backlog item (both reasons are written
// out in full on the enum values in
// `bundle/go/bundle/types.go`):
//
//   - psiphon is a third party's proprietary NETWORK. A
//     self-hosted publisher can hand a client off to Psiphon
//     Inc.'s infrastructure; it cannot run it. Vendoring the
//     GPLv3 client would change the licence posture of the whole
//     binary and still leave nothing for a publisher to deploy.
//
//   - conjure is refraction networking. It requires a
//     COOPERATING ISP operating a refraction station on a transit
//     link, answering for unused addresses in that ISP's own
//     space. A publisher renting a VPS has neither. The client
//     half is inert without the station.
//
// A build tag whose false branch is the only reachable branch is
// a worse lie than a constant, so the tag pair is gone. If either
// tree ever does land, this file is the place that has to change,
// and the change is one word each.
//
// The KEY NAMES are deliberately unchanged. They are consumed by
// `test-rigs/distribution-failure` and documented in
// specs/psiphon-route-v1.md, specs/conjure-route-v1.md and
// specs/engine-abi-v1.md; the names were never the problem, the
// values were.

package abi

const psiphonCompiledIn = false

const conjureCompiledIn = false
