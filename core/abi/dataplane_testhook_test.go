package abi

// The ABI's unit tests drive the deterministic engine.Stub, which by
// definition has no data plane, so SetRoute's fail-closed guard would
// short-circuit every test that exercises route activation, posture
// transitions, budgets or refresh. Pin the flag on for the test binary
// — the tests are asserting the ABI's bookkeeping, not the tunnel.
//
// The guard itself is covered by TestSetRoute_FailsClosedWithoutDataPlane
// in dataplane_test.go, which flips the flag back off around one call.
//
// Deliberately untagged so it applies to both `go test ./...` and
// `go test -tags singbox ./...` (the latter also pins the driver back
// to the Stub — see driver_singbox_stub_test.go).
func init() { dataPlaneLinked = true }
