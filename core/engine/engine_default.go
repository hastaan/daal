//go:build !singbox

package engine

// NewDefaultDriver returns the engine driver that the ABI should link
// against in the absence of a real data plane. Unit tests, the
// ABI-stability soak, and any release build that has NOT been built
// with `-tags singbox` get the deterministic in-process Stub.
//
// The real sing-box driver lives in engine_singbox.go behind
// `//go:build singbox`. Phase 45 wires it through tools/build-engine-
// android.sh and tools/build-engine-ios.sh, which append `,singbox` to
// `-tags cshared` so the release artefact picks up the real driver
// without disturbing the test build.
func NewDefaultDriver() Driver {
	return NewStub()
}
