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

// HasRealDataPlane reports whether this build links a data plane that
// can actually carry a user's traffic.
//
// It is FALSE here, and that is not a detail: without `-tags singbox`
// the Driver is the deterministic Stub, whose Start() returns nil and
// publishes a "Connected" state event without opening a socket. The
// ABI consumes this constant (core/abi/dataplane.go) to fail SetRoute
// closed, because a censorship-circumvention client that renders
// "Connected" while traffic is in the clear is worse than one that
// refuses to connect.
const HasRealDataPlane = false

// HasByteAccounting reports whether this build can count the bytes that
// actually crossed the tunnel. It is the twin of HasRealDataPlane, and
// it exists for the same reason: a UI must be able to tell "no traffic
// moved" apart from "nobody is counting".
//
// FALSE here because the Stub carries no traffic at all — Stub.Stats()
// returns (0, 0, nil) unconditionally (engine.go). The sing-box build
// declares its own value; see engine_singbox.go.
const HasByteAccounting = false
