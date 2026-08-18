package abi

import (
	"errors"

	"daal/core/engine"
)

// dataPlaneLinked mirrors engine.HasRealDataPlane — a compile-time
// fact, not a runtime probe. It is a var only so the package's own
// tests can pin it (see dataplane_testhook_test.go); nothing in
// production writes it.
//
// WHY THIS EXISTS. `newEngineDriver` resolves to engine.NewStub() on
// every build that lacks `-tags singbox`, and Stub.Start() returns nil
// and publishes a "Connected" state event without touching the
// network. SetRoute then calls pm.Connected() and advances the posture
// to ImportedActive, which the GUIs map straight onto "Connected ·
// Routing" (client-ui/src/backends/tauri.ts postureToConnState). The
// desktop is exactly such a build: every route by which the desktop
// engine is actually produced compiles ./cmd/libdaalcore with `-tags
// cshared` and nothing else, so a desktop user could press Connect, be
// told they were connected, and browse in the clear.
//
// The tag set per artefact, for the record (verified by reading each
// build site, not by recollection — there is no `daal build` command):
//
//	tools/build-engine-android.sh   cshared,singbox,...  real
//	tools/build-engine-ios.sh       cshared,singbox,...  real
//	appveyor.yml:252 (Windows .dll) cshared              STUB
//	appveyor.yml:339 (macOS .dylib) cshared              STUB
//	client-shell/tauri/README.md    cshared              STUB
//	tools/preflight-appveyor.py:257 cshared              STUB
//
// Fixing the desktop's data plane is a wave of its own. Fixing the LIE
// is not, so SetRoute refuses to activate a route on a build that
// cannot carry it.
var dataPlaneLinked = engine.HasRealDataPlane

// ErrNoDataPlane is returned by SetRoute when the running binary has no
// data plane linked. The message is user-facing (it reaches the GUI via
// the C ABI error string) and deliberately says what is missing rather
// than failing with a generic error.
var ErrNoDataPlane = errors.New(
	"abi: no data plane linked in this build — this binary cannot carry traffic, " +
		"so it refuses to report a connection it does not have " +
		"(rebuild libdaalcore with -tags singbox)")

// DataPlaneKind is the value rendered as `data_plane` in the
// diagnostics blob. "singbox" means a real in-process data plane is
// linked; "none" means the Stub is linked and the binary cannot tunnel.
//
// Surfacing this lets a GUI warn BEFORE the user presses Connect
// instead of only reacting to the refusal.
func DataPlaneKind() string {
	if dataPlaneLinked {
		return "singbox"
	}
	return "none"
}
