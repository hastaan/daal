// Command wb-client is worldbox's stand-in for the PHONE: the Android
// shell around the engine, not the engine.
//
// It links the same daal/core/abi the Android .so exports and drives it
// through the same five calls DaalVpnService.kt makes, in the same order:
//
//	registerProtectCallback → establish TUN → engine_set_tun_fd →
//	engine_set_route → (traffic) → engine_clear_route
//
// What it supplies is exactly what the Android platform supplies and the
// engine cannot: a TUN file descriptor, per-uid routing that sends every
// other app's traffic into it, and the exclusion of its own uid that
// keeps the engine's upstream sockets out of it. Nothing is added to the engine to make this
// possible — no lab inbound, no build tag in core/ — which is why this
// lives in a test-rig binary that the release build never sees
// (driver/isolation_test.go proves it).
//
// It only does anything under `-tags singbox` with cgo on Linux; the
// default build is a stub so `go vet ./...` stays cheap and green.
package main
