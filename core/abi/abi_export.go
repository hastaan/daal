//go:build cshared

// Package abi provides a //export surface for `go build -buildmode=c-shared`
// builds (Tauri sidecar / desktop). Only wired with the cshared tag so the
// default test build is unaffected.
package abi

import "C"

import (
	"fmt"
	"unsafe"
)

//export engine_init
func engine_init(stateDir *C.char, logLevel *C.char) C.int {
	if err := Init(C.GoString(stateDir), C.GoString(logLevel)); err != nil {
		return exportFail("engine_init", err)
	}
	return 0
}

//export engine_shutdown
func engine_shutdown() C.int {
	if err := Shutdown(); err != nil {
		return exportFail("engine_shutdown", err)
	}
	return 0
}

//export engine_version
func engine_version() *C.char {
	return C.CString(VersionString())
}

//export engine_set_route
func engine_set_route(routeID *C.char) C.int {
	id := C.GoString(routeID)
	if err := SetRoute(id); err != nil {
		return exportRouteFail("engine_set_route", id, err)
	}
	return 0
}

//export engine_clear_route
func engine_clear_route() C.int {
	if err := ClearRoute(); err != nil {
		return exportFail("engine_clear_route", err)
	}
	return 0
}

//export engine_set_mode
func engine_set_mode(mode *C.char) C.int {
	if err := SetMode(C.GoString(mode)); err != nil {
		return exportFail("engine_set_mode", err)
	}
	return 0
}

//export engine_apply_cooldown
func engine_apply_cooldown(routeID *C.char, seconds C.int) C.int {
	if err := ApplyCooldown(C.GoString(routeID), int(seconds)); err != nil {
		return exportFail("engine_apply_cooldown", err)
	}
	return 0
}

//export engine_probe_udp
func engine_probe_udp(timeoutMs C.int) C.int { return C.int(ProbeUDP(int(timeoutMs))) }

//export engine_probe_dns
func engine_probe_dns(timeoutMs C.int) C.int { return C.int(ProbeDNS(int(timeoutMs))) }

//export engine_probe_tcp443
func engine_probe_tcp443(timeoutMs C.int) C.int { return C.int(ProbeTCP443(int(timeoutMs))) }

//export engine_stats_redacted
func engine_stats_redacted(out unsafe.Pointer, outLen C.int) C.int {
	body, err := StatsRedacted()
	if err != nil {
		return exportFail("engine_stats_redacted", err)
	}
	return copyOut(body, out, outLen)
}

//export engine_export_diagnostics
func engine_export_diagnostics(out unsafe.Pointer, outLen C.int) C.int {
	body, err := ExportDiagnostics()
	if err != nil {
		return exportFail("engine_export_diagnostics", err)
	}
	return copyOut(body, out, outLen)
}

//export engine_import_sbp
func engine_import_sbp(path *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := ImportSBP(C.GoString(path))
	if err != nil {
		// The verdict JSON is the answer; the error is only noted.
		noteExportError("engine_import_sbp", err)
	}
	return copyOut(body, out, outLen)
}

//export engine_resolve_trust_prompt
func engine_resolve_trust_prompt(fingerprint *C.char, decision C.int,
	out unsafe.Pointer, outLen C.int) C.int {
	body, err := ResolveTrustPrompt(C.GoString(fingerprint), int(decision))
	if err != nil {
		noteExportError("engine_resolve_trust_prompt", err)
	}
	return copyOut(body, out, outLen)
}

// exportFail is the ONE way an export wrapper returns -1 for a Go
// error: it records "engine_<name>: <scrubbed error>" in the engine log
// and in the recent-errors ring (export_errors.go) and returns -1. A
// wrapper must not `return -1` for an error any other way, or the
// failure is invisible again.
func exportFail(call string, err error) C.int {
	noteExportError(call, err)
	return -1
}

// exportRouteFail is exportFail for engine_set_route: the route id and
// a closed code only — never the error text, which can carry the
// relay's address.
func exportRouteFail(call, routeID string, err error) C.int {
	noteRouteError(call, routeID, err)
	return -1
}

// exportFailCode is exportFail for the wrappers whose negative code
// carries meaning (-2 wrong profile, -4 bad argument, …) or that fail
// without a Go error in hand.
func exportFailCode(call string, code C.int, what string) C.int {
	noteExportFailure(call, what)
	return code
}

// exportCode passes through the status code of a setter that returns
// one, recording it when it is negative.
func exportCode(call string, code int) C.int {
	if code < 0 {
		noteExportFailure(call, fmt.Sprintf("refused with code %d", code))
	}
	return C.int(code)
}

// exportNotReady is the "engine_init has not completed" exit.
func exportNotReady(call string) C.int {
	return exportFailCode(call, -1, "engine not initialized")
}

func copyOut(body string, out unsafe.Pointer, outLen C.int) C.int {
	if out == nil || outLen <= 0 {
		return C.int(len(body))
	}
	max := int(outLen) - 1
	if max <= 0 {
		noteExportFailure("copy_out", "output buffer too small")
		return -2
	}
	n := len(body)
	if n > max {
		n = max
	}
	dst := unsafe.Slice((*byte)(out), int(outLen))
	copy(dst, body[:n])
	dst[n] = 0
	return C.int(n)
}

// The c-shared wrapper lives in cmd/libdaalcore; this file only
// declares //export symbols.
