//go:build cshared

// Package abi provides a //export surface for `go build -buildmode=c-shared`
// builds (Tauri sidecar / desktop). Only wired with the cshared tag so the
// default test build is unaffected.
package abi

import "C"

import (
	"unsafe"
)

//export engine_init
func engine_init(stateDir *C.char, logLevel *C.char) C.int {
	if err := Init(C.GoString(stateDir), C.GoString(logLevel)); err != nil {
		return -1
	}
	return 0
}

//export engine_shutdown
func engine_shutdown() C.int {
	if err := Shutdown(); err != nil {
		return -1
	}
	return 0
}

//export engine_version
func engine_version() *C.char {
	return C.CString(VersionString())
}

//export engine_set_route
func engine_set_route(routeID *C.char) C.int {
	if err := SetRoute(C.GoString(routeID)); err != nil {
		return -1
	}
	return 0
}

//export engine_clear_route
func engine_clear_route() C.int {
	if err := ClearRoute(); err != nil {
		return -1
	}
	return 0
}

//export engine_set_mode
func engine_set_mode(mode *C.char) C.int {
	if err := SetMode(C.GoString(mode)); err != nil {
		return -1
	}
	return 0
}

//export engine_apply_cooldown
func engine_apply_cooldown(routeID *C.char, seconds C.int) C.int {
	if err := ApplyCooldown(C.GoString(routeID), int(seconds)); err != nil {
		return -1
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
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_export_diagnostics
func engine_export_diagnostics(out unsafe.Pointer, outLen C.int) C.int {
	body, err := ExportDiagnostics()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}

//export engine_import_sbp
func engine_import_sbp(path *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, _ := ImportSBP(C.GoString(path))
	return copyOut(body, out, outLen)
}

//export engine_resolve_trust_prompt
func engine_resolve_trust_prompt(fingerprint *C.char, decision C.int,
	out unsafe.Pointer, outLen C.int) C.int {
	body, _ := ResolveTrustPrompt(C.GoString(fingerprint), int(decision))
	return copyOut(body, out, outLen)
}

func copyOut(body string, out unsafe.Pointer, outLen C.int) C.int {
	if out == nil || outLen <= 0 {
		return C.int(len(body))
	}
	max := int(outLen) - 1
	if max <= 0 {
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
