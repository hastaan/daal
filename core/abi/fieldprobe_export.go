//go:build cshared

package abi

import "C"

import "unsafe"

// The network test (field probe v2). See fieldprobe.go and
// specs/field-probe-v2.md. Every call writes JSON to a caller-owned
// buffer (copyOut) and returns the bytes written, or -1 for an engine
// that is not initialised or an argument that is not JSON. A refusal is
// NOT -1: it is {"started":false,"refused":"<code>"} /
// {"sealed":false,"refused":"<code>"}.

// engine_field_probe_start starts a run in the background.
//
//	int engine_field_probe_start(const char* opts_json, void* out, int out_len);
//
//	opts_json {"network_label","dns_servers":[…],"private_dns",
//	           "consent_version","vpn_active","ipv6_global","blocked"}
//
//export engine_field_probe_start
func engine_field_probe_start(optsJSON *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := FieldProbeStart(C.GoString(optsJSON))
	if err != nil {
		return exportFail("engine_field_probe_start", err)
	}
	return copyOut(body, out, outLen)
}

// engine_field_probe_status: running progress, the kept result with its
// summary keys, or (idle) what the test would do.
//
//	int engine_field_probe_status(void* out, int out_len);
//
//export engine_field_probe_status
func engine_field_probe_status(out unsafe.Pointer, outLen C.int) C.int {
	body, err := FieldProbeStatus()
	if err != nil {
		return exportFail("engine_field_probe_status", err)
	}
	return copyOut(body, out, outLen)
}

// engine_field_probe_cancel stops a run, keeping its partial result.
// reason: "" | "backgrounded" | "network_changed" | "vpn_active" |
// "connecting". Returns 1 if a run was going, 0 if not.
//
//	int engine_field_probe_cancel(const char* reason);
//
//export engine_field_probe_cancel
func engine_field_probe_cancel(reason *C.char) C.int {
	if FieldProbeCancel(C.GoString(reason)) {
		return 1
	}
	return 0
}

// engine_field_probe_seal writes the sealed report file.
//
//	int engine_field_probe_seal(const char* opts_json, void* out, int out_len);
//
//	opts_json {"notes","transient","out_path","net_kind"} — transient:
//	the engine picks the folder (inside the state directory) and
//	ignores out_path.
//
//export engine_field_probe_seal
func engine_field_probe_seal(optsJSON *C.char, out unsafe.Pointer, outLen C.int) C.int {
	body, err := FieldProbeSeal(C.GoString(optsJSON))
	if err != nil {
		return exportFail("engine_field_probe_seal", err)
	}
	return copyOut(body, out, outLen)
}

// engine_field_probe_discard deletes every kept result and transient
// sealed file. Returns how many results were deleted, or -1.
//
//	int engine_field_probe_discard(void);
//
//export engine_field_probe_discard
func engine_field_probe_discard() C.int {
	n, err := FieldProbeDiscard()
	if err != nil {
		return exportFail("engine_field_probe_discard", err)
	}
	return C.int(n)
}
