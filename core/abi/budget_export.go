//go:build cshared

package abi

import "C"

import "unsafe"

// engine_set_route_budget (Phase 2A) is the 36th release ABI symbol.
// Validates the tag against the closed budget caps map; returns
// JSON ({"applied":true,...}) on success or
// ({"error":"unknown_budget_tag","tag":"..."}) on rejection.

//export engine_set_route_budget
func engine_set_route_budget(routeID *C.char, budgetTag *C.char,
	out unsafe.Pointer, outLen C.int) C.int {
	body, err := SetRouteBudget(C.GoString(routeID), C.GoString(budgetTag))
	if err != nil && body == "" {
		return -1
	}
	if err != nil {
		// Tag rejection: write the error JSON, return -1 so the host
		// distinguishes from a clean apply.
		_ = copyOut(body, out, outLen)
		return -1
	}
	return copyOut(body, out, outLen)
}
