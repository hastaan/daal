//go:build cshared

package abi

import "C"

import "unsafe"

// engine_scheduler_status (Phase 2F) is the 35th release ABI symbol.
// It returns a JSON snapshot — see core/scheduler.Scheduler.StatusJSON
// for the schema.

//export engine_scheduler_status
func engine_scheduler_status(out unsafe.Pointer, outLen C.int) C.int {
	body, err := SchedulerStatus()
	if err != nil {
		return -1
	}
	return copyOut(body, out, outLen)
}
