//go:build cshared

package abi

import "C"

import (
	"time"
	"unsafe"
)

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

// engine_scheduler_tick (Gap 4-recipient) drives one scheduler.Tick
// at the host's wall-clock. The host (the Tauri shell, in
// production) calls this on a ~60 s background timer while the GUI
// is running, so the per-row ProfileUpdateMin cadence in
// scheduler.Plan actually fires. Without a host timer, subscription
// auto-refresh never happens — the existing
// engine_scheduler_status is read-only.
//
// Append-only: this is the 36th release ABI symbol. Returns 0 on
// success, -1 on engine-not-initialized or unrecoverable scheduler
// error.

//export engine_scheduler_tick
func engine_scheduler_tick() C.int {
	if err := SchedulerTick(time.Now().UTC()); err != nil {
		return -1
	}
	return 0
}
