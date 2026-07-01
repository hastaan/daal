package engine

import (
	"sync/atomic"
)

// platform.go owns the two pieces of host-supplied state the singBox
// driver consumes at Start time: the TUN file descriptor and the
// protect-callback C function pointer. The ABI layer pushes both into
// these atomics (CurrentTunFD / CurrentProtectCallback are the read
// path) so the engine package never has to import core/abi — that
// import cycle is the reason the values live here and not in abi.
//
// Phase 45 (data plane) writes happen from:
//   - abi.SetTunFD       → SetCurrentTunFD(fd)
//   - abi.ClearTunFD     → SetCurrentTunFD(-1)
//   - abi.RegisterProtectCallback → SetCurrentProtectCallback(ptr)
//
// Reads happen from engine_singbox.go's singBox.Start when assembling
// the TUN inbound and the upstream-socket protect closure.

var (
	currentTunFD          atomic.Int32
	currentProtectCBPtr   atomic.Uintptr
)

func init() {
	currentTunFD.Store(-1)
}

// SetCurrentTunFD is called by the abi layer when the host hands a new
// fd in (or by abi.Clear with fd == -1). The engine does NOT own the
// lifetime of fd here; ownership semantics are enforced inside the
// abi.SetTunFD / abi.ClearTunFD wrappers.
func SetCurrentTunFD(fd int) {
	currentTunFD.Store(int32(fd))
}

// CurrentTunFD returns the latest fd handed in by the host, or -1.
func CurrentTunFD() int {
	return int(currentTunFD.Load())
}

// SetCurrentProtectCallback stores the C function pointer the host
// registered. ptr == 0 clears the binding.
func SetCurrentProtectCallback(ptr uintptr) {
	currentProtectCBPtr.Store(ptr)
}

// CurrentProtectCallback returns the registered pointer; the singBox
// driver dereferences it via cgo. Returns 0 if no callback is set.
func CurrentProtectCallback() uintptr {
	return currentProtectCBPtr.Load()
}
