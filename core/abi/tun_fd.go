package abi

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"

	"daal/core/engine"
)

// Phase 45 — TUN fd handoff + VpnService.protect() callback.
//
// The Android VpnService gives us a TUN file descriptor via
// `Builder.establish() → ParcelFileDescriptor.detachFd()`. The Linux
// privileged tun-helper gives us one via SCM_RIGHTS over a Unix
// abstract socket. On both platforms the same engine_set_tun_fd ABI
// receives that fd and the in-process sing-box driver consumes it as
// its TUN inbound. The engine takes ownership of the fd; the caller
// MUST NOT close it after a successful set call.
//
// engine_register_protect_callback wires a C function pointer that the
// driver invokes for every upstream socket it opens, so the host
// (Android: VpnService.protect; Linux: a no-op) can exclude the
// socket from the TUN before its first dial. The callback signature
// is `int (*)(int fd)` — non-zero return == "protect succeeded";
// zero == "protect failed, driver should refuse to use this socket".
//
// Privacy invariants:
//   - The fd never leaves the engine process; it crosses the ABI as
//     an int handle and is then claimed by the driver's syscall path.
//   - The protect callback receives only the int fd; the host never
//     sees the destination address.
//   - All three calls are idempotent; clear is safe to call without
//     a prior set; setting twice rotates the fd (the old one is
//     closed).

// TunFDDriver is the driver-side hook the singBox engine implements.
// The Stub leaves it as a no-op; the real driver in
// core/engine/engine_singbox.go installs a closure that re-builds the
// TUN inbound when the fd changes.
//
// We deliberately do not extend engine.Driver itself with these
// methods — they belong to the singBox driver only, and the ABI
// reaches them via a registered hook rather than a type assertion so
// the ABI doesn't import the singbox-tagged package.
type TunFDDriver interface {
	OnTunFD(fd int) error
	OnClearTunFD() error
}

// ProtectCallback is the host-supplied excluder. The driver calls it
// before connecting/sending from a freshly opened upstream socket.
type ProtectCallback func(fd int) bool

var (
	tunFDMu       sync.Mutex
	tunFDCurrent  int = -1
	tunFDOwned    bool
	tunFDDriverHk TunFDDriver

	protectCallbackPtr atomic.Uintptr // C function pointer; 0 = unset
)

// RegisterTunFDDriver is called by the driver constructor (engine_singbox.go)
// so the ABI knows where to forward fd events. The Stub does not call
// this; tests inject their own hook via SetTunFDDriverForTest.
func RegisterTunFDDriver(d TunFDDriver) {
	tunFDMu.Lock()
	tunFDDriverHk = d
	tunFDMu.Unlock()
}

// SetTunFDDriverForTest is the test-only seam.
func SetTunFDDriverForTest(d TunFDDriver) { RegisterTunFDDriver(d) }

// SetTunFD takes ownership of fd, hands it to the registered driver,
// and returns a small JSON envelope. After a successful return the
// caller MUST NOT close(fd).
func SetTunFD(fd int) (string, error) {
	if fd < 0 {
		return "", fmt.Errorf("abi: invalid tun fd %d", fd)
	}
	tunFDMu.Lock()
	previous := tunFDCurrent
	previousOwned := tunFDOwned
	tunFDCurrent = fd
	tunFDOwned = true
	hook := tunFDDriverHk
	tunFDMu.Unlock()

	if previousOwned && previous >= 0 && previous != fd {
		// Rotate: close the old fd before installing the new one.
		_ = syscall.Close(previous)
	}

	// Mirror to the engine-side atomic so the singBox driver picks
	// the fd up at its next Start() without an import cycle.
	engine.SetCurrentTunFD(fd)

	if hook != nil {
		if err := hook.OnTunFD(fd); err != nil {
			// Driver rejected the fd — release ownership and surface
			// the error so the host can close its dup.
			tunFDMu.Lock()
			tunFDCurrent = -1
			tunFDOwned = false
			tunFDMu.Unlock()
			engine.SetCurrentTunFD(-1)
			return "", err
		}
	}

	body, _ := json.Marshal(map[string]any{
		"applied": true,
		"fd":      fd,
	})
	return string(body), nil
}

// ClearTunFD asks the driver to stop using the fd, then closes it. Safe
// to call even if no fd was set.
func ClearTunFD() (string, error) {
	tunFDMu.Lock()
	fd := tunFDCurrent
	owned := tunFDOwned
	hook := tunFDDriverHk
	tunFDCurrent = -1
	tunFDOwned = false
	tunFDMu.Unlock()

	if hook != nil {
		_ = hook.OnClearTunFD()
	}
	if owned && fd >= 0 {
		_ = syscall.Close(fd)
	}
	engine.SetCurrentTunFD(-1)
	body, _ := json.Marshal(map[string]any{
		"cleared": true,
	})
	return string(body), nil
}

// RegisterProtectCallback stores the C function pointer the driver
// will call for each upstream socket. ptr == 0 clears the binding.
func RegisterProtectCallback(ptr uintptr) (string, error) {
	protectCallbackPtr.Store(ptr)
	engine.SetCurrentProtectCallback(ptr)
	body, _ := json.Marshal(map[string]any{
		"registered": ptr != 0,
	})
	return string(body), nil
}

// CurrentProtectCallback returns the registered pointer; the singBox
// driver dereferences it via cgo. Returns 0 if no callback is set.
func CurrentProtectCallback() uintptr {
	return protectCallbackPtr.Load()
}

// CurrentTunFD returns the current fd or -1 if none. Used by the
// singBox driver to (re)attach a TUN inbound after a hot driver swap.
func CurrentTunFD() int {
	tunFDMu.Lock()
	defer tunFDMu.Unlock()
	return tunFDCurrent
}

// resetTunFDForShutdown is called from Shutdown so a subsequent Init()
// in the same process starts fresh.
func resetTunFDForShutdown() {
	tunFDMu.Lock()
	fd := tunFDCurrent
	owned := tunFDOwned
	tunFDCurrent = -1
	tunFDOwned = false
	tunFDDriverHk = nil
	tunFDMu.Unlock()
	if owned && fd >= 0 {
		_ = syscall.Close(fd)
	}
	protectCallbackPtr.Store(0)
	engine.SetCurrentTunFD(-1)
	engine.SetCurrentProtectCallback(0)
}
