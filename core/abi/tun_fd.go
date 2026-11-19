package abi

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

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
// Ownership inside the engine: the fd handed in here is closed exactly
// once, by core/engine (AdoptTunFD on a rotate, ReleaseTunFD on clear
// or shutdown). A running sing-box instance never uses that number: it
// is given a duplicate, which it alone closes. See engine/platform.go.
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
	tunFDCurrent = fd
	hook := tunFDDriverHk

	// The engine package owns the host's copy from here and is the only
	// thing that ever closes it (engine/platform.go, "ONE OWNER PER
	// COPY"). On a rotate it closes the copy this one replaces — the
	// HOST's previous copy only: a sing-box instance still running on
	// the previous TUN holds a duplicate of its own, which it closes
	// when it is torn down. Done under tunFDMu so two concurrent sets
	// cannot leave abi and engine disagreeing about which fd is current.
	engine.AdoptTunFD(fd)
	tunFDMu.Unlock()

	if hook != nil {
		if err := hook.OnTunFD(fd); err != nil {
			// Driver rejected the fd — give it back unclosed and
			// surface the error so the host can close its copy. Only
			// if it is still the current one: a newer set owns its own.
			tunFDMu.Lock()
			if tunFDCurrent == fd {
				tunFDCurrent = -1
				engine.DisownTunFD()
			}
			tunFDMu.Unlock()
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
	hook := tunFDDriverHk
	tunFDCurrent = -1
	// Closes the host's copy, once. A sing-box instance that is still
	// up (ClearRoute normally ran first and stopped it) keeps working on
	// its own duplicate until it is closed.
	engine.ReleaseTunFD()
	tunFDMu.Unlock()

	if hook != nil {
		_ = hook.OnClearTunFD()
	}
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
	tunFDCurrent = -1
	tunFDDriverHk = nil
	engine.ReleaseTunFD()
	tunFDMu.Unlock()
	protectCallbackPtr.Store(0)
	engine.SetCurrentProtectCallback(0)
}
