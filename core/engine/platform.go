package engine

import (
	"errors"
	"sync"
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
//   - abi.SetTunFD       → AdoptTunFD(fd)
//   - abi.ClearTunFD     → ReleaseTunFD()
//   - abi.RegisterProtectCallback → SetCurrentProtectCallback(ptr)
//
// Reads happen from engine_singbox.go's singBox.Start when assembling
// the TUN inbound and the upstream-socket protect closure.

var (
	// tunMu guards the TUN fd: installing it, releasing it, and — the
	// reason it exists — duplicating it for a sing-box instance. The fd
	// NUMBER is only meaningful while the host's copy is open, so the
	// dup in dupTunFD and the close in ReleaseTunFD/AdoptTunFD must not
	// interleave: a number read here, closed there and reused by any
	// other open() in the process would hand sing-box a database file
	// as its TUN.
	tunMu               sync.Mutex
	currentTunFD        atomic.Int32
	currentTunOwned     bool
	currentProtectCBPtr atomic.Uintptr
)

func init() {
	currentTunFD.Store(-1)
}

// TUN fd ownership — ONE OWNER PER COPY.
//
//   - The copy the host handed over (engine_set_tun_fd) belongs to this
//     file. It is closed exactly once: by the AdoptTunFD that replaces
//     it, or by ReleaseTunFD. Nothing else closes that number.
//   - Every sing-box instance gets a duplicate of its own
//     (androidPlatform.OpenInterface → dupTunFD). sing-tun wraps the
//     duplicate in an os.File and closes it when the instance closes.
//
// Before this, both sides closed the SAME number: abi on rotate/clear,
// sing-tun when the old instance was torn down. Between the two closes
// the number was free, the process's next open() got it (the route
// store's SQLite file, in practice), and the second close shut that —
// which is how a route switch on a phone left the tunnel carrying
// traffic and every store-backed screen dead.

// AdoptTunFD takes ownership of fd as the host's current TUN and closes
// the one it replaces (if it was owned and is a different number).
func AdoptTunFD(fd int) {
	tunMu.Lock()
	defer tunMu.Unlock()
	prev, prevOwned := int(currentTunFD.Load()), currentTunOwned
	currentTunFD.Store(int32(fd))
	currentTunOwned = fd >= 0
	if prevOwned && prev >= 0 && prev != fd {
		_ = closeFD(prev)
	}
}

// ReleaseTunFD closes the host's current TUN fd, if this file owns one.
// Instances already running keep their own duplicates until they close.
func ReleaseTunFD() {
	tunMu.Lock()
	defer tunMu.Unlock()
	fd, owned := int(currentTunFD.Load()), currentTunOwned
	currentTunFD.Store(-1)
	currentTunOwned = false
	if owned && fd >= 0 {
		_ = closeFD(fd)
	}
}

// DisownTunFD forgets the current fd WITHOUT closing it: the host keeps
// it (engine_set_tun_fd failed, and the contract there is that a failed
// set leaves the fd the caller's).
func DisownTunFD() {
	tunMu.Lock()
	defer tunMu.Unlock()
	currentTunFD.Store(-1)
	currentTunOwned = false
}

// dupTunFD returns a duplicate of the current TUN fd for one sing-box
// instance to own. The caller closes it on every path that does not
// hand it to something that will.
func dupTunFD() (int, error) {
	tunMu.Lock()
	defer tunMu.Unlock()
	fd := int(currentTunFD.Load())
	if fd < 0 {
		return -1, errTunFDNotSet
	}
	return dupFD(fd)
}

var errTunFDNotSet = errors.New("engine: TUN fd not set; host must call engine_set_tun_fd before engine_set_route")

// SetCurrentTunFD records fd as the current TUN WITHOUT taking
// ownership of it (nothing here will ever close it). Tests use it; the
// ABI goes through AdoptTunFD / ReleaseTunFD.
func SetCurrentTunFD(fd int) {
	tunMu.Lock()
	defer tunMu.Unlock()
	currentTunFD.Store(int32(fd))
	currentTunOwned = false
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
