package abi

import (
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// mockTunFDDriver records OnTunFD / OnClearTunFD calls so the test can
// assert the ABI's hand-off semantics without pulling in a real driver.
type mockTunFDDriver struct {
	setFD    int32
	clearN   int32
	failNext atomic.Bool
}

func (m *mockTunFDDriver) OnTunFD(fd int) error {
	if m.failNext.Load() {
		m.failNext.Store(false)
		return errors.New("driver: rejected")
	}
	atomic.StoreInt32(&m.setFD, int32(fd))
	return nil
}

func (m *mockTunFDDriver) OnClearTunFD() error {
	atomic.AddInt32(&m.clearN, 1)
	return nil
}

// fdIsOpen tries fcntl(F_GETFD); EBADF means closed.
func fdIsOpen(fd int) bool {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return errno == 0
}

// TestSetTunFdOwnershipSemantics pins Phase 45 invariant 3:
// engine_set_tun_fd takes ownership; the engine closes it on
// engine_clear_tun_fd. A subsequent set with a different fd rotates
// (the previous fd is closed).
func TestSetTunFdOwnershipSemantics(t *testing.T) {
	resetTunFDForShutdown()
	t.Cleanup(resetTunFDForShutdown)

	drv := &mockTunFDDriver{}
	RegisterTunFDDriver(drv)

	// Open a real fd via pipe(2) so the close assertion is meaningful.
	r1, w1, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer w1.Close() // we only care about the read end's fd
	fd1 := int(r1.Fd())

	body, err := SetTunFD(fd1)
	if err != nil {
		t.Fatalf("SetTunFD(fd1) error: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode SetTunFD body: %v (%q)", err, body)
	}
	if env["applied"] != true {
		t.Fatalf("expected applied=true, got %v", env)
	}
	if int(atomic.LoadInt32(&drv.setFD)) != fd1 {
		t.Fatalf("driver did not see fd1; got %d", drv.setFD)
	}
	if !fdIsOpen(fd1) {
		t.Fatalf("fd1 (%d) closed prematurely", fd1)
	}

	// Rotate: set a fresh fd; previous should be closed.
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	defer w2.Close()
	fd2 := int(r2.Fd())

	if _, err := SetTunFD(fd2); err != nil {
		t.Fatalf("SetTunFD(fd2) error: %v", err)
	}
	if fdIsOpen(fd1) {
		t.Fatalf("rotate did not close previous fd1 (%d)", fd1)
	}
	if !fdIsOpen(fd2) {
		t.Fatalf("fd2 (%d) closed prematurely after rotate", fd2)
	}

	// Clear: engine closes the current fd.
	if _, err := ClearTunFD(); err != nil {
		t.Fatalf("ClearTunFD: %v", err)
	}
	if fdIsOpen(fd2) {
		t.Fatalf("ClearTunFD did not close fd2 (%d)", fd2)
	}
	if atomic.LoadInt32(&drv.clearN) != 1 {
		t.Fatalf("expected one OnClearTunFD call, got %d", drv.clearN)
	}

	// Idempotency: second clear is a no-op.
	if _, err := ClearTunFD(); err != nil {
		t.Fatalf("second ClearTunFD: %v", err)
	}

	// File descriptors are claimed; mark the *os.File so finalizers
	// don't double-close.
	_ = r1
	_ = r2
}

// TestSetTunFdReleasesOwnershipOnDriverFailure: when the driver
// rejects the fd, the ABI must NOT keep it; the host can safely close
// its dup.
func TestSetTunFdReleasesOwnershipOnDriverFailure(t *testing.T) {
	resetTunFDForShutdown()
	t.Cleanup(resetTunFDForShutdown)

	drv := &mockTunFDDriver{}
	drv.failNext.Store(true)
	RegisterTunFDDriver(drv)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	fd := int(r.Fd())

	if _, err := SetTunFD(fd); err == nil {
		t.Fatal("expected SetTunFD to surface driver error")
	}
	if CurrentTunFD() != -1 {
		t.Fatalf("ABI still owns fd after rejection: %d", CurrentTunFD())
	}
	if !fdIsOpen(fd) {
		t.Fatalf("ABI closed fd despite rejection (%d)", fd)
	}
}

// TestSetTunFdRejectsNegative pins the obvious foot-gun.
func TestSetTunFdRejectsNegative(t *testing.T) {
	resetTunFDForShutdown()
	t.Cleanup(resetTunFDForShutdown)

	if _, err := SetTunFD(-1); err == nil {
		t.Fatal("expected SetTunFD(-1) to error")
	}
}

// TestProtectCallbackRegistration pins Phase 45 invariant 4: the host
// can register a C function pointer the singBox driver uses to exclude
// upstream sockets from the TUN. The pointer is opaque to the ABI;
// here we use a sentinel address and assert round-tripping.
func TestProtectCallbackRegistration(t *testing.T) {
	resetTunFDForShutdown()
	t.Cleanup(resetTunFDForShutdown)

	if CurrentProtectCallback() != 0 {
		t.Fatalf("expected no callback at start, got %x", CurrentProtectCallback())
	}

	const sentinel uintptr = 0xC0FFEE_F00D
	body, err := RegisterProtectCallback(sentinel)
	if err != nil {
		t.Fatalf("RegisterProtectCallback: %v", err)
	}
	var env map[string]any
	_ = json.Unmarshal([]byte(body), &env)
	if env["registered"] != true {
		t.Fatalf("expected registered=true, got %v", env)
	}
	if got := CurrentProtectCallback(); got != sentinel {
		t.Fatalf("expected %x got %x", sentinel, got)
	}

	// Pass 0 to clear.
	if _, err := RegisterProtectCallback(0); err != nil {
		t.Fatalf("clear RegisterProtectCallback: %v", err)
	}
	if CurrentProtectCallback() != 0 {
		t.Fatalf("expected callback cleared, got %x", CurrentProtectCallback())
	}
}
