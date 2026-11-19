package abi

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"

	"daal/core/engine"
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

// rawPipe returns the read end of a pipe as a bare fd number. Bare on
// purpose: an *os.File would close the number again from its finalizer,
// which is the very double close these tests are about.
func rawPipe(t *testing.T) int {
	t.Helper()
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(p[1]) })
	return p[0]
}

// TestSetTunFdOwnershipSemantics pins who closes what.
//
// engine_set_tun_fd takes ownership of the HOST's copy and the engine
// closes that copy exactly once: when a later set replaces it, or on
// engine_clear_tun_fd. A running instance never works on that number —
// it holds a duplicate (engine.androidPlatform.OpenInterface) that only
// the instance closes. So a rotate and a clear must leave a duplicate
// taken earlier fully usable, and must never close a number twice.
//
// (This test used to assert only "rotate closes the previous fd", which
// was true and was the bug: the old instance was still running on that
// same number and closed it again later.)
func TestSetTunFdOwnershipSemantics(t *testing.T) {
	resetTunFDForShutdown()
	t.Cleanup(resetTunFDForShutdown)

	drv := &mockTunFDDriver{}
	RegisterTunFDDriver(drv)

	fd1 := rawPipe(t)
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
	if engine.CurrentTunFD() != fd1 {
		t.Fatalf("engine sees TUN fd %d, want %d", engine.CurrentTunFD(), fd1)
	}
	// The instance running on TUN 1 holds its own copy.
	inst1, err := syscall.Dup(fd1)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	defer syscall.Close(inst1)

	// Rotate: the host's previous copy is closed; the instance's is not.
	fd2 := rawPipe(t)
	if _, err := SetTunFD(fd2); err != nil {
		t.Fatalf("SetTunFD(fd2) error: %v", err)
	}
	if fdIsOpen(fd1) {
		t.Fatalf("rotate did not close the host's previous copy fd1 (%d)", fd1)
	}
	if !fdIsOpen(inst1) {
		t.Fatalf("rotate closed the running instance's own copy (%d)", inst1)
	}
	if !fdIsOpen(fd2) {
		t.Fatalf("fd2 (%d) closed prematurely after rotate", fd2)
	}

	// The number fd1 had is now free and is reused by something
	// unrelated. Nothing the engine does from here may close it.
	unrelated, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer syscall.Close(unrelated)
	if unrelated != fd1 {
		if err := syscall.Dup2(unrelated, fd1); err != nil {
			t.Fatalf("dup2: %v", err)
		}
		defer syscall.Close(fd1)
	}

	// Setting the SAME fd again is not a rotate and closes nothing.
	if _, err := SetTunFD(fd2); err != nil {
		t.Fatalf("SetTunFD(fd2) again: %v", err)
	}
	if !fdIsOpen(fd2) {
		t.Fatalf("re-setting the current fd closed it (%d)", fd2)
	}

	inst2, err := syscall.Dup(fd2)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	defer syscall.Close(inst2)

	// Clear: the engine closes the host's current copy, once.
	if _, err := ClearTunFD(); err != nil {
		t.Fatalf("ClearTunFD: %v", err)
	}
	if fdIsOpen(fd2) {
		t.Fatalf("ClearTunFD did not close fd2 (%d)", fd2)
	}
	if !fdIsOpen(inst2) {
		t.Fatalf("ClearTunFD closed an instance's own copy (%d)", inst2)
	}
	if atomic.LoadInt32(&drv.clearN) != 1 {
		t.Fatalf("expected one OnClearTunFD call, got %d", drv.clearN)
	}
	if engine.CurrentTunFD() != -1 {
		t.Fatalf("engine still sees TUN fd %d after clear", engine.CurrentTunFD())
	}

	// fd2's number is reused too; a second clear and a shutdown reset
	// must both be no-ops for it.
	again, err := syscall.Open("/dev/null", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer syscall.Close(again)
	if again != fd2 {
		if err := syscall.Dup2(again, fd2); err != nil {
			t.Fatalf("dup2: %v", err)
		}
		defer syscall.Close(fd2)
	}
	if _, err := ClearTunFD(); err != nil {
		t.Fatalf("second ClearTunFD: %v", err)
	}
	resetTunFDForShutdown()
	if !fdIsOpen(fd2) {
		t.Fatalf("a second clear / shutdown closed fd %d again after it had been reused", fd2)
	}
	if !fdIsOpen(fd1) {
		t.Fatalf("an unrelated file on the first TUN's old number (%d) was closed", fd1)
	}
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

	fd := rawPipe(t)
	defer syscall.Close(fd)

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
