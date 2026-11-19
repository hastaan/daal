//go:build singbox && linux

package engine

import (
	"errors"
	"sync"
	"testing"

	boxoption "github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

// These tests drive the REAL androidPlatform.OpenInterface and the real
// sing-tun (tun.New wraps the fd it is given in an os.File and closes
// it on Close — exactly what a sing-box instance does at teardown). The
// "TUN" is the read end of a pipe: with a file descriptor supplied
// sing-tun performs no ioctl on it, so any fd exercises the ownership
// code. What cannot be had in a unit test is a kernel TUN device.

// closeCounter wraps closeFD and records every close by fd number.
type closeCounter struct {
	mu     sync.Mutex
	closes map[int]int
	failed []int // closes that returned an error (EBADF = closed twice)
}

func countCloses(t *testing.T) *closeCounter {
	t.Helper()
	cc := &closeCounter{closes: map[int]int{}}
	orig := closeFD
	closeFD = func(fd int) error {
		err := orig(fd)
		cc.mu.Lock()
		cc.closes[fd]++
		if err != nil {
			cc.failed = append(cc.failed, fd)
		}
		cc.mu.Unlock()
		return err
	}
	t.Cleanup(func() { closeFD = orig })
	return cc
}

func pipeRead(t *testing.T) (r int) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[1]) })
	return p[0]
}

func fdOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

func sameFile(t *testing.T, a, b int) bool {
	t.Helper()
	var sa, sb unix.Stat_t
	if err := unix.Fstat(a, &sa); err != nil {
		return false
	}
	if err := unix.Fstat(b, &sb); err != nil {
		return false
	}
	return sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

func tunOptions() *tun.Options {
	return &tun.Options{Name: "daal-test", MTU: 1500, EXP_DisableDNSHijack: true}
}

// The route switch seen on the phone. Route A is running on TUN A; the
// host establishes TUN B and hands it over (the engine closes the
// host's copy of A); the process opens some unrelated file, which the
// kernel gives A's old number; then the old instance is torn down.
// That teardown must close the old instance's OWN copy and nothing
// else — before the fix it closed the unrelated file (the route store's
// database, on the phone).
func TestTunSwitchDoesNotCloseAnUnrelatedFD(t *testing.T) {
	t.Cleanup(ReleaseTunFD)
	p := newAndroidPlatform()

	fdA := pipeRead(t)
	AdoptTunFD(fdA)
	tunA, err := p.OpenInterface(tunOptions(), boxoption.TunPlatformOptions{})
	if err != nil {
		t.Fatalf("OpenInterface(A): %v", err)
	}

	// The host's new TUN arrives; the host's copy of A is closed.
	fdB := pipeRead(t)
	AdoptTunFD(fdB)
	if fdOpen(fdA) {
		t.Fatalf("rotate left the host's previous TUN copy (fd %d) open", fdA)
	}

	// Something unrelated is opened and lands on A's old number. The
	// kernel's lowest-free rule usually puts it there by itself; Dup3
	// makes it certain.
	ref, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	unrelated := fdA
	if ref == fdA {
		if ref, err = unix.FcntlInt(uintptr(fdA), unix.F_DUPFD_CLOEXEC, 3); err != nil {
			t.Fatalf("dup: %v", err)
		}
	} else if err := unix.Dup3(ref, fdA, unix.O_CLOEXEC); err != nil {
		t.Fatalf("dup3 onto the freed number: %v", err)
	}
	defer unix.Close(ref)
	defer unix.Close(unrelated)

	// Start(B) tears the old instance down.
	if err := tunA.Close(); err != nil {
		t.Fatalf("closing the old instance's TUN: %v", err)
	}

	if !fdOpen(unrelated) {
		t.Fatalf("tearing down the old instance closed an unrelated fd (%d) that had reused the old TUN's number", unrelated)
	}
	if !sameFile(t, unrelated, ref) {
		t.Fatalf("fd %d no longer refers to the unrelated file", unrelated)
	}
	if !fdOpen(fdB) {
		t.Fatalf("the new TUN (fd %d) was closed by the switch", fdB)
	}
}

// Disconnect: ClearRoute stops the instance (its copy), then
// ClearTunFD releases the host's copy. Each number is closed exactly
// once and no close fails — a failed close (EBADF) is a second close
// of a number somebody else may already have been given.
func TestTunDisconnectClosesEachCopyOnce(t *testing.T) {
	t.Cleanup(ReleaseTunFD)
	p := newAndroidPlatform()
	cc := countCloses(t)

	// Record the duplicate sing-tun is handed.
	var dupGiven int
	origOpen := openTun
	openTun = func(o tun.Options) (tun.Tun, error) {
		dupGiven = o.FileDescriptor
		return origOpen(o)
	}
	t.Cleanup(func() { openTun = origOpen })

	host := pipeRead(t)
	AdoptTunFD(host)
	tunIf, err := p.OpenInterface(tunOptions(), boxoption.TunPlatformOptions{})
	if err != nil {
		t.Fatalf("OpenInterface: %v", err)
	}
	if dupGiven == host || dupGiven < 3 {
		t.Fatalf("sing-tun was handed fd %d; it must get a duplicate of the host's fd %d, never the number itself", dupGiven, host)
	}
	if !sameFile(t, dupGiven, host) {
		t.Fatalf("the duplicate (fd %d) is not the host's TUN", dupGiven)
	}

	// ClearRoute → driver.Stop → instance closed.
	if err := tunIf.Close(); err != nil {
		t.Fatalf("instance close: %v", err)
	}
	if fdOpen(dupGiven) {
		t.Fatalf("the instance's copy (fd %d) is still open after it closed", dupGiven)
	}
	if !fdOpen(host) {
		t.Fatalf("closing the instance closed the HOST's copy (fd %d): the engine's release would then close that number a second time", host)
	}

	// ClearTunFD.
	ReleaseTunFD()
	if fdOpen(host) {
		t.Fatalf("ReleaseTunFD left the host's copy (fd %d) open", host)
	}
	// And again, as resetTunFDForShutdown does after a clear.
	ReleaseTunFD()

	cc.mu.Lock()
	defer cc.mu.Unlock()
	if len(cc.failed) != 0 {
		t.Fatalf("closes of an fd that was not open (double close): %v", cc.failed)
	}
	if cc.closes[host] != 1 {
		t.Fatalf("the host's copy was closed %d times by the engine, want exactly 1 (all closes: %v)", cc.closes[host], cc.closes)
	}
}

// A start that is superseded or fails after the duplicate was made must
// not leak it, and must not touch the host's copy.
func TestOpenInterfaceClosesItsDuplicateOnFailure(t *testing.T) {
	t.Cleanup(ReleaseTunFD)
	p := newAndroidPlatform()
	cc := countCloses(t)

	var dupGiven int
	origOpen := openTun
	openTun = func(o tun.Options) (tun.Tun, error) {
		dupGiven = o.FileDescriptor
		return nil, errors.New("tun: refused")
	}
	t.Cleanup(func() { openTun = origOpen })

	host := pipeRead(t)
	AdoptTunFD(host)
	if _, err := p.OpenInterface(tunOptions(), boxoption.TunPlatformOptions{}); err == nil {
		t.Fatal("OpenInterface succeeded although the TUN could not be opened")
	}
	if dupGiven == host {
		t.Fatalf("sing-tun was handed the host's own fd %d", host)
	}
	if fdOpen(dupGiven) {
		t.Fatalf("the duplicate (fd %d) leaked on the failure path", dupGiven)
	}
	if !fdOpen(host) {
		t.Fatalf("the failure path closed the host's copy (fd %d)", host)
	}
	cc.mu.Lock()
	n := cc.closes[dupGiven]
	cc.mu.Unlock()
	if n != 1 {
		t.Fatalf("the duplicate was closed %d times, want 1", n)
	}
}

// No TUN handed over: a clear error, nothing duplicated.
func TestOpenInterfaceWithoutTunFD(t *testing.T) {
	ReleaseTunFD()
	p := newAndroidPlatform()
	if _, err := p.OpenInterface(tunOptions(), boxoption.TunPlatformOptions{}); !errors.Is(err, errTunFDNotSet) {
		t.Fatalf("OpenInterface with no TUN fd: err = %v, want errTunFDNotSet", err)
	}
}

// A failed engine_set_tun_fd hands the fd back: DisownTunFD forgets it
// without closing it.
func TestDisownTunFDDoesNotClose(t *testing.T) {
	t.Cleanup(ReleaseTunFD)
	host := pipeRead(t)
	t.Cleanup(func() { _ = unix.Close(host) })
	AdoptTunFD(host)
	DisownTunFD()
	if CurrentTunFD() != -1 {
		t.Fatalf("CurrentTunFD = %d after disown", CurrentTunFD())
	}
	ReleaseTunFD()
	if !fdOpen(host) {
		t.Fatalf("a disowned fd (%d) was closed by the engine", host)
	}
}
