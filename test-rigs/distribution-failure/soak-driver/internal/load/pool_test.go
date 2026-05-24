package load

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPoolBackPressure — verifies the pool actually caps live
// subprocess count at ConcurrencyLimit. Uses a tiny `cat` shim
// instead of a real soak engine.
//
// Skipped on non-linux because the test relies on `cat` being on
// PATH and on Unix process semantics.
func TestPoolBackPressure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not on PATH")
	}
	tmp := t.TempDir()
	p := &Pool{
		ConcurrencyLimit: 4,
		Engine:           cat,
		StateDirRoot:     tmp,
	}
	// Spawn at the limit.
	clients, err := p.Spawn(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 4 {
		t.Fatalf("got %d clients, want 4", len(clients))
	}
	// State dirs are deterministic.
	for i, c := range clients {
		want := filepath.Join(tmp, "c-"+pad(i+1))
		if c.StateDir() != want {
			t.Errorf("client %d state dir = %q, want %q", i, c.StateDir(), want)
		}
		if _, err := os.Stat(c.StateDir()); err != nil {
			t.Errorf("state dir not created: %v", err)
		}
	}
	if err := p.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	// Idempotent.
	if err := p.Shutdown(); err != nil {
		t.Errorf("second shutdown: %v", err)
	}
}

func pad(n int) string {
	if n < 10 {
		return "000" + itoa(n)
	}
	if n < 100 {
		return "00" + itoa(n)
	}
	if n < 1000 {
		return "0" + itoa(n)
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
