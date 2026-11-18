package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The naive outbound is sing-box's wrapper around cronet-go, and the
// version of cronet-go this module pins decides whether the engine can
// be killed by its own dependency.
//
// cronet-go before upstream commit 172bb4ede18c ("Fix bidirectional
// stream cancel racing with destroy", 2026-09-12) closed a connection
// like this:
//
//	Close():      lock; close(c.close); unlock
//	              if c.cancelled.CompareAndSwap(false, true) { c.stream.Cancel() }
//	terminate():  lock; mark terminated; unlock        (Cronet's network thread)
//	              c.stream.Destroy()
//
// Nothing stopped Destroy from running between Close's compare-and-swap
// and its Cancel, so Cancel could be called on a freed native stream.
// That is not an error return: it is SIGSEGV inside libcronet (or glibc
// aborting on a corrupted heap), i.e. the whole engine process — on a
// phone, the VPN service. It fired about once in 170 naive sessions when
// several sessions were being opened and closed side by side.
//
// The first build of cronet-go's module branch that carries the fix is
// the one below (it is what sing-box 1.14.1 ships). Pinned here as a
// floor, so a `go mod tidy`, a sing-box bump or a hand edit that drags
// the module back fails this test instead of bringing the crash back.
const cronetGoFixedTimestamp = "20260912104727" // v0.0.0-20260912104727-0d28acc44093

var pseudoVersion = regexp.MustCompile(`^v0\.0\.0-(\d{14})-[0-9a-f]{12}$`)

// cronetPins returns module path → version for every cronet-go module
// in this module's go.mod.
func cronetPins(t *testing.T) map[string]string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatalf("read core/go.mod: %v", err)
	}
	pins := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[0], "github.com/sagernet/cronet-go") {
			pins[f[0]] = f[1]
		}
	}
	if pins["github.com/sagernet/cronet-go"] == "" {
		t.Fatal("core/go.mod does not pin github.com/sagernet/cronet-go; this test is not looking at the engine's module")
	}
	return pins
}

func TestCronetGoCarriesTheCancelDestroyFix(t *testing.T) {
	pins := cronetPins(t)
	for _, mod := range []string{"github.com/sagernet/cronet-go", "github.com/sagernet/cronet-go/all"} {
		v := pins[mod]
		m := pseudoVersion.FindStringSubmatch(v)
		if m == nil {
			// A tagged release would be newer than any of this; the tags
			// that exist today (v0.0.1-143.…) are OLDER than the fix and
			// must not slip through as "a real version".
			t.Fatalf("%s is pinned at %q, which this test cannot date. If upstream has started tagging releases that contain commit 172bb4ede18c, teach this test about them; the v0.0.1-* tags do not", mod, v)
		}
		if m[1] < cronetGoFixedTimestamp {
			t.Errorf("%s is pinned at %s, older than the first build with the Close/Destroy fix (v0.0.0-%s-0d28acc44093): the engine process can die with SIGSEGV in BidirectionalStreamCancel when a naive connection closes as its stream terminates",
				mod, v, cronetGoFixedTimestamp)
		}
	}
	if pins["github.com/sagernet/cronet-go"] != pins["github.com/sagernet/cronet-go/all"] {
		t.Errorf("cronet-go (%s) and cronet-go/all (%s) are pinned apart; they are one upstream commit and must move together",
			pins["github.com/sagernet/cronet-go"], pins["github.com/sagernet/cronet-go/all"])
	}
}

// The Go wrapper and the native library are two halves of one C ABI.
// The library ships as per-platform modules (cronet-go/lib/<os>_<arch>)
// that cronet-go/all pins to ONE version; if some of them lag, the
// engine on that platform loads a libcronet whose functions take
// different arguments than the wrapper passes.
func TestCronetLibModulesMoveTogether(t *testing.T) {
	pins := cronetPins(t)
	seen := map[string][]string{}
	for mod, v := range pins {
		if strings.HasPrefix(mod, "github.com/sagernet/cronet-go/lib/") {
			seen[v] = append(seen[v], strings.TrimPrefix(mod, "github.com/sagernet/cronet-go/lib/"))
		}
	}
	if len(seen) == 0 {
		t.Fatal("core/go.mod pins no cronet-go/lib/* module")
	}
	if len(seen) != 1 {
		t.Errorf("cronet-go/lib/* modules are pinned at %d different versions: %v", len(seen), seen)
	}
	for v := range seen {
		m := pseudoVersion.FindStringSubmatch(v)
		if m == nil {
			t.Fatalf("cronet-go/lib/* is pinned at %q, which this test cannot date", v)
		}
		// The libraries are built a few minutes BEFORE the wrapper commit
		// that references them, on the same day.
		if m[1][:8] < cronetGoFixedTimestamp[:8] {
			t.Errorf("cronet-go/lib/* is pinned at %s, from before the wrapper this module pins: the two do not share a C ABI", v)
		}
	}
}

// Belt and braces: read the pinned source itself, when it is in the
// module cache, and check the shape of the fix rather than its date.
// Skipped (not failed) on a machine that has never downloaded it.
func TestCronetGoCloseCancelsUnderTheLock(t *testing.T) {
	pins := cronetPins(t)
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Skipf("go env GOMODCACHE: %v", err)
	}
	src := filepath.Join(strings.TrimSpace(string(out)), "github.com", "sagernet",
		"cronet-go@"+pins["github.com/sagernet/cronet-go"], "bidirectional_conn.go")
	body, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("pinned cronet-go is not in the module cache (%v)", err)
	}
	text := string(body)
	if strings.Contains(text, "cancelled.CompareAndSwap") {
		t.Errorf("%s still decides to Cancel with a compare-and-swap outside the lock — the check-then-act race with terminate()'s Destroy", src)
	}
	if !strings.Contains(text, "func (c *BidirectionalConn) cancelLocked()") {
		t.Errorf("%s has no cancelLocked(): the shape of the upstream fix (Cancel and Destroy both under c.access) is gone; re-read Close and terminate before trusting this version", src)
	}
}
