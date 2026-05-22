//go:build !no_wasm

package wasm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// helloModuleWAT is a minimal WASM module written in WebAssembly
// Text format. wazero compiles WAT in-tree; the binary fixture
// would otherwise need to be checked in. The module only
// imports `_start` from WASI (no-op body) which is sufficient
// to instantiate.
const helloModuleWAT = `(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (func (export "_start"))
  (memory (export "memory") 1)
)`

// trapModuleWAT instantiates fine but traps when its
// `water_transport_dial_target` is called — used to exercise
// the OutcomeHostCallbackError branch.
const trapModuleWAT = `(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (func (export "_start"))
  (func (export "water_transport_dial_target") (param i32 i32)
    unreachable)
  (memory (export "memory") 1)
)`

// fuelHogModuleWAT enters an empty loop on dial; the fuel cap
// (mapped to a wall-clock budget at 3E) MUST cancel it and
// surface OutcomeFuelExhausted.
const fuelHogModuleWAT = `(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (func (export "_start"))
  (func (export "water_transport_dial_target") (param i32 i32)
    (loop $L
      br $L))
  (memory (export "memory") 1)
)`

func compileWAT(t *testing.T, src string) []byte {
	t.Helper()
	// wazero's WAT-to-binary compiler ships under
	// `experimental/text`. Avoid that import in the package
	// proper; tests can pull it in.
	bytes, err := watCompile(src)
	if err != nil {
		t.Fatalf("wat compile: %v", err)
	}
	return bytes
}

// hashOf is a test convenience that returns the hex SHA-256.
func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestVerifyHash_RoundTrip — same-bytes verifies, different
// bytes fail with ErrHashMismatch.
func TestVerifyHash_RoundTrip(t *testing.T) {
	body := []byte("hello-world")
	if err := VerifyHash(body, hashOf(body)); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHash(body, strings.Repeat("0", 64)); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("got %v, want ErrHashMismatch", err)
	}
}

// TestLoad_OversizeRejected — 4 MiB + 1 byte rejects with
// ErrModuleOversize before the runtime is constructed.
func TestLoad_OversizeRejected(t *testing.T) {
	l := NewLoader()
	body := make([]byte, MaxModuleBytes+1)
	_, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "ovr-test",
		SHA256Hex: hashOf(body),
		WASMBytes: body,
	}, nil)
	if !errors.Is(err, ErrModuleOversize) {
		t.Fatalf("got %v, want ErrModuleOversize", err)
	}
}

// TestLoad_HashMismatchRejected — a wrong sha256 fails fast.
func TestLoad_HashMismatchRejected(t *testing.T) {
	l := NewLoader()
	body := compileWAT(t, helloModuleWAT)
	_, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "hash-test",
		SHA256Hex: strings.Repeat("a", 64),
		WASMBytes: body,
	}, nil)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("got %v, want ErrHashMismatch", err)
	}
}

// TestLoad_KilledRejected — a kill-switched module fails with
// ErrModuleKilled.
func TestLoad_KilledRejected(t *testing.T) {
	l := NewLoader()
	body := compileWAT(t, helloModuleWAT)
	h := hashOf(body)
	l.MarkKilled(h)
	_, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "killed-test",
		SHA256Hex: h,
		WASMBytes: body,
	}, nil)
	if !errors.Is(err, ErrModuleKilled) {
		t.Fatalf("got %v, want ErrModuleKilled", err)
	}
}

// TestLoad_HappyPath — a well-formed hello module loads.
func TestLoad_HappyPath(t *testing.T) {
	l := NewLoader()
	body := compileWAT(t, helloModuleWAT)
	mod, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "hello-test",
		SHA256Hex: hashOf(body),
		WASMBytes: body,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = mod.Close() })
	if mod.Slug != "hello-test" {
		t.Errorf("slug round-trip: %q", mod.Slug)
	}
	if mod.LoadedAt.IsZero() {
		t.Error("LoadedAt zero")
	}
}

// TestValidSlug — locked regex `[a-z0-9_-]{3,32}`.
func TestValidSlug(t *testing.T) {
	good := []string{"hello", "abc-123", "a_b_c", "x-y-z"}
	bad := []string{"", "ab", strings.Repeat("a", 33), "ABC", "with space", "/slash"}
	for _, s := range good {
		if !validSlug(s) {
			t.Errorf("validSlug(%q) = false; want true", s)
		}
	}
	for _, s := range bad {
		if validSlug(s) {
			t.Errorf("validSlug(%q) = true; want false", s)
		}
	}
}

// TestEndsInPort443 — locked TCP/443-only restriction.
func TestEndsInPort443(t *testing.T) {
	cases := map[string]bool{
		"example.com:443":    true,
		"1.2.3.4:443":        true,
		"example.com:80":     false,
		"example.com":        false,
		"host:443:something": false,
		"":                   false,
	}
	for in, want := range cases {
		if got := endsInPort443(in); got != want {
			t.Errorf("endsInPort443(%q) = %v; want %v", in, got, want)
		}
	}
}

// TestIsKnownOutcome — closed enum surface.
func TestIsKnownOutcome(t *testing.T) {
	for _, o := range AllOutcomes() {
		if !IsKnownOutcome(string(o)) {
			t.Errorf("known outcome rejected: %s", o)
		}
	}
	if IsKnownOutcome("certified_organic") {
		t.Error("unknown outcome accepted")
	}
}

// TestDial_TrapBecomesHostCallbackError — a module that traps
// surfaces as OutcomeHostCallbackError.
func TestDial_TrapBecomesHostCallbackError(t *testing.T) {
	l := NewLoader()
	body := compileWAT(t, trapModuleWAT)
	mod, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "trap-test",
		SHA256Hex: hashOf(body),
		WASMBytes: body,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = mod.Close() })
	out, _ := Dial(context.Background(), mod, nil, "example.com:443")
	if out != OutcomeHostCallbackError {
		t.Errorf("got %s, want host_callback_error", out)
	}
}

// TestDial_FuelHogBecomesFuelExhausted — a runaway loop is
// killed under the fuel cap rather than the dial timeout.
// The fuel cap maps to a wall-clock budget shorter than the
// dial timeout (see `withFuel`); the test confirms the right
// outcome surfaces.
func TestDial_FuelHogBecomesFuelExhausted(t *testing.T) {
	l := NewLoader()
	body := compileWAT(t, fuelHogModuleWAT)
	mod, err := l.Load(context.Background(), ModuleSpec{
		Slug:      "fuel-hog",
		SHA256Hex: hashOf(body),
		WASMBytes: body,
	}, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = mod.Close() })
	start := time.Now()
	out, _ := Dial(context.Background(), mod, nil, "example.com:443")
	elapsed := time.Since(start)
	if out != OutcomeFuelExhausted {
		t.Errorf("got %s, want fuel_exhausted", out)
	}
	// Fuel cancels well before the dial timeout — locked at
	// 3E. The test is loose to absorb CI jitter.
	if elapsed >= DialTimeout {
		t.Errorf("fuel kill took %s; should be < %s", elapsed, DialTimeout)
	}
}
