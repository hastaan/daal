package abi

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestInit_NoNilDerefFromConcurrentReaders is a regression test for the
// alpha.1 Android crash. The previous Init() implementation published
// globalCore before populating its sub-fields:
//
//	globalCore = &Core{...}            // pm = nil here
//	...                                // many lines of setup
//	globalCore.pm = pathmanager.New()
//
// A concurrent caller (the Kotlin polling loop kicked off by
// RouteHealthBanner.onResume) saw globalCore non-nil, called
// DiagnosticsExplain, derefed c.pm, hit nil, and crashed the whole
// process via SIGSEGV.
//
// What the test exercises: pollers spinning up *before* Init begins
// (mirroring the Android lifecycle where ON_RESUME can fire ahead of
// the async bridge.init coroutine), then Init runs, pollers continue.
// The contract the entry points MUST honour is "never crash the
// process; either succeed or return a clean error".
//
// (Shutdown-during-poll is a separate class of race covered by a
// future test once the engine grows reference-counted teardown; the
// alpha.1 bug we're regression-testing for is purely the
// init-time-race.)
func TestInit_NoNilDerefFromConcurrentReaders(t *testing.T) {
	// Ensure clean slate so the first read after pollers start sees
	// nil globalCore, exercising the pre-Init path.
	_ = Shutdown()

	var stop atomic.Bool
	var pollerPanic atomic.Value // string
	var wg sync.WaitGroup

	// Spawn pollers that hit the entry points the Android UI calls
	// before / during / after Init. The polling loop on Kotlin's side
	// already wraps each call in `try { ... } catch (Throwable)`, so
	// the contract these functions MUST honour is "return cleanly,
	// never crash the process".
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					pollerPanic.Store(toString(r))
				}
			}()
			for !stop.Load() {
				_, _ = DiagnosticsExplain()
				_, _ = SchedulerStatus()
				_, _ = SubscriptionList()
				_, _ = BootstrapStatus()
				_, _ = PointerRotationStatus()
			}
		}()
	}

	// Let the pollers run briefly while globalCore is nil so the
	// pre-Init code path is hammered.
	for i := 0; i < 100 && !stop.Load(); i++ {
		if v := pollerPanic.Load(); v != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("polling goroutine panicked before Init: %v", v)
		}
	}

	// Now run Init. The pollers see the publish-then-mutate window
	// (or, post-fix, the atomic publish) right here. With the old
	// Init, this is where a polling goroutine would deref nil pm.
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		stop.Store(true)
		wg.Wait()
		t.Fatalf("Init: %v", err)
	}

	// Let pollers run a bit longer post-Init to confirm the
	// initialised path is also crash-free.
	for i := 0; i < 1000 && !stop.Load(); i++ {
		if v := pollerPanic.Load(); v != nil {
			stop.Store(true)
			_ = Shutdown()
			wg.Wait()
			t.Fatalf("polling goroutine panicked after Init: %v", v)
		}
	}

	stop.Store(true)
	wg.Wait()
	_ = Shutdown()

	if v := pollerPanic.Load(); v != nil {
		t.Fatalf("polling goroutine panicked: %v", v)
	}
}

// TestEntryPoints_ReturnErrorBeforeInit guards the Kotlin polling
// contract: every engine function the UI may legitimately invoke
// during the Init window MUST return an error, not panic. A panic on
// a gomobile-bound thread terminates the process via SIGABRT before
// the deferred recover runs (the goroutine is LockOSThread'd to a
// JNI worker), so the Kotlin `catch (Throwable)` would never fire.
//
// Add new entry points to `polledByUI` whenever a screen starts
// polling them; the test will fail loudly if any entry point reaches
// for a nil `globalCore` field.
func TestEntryPoints_ReturnErrorBeforeInit(t *testing.T) {
	// Ensure clean state. Earlier tests may have left globalCore set.
	_ = Shutdown()

	polledByUI := []struct {
		name string
		call func() error
	}{
		{"DiagnosticsExplain", func() error { _, e := DiagnosticsExplain(); return e }},
		{"SchedulerStatus", func() error { _, e := SchedulerStatus(); return e }},
		{"SubscriptionList", func() error { _, e := SubscriptionList(); return e }},
		{"BootstrapStatus", func() error { _, e := BootstrapStatus(); return e }},
		{"PointerRotationStatus", func() error { _, e := PointerRotationStatus(); return e }},
	}

	for _, c := range polledByUI {
		c := c
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked before Init: %v", c.name, r)
				}
			}()
			err := c.call()
			if err == nil {
				t.Errorf("%s: expected error before Init, got nil", c.name)
			}
		})
	}
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}
