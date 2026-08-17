package abi

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// SchedulerTick grew two host drivers in this step (the Android
// VpnService pump and the tunnel-up tick) on top of the desktop shell's
// 60 s thread, so the two properties a background pump depends on are
// worth pinning: it must not panic when the engine is not initialized,
// and concurrent callers must not tear each other's executor apart.

// A pump owned by a service whose lifecycle is not the engine's will
// eventually tick after Shutdown. Before the readiness check that path
// went through EvaluateAutoPromotion → mustCore() → panic, and a panic
// crossing JNI/gomobile kills the app process rather than the tick.
func TestSchedulerTickWithoutInitReturnsErrorNotPanic(t *testing.T) {
	_ = Shutdown()

	err := SchedulerTick(time.Now().UTC())
	if err == nil {
		t.Fatal("SchedulerTick with no engine: want error, got nil")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("SchedulerTick with no engine: want a not-initialized error, got %v", err)
	}
}

// Overlapping ticks are dropped, not queued, and must be safe: run this
// under -race, which is where a second tick entering the executor
// concurrently would show up.
func TestSchedulerTickConcurrentCallsAreSerialized(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = Shutdown() }()

	now := time.Now().UTC()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A dropped tick is normal backpressure and reports nil, so
			// any error here is a real failure.
			if err := SchedulerTick(now); err != nil {
				t.Errorf("SchedulerTick: %v", err)
			}
		}()
	}
	wg.Wait()

	if tickInFlight.Load() {
		t.Fatal("tickInFlight still set after every tick returned")
	}
}
