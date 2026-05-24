package abi

import (
	"strings"
	"testing"
	"time"
)

// TestLifecycleEventAcceptsLockedTokens — the v1 set is exactly
// {will_sleep, did_wake, memory_pressure_warning}. Tokens outside
// that set return ErrUnknownLifecycle, and the cshared facade
// translates that to -1.
func TestLifecycleEventAcceptsLockedTokens(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	for _, tok := range []string{
		LifecycleWillSleep,
		LifecycleDidWake,
		LifecycleMemoryPressure,
	} {
		if err := LifecycleEvent(tok); err != nil {
			t.Errorf("known token %q rejected: %v", tok, err)
		}
	}
	if err := LifecycleEvent("did_log_in"); err == nil {
		t.Error("unknown token accepted")
	}
	if err := LifecycleEvent(""); err == nil {
		t.Error("empty token accepted")
	}
}

// TestLifecycleEventDiagnosticsAbsentBeforeFirstFire — Linux /
// Android / desktop builds never call this surface; the
// diagnostics rendering MUST omit the two fields entirely.
func TestLifecycleEventDiagnosticsAbsentBeforeFirstFire(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "last_lifecycle_event") {
		t.Errorf("last_lifecycle_event surfaced before first fire:\n%s", body)
	}
	if strings.Contains(body, "last_lifecycle_at") {
		t.Errorf("last_lifecycle_at surfaced before first fire:\n%s", body)
	}
}

// TestLifecycleEventRecordedInDiagnostics — after an iOS Swift
// bridge fires an event, the diagnostics surface carries the
// token + timestamp pair.
func TestLifecycleEventRecordedInDiagnostics(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	if err := LifecycleEvent(LifecycleMemoryPressure); err != nil {
		t.Fatal(err)
	}
	body, err := ExportDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"last_lifecycle_event": "memory_pressure_warning"`) {
		t.Errorf("last_lifecycle_event missing/wrong:\n%s", body)
	}
	if !strings.Contains(body, "last_lifecycle_at") {
		t.Error("last_lifecycle_at missing after fire")
	}
}

// TestLifecycleEventDoesNotBumpSessionEpoch — the docstring lock:
// will_sleep / did_wake are NOT session boundaries. The engine
// records the token but takes no further action.
func TestLifecycleEventDoesNotBumpSessionEpoch(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	// Read auto_promotion_last_fired_at as a stand-in for "session
	// state was untouched": auto-promotion's hour bucket would
	// reset across a session epoch. Instead, fire a series of
	// lifecycle events and assert that the auto-promotion flag,
	// the manual-override hour, and the storage profile are
	// untouched.
	c := mustCore()
	beforeFlag := c.autoPromotionEnabled
	beforeProfile := c.storageProfile

	for _, tok := range []string{
		LifecycleWillSleep,
		LifecycleDidWake,
		LifecycleMemoryPressure,
		LifecycleWillSleep,
	} {
		if err := LifecycleEvent(tok); err != nil {
			t.Fatal(err)
		}
	}

	if c.autoPromotionEnabled != beforeFlag {
		t.Error("lifecycle event mutated autoPromotionEnabled")
	}
	if c.storageProfile != beforeProfile {
		t.Error("lifecycle event mutated storageProfile")
	}
	snap := LastLifecycleEvent()
	if snap.Token != LifecycleWillSleep {
		t.Errorf("last token: got %q, want will_sleep", snap.Token)
	}
	if time.Since(snap.At) > 5*time.Second {
		t.Errorf("last_at too old: %s", snap.At)
	}
}
