package abi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"daal/core/netmem"
)

// The netmem TTL was written together with Sweep, and until this pass
// nothing called Sweep — the retention bound existed only in a doc
// comment. These tests pin the wiring, not the sweep logic
// (netmem/store_test.go owns that).

func TestSweepNetworkMemory_DropsExpiredBlobsAndStamps(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	store := netmemStore()
	if store == nil {
		t.Fatal("netmem store unavailable")
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// One blob well past netmem.TTL, one inside it.
	if err := store.Put("aaaaaaaaaaaaaaaa", netmem.Snapshot{Mode: "normal"},
		now.Add(-netmem.TTL-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.Put("bbbbbbbbbbbbbbbb", netmem.Snapshot{Mode: "normal"},
		now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	exe := &refreshExecutor{store: loadedCore().store, now: nowUTC}
	if err := exe.SweepNetworkMemory(context.Background(), now); err != nil {
		t.Fatalf("SweepNetworkMemory: %v", err)
	}

	ids, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ids, ",")
	if strings.Contains(got, "aaaaaaaaaaaaaaaa") {
		t.Fatalf("expired blob survived the sweep: %v", ids)
	}
	if !strings.Contains(got, "bbbbbbbbbbbbbbbb") {
		t.Fatalf("in-TTL blob was swept: %v", ids)
	}

	// The stamp is what stops the sweep re-running (and re-decrypting
	// every blob) on the next 60-second tick.
	val, err := loadedCore().store.GetSecret("scheduler:last-netmem-sweep")
	if err != nil || len(val) == 0 {
		t.Fatalf("sweep did not stamp: %v %q", err, val)
	}
	if string(val) != now.Format(time.RFC3339) {
		t.Fatalf("stamp = %q, want %q", val, now.Format(time.RFC3339))
	}
}

func TestSchedulerStatus_AdvertisesTheNetmemSweep(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()

	body, err := SchedulerStatus()
	if err != nil {
		t.Fatalf("SchedulerStatus: %v", err)
	}
	var st struct {
		NextDue []struct {
			Kind string `json:"kind"`
		} `json:"next_due"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatal(err)
	}
	// A retention job the user cannot see the schedule of is a
	// retention job nobody can audit.
	for _, a := range st.NextDue {
		if a.Kind == "netmem-sweep" {
			return
		}
	}
	t.Fatalf("netmem-sweep missing from scheduler status: %s", body)
}

func TestStoreSource_LastNetmemSweepSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	c := loadedCore()
	now := time.Date(2026, 8, 18, 9, 0, 0, 0, time.UTC)
	if err := c.store.PutSecret("scheduler:last-netmem-sweep",
		[]byte(now.Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	src := storeSource{store: c.store, now: nowUTC}
	if got := src.LastNetmemSweep(); !got.Equal(now) {
		t.Fatalf("LastNetmemSweep = %v, want %v", got, now)
	}
	if err := Shutdown(); err != nil {
		t.Fatal(err)
	}

	// Re-open the same state dir: the cadence must resume, not reset.
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	defer Shutdown()
	src2 := storeSource{store: loadedCore().store, now: nowUTC}
	if got := src2.LastNetmemSweep(); !got.Equal(now) {
		t.Fatalf("after restart LastNetmemSweep = %v, want %v", got, now)
	}
}
