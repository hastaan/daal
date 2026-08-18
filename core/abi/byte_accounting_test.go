package abi

import (
	"context"
	"encoding/json"
	"testing"

	"daal/core/engine"
)

// Both surfaces that read driver.Stats() must report NULL, not 0, on a
// build that cannot count bytes.
//
// The distinction is the whole point. `0` means "counted, nothing
// moved" — a measurement. `null` means "nobody counted" — the absence
// of one. Before this wave `ThroughputSnapshot` divided counters no
// code ever incremented, so the Connection page printed "↑ 0 B/s
// ↓ 0 B/s" for the life of every session; `StatsRedacted` still emitted
// a flat `bytes_in: 0` into the blob a user exports and hands to a
// helper, where it reads as the diagnosis "the tunnel carried nothing".
//
// This test is the guard the original defect did not have. It is
// written against `engine.HasByteAccounting` rather than a hardcoded
// expectation, so the day the real counter lands and the constant flips
// the test follows it instead of going red.
func TestByteCountersReportNullWhenUnmeasured(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })

	t.Run("stats_redacted", func(t *testing.T) {
		// driver.Stats() refuses while disconnected, so bring the
		// driver up directly. Going through SetRoute is not an option
		// here: on a build with no data plane it now fails closed by
		// design (TestSetRoute_FailsClosedWithoutDataPlane), and the
		// blob this test guards is exactly the one Android — which IS
		// connected, and still cannot count — produces.
		if err := loadedCore().driver.Start(context.Background(), []byte(`{}`)); err != nil {
			t.Fatalf("driver.Start: %v", err)
		}
		t.Cleanup(func() { _ = loadedCore().driver.Stop() })

		body, err := StatsRedacted()
		if err != nil {
			t.Fatalf("StatsRedacted: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("unmarshal %q: %v", body, err)
		}
		for _, k := range []string{"bytes_in", "bytes_out"} {
			if _, present := m[k]; !present {
				t.Fatalf("%s missing from stats_redacted: %s", k, body)
			}
			if engine.HasByteAccounting {
				if m[k] == nil {
					t.Fatalf("%s is null on a build WITH byte accounting: %s", k, body)
				}
				continue
			}
			if m[k] != nil {
				t.Fatalf("%s = %v on a build with no byte accounting, want null: %s", k, m[k], body)
			}
		}
	})

	t.Run("throughput_snapshot", func(t *testing.T) {
		// Two calls: the first has no predecessor to difference
		// against and is null on every build, so the assertion that
		// distinguishes the two build variants has to be the second.
		if _, err := ThroughputSnapshot(); err != nil {
			t.Fatalf("ThroughputSnapshot: %v", err)
		}
		body, err := ThroughputSnapshot()
		if err != nil {
			t.Fatalf("ThroughputSnapshot: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("unmarshal %q: %v", body, err)
		}
		for _, k := range []string{"up_bps", "down_bps"} {
			if _, present := m[k]; !present {
				t.Fatalf("%s missing from throughput_snapshot: %s", k, body)
			}
			if !engine.HasByteAccounting && m[k] != nil {
				t.Fatalf("%s = %v on a build with no byte accounting, want null: %s", k, m[k], body)
			}
		}
		if _, present := m["window_ms"]; !present {
			t.Fatalf("window_ms missing: %s", body)
		}
	})
}
