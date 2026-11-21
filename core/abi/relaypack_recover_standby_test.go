package abi

import (
	"testing"

	"daal/core/refresh"
)

// A walk that brought a standby key the store kept found a new address
// for the route, just as a newly applied pack does: the walk reports
// "updated" and the route is checked again on it.
func TestRecoverSummary_StandbyKeyCountsAsApplied(t *testing.T) {
	got, _, _ := recoverSummary([]refresh.RelayPackResult{
		{RelayPackID: "p1", Outcome: refresh.OutcomeFreshnessUnchanged, StandbyKeyAccepted: true},
	})
	if got != RecoverUpdated {
		t.Fatalf("state = %q, want %q", got, RecoverUpdated)
	}
	got, _, _ = recoverSummary([]refresh.RelayPackResult{{RelayPackID: "p1", Outcome: refresh.OutcomeFreshnessUnchanged}})
	if got != RecoverUnchanged {
		t.Fatalf("state = %q, want %q", got, RecoverUnchanged)
	}
}

// The engine's refresher hands standby keys to the store.
func TestRelayPackRefresher_HasTheStandbyKeySink(t *testing.T) {
	if err := Init(t.TempDir(), "warn"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Shutdown() })
	rp, err := ensureRelayPackRefresh()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rp.StandbyKeys.(StandbyKeySink); !ok {
		t.Fatalf("StandbyKeys = %T, want abi.StandbyKeySink", rp.StandbyKeys)
	}
}
