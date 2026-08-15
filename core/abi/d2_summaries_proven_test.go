package abi

import (
	"testing"

	"daal/core/routestore"
)

// TestRowToDisplay_Proven asserts the Proven flag mirrors whether the
// route has ever recorded a success. This is what lets the UI show
// "not tested yet" instead of presenting the placeholder 50% health of
// an unproven route as a measured score.
func TestRowToDisplay_Proven(t *testing.T) {
	cases := []struct {
		name        string
		lastSuccess string
		wantProven  bool
	}{
		{"never succeeded", "", false},
		{"blank/whitespace only", "   ", false},
		{"has a success bucket", "2026-08-15T11:00:00Z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := routestore.RouteRow{
				RouteID:           "pub/r1",
				LastSuccessBucket: tc.lastSuccess,
			}
			got := rowToDisplay(row, computeHealthPctLastHour(row))
			if got.Proven != tc.wantProven {
				t.Fatalf("Proven=%v, want %v (LastSuccessBucket=%q)",
					got.Proven, tc.wantProven, tc.lastSuccess)
			}
			// An unproven route must never claim health above the 50 cap —
			// that's the placeholder the UI must not present as measured.
			if !got.Proven && got.HealthPct > 50 {
				t.Fatalf("unproven route has HealthPct=%v > 50", got.HealthPct)
			}
		})
	}
}
