package budget

import (
	"reflect"
	"testing"
)

func TestCapForKnownTags(t *testing.T) {
	cases := map[string]uint64{
		TagEmergency:    50 * MiB,
		TagLifelineOnly: 100 * MiB,
		TagLow:          500 * MiB,
		TagNormal:       5 * GiB,
		TagBulkCapable:  0,
		TagExperimental: 5 * GiB,
	}
	for tag, want := range cases {
		got, err := CapFor(tag)
		if err != nil {
			t.Fatalf("CapFor(%q) returned err: %v", tag, err)
		}
		if got != want {
			t.Errorf("CapFor(%q) = %d, want %d", tag, got, want)
		}
	}
}

func TestCapForUnknownTag(t *testing.T) {
	if _, err := CapFor("definitely-not-a-tag"); err != ErrUnknownTag {
		t.Fatalf("expected ErrUnknownTag, got %v", err)
	}
}

func TestKnownTagsSortedAndComplete(t *testing.T) {
	got := KnownTags()
	if len(got) != 6 {
		t.Fatalf("expected 6 tags, got %d: %v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("KnownTags not sorted: %v", got)
		}
	}
}

// Phase 2A-Polish: verify the V2.1 cap table with hourly + session +
// modes_allowed columns is encoded byte-for-byte in caps.go.
func TestFullCapForKnownTags(t *testing.T) {
	cases := map[string]Cap{
		TagEmergency:    {Hourly: 50 * MiB, Session: 200 * MiB, ModesAllowed: []string{"lifeline"}},
		TagLifelineOnly: {Hourly: 100 * MiB, Session: 500 * MiB, ModesAllowed: []string{"lifeline"}},
		TagLow:          {Hourly: 500 * MiB, Session: 2 * GiB, ModesAllowed: []string{"lifeline", "normal"}},
		TagNormal:       {Hourly: 5 * GiB, Session: 0, ModesAllowed: []string{"lifeline", "normal"}},
		TagBulkCapable:  {Hourly: 0, Session: 0, ModesAllowed: []string{"lifeline", "normal", "bulk"}},
		TagExperimental: {Hourly: 5 * GiB, Session: 0, ModesAllowed: []string{"lifeline", "normal"}},
	}
	for tag, want := range cases {
		got, err := FullCapFor(tag)
		if err != nil {
			t.Fatalf("FullCapFor(%q): %v", tag, err)
		}
		if got.Hourly != want.Hourly {
			t.Errorf("FullCapFor(%q).Hourly = %d, want %d", tag, got.Hourly, want.Hourly)
		}
		if got.Session != want.Session {
			t.Errorf("FullCapFor(%q).Session = %d, want %d", tag, got.Session, want.Session)
		}
		if !reflect.DeepEqual(got.ModesAllowed, want.ModesAllowed) {
			t.Errorf("FullCapFor(%q).ModesAllowed = %v, want %v", tag, got.ModesAllowed, want.ModesAllowed)
		}
	}
}

func TestFullCapForUnknownTag(t *testing.T) {
	got, err := FullCapFor("definitely-not-a-tag")
	if err != ErrUnknownTag {
		t.Fatalf("expected ErrUnknownTag, got %v", err)
	}
	if got.Hourly != 0 || got.Session != 0 || got.ModesAllowed != nil {
		t.Errorf("expected zero-value Cap on unknown tag, got %+v", got)
	}
}

// TestCapsAreClosedToMutation asserts FullCapFor returns a defensive
// copy of ModesAllowed; mutating the returned slice must NOT change
// the closed table for subsequent callers.
func TestCapsAreClosedToMutation(t *testing.T) {
	first, err := FullCapFor(TagEmergency)
	if err != nil {
		t.Fatalf("FullCapFor: %v", err)
	}
	if len(first.ModesAllowed) == 0 {
		t.Fatal("emergency tag should have at least one allowed mode")
	}
	// Stomp the slice.
	first.ModesAllowed[0] = "STOMPED"
	first.ModesAllowed = append(first.ModesAllowed, "EXTRA")

	second, err := FullCapFor(TagEmergency)
	if err != nil {
		t.Fatalf("FullCapFor (second): %v", err)
	}
	if !reflect.DeepEqual(second.ModesAllowed, []string{"lifeline"}) {
		t.Errorf("closed table mutated by caller: %v", second.ModesAllowed)
	}
}
