package load

import (
	"path/filepath"
	"testing"
)

// TestLockedDefaultMix locks the 60/35/5 invariant from
// `phases of development/27-phase-3-soak-success-metric.md` §5.
// Any change to this constant requires a roadmap amendment.
func TestLockedDefaultMix(t *testing.T) {
	if err := LockedDefaultMix.Validate(); err != nil {
		t.Fatalf("LockedDefaultMix invalid: %v", err)
	}
	got := LockedDefaultMix.Counts(1000)
	want := map[PlatformTag]int{
		PlatformLinux:   600,
		PlatformAndroid: 350,
		PlatformIOS:     50,
	}
	for tag, n := range want {
		if got[tag] != n {
			t.Errorf("LockedDefaultMix.Counts(1000)[%s] = %d, want %d", tag, got[tag], n)
		}
	}
}

func TestMixValidate(t *testing.T) {
	cases := []struct {
		name    string
		mix     Mix
		wantErr bool
	}{
		{"empty", Mix{}, true},
		{"linux-only-100", Mix{{PlatformLinux, 100}}, false},
		{"sum-99", Mix{{PlatformLinux, 99}}, true},
		{"sum-101", Mix{{PlatformLinux, 60}, {PlatformAndroid, 41}}, true},
		{"unknown", Mix{{PlatformTag("windows"), 100}}, true},
		{"duplicate", Mix{{PlatformLinux, 50}, {PlatformLinux, 50}}, true},
		{"negative", Mix{{PlatformLinux, -10}, {PlatformAndroid, 110}}, true},
		{"locked", LockedDefaultMix, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.mix.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestMixCountsRoundtripsToTotal(t *testing.T) {
	for _, n := range []int{100, 333, 1000, 1001, 7} {
		got := LockedDefaultMix.Counts(n)
		sum := got[PlatformLinux] + got[PlatformAndroid] + got[PlatformIOS]
		if sum != n {
			t.Errorf("Counts(%d) sum=%d want %d (got %v)", n, sum, n, got)
		}
	}
}

func TestParseMix_DefaultWhenEmpty(t *testing.T) {
	mix, err := ParseMix("", 1000)
	if err != nil {
		t.Fatalf("ParseMix empty: %v", err)
	}
	if len(mix) != 3 {
		t.Fatalf("ParseMix empty: want 3 slices, got %d", len(mix))
	}
}

func TestParseMix_LockedTriple(t *testing.T) {
	mix, err := ParseMix("linux:600,android:350,ios:50", 1000)
	if err != nil {
		t.Fatalf("ParseMix triple: %v", err)
	}
	if err := mix.Validate(); err != nil {
		t.Fatalf("ParseMix triple invalid: %v", err)
	}
	got := mix.Counts(1000)
	if got[PlatformLinux] != 600 || got[PlatformAndroid] != 350 || got[PlatformIOS] != 50 {
		t.Errorf("ParseMix triple Counts(1000) = %v, want 600/350/50", got)
	}
}

func TestParseMix_RejectsBadInputs(t *testing.T) {
	cases := []string{
		"linux:600,android:350",                // sums to 950
		"linux:600,android:350,ios:50,linux:0", // duplicate
		"windows:100",                          // unknown platform
		"linux:abc",                            // bad count
		"linux:-100,android:1100",              // negative count
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := ParseMix(c, 1000); err == nil {
				t.Errorf("ParseMix(%q) want error", c)
			}
		})
	}
}

func TestPlatformBinary(t *testing.T) {
	linux := "/opt/daal/bin/daal-soak-engine"
	cases := []struct {
		tag  PlatformTag
		want string
	}{
		{PlatformLinux, linux},
		{PlatformAndroid, filepath.Join(filepath.Dir(linux), "daal-soak-engine-android")},
		{PlatformIOS, filepath.Join(filepath.Dir(linux), "daal-soak-engine-ios")},
	}
	for _, c := range cases {
		got, err := PlatformBinary(linux, c.tag)
		if err != nil {
			t.Errorf("PlatformBinary(%s): %v", c.tag, err)
			continue
		}
		if got != c.want {
			t.Errorf("PlatformBinary(%s) = %q, want %q", c.tag, got, c.want)
		}
	}
	if _, err := PlatformBinary(linux, PlatformTag("xbox")); err == nil {
		t.Errorf("PlatformBinary unknown: want error")
	}
}
