package modifiers

import "testing"

func TestPlatformFromGOOS(t *testing.T) {
	cases := []struct {
		goos    string
		desktop bool
		want    Platform
		ok      bool
	}{
		{"linux", true, PlatformLinuxDesktop, true},
		{"linux", false, PlatformAndroid, true},
		{"darwin", true, PlatformMacOSDesktop, true},
		{"darwin", false, PlatformIOS, true},
		{"windows", true, PlatformWindowsDesktop, true},
		{"windows", false, PlatformWindowsDesktop, true}, // desktop-hint irrelevant on Windows
		{"android", true, PlatformAndroid, true},
		{"ios", false, PlatformIOS, true},
		{"freebsd", true, "", false},
		{"plan9", false, "", false},
		{"", true, "", false},
	}
	for _, c := range cases {
		got, ok := PlatformFromGOOS(c.goos, c.desktop)
		if got != c.want || ok != c.ok {
			t.Errorf("PlatformFromGOOS(%q, %v) = (%q, %v), want (%q, %v)",
				c.goos, c.desktop, got, ok, c.want, c.ok)
		}
	}
}

// TestIsKindAllowedOnPlatform_AllReservedSlotsRejected verifies
// locked invariants 38 + 40: at FRP-12 ship every registered kind
// is PENDING, so IsKindAllowedOnPlatform returns false for every
// (kind, platform) pair regardless of platforms[] list contents.
func TestIsKindAllowedOnPlatform_AllReservedSlotsRejected(t *testing.T) {
	platforms := []Platform{
		PlatformLinuxDesktop, PlatformWindowsDesktop, PlatformMacOSDesktop,
		PlatformAndroid, PlatformIOS,
	}
	for _, k := range AllKinds() {
		for _, p := range platforms {
			if IsKindAllowedOnPlatform(k, p) {
				t.Errorf("IsKindAllowedOnPlatform(%s, %s) = true; should be false at FRP-12 ship (PENDING)", k, p)
			}
		}
	}
}

func TestIsKindAllowedOnPlatform_UnknownKind(t *testing.T) {
	if IsKindAllowedOnPlatform("nonexistent_kind", PlatformLinuxDesktop) {
		t.Error("unknown kind should never be allowed")
	}
}
