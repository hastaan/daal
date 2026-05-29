package modifiers

// PlatformFromGOOS maps a runtime.GOOS value (plus a hint about
// whether the process is a desktop UI build) to one of the Platform
// enum values understood by per-modifier specs.
//
// The desktopHint bool disambiguates linux desktop from android
// (both report runtime.GOOS == "linux") and darwin desktop from ios
// (both report runtime.GOOS == "darwin"). Desktop builds pass true;
// Android / iOS engine builds pass false.
//
// Returns ("", false) for goos values the framework does not
// recognise; callers MUST treat unknown platforms as "no modifier
// is permitted" (locked invariant 40).
func PlatformFromGOOS(goos string, desktopHint bool) (Platform, bool) {
	switch goos {
	case "linux":
		if desktopHint {
			return PlatformLinuxDesktop, true
		}
		return PlatformAndroid, true
	case "darwin":
		if desktopHint {
			return PlatformMacOSDesktop, true
		}
		return PlatformIOS, true
	case "windows":
		return PlatformWindowsDesktop, true
	case "android":
		return PlatformAndroid, true
	case "ios":
		return PlatformIOS, true
	}
	return "", false
}

// IsKindAllowedOnPlatform returns true iff the modifier kind is
// registered AND its Status is PASS AND the platform appears in its
// platforms[] list. Returns false for unknown kinds, PENDING /
// REJECTED / DEPRECATED kinds, or kinds whose platforms[] does not
// include p (locked invariants 38 + 40).
//
// At FRP-12 ship every registered kind is PENDING, so this function
// returns false for every (kind, platform) pair.
func IsKindAllowedOnPlatform(kind string, p Platform) bool {
	m, err := Lookup(kind)
	if err != nil {
		return false
	}
	if m.Status != StatusPass {
		return false
	}
	for _, plat := range m.Platforms {
		if plat == p {
			return true
		}
	}
	return false
}
