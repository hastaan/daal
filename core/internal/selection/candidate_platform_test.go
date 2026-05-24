package selection

import (
	"errors"
	"testing"
)

// noPassPolicy mirrors FRP-12-ship behaviour: every kind PENDING
// → never Pass.
func noPassPolicy(kind string) AllowOf {
	return AllowOf{Pass: false}
}

// linuxOnlyPassPolicy is a synthetic test policy: client_desync
// is PASS on linux-desktop only.
func linuxOnlyPassPolicy(kind string) AllowOf {
	if kind == "client_desync" {
		return MakeAllow(true, "linux-desktop")
	}
	return AllowOf{Pass: false}
}

func TestRejectByPlatform_NoModifiersIsNoOp(t *testing.T) {
	for _, in := range []string{"", "null", "[]"} {
		if err := RejectByPlatform(in, "linux", true, noPassPolicy); err != nil {
			t.Errorf("RejectByPlatform(%q): %v, want nil", in, err)
		}
	}
}

func TestRejectByPlatform_RejectsAtFRP12Ship(t *testing.T) {
	// FRP-12 ship: every registered kind is PENDING → noPassPolicy.
	in := `[{"kind":"client_desync","platform":"linux_desktop_only"}]`
	err := RejectByPlatform(in, "linux", true, noPassPolicy)
	if err == nil {
		t.Fatal("RejectByPlatform with PENDING-only policy should reject; got nil")
	}
	if !errors.Is(err, ErrModifierPlatform) {
		t.Errorf("error %v; want IMP_MODIFIER_PLATFORM (ErrModifierPlatform)", err)
	}
}

func TestRejectByPlatform_PassOnAllowedPlatform(t *testing.T) {
	in := `[{"kind":"client_desync"}]`
	err := RejectByPlatform(in, "linux", true, linuxOnlyPassPolicy)
	if err != nil {
		t.Errorf("RejectByPlatform on linux-desktop with PASS policy: %v, want nil", err)
	}
}

func TestRejectByPlatform_RejectsOnDisallowedPlatform(t *testing.T) {
	in := `[{"kind":"client_desync"}]`
	// Same kind PASS-on-linux-desktop policy, but request runtime
	// is android.
	err := RejectByPlatform(in, "linux", false, linuxOnlyPassPolicy)
	if err == nil {
		t.Fatal("RejectByPlatform on android with linux-only policy should reject; got nil")
	}
	if !errors.Is(err, ErrModifierPlatform) {
		t.Errorf("error %v; want ErrModifierPlatform", err)
	}
}

func TestRejectByPlatform_RejectsUnknownKind(t *testing.T) {
	in := `[{"kind":"some_unknown_modifier"}]`
	err := RejectByPlatform(in, "linux", true, linuxOnlyPassPolicy)
	if err == nil || !errors.Is(err, ErrModifierPlatform) {
		t.Errorf("unknown kind should reject; got %v", err)
	}
}

func TestRejectByPlatform_MalformedJSONRejected(t *testing.T) {
	err := RejectByPlatform("not json", "linux", true, noPassPolicy)
	if err == nil || !errors.Is(err, ErrModifierPlatform) {
		t.Errorf("malformed JSON should reject; got %v", err)
	}
}

func TestRejectByPlatform_NilPolicyRejects(t *testing.T) {
	in := `[{"kind":"client_desync"}]`
	err := RejectByPlatform(in, "linux", true, nil)
	if err == nil {
		t.Error("nil policy with non-empty modifiers should reject")
	}
}

func TestRejectByPlatform_UnknownGOOSRejects(t *testing.T) {
	in := `[{"kind":"client_desync"}]`
	err := RejectByPlatform(in, "plan9", true, linuxOnlyPassPolicy)
	if err == nil || !errors.Is(err, ErrModifierPlatform) {
		t.Errorf("unknown GOOS should reject; got %v", err)
	}
}

func TestPlatformFromGOOSEngine(t *testing.T) {
	cases := []struct {
		goos    string
		desktop bool
		want    string
		ok      bool
	}{
		{"linux", true, "linux-desktop", true},
		{"linux", false, "android", true},
		{"darwin", true, "macos-desktop", true},
		{"darwin", false, "ios", true},
		{"windows", true, "windows-desktop", true},
		{"android", false, "android", true},
		{"ios", false, "ios", true},
		{"plan9", true, "", false},
	}
	for _, c := range cases {
		got, ok := platformFromGOOS(c.goos, c.desktop)
		if got != c.want || ok != c.ok {
			t.Errorf("platformFromGOOS(%q,%v) = (%q,%v), want (%q,%v)",
				c.goos, c.desktop, got, ok, c.want, c.ok)
		}
	}
}
