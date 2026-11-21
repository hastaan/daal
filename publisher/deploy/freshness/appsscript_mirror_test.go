package freshness

import (
	"errors"
	"strings"
	"testing"
)

const asURL = "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec?k=AAAAAAAAAAAAAAAAAAAAAA"

// D-3: the Google channel alone satisfies the floor; nothing else does.
func TestMirrorFloorAdmitsTheGoogleChannelAlone(t *testing.T) {
	set, err := NewMirrorSet([]Mirror{{Provider: ProviderAppsScript, URL: asURL}})
	if err != nil || set.Len() != 1 || !set.MeetsFloor() {
		t.Fatalf("%v %v", set, err)
	}
	if _, err := NewMirrorSet([]Mirror{{Provider: ProviderR2, URL: "https://r2.example.com/f.json"}}); !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("one r2 mirror: %v", err)
	}
	// A label that only looks like it.
	if _, err := NewMirrorSet([]Mirror{{Provider: "appsscript2", URL: asURL}}); !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("another label: %v", err)
	}
	var zero *MirrorSet
	if zero.MeetsFloor() {
		t.Fatal("a nil set has no floor")
	}
	if !MeetsMirrorFloor([]Provider{ProviderR2, ProviderAppsScript}) || MeetsMirrorFloor(nil) {
		t.Fatal("floor")
	}
}

// An appsscript mirror has one URL shape, wherever the label appears.
func TestAppsScriptMirrorURLShape(t *testing.T) {
	id, tok, err := ValidateAppsScriptURL(asURL)
	if err != nil || id != "AKfycbx0123456789abcdefghij" || tok != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("%q %q %v", id, tok, err)
	}
	base := "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec"
	for _, bad := range []string{
		base,
		base + "?k=short",
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA&x=1",
		base + "?x=1&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA#frag",
		strings.Replace(asURL, "script.google.com", "script.google.com:8443", 1),
		strings.Replace(asURL, "script.google.com", "evil.example", 1),
		strings.Replace(asURL, "/macros/s/", "/a/macros/example.org/s/", 1),
		strings.Replace(asURL, "/exec", "/dev", 1),
		strings.Replace(asURL, "https://", "http://", 1),
		"https://script.google.com/macros/s/short/exec?k=AAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, _, err := ValidateAppsScriptURL(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
		if _, err := NewMirrorSet([]Mirror{{Provider: ProviderAppsScript, URL: bad}}); err == nil {
			t.Errorf("mirror set accepted %s", bad)
		}
	}
}
