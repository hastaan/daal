package freshness

import (
	"errors"
	"strings"
	"testing"
)

const asURL = "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA"

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
	id, slot, tok, err := ValidateAppsScriptURL(asURL)
	if err != nil || id != "AKfycbx0123456789abcdefghij" || slot != "AAAAAAAAAAA" || tok != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("%q %q %q %v", id, slot, tok, err)
	}
	base := "https://script.google.com/macros/s/AKfycbx0123456789abcdefghij/exec"
	if id, err := ValidateAppsScriptBase(base); err != nil || id != "AKfycbx0123456789abcdefghij" {
		t.Fatalf("base: %q %v", id, err)
	}
	for _, bad := range []string{base + "?", base + "?s=AAAAAAAAAAA", base + "#f", base + "/"} {
		if _, err := ValidateAppsScriptBase(bad); err == nil {
			t.Errorf("base accepted %s", bad)
		}
	}
	for _, bad := range []string{
		base,
		// The single-relay shape of the first build: never deployed,
		// no longer read.
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAAAA&k=short",
		base + "?s=short&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?k=AAAAAAAAAAAAAAAAAAAAAA&s=AAAAAAAAAAA",
		base + "?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA&x=1",
		base + "?s=AAAAAAAAAAA&s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
		base + "?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA#frag",
		base + "?s=AAAAAAAAA%41A&k=AAAAAAAAAAAAAAAAAAAAAA",
		strings.Replace(asURL, "script.google.com", "script.google.com:8443", 1),
		strings.Replace(asURL, "script.google.com", "evil.example", 1),
		strings.Replace(asURL, "/macros/s/", "/a/macros/example.org/s/", 1),
		strings.Replace(asURL, "/exec", "/dev", 1),
		strings.Replace(asURL, "https://", "http://", 1),
		"https://script.google.com/macros/s/short/exec?s=AAAAAAAAAAA&k=AAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, _, _, err := ValidateAppsScriptURL(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
		if _, err := NewMirrorSet([]Mirror{{Provider: ProviderAppsScript, URL: bad}}); err == nil {
			t.Errorf("mirror set accepted %s", bad)
		}
	}
}
