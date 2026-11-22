package fieldprobe

import (
	"errors"
	"strings"
	"testing"
	"time"

	"daal/core/diagnostics"
)

func resetAtHello() diagnostics.Observation {
	return diagnostics.Observation{Phase: diagnostics.PhaseHandshake, TLS: true, Reset: true}
}

func TestTargets_DefaultLoads(t *testing.T) {
	tg, err := DefaultTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(tg.SHA256) != 64 || tg.Version == "" {
		t.Fatal("version / sha")
	}
}

func TestTargets_RefusesWhatTheTestMustNeverTouch(t *testing.T) {
	base := string(defaultTargetsJSON)
	for name, mut := range map[string]string{
		"domestic name":      strings.Replace(base, `"white_name": "hcaptcha.com"`, `"white_name": "www.example.ir"`, 1),
		"address for a name": strings.Replace(base, `"github": "github.com"`, `"github": "140.82.121.4"`, 1),
		"tor":                strings.Replace(base, `"neutral_sni": "github.com"`, `"neutral_sni": "www.torproject.org"`, 1),
		"vpn service":        strings.Replace(base, `"neutral_sni": "github.com"`, `"neutral_sni": "nordvpn.com"`, 1),
		"other resolver":     strings.Replace(base, `"public_resolver": "1.1.1.1:53"`, `"public_resolver": "8.8.8.8:53"`, 1),
		"domestic flag":      strings.Replace(base, `"expect": ""`, `"expect": "", "domestic": true`, 1),
		"catch-all block":    strings.Replace(base, `"140.82.112.0/20"`, `"0.0.0.0/1"`, 1),
		"private block":      strings.Replace(base, `"140.82.112.0/20"`, `"10.0.0.0/8"`, 1),
		"role without block": strings.Replace(base, `"github": [`, `"other": [`, 1),
		"domestic list":      strings.Replace(base, `"version":`, `"domestic": ["x.example"], "version":`, 1),
		"unknown field":      strings.Replace(base, `"version":`, `"extra": 1, "version":`, 1),
		"relative path":      strings.Replace(base, `"white_path": "/1/api.js"`, `"white_path": "1/api.js"`, 1),
	} {
		if mut == base {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := LoadTargets([]byte(mut)); !errors.Is(err, ErrTargets) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	var h History
	if ok, _ := h.Allow("wifi-1", now); !ok {
		t.Fatal("first run refused")
	}
	h.Note("wifi-1", now)
	if ok, wait := h.Allow("wifi-1", now.Add(time.Hour)); ok || wait != 5*time.Hour {
		t.Fatalf("same network an hour later: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := h.Allow("cell-1", now.Add(time.Hour)); !ok {
		t.Fatal("another network refused")
	}
	h.Note("cell-1", now.Add(time.Hour))
	h.Note("wifi-2", now.Add(2*time.Hour))
	if ok, _ := h.Allow("eth-1", now.Add(3*time.Hour)); ok {
		t.Fatal("a fourth run in a day allowed")
	}
	if ok, _ := h.Allow("wifi-1", now.Add(25*time.Hour)); !ok {
		t.Fatal("still refused a day later")
	}
}

func TestResolverClass(t *testing.T) {
	for in, want := range map[string]string{"192.168.1.1": "private", "1.1.1.1": "well_known_public",
		"217.218.127.127": "isp_public", "": "unknown"} {
		var xs []string
		if in != "" {
			xs = []string{in}
		}
		if got := ResolverClass(ParseResolvers(xs)); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
