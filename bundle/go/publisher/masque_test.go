package publisher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// Phase 3C. Tests for the `daal-publish masque-bridge`
// helper.

func TestMasqueBridge_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name string
		opts MasqueBridgeOptions
		want string
	}{
		{"empty endpoint", MasqueBridgeOptions{Endpoint: ""}, "--endpoint is required"},
		{"http scheme", MasqueBridgeOptions{Endpoint: "http://m.example.com/m"}, "must be https"},
		{"missing host", MasqueBridgeOptions{Endpoint: "https:///m"}, "must have a host"},
		{"missing path", MasqueBridgeOptions{Endpoint: "https://m.example.com"}, "non-empty path"},
		{"root path only", MasqueBridgeOptions{Endpoint: "https://m.example.com/"}, "non-empty path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := MasqueBridge(c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got err=%v, want substring %q", err, c.want)
			}
		})
	}
}

func TestMasqueBridge_RoundTripsThroughBundleParser(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.json")
	stub, host, err := MasqueBridge(MasqueBridgeOptions{
		Endpoint: "https://m.example.com:8443/.well-known/masque/udp",
		Validity: 7 * 24 * time.Hour,
		OutPath:  out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if host != "m.example.com" {
		t.Errorf("host: got %q want m.example.com", host)
	}
	if stub.ID != "mq-m-example-com" {
		t.Errorf("default id: got %q", stub.ID)
	}
	if stub.TransportFamily != string(bundle.TransportMASQUE) {
		t.Errorf("transport_family: got %q want masque", stub.TransportFamily)
	}
	if stub.ScarcityClass != "experimental" {
		t.Errorf("scarcity_class: got %q want experimental", stub.ScarcityClass)
	}
	if stub.MasqueEndpoint != "https://m.example.com:8443/.well-known/masque/udp" {
		t.Errorf("masque_endpoint: got %q", stub.MasqueEndpoint)
	}
	if string(stub.FamilySpecificConfig) != `{}` {
		t.Errorf("family_specific_config default: got %s want {}", stub.FamilySpecificConfig)
	}

	// File written and contains the new field.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"transport_family": "masque"`) {
		t.Errorf("disk contents missing transport_family:\n%s", body)
	}
	if !strings.Contains(string(body), `"masque_endpoint":`) {
		t.Errorf("disk contents missing masque_endpoint:\n%s", body)
	}
}

func TestMasqueBridge_DefaultValiditySevenDays(t *testing.T) {
	stub, _, err := MasqueBridge(MasqueBridgeOptions{
		Endpoint: "https://m.example.com/m",
	})
	if err != nil {
		t.Fatal(err)
	}
	from, _ := time.Parse(time.RFC3339, stub.ValidFrom)
	until, _ := time.Parse(time.RFC3339, stub.ValidUntil)
	span := until.Sub(from)
	if span < 7*24*time.Hour-time.Minute || span > 7*24*time.Hour+time.Minute {
		t.Errorf("default validity span: got %v want ~7d", span)
	}
}

func TestMasqueBridge_HonoursOverrides(t *testing.T) {
	stub, _, err := MasqueBridge(MasqueBridgeOptions{
		Endpoint:                     "https://m.example.com/m",
		RouteID:                      "mq-custom",
		Validity:                     3 * time.Hour,
		CaveatFAIR:                   "موقت",
		ExperimentalMinEngineVersion: "0.7.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if stub.ID != "mq-custom" {
		t.Errorf("custom id lost: got %q", stub.ID)
	}
	if stub.CaveatFAIR == "" {
		t.Error("caveat lost")
	}
	if stub.ExperimentalMinEngineVersion != "0.7.2" {
		t.Errorf("min version lost: got %q", stub.ExperimentalMinEngineVersion)
	}
}
