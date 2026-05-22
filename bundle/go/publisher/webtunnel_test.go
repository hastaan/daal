package publisher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

// Phase 3A. Tests for the `daal-publish webtunnel-bridge`
// helper.

func TestWebTunnelBridge_RejectsBadInputs(t *testing.T) {
	cases := []struct {
		name string
		opts WebTunnelBridgeOptions
		want string
	}{
		{"empty url", WebTunnelBridgeOptions{URL: ""}, "--url is required"},
		{"http instead of https", WebTunnelBridgeOptions{URL: "http://example.com/p"}, "must be https"},
		{"missing host", WebTunnelBridgeOptions{URL: "https:///path"}, "must have a host"},
		{"empty path", WebTunnelBridgeOptions{URL: "https://example.com"}, "non-empty secret path"},
		{"root path only", WebTunnelBridgeOptions{URL: "https://example.com/"}, "non-empty secret path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := WebTunnelBridge(c.opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got err=%v, want substring %q", err, c.want)
			}
		})
	}
}

func TestWebTunnelBridge_RoundTripsThroughBundleParser(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.json")
	stub, host, err := WebTunnelBridge(WebTunnelBridgeOptions{
		URL:      "https://wt.example.com:8443/sec/0123456789abcdef",
		Validity: 7 * 24 * time.Hour,
		OutPath:  out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if host != "wt.example.com" {
		t.Errorf("host: got %q want wt.example.com", host)
	}
	if stub.ID != "wt-wt-example-com" {
		t.Errorf("default id: got %q", stub.ID)
	}
	if stub.TransportFamily != string(bundle.TransportWebTunnel) {
		t.Errorf("transport_family: got %q", stub.TransportFamily)
	}
	if stub.ScarcityClass != "experimental" {
		t.Errorf("scarcity_class: got %q want experimental", stub.ScarcityClass)
	}

	// Family-specific config MUST be a JSON object containing the
	// three locked WebTunnel keys.
	var cfg map[string]any
	if err := json.Unmarshal(stub.FamilySpecificConfig, &cfg); err != nil {
		t.Fatalf("family_specific_config not JSON: %v", err)
	}
	if cfg["webtunnel_secret_path"] != "/sec/0123456789abcdef" {
		t.Errorf("secret_path: got %v", cfg["webtunnel_secret_path"])
	}
	if cfg["webtunnel_sni"] != "wt.example.com" {
		t.Errorf("sni: got %v", cfg["webtunnel_sni"])
	}
	alpns, _ := cfg["webtunnel_alpn"].([]any)
	if len(alpns) != 1 || alpns[0] != "http/1.1" {
		t.Errorf("alpn default: got %v", alpns)
	}

	// File written.
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"transport_family": "webtunnel"`) {
		t.Errorf("disk contents missing transport_family:\n%s", body)
	}
}

func TestWebTunnelBridge_HonoursOverrides(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.json")
	stub, _, err := WebTunnelBridge(WebTunnelBridgeOptions{
		URL:                          "https://example.com/abc",
		RouteID:                      "wt-custom",
		ALPN:                         []string{"h2", "http/1.1"},
		CaveatFAIR:                   "تنها برای تست",
		ExperimentalMinEngineVersion: "0.7.0",
		OutPath:                      out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stub.ID != "wt-custom" {
		t.Errorf("custom id lost: got %q", stub.ID)
	}
	if stub.CaveatFAIR == "" {
		t.Error("caveat lost")
	}
	if stub.ExperimentalMinEngineVersion != "0.7.0" {
		t.Errorf("min version lost: got %q", stub.ExperimentalMinEngineVersion)
	}
	var cfg map[string]any
	_ = json.Unmarshal(stub.FamilySpecificConfig, &cfg)
	alpns, _ := cfg["webtunnel_alpn"].([]any)
	if len(alpns) != 2 {
		t.Errorf("custom alpn count: got %d", len(alpns))
	}
}
