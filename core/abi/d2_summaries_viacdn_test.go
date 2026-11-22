package abi

import (
	"encoding/json"
	"strings"
	"testing"

	"daal/core/routestore"
)

// TestRowToDisplay_ViaCDN: a route that reaches its relay through
// Cloudflare (exposure cdn_fronted, the `_cdn_endpoint` carrier) says so,
// so the UI can name it "WebSocket TLS · Cloudflare" instead of showing a
// second plain "WebSocket TLS". Every other row says false, and the key
// is always on the wire.
func TestRowToDisplay_ViaCDN(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"cdn_fronted", true},
		{" CDN_FRONTED ", true},
		{"direct_vps", false},
		{"", false},
		{"serverless_external", false},
	}
	for _, tc := range cases {
		row := routestore.RouteRow{RouteID: "pub/r1", TransportFamily: "websocket-tls", ExposureMode: tc.mode}
		got := rowToDisplay(row, observeRoute(row, nil))
		if got.ViaCDN != tc.want {
			t.Errorf("ExposureMode=%q: ViaCDN=%v, want %v", tc.mode, got.ViaCDN, tc.want)
		}
		body, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), `"via_cdn":`) {
			t.Errorf("ExposureMode=%q: via_cdn missing from %s", tc.mode, body)
		}
	}
}
