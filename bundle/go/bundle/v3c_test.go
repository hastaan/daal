package bundle

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Phase 3C bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3C widening" and
// specs/masque-ladder-v1.md.

// TestSBPv1_MasqueEndpointRoundTripOnMasqueRoute — a parseable
// `https://host/path` round-trips through Build → Parse →
// Verify on a `transport_family=masque` route.
func TestSBPv1_MasqueEndpointRoundTripOnMasqueRoute(t *testing.T) {
	m := baseManifest(t, "experimental", "masque", time.Now().Add(24*time.Hour))
	m.Routes[0].MasqueEndpoint = "https://m.example.com/.well-known/masque/udp"
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := b.Manifest.Routes[0].MasqueEndpoint; got != "https://m.example.com/.well-known/masque/udp" {
		t.Errorf("endpoint round-trip: got %q", got)
	}
}

// TestSBPv1_MasqueEndpointEmptyOnMasqueRouteAccepted — an empty
// endpoint on a masque route is allowed at import time. The
// engine treats it as "no usable endpoint" and filters at
// activation; this matches 3A's `family_specific_config` rule
// (optional fields are optional).
func TestSBPv1_MasqueEndpointEmptyOnMasqueRouteAccepted(t *testing.T) {
	m := baseManifest(t, "experimental", "masque", time.Now().Add(24*time.Hour))
	// Endpoint left empty.
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Errorf("empty endpoint on masque route: %v", err)
	}
}

// TestSBPv1_MasqueEndpointOnNonMasqueRouteRejected — a
// masque_endpoint on, e.g., a vless-reality route is rejected
// at verify time so the routes[] shape stays unambiguous.
func TestSBPv1_MasqueEndpointOnNonMasqueRouteRejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Routes[0].MasqueEndpoint = "https://x.example.com/m"
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrMasqueEndpointOnNonMasqueRoute) {
		t.Fatalf("got %v, want ErrMasqueEndpointOnNonMasqueRoute", err)
	}
}

// TestSBPv1_MasqueEndpointMalformedRejected — http://, missing
// host, missing path, and unparseable strings all reject with
// ErrMasqueEndpointMalformed.
func TestSBPv1_MasqueEndpointMalformedRejected(t *testing.T) {
	cases := map[string]string{
		"http scheme":        "http://m.example.com/m",
		"empty host":         "https:///m",
		"missing path":       "https://m.example.com",
		"path-is-just-slash": "https://m.example.com/",
		"unparseable":        "://broken",
	}
	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest(t, "experimental", "masque", time.Now().Add(24*time.Hour))
			m.Routes[0].MasqueEndpoint = url
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrMasqueEndpointMalformed) {
				t.Errorf("got %v, want ErrMasqueEndpointMalformed", err)
			}
		})
	}
}

// TestSBPv1_MasqueRouteCarriesScarcityExperimental — the V3
// taxonomy lands MASQUE at Experimental maturity; the parser
// accepts `scarcity_class = "experimental"` for masque routes
// (regression guarding against accidental scarcity-class
// drift). Other scarcity classes are NOT prohibited at parse
// time — the routestore family table is the gatekeeper.
func TestSBPv1_MasqueRouteCarriesScarcityExperimental(t *testing.T) {
	m := baseManifest(t, "experimental", "masque", time.Now().Add(24*time.Hour))
	m.Routes[0].MasqueEndpoint = "https://m.example.com/m"
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.Routes[0].ScarcityClass != "experimental" {
		t.Errorf("scarcity round-trip: got %q", b.Manifest.Routes[0].ScarcityClass)
	}
}
