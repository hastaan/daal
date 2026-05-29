package bundle

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// Phase 3D bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3D widening",
// specs/psiphon-route-v1.md, and specs/conjure-route-v1.md.

const (
	v3dGoodPubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func goodPsiphonBlobB64(n int) string {
	if n <= 0 {
		n = 4096
	}
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i & 0xff)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// TestSBPv1_PsiphonBlobRoundTripOnPsiphonRoute — a properly-
// sized base64 blob round-trips through Build → Parse →
// Verify on a `transport_family=psiphon` route.
func TestSBPv1_PsiphonBlobRoundTripOnPsiphonRoute(t *testing.T) {
	m := baseManifest(t, "normal", "psiphon", time.Now().Add(24*time.Hour))
	m.Routes[0].PsiphonBundleBlobB64 = goodPsiphonBlobB64(4096)
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.Routes[0].PsiphonBundleBlobB64 == "" {
		t.Errorf("blob did not round-trip")
	}
	decoded, err := base64.StdEncoding.DecodeString(b.Manifest.Routes[0].PsiphonBundleBlobB64)
	if err != nil {
		t.Errorf("decode: %v", err)
	}
	if len(decoded) != 4096 {
		t.Errorf("decoded len: got %d want 4096", len(decoded))
	}
}

// TestSBPv1_PsiphonBlobOnNonPsiphonRouteRejected — a Psiphon
// blob on, e.g., a vless-reality route is rejected at verify
// time (defence in depth).
func TestSBPv1_PsiphonBlobOnNonPsiphonRouteRejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Routes[0].PsiphonBundleBlobB64 = goodPsiphonBlobB64(4096)
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); !errors.Is(err, ErrPsiphonBlobOnNonPsiphonRoute) {
		t.Fatalf("got %v, want ErrPsiphonBlobOnNonPsiphonRoute", err)
	}
}

// TestSBPv1_PsiphonBlobMalformedRejected — base64 that decodes
// to <256 or >65536 bytes, or that fails to decode at all,
// rejects with ErrPsiphonBlobMalformed.
func TestSBPv1_PsiphonBlobMalformedRejected(t *testing.T) {
	cases := map[string]string{
		"not base64":    "@@@@@@@@",
		"too small":     base64.StdEncoding.EncodeToString(make([]byte, 100)),
		"too large":     base64.StdEncoding.EncodeToString(make([]byte, 70000)),
		"exactly 255":   base64.StdEncoding.EncodeToString(make([]byte, 255)),
		"exactly 65537": base64.StdEncoding.EncodeToString(make([]byte, 65537)),
	}
	for name, blob := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest(t, "normal", "psiphon", time.Now().Add(24*time.Hour))
			m.Routes[0].PsiphonBundleBlobB64 = blob
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrPsiphonBlobMalformed) {
				t.Errorf("got %v, want ErrPsiphonBlobMalformed", err)
			}
		})
	}
}

// TestSBPv1_ConjureRoundTripOnConjureRoute — a fully-populated
// Conjure route round-trips.
func TestSBPv1_ConjureRoundTripOnConjureRoute(t *testing.T) {
	m := baseManifest(t, "experimental", "conjure", time.Now().Add(24*time.Hour))
	m.Routes[0].ConjurePhantomSubnets = []string{
		"192.122.190.0/24",
		"2001:48a8:687f::/48",
	}
	m.Routes[0].ConjureStationPubkey = v3dGoodPubkey
	m.Routes[0].ConjureDecoyPool = []string{"www.example.com", "static.example.org"}
	data := mustSignedBundle(t, m, nil)
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(b.Manifest.Routes[0].ConjurePhantomSubnets) != 2 {
		t.Errorf("phantom subnets did not round-trip")
	}
	if b.Manifest.Routes[0].ConjureStationPubkey != v3dGoodPubkey {
		t.Errorf("station pubkey did not round-trip")
	}
	if len(b.Manifest.Routes[0].ConjureDecoyPool) != 2 {
		t.Errorf("decoy pool did not round-trip")
	}
}

// TestSBPv1_ConjureFieldOnNonConjureRouteRejected — any of the
// Conjure fields on a non-conjure route rejects with
// ErrConjureFieldOnNonConjureRoute.
func TestSBPv1_ConjureFieldOnNonConjureRouteRejected(t *testing.T) {
	cases := map[string]func(*RouteManifestEntry){
		"phantom subnets": func(r *RouteManifestEntry) { r.ConjurePhantomSubnets = []string{"192.122.190.0/24"} },
		"station pubkey":  func(r *RouteManifestEntry) { r.ConjureStationPubkey = v3dGoodPubkey },
		"decoy pool":      func(r *RouteManifestEntry) { r.ConjureDecoyPool = []string{"www.example.com"} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
			mut(&m.Routes[0])
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrConjureFieldOnNonConjureRoute) {
				t.Errorf("got %v, want ErrConjureFieldOnNonConjureRoute", err)
			}
		})
	}
}

// TestSBPv1_ConjurePhantomSubnetsTooBroadRejected — IPv4 /16 and
// IPv6 /16 are below the locked-at-3D floors and are refused.
func TestSBPv1_ConjurePhantomSubnetsTooBroadRejected(t *testing.T) {
	// Note: empty phantom subnets on a Conjure route is NOT a
	// parse-time rejection — a publisher MAY pre-publish a
	// route stub before wiring up the station. The engine
	// filters such routes at activation time. This matches the
	// 3A `family_specific_config` / 3C `masque_endpoint`
	// pattern.
	cases := map[string][]string{
		"ipv4 too broad": {"192.122.0.0/16"},
		"ipv6 too broad": {"2001::/16"},
		"unparseable":    {"not-a-cidr"},
		"missing prefix": {"192.122.190.0"},
		"prefix-only":    {"/24"},
	}
	for name, subnets := range cases {
		t.Run(name, func(t *testing.T) {
			m := baseManifest(t, "experimental", "conjure", time.Now().Add(24*time.Hour))
			m.Routes[0].ConjurePhantomSubnets = subnets
			m.Routes[0].ConjureStationPubkey = v3dGoodPubkey
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrConjurePhantomSubnetsMalformed) {
				t.Errorf("subnets=%v got %v, want ErrConjurePhantomSubnetsMalformed", subnets, err)
			}
		})
	}
}

// TestSBPv1_ConjureStationPubkeyMalformedRejected — non-64-char
// or non-hex station pubkey is rejected.
func TestSBPv1_ConjureStationPubkeyMalformedRejected(t *testing.T) {
	// Note: empty station pubkey on a Conjure route is NOT a
	// parse-time rejection (publisher pre-stub pattern);
	// engine filters at activation.
	cases := []string{
		"deadbeef",              // too short
		strings.Repeat("z", 64), // non-hex
		strings.Repeat("a", 63), // off-by-one short
		strings.Repeat("a", 65), // off-by-one long
	}
	for _, k := range cases {
		t.Run(k, func(t *testing.T) {
			m := baseManifest(t, "experimental", "conjure", time.Now().Add(24*time.Hour))
			m.Routes[0].ConjurePhantomSubnets = []string{"192.122.190.0/24"}
			m.Routes[0].ConjureStationPubkey = k
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrConjureStationPubkeyMalformed) {
				t.Errorf("pubkey=%q got %v, want ErrConjureStationPubkeyMalformed", k, err)
			}
		})
	}
}

// TestSBPv1_ConjureDecoyPoolMalformedRejected — RFC 1123
// violations in the decoy pool surface as
// ErrConjureDecoyPoolMalformed.
func TestSBPv1_ConjureDecoyPoolMalformedRejected(t *testing.T) {
	cases := [][]string{
		{""},
		{"-bad.example.com"},
		{"bad-.example.com"},
		{"trailing.dot."},
	}
	for _, pool := range cases {
		t.Run(strings.Join(pool, ","), func(t *testing.T) {
			m := baseManifest(t, "experimental", "conjure", time.Now().Add(24*time.Hour))
			m.Routes[0].ConjurePhantomSubnets = []string{"192.122.190.0/24"}
			m.Routes[0].ConjureStationPubkey = v3dGoodPubkey
			m.Routes[0].ConjureDecoyPool = pool
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); !errors.Is(err, ErrConjureDecoyPoolMalformed) {
				t.Errorf("pool=%v got %v, want ErrConjureDecoyPoolMalformed", pool, err)
			}
		})
	}
}
