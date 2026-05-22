package conjure

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	goodPubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func goodIPv4Subnet() string { return "192.122.190.0/24" }
func goodIPv6Subnet() string { return "2001:48a8:687f::/48" }

func okDialer(rawPhantom string) ConjureDialer {
	return func(ctx context.Context, phantomSubnets []string, stationPubkey []byte, decoyPool []string) (string, *Conn, error) {
		return rawPhantom, &Conn{}, nil
	}
}

// TestFamilyIDIsConjure — the 3A taxonomy mandates the family
// ID; a constant-string regression keeps it stable.
func TestFamilyIDIsConjure(t *testing.T) {
	if FamilyID != "conjure" {
		t.Fatalf("FamilyID drifted: %q", FamilyID)
	}
}

// TestFloorsLockedAtV1 — `specs/conjure-route-v1.md` locks the
// /24 IPv4 and /32 IPv6 floors; the constants here are the
// load-bearing copy and must not silently widen.
func TestFloorsLockedAtV1(t *testing.T) {
	if MinIPv4PrefixLen != 24 {
		t.Errorf("MinIPv4PrefixLen drifted: %d", MinIPv4PrefixLen)
	}
	if MinIPv6PrefixLen != 32 {
		t.Errorf("MinIPv6PrefixLen drifted: %d", MinIPv6PrefixLen)
	}
	if StationPubkeyHexLen != 64 {
		t.Errorf("StationPubkeyHexLen drifted: %d", StationPubkeyHexLen)
	}
}

// TestHandler_UnavailableInBuildWithoutConjure — modeled by a
// nil dialer (a future `-tags no_conjure` excluder would do
// the same). Dial returns ErrFamilyHandlerUnavailable.
func TestHandler_UnavailableInBuildWithoutConjure(t *testing.T) {
	h := NewHandler(nil)
	if h.Available() {
		t.Error("Available() should be false with nil dialer")
	}
	_, err := h.Dial(context.Background(), Route{
		RouteID:        "rA",
		PhantomSubnets: []string{goodIPv4Subnet()},
		StationPubkey:  goodPubkey,
	})
	if !errors.Is(err, ErrFamilyHandlerUnavailable) {
		t.Errorf("got %v, want ErrFamilyHandlerUnavailable", err)
	}
}

// TestValidatePhantomSubnet_FloorsAndParse — the floors are
// /24 IPv4 and /32 IPv6 per the locked spec.
func TestValidatePhantomSubnet_FloorsAndParse(t *testing.T) {
	cases := []struct {
		cidr    string
		wantErr bool
	}{
		{"192.122.190.0/24", false},
		{"192.122.190.0/25", false},
		{"192.122.190.0/16", true}, // too broad IPv4
		{"2001:48a8:687f::/32", false},
		{"2001:48a8:687f::/48", false},
		{"2001:48a8:687f::/16", true}, // too broad IPv6
		{"not-a-cidr", true},
		{"", true},
	}
	for _, c := range cases {
		err := ValidatePhantomSubnet(c.cidr)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidatePhantomSubnet(%q) err=%v wantErr=%v", c.cidr, err, c.wantErr)
		}
	}
}

// TestHandler_PhantomRotationAcrossDials — the upstream
// library is responsible for choosing a phantom from the
// supplied pool; the shim records the HASHED phantom into the
// diagnostic callback. We exercise this by varying the
// "rawPhantom" the dialer reports across two calls and
// confirming the hashes differ deterministically.
func TestHandler_PhantomRotationAcrossDials(t *testing.T) {
	var hashes []string
	rawIPs := []string{"192.122.190.5", "192.122.190.42"}
	idx := 0
	dialer := func(ctx context.Context, phantomSubnets []string, stationPubkey []byte, decoyPool []string) (string, *Conn, error) {
		ip := rawIPs[idx%len(rawIPs)]
		idx++
		return ip, &Conn{}, nil
	}
	h := NewHandler(dialer, WithRecordPhantomInUse(func(hashHex string) {
		hashes = append(hashes, hashHex)
	}))
	for i := 0; i < 2; i++ {
		_, err := h.Dial(context.Background(), Route{
			RouteID:        "cj-1",
			PhantomSubnets: []string{goodIPv4Subnet()},
			StationPubkey:  goodPubkey,
		})
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
	if hashes[0] == hashes[1] {
		t.Errorf("phantom hashes did not rotate: %q", hashes[0])
	}
	for _, h := range hashes {
		if len(h) != 16 {
			t.Errorf("hash len: got %d want 16 (%q)", len(h), h)
		}
		if strings.ContainsAny(h, "0123456789abcdef") == false {
			t.Errorf("hash not lowercase hex: %q", h)
		}
	}
	// Privacy invariant: the raw IP MUST NOT leak through the
	// hash (sanity check; a hash starting with the IP's bytes
	// would be a bug).
	for i, ip := range rawIPs {
		if strings.HasPrefix(hashes[i], ip[:8]) {
			t.Errorf("hash %q leaked raw IP %q", hashes[i], ip)
		}
	}
}

// TestHandler_StationPubkeyMalformedRejected — wrong length or
// non-hex pubkey is refused.
func TestHandler_StationPubkeyMalformedRejected(t *testing.T) {
	cases := []string{
		"",
		"deadbeef",              // too short
		strings.Repeat("z", 64), // non-hex
		strings.Repeat("a", 63), // off-by-one short
		strings.Repeat("a", 65), // off-by-one long
	}
	h := NewHandler(okDialer("1.2.3.4"))
	for _, k := range cases {
		_, err := h.Dial(context.Background(), Route{
			RouteID:        "rA",
			PhantomSubnets: []string{goodIPv4Subnet()},
			StationPubkey:  k,
		})
		if !errors.Is(err, ErrStationPubkeyMalformed) {
			t.Errorf("pubkey=%q got %v, want ErrStationPubkeyMalformed", k, err)
		}
	}
}

// TestHandler_DecoyHostMalformedRejected — RFC 1123 violations
// in the decoy pool surface as ErrDecoyHostMalformed.
func TestHandler_DecoyHostMalformedRejected(t *testing.T) {
	bad := []string{
		"",
		"-bad.example.com",
		"bad-.example.com",
		"bad..example.com",
		"trailing.dot.",
		strings.Repeat("a", 64) + ".example.com", // label > 63
	}
	h := NewHandler(okDialer("1.2.3.4"))
	for _, host := range bad {
		_, err := h.Dial(context.Background(), Route{
			RouteID:        "rA",
			PhantomSubnets: []string{goodIPv4Subnet()},
			StationPubkey:  goodPubkey,
			DecoyPool:      []string{host},
		})
		if !errors.Is(err, ErrDecoyHostMalformed) {
			t.Errorf("host=%q got %v, want ErrDecoyHostMalformed", host, err)
		}
	}
}

// TestHandler_NoPhantomSubnetsRejected — defence-in-depth at
// the engine layer; the bundle parser also rejects.
func TestHandler_NoPhantomSubnetsRejected(t *testing.T) {
	h := NewHandler(okDialer("1.2.3.4"))
	_, err := h.Dial(context.Background(), Route{
		RouteID:       "rA",
		StationPubkey: goodPubkey,
	})
	if !errors.Is(err, ErrNoPhantomSubnets) {
		t.Errorf("got %v, want ErrNoPhantomSubnets", err)
	}
}

// TestHashPhantom_DeterministicAndShort — the diagnostic must
// be 16 hex chars and stable for the same input.
func TestHashPhantom_DeterministicAndShort(t *testing.T) {
	h1 := HashPhantom("192.122.190.5")
	h2 := HashPhantom("192.122.190.5")
	if h1 != h2 {
		t.Errorf("HashPhantom not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 16 {
		t.Errorf("HashPhantom len: got %d want 16", len(h1))
	}
	if HashPhantom("192.122.190.5") == HashPhantom("192.122.190.6") {
		t.Errorf("hash collision on adjacent IPs")
	}
}

// TestValidDecoyHost_AcceptsCommonShapes — sanity coverage on
// the RFC 1123 helper for the cases the publisher CLI needs to
// pass through.
func TestValidDecoyHost_AcceptsCommonShapes(t *testing.T) {
	good := []string{
		"www.example.com",
		"a.b.c.d.e.f",
		"static.example.org",
		"some-host-1.example.io",
	}
	for _, h := range good {
		if !ValidDecoyHost(h) {
			t.Errorf("ValidDecoyHost(%q) = false; want true", h)
		}
	}
}
