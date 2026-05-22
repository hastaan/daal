package publisher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodConjurePubkey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestConjureBridge_HappyPath — happy path with mixed v4/v6
// phantom subnets emits a usable route stub with the expected
// `transport_family = "conjure"` token and default
// `scarcity_class = "experimental"`.
func TestConjureBridge_HappyPath(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "stub.json")

	stub, fpPrefix, err := ConjureBridge(ConjureBridgeOptions{
		StationPubkey:  goodConjurePubkey,
		PhantomSubnets: []string{"192.122.190.0/24", "2001:48a8:687f::/48"},
		DecoyPool:      []string{"www.example.com", "static.example.org"},
		OutPath:        out,
	})
	if err != nil {
		t.Fatalf("ConjureBridge: %v", err)
	}
	if stub.TransportFamily != "conjure" {
		t.Errorf("transport_family: got %q", stub.TransportFamily)
	}
	if stub.ScarcityClass != "experimental" {
		t.Errorf("default scarcity: got %q", stub.ScarcityClass)
	}
	if !strings.HasPrefix(stub.ID, "cj-") {
		t.Errorf("default ID prefix: got %q", stub.ID)
	}
	if !strings.HasSuffix(stub.ID, fpPrefix) {
		t.Errorf("default ID suffix: got %q want suffix %q", stub.ID, fpPrefix)
	}
	if len(stub.ConjurePhantomSubnets) != 2 {
		t.Errorf("phantom subnets: %v", stub.ConjurePhantomSubnets)
	}
	if stub.ConjureStationPubkey != goodConjurePubkey {
		t.Errorf("station pubkey: %q", stub.ConjureStationPubkey)
	}

	// Round-trip through JSON.
	body, _ := os.ReadFile(out)
	var parsed ConjureRouteStub
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
}

// TestConjureBridge_BroadSubnetRejected — /16 IPv4 + /16 IPv6
// are below the locked-at-3D floors.
func TestConjureBridge_BroadSubnetRejected(t *testing.T) {
	cases := [][]string{
		{"192.122.0.0/16"},
		{"2001::/16"},
	}
	for _, subnets := range cases {
		_, _, err := ConjureBridge(ConjureBridgeOptions{
			StationPubkey:  goodConjurePubkey,
			PhantomSubnets: subnets,
		})
		if err == nil || !strings.Contains(err.Error(), "phantom subnet") {
			t.Errorf("subnets=%v got %v", subnets, err)
		}
	}
}

// TestConjureBridge_MalformedPubkeyRejected — wrong-length or
// non-hex station pubkey fails.
func TestConjureBridge_MalformedPubkeyRejected(t *testing.T) {
	cases := []string{
		"",
		"deadbeef",
		strings.Repeat("z", 64),
		strings.Repeat("a", 63),
	}
	for _, k := range cases {
		_, _, err := ConjureBridge(ConjureBridgeOptions{
			StationPubkey:  k,
			PhantomSubnets: []string{"192.122.190.0/24"},
		})
		if err == nil || !strings.Contains(err.Error(), "station pubkey") {
			t.Errorf("pubkey=%q got %v", k, err)
		}
	}
}

// TestConjureBridge_MalformedDecoyRejected — RFC 1123
// violations in the decoy pool fail.
func TestConjureBridge_MalformedDecoyRejected(t *testing.T) {
	bad := [][]string{
		{""},
		{"-bad.example.com"},
		{"trailing.dot."},
	}
	for _, pool := range bad {
		_, _, err := ConjureBridge(ConjureBridgeOptions{
			StationPubkey:  goodConjurePubkey,
			PhantomSubnets: []string{"192.122.190.0/24"},
			DecoyPool:      pool,
		})
		if err == nil || !strings.Contains(err.Error(), "decoy host") {
			t.Errorf("pool=%v got %v", pool, err)
		}
	}
}

// TestConjureBridge_MixedV4V6SubnetsAccepted — the validator
// accepts an IPv4 subnet at /24 alongside an IPv6 subnet at /32.
func TestConjureBridge_MixedV4V6SubnetsAccepted(t *testing.T) {
	_, _, err := ConjureBridge(ConjureBridgeOptions{
		StationPubkey:  goodConjurePubkey,
		PhantomSubnets: []string{"192.122.190.0/24", "2001:48a8:687f::/32"},
	})
	if err != nil {
		t.Errorf("mixed v4/v6: %v", err)
	}
}
