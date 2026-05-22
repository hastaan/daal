package relaypack

import (
	"net"
	"strings"
	"testing"

	"daal/publisher/deploy/provider"
)

func mkRec() *provider.OperatorRecord {
	return &provider.OperatorRecord{
		Provider:   "hetzner",
		ServerID:   "12345",
		Region:     "fsn1",
		ServerType: "cx22",
		PublicIP:   net.ParseIP("5.75.0.1"),
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality"},
			{Family: "hysteria2"},
		},
	}
}

func TestDeriveRelayPackID_Deterministic(t *testing.T) {
	id1 := DeriveRelayPackID(mkRec())
	id2 := DeriveRelayPackID(mkRec())
	if id1 != id2 {
		t.Fatalf("non-deterministic: %s vs %s", id1, id2)
	}
	if !strings.HasPrefix(id1, "rp-") {
		t.Fatalf("missing rp- prefix: %s", id1)
	}
	if len(id1) != 3+32 { // "rp-" + 16 bytes hex
		t.Fatalf("unexpected length %d for %s", len(id1), id1)
	}
}

func TestDeriveRelayPackID_StableUnderCandidateReordering(t *testing.T) {
	a := mkRec()
	b := mkRec()
	b.Candidates[0], b.Candidates[1] = b.Candidates[1], b.Candidates[0]
	if DeriveRelayPackID(a) != DeriveRelayPackID(b) {
		t.Fatalf("id should be stable under candidate-set reordering")
	}
}

func TestDeriveRelayPackID_ChangesWithPublicIP(t *testing.T) {
	a := mkRec()
	b := mkRec()
	b.PublicIP = net.ParseIP("5.75.0.2")
	if DeriveRelayPackID(a) == DeriveRelayPackID(b) {
		t.Fatalf("id should change when public_ip changes")
	}
}

func TestDeriveRelayPackID_ChangesWithFamilySet(t *testing.T) {
	a := mkRec()
	b := mkRec()
	b.Candidates = append(b.Candidates, provider.CandidateMeta{Family: "tuic"})
	if DeriveRelayPackID(a) == DeriveRelayPackID(b) {
		t.Fatalf("id should change when family set changes")
	}
}

func TestDeriveRelayPackID_NilRecord(t *testing.T) {
	if got := DeriveRelayPackID(nil); got != "" {
		t.Fatalf("expected empty for nil record, got %q", got)
	}
}
