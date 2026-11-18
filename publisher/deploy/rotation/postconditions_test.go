package rotation

// THE SPECIFICATION THAT OUTLIVED THE GO EXECUTOR.
//
// executor_test.go / l3_swap_test.go / l3_bind_test.go used to drive
// these two checks through a fake provider and a fake store, which
// tested the deleted Go executor's ordering as much as the checks
// themselves. The checks are still live — `daal-deploy assign-fip` runs
// both after the adapter returns — so they keep their tests, driven
// directly. The ORDERING those files also pinned now lives where the
// ordering runs: the wizard's rotate_execute tests in
// client-shell/tauri/daal-wizard/src/commands.rs. See
// docs/decisions/0004-one-rotation-executor.md.

import (
	"errors"
	"net"
	"testing"

	"daal/publisher/deploy/provider"
)

func newRecord(withFipID string) *provider.OperatorRecord {
	rec := &provider.OperatorRecord{
		Provider:        "hetzner",
		ServerID:        "srv-1",
		ServerType:      "cpx21",
		Region:          "fsn1",
		PublicIP:        net.ParseIP("198.51.100.10"),
		PublisherPubKey: []byte("placeholder"),
		// Candidates carry the SECOND copy of the dialled address.
		// A swap that moves rec.PublicIP and leaves these behind is
		// the half-applied state that signs a self-contradicting pack.
		Candidates: []provider.CandidateMeta{
			{Family: "vless-reality", Port: 443,
				PublicRiskTags: []string{"public_ip:198.51.100.10", "public_port:tcp443"}},
			{Family: "hysteria2", Port: 443,
				PublicRiskTags: []string{"public_ip:198.51.100.10", "public_port:udp443"}},
		},
	}
	if withFipID != "" {
		rec.FloatingIPID = withFipID
	}
	return rec
}

// An adapter that attaches the address and leaves the record naming the
// old one is the pre-Step-9 Hetzner adapter, and the Vultr and Stark
// adapters today. It must fail, loudly, rather than let the binder sign
// a pack aimed at the address the operator is rotating away from.
func TestCheckAddressMoved_UnmovedRecordIsRejected(t *testing.T) {
	same := net.ParseIP("198.51.100.10")
	err := CheckAddressMoved(same, same)
	if !errors.Is(err, ErrL3AddressUnchanged) {
		t.Fatalf("err = %v, want ErrL3AddressUnchanged", err)
	}
	// The message has to name the address, because the operator's next
	// question is "which one am I still on".
	if !contains(err.Error(), "198.51.100.10") {
		t.Errorf("error does not name the address the relay is stuck on: %v", err)
	}
}

func TestCheckAddressMoved_EmptyAfterIsRejected(t *testing.T) {
	if err := CheckAddressMoved(net.ParseIP("198.51.100.10"), nil); !errors.Is(err, ErrL3AddressUnchanged) {
		t.Fatalf("err = %v, want ErrL3AddressUnchanged", err)
	}
}

func TestCheckAddressMoved_RealSwapPasses(t *testing.T) {
	if err := CheckAddressMoved(net.ParseIP("198.51.100.10"), net.ParseIP("203.0.113.7")); err != nil {
		t.Fatalf("a genuine swap must pass: %v", err)
	}
	// No prior address (the relay was on the server's primary and the
	// record did not record it) is not evidence of a non-swap.
	if err := CheckAddressMoved(nil, net.ParseIP("203.0.113.7")); err != nil {
		t.Fatalf("unknown prior address must not fail the check: %v", err)
	}
}

// The record keeps TWO copies of the dialled address. An adapter that
// moves PublicIP and forgets the candidate tags signs a pack that dials
// one address and declares another.
func TestCheckRecordAddressConsistent(t *testing.T) {
	rec := newRecord("")
	if err := CheckRecordAddressConsistent(rec); err != nil {
		t.Fatalf("a freshly built record should be consistent: %v", err)
	}
	rec.PublicIP = net.ParseIP("203.0.113.9")
	if err := CheckRecordAddressConsistent(rec); !errors.Is(err, ErrRecordAddressInconsistent) {
		t.Errorf("moving PublicIP alone: err = %v, want ErrRecordAddressInconsistent", err)
	}

	rec = newRecord("")
	rec.Candidates[0].PublicRiskTags = []string{"public_port:tcp443"}
	if err := CheckRecordAddressConsistent(rec); !errors.Is(err, ErrRecordAddressInconsistent) {
		t.Errorf("candidate with no public_ip tag: err = %v, want ErrRecordAddressInconsistent", err)
	}
}

// The budget is a cross-language pin. Go no longer enforces it — the
// wizard does — so this asserts the NUMBER, which is the only thing
// this side still owns. If it changes here without changing
// L3_FAST_PATH_BUDGET in commands.rs and the soak rig's
// v1-5-l3-fast-path scenario, two green suites sit on opposite sides of
// one promise.
func TestL3FastPathBudgetIsFifteenSeconds(t *testing.T) {
	if got := L3FastPathBudget.Seconds(); got != 15 {
		t.Fatalf("L3FastPathBudget = %vs, want 15s (and see docs/backlog-post-45.md W3-10 before moving it)", got)
	}
}
