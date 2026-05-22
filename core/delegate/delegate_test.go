//go:build !no_delegate_share

package delegate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestIsValidPolicy_ClosedEnum locks the v1 closed enum.
func TestIsValidPolicy_ClosedEnum(t *testing.T) {
	for _, p := range []Policy{PolicyNone, PolicyDelegatedN, PolicyTransitive} {
		if !IsValidPolicy(p) {
			t.Errorf("IsValidPolicy(%q): got false, want true", p)
		}
	}
	for _, p := range []Policy{"", "transitive_5", "delegated", "yolo"} {
		if IsValidPolicy(p) {
			t.Errorf("IsValidPolicy(%q): got true, want false", p)
		}
	}
}

// TestEnforcePolicy_NoneRefuses — the locked-at-3F default.
func TestEnforcePolicy_NoneRefuses(t *testing.T) {
	if got := EnforcePolicy(PolicyNone, 0, 0); got != OutcomePolicyRefuses {
		t.Errorf("PolicyNone: %q", got)
	}
}

// TestEnforcePolicy_DelegatedNCapArith — < cap passes, >= cap rejects.
func TestEnforcePolicy_DelegatedNCapArith(t *testing.T) {
	cases := []struct {
		cap, count uint8
		want       Outcome
	}{
		{10, 0, OutcomeOK},
		{10, 9, OutcomeOK},
		{10, 10, OutcomeCapExhausted},
		{10, 11, OutcomeCapExhausted},
		{0, 0, OutcomeCapExhausted}, // cap=0 always rejects (count>=cap)
	}
	for _, c := range cases {
		got := EnforcePolicy(PolicyDelegatedN, c.cap, c.count)
		if got != c.want {
			t.Errorf("delegated_n cap=%d count=%d: got %q, want %q",
				c.cap, c.count, got, c.want)
		}
	}
}

// TestEnforcePolicy_TransitiveAlwaysAllows — sender-side
// transitive admits unconditionally; depth is enforced
// receiver-side.
func TestEnforcePolicy_TransitiveAlwaysAllows(t *testing.T) {
	for _, count := range []uint8{0, 1, 100, 255} {
		if got := EnforcePolicy(PolicyTransitive, 0, count); got != OutcomeOK {
			t.Errorf("transitive count=%d: %q", count, got)
		}
	}
}

// TestEnforceChainDepth_FiveCap locks the depth=5 invariant.
func TestEnforceChainDepth_FiveCap(t *testing.T) {
	for d := 0; d < 5; d++ {
		if got := EnforceChainDepth(d); got != OutcomeOK {
			t.Errorf("depth %d: %q", d, got)
		}
	}
	for _, d := range []int{5, 6, 100} {
		if got := EnforceChainDepth(d); got != OutcomeChainDepthExceeded {
			t.Errorf("depth %d: %q", d, got)
		}
	}
}

// TestAppendHopVerifyChain_OneHop — basic round-trip.
func TestAppendHopVerifyChain_OneHop(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	origSig := []byte("publisher-sig-bytes")
	chain, err := AppendHop(nil, origSig, "recipient-fp", priv, time.Now())
	if err != nil {
		t.Fatalf("AppendHop: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain len: %d", len(chain))
	}
	depth, err := VerifyChain(chain, origSig, "recipient-fp")
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if depth != 1 {
		t.Errorf("depth: %d", depth)
	}
}

// TestVerifyChain_FiveHops — verifies a 5-hop chain.
func TestVerifyChain_FiveHops(t *testing.T) {
	origSig := []byte("orig-sig-5h")
	var chain []ChainHop
	for i := 0; i < 5; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		c2, err := AppendHop(chain, origSig, "next-recipient", priv, time.Now())
		if err != nil {
			t.Fatalf("AppendHop hop %d: %v", i, err)
		}
		chain = c2
	}
	depth, err := VerifyChain(chain, origSig, "next-recipient")
	if err != nil {
		t.Fatalf("VerifyChain depth-5: %v", err)
	}
	if depth != 5 {
		t.Errorf("depth: %d", depth)
	}
}

// TestAppendHop_RejectsAtDepth5 — a 6th AppendHop refuses.
func TestAppendHop_RejectsAtDepth5(t *testing.T) {
	origSig := []byte("orig")
	var chain []ChainHop
	for i := 0; i < 5; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		c2, _ := AppendHop(chain, origSig, "x", priv, time.Now())
		chain = c2
	}
	_, priv6, _ := ed25519.GenerateKey(rand.Reader)
	_, err := AppendHop(chain, origSig, "x", priv6, time.Now())
	if !errors.Is(err, ErrChainTooDeep) {
		t.Errorf("got %v, want ErrChainTooDeep", err)
	}
}

// TestVerifyChain_RejectsTamperedHop — flipping any byte of any
// hop's signature breaks the walk.
func TestVerifyChain_RejectsTamperedHop(t *testing.T) {
	origSig := []byte("orig-tamper")
	var chain []ChainHop
	for i := 0; i < 3; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		c2, _ := AppendHop(chain, origSig, "r", priv, time.Now())
		chain = c2
	}
	// Flip a character in the middle hop's signature.
	tampered := make([]ChainHop, len(chain))
	copy(tampered, chain)
	bad := []byte(tampered[1].SignatureB64)
	bad[0] ^= 0x01
	tampered[1].SignatureB64 = string(bad)
	_, err := VerifyChain(tampered, origSig, "")
	if err == nil || !errors.Is(err, ErrChainBroken) {
		t.Errorf("got %v, want ErrChainBroken", err)
	}
}

// TestVerifyChain_RejectsDifferentOrigSig — a chain is bound to
// the original publisher signature; swapping it out invalidates
// every hop.
func TestVerifyChain_RejectsDifferentOrigSig(t *testing.T) {
	origSig := []byte("orig-A")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain, _ := AppendHop(nil, origSig, "r", priv, time.Now())
	_, err := VerifyChain(chain, []byte("orig-B"), "")
	if err == nil || !errors.Is(err, ErrChainBroken) {
		t.Errorf("got %v, want ErrChainBroken (different origSig)", err)
	}
}

// TestVerifyChain_ExpectedRecipientMismatch — locks the
// optional recipient-binding check.
func TestVerifyChain_ExpectedRecipientMismatch(t *testing.T) {
	origSig := []byte("orig")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain, _ := AppendHop(nil, origSig, "alice", priv, time.Now())
	_, err := VerifyChain(chain, origSig, "bob")
	if err == nil || !errors.Is(err, ErrChainBroken) {
		t.Errorf("got %v, want ErrChainBroken (recipient mismatch)", err)
	}
}

// TestEnforceCap_PerEntry — locks the inequality.
func TestEnforceCap_PerEntry(t *testing.T) {
	caps := []CapEntry{
		{RouteID: "r1", SharedWithCountAtSignTime: 0, CapAtSignTime: 10},
		{RouteID: "r2", SharedWithCountAtSignTime: 5, CapAtSignTime: 10},
		{RouteID: "r3", SharedWithCountAtSignTime: 9, CapAtSignTime: 10},
	}
	if err := EnforceCap(caps); err != nil {
		t.Errorf("under-cap caps: %v", err)
	}
	caps = append(caps, CapEntry{RouteID: "rX", SharedWithCountAtSignTime: 10, CapAtSignTime: 10})
	if err := EnforceCap(caps); !errors.Is(err, ErrCapExceeded) {
		t.Errorf("got %v, want ErrCapExceeded", err)
	}
}

// TestParseUint8Cap_Bounds — 0..255 valid; rest reject.
func TestParseUint8Cap_Bounds(t *testing.T) {
	if n, err := ParseUint8Cap(""); err != nil || n != 0 {
		t.Errorf("empty: %d %v", n, err)
	}
	if n, err := ParseUint8Cap("0"); err != nil || n != 0 {
		t.Errorf("zero: %d %v", n, err)
	}
	if n, err := ParseUint8Cap("255"); err != nil || n != 255 {
		t.Errorf("max: %d %v", n, err)
	}
	for _, s := range []string{"256", "-1", "abc", "1.5"} {
		if _, err := ParseUint8Cap(s); !errors.Is(err, ErrCapMalformed) {
			t.Errorf("%q: got %v, want ErrCapMalformed", s, err)
		}
	}
}

// TestOutcomeJSON_Shape — wire-format check for the ABI error
// envelope.
func TestOutcomeJSON_Shape(t *testing.T) {
	got := OutcomeJSON(OutcomePolicyRefuses, "delegate_caps[0]")
	for _, want := range []string{`"error":"policy_refuses"`, `"detail":"delegate_caps[0]"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}
