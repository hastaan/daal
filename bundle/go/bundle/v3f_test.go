package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// Phase 3F bundle-format widening tests. See
// specs/sbp-v1.md "Phase 3F widening" and
// specs/delegate-keys-v1.md.

// TestSBPv1_RedistributionPolicyRoundTrip — the three locked
// values + cap field round-trip through Build → Parse → Verify.
func TestSBPv1_RedistributionPolicyRoundTrip(t *testing.T) {
	cases := []struct {
		policy string
		cap    uint8
	}{
		{"none", 0},
		{"delegated_n", 10},
		{"transitive", 0},
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
			m.Routes[0].RedistributionPolicy = c.policy
			m.Routes[0].RedistributionCap = c.cap
			data := mustSignedBundle(t, m, nil)
			b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyBundle(b); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := b.Manifest.Routes[0].RedistributionPolicy; got != c.policy {
				t.Errorf("policy round-trip: got %q want %q", got, c.policy)
			}
			if got := b.Manifest.Routes[0].RedistributionCap; got != c.cap {
				t.Errorf("cap round-trip: got %d want %d", got, c.cap)
			}
		})
	}
}

// TestSBPv1_RedistributionPolicyMalformedRejected — any value
// outside the closed enum rejects.
func TestSBPv1_RedistributionPolicyMalformedRejected(t *testing.T) {
	for _, p := range []string{"yolo", "delegated", "transitive_5", "unlimited"} {
		t.Run(p, func(t *testing.T) {
			m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
			m.Routes[0].RedistributionPolicy = p
			data := mustSignedBundle(t, m, nil)
			b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err := VerifyBundle(b); !errors.Is(err, ErrRedistributionPolicyMalformed) {
				t.Errorf("got %v, want ErrRedistributionPolicyMalformed", err)
			}
		})
	}
}

// TestSBPv1_DelegatedNRequiresCap — `delegated_n` without a cap
// rejects; non-`delegated_n` with a cap rejects.
func TestSBPv1_DelegatedNRequiresCap(t *testing.T) {
	cases := []struct {
		name    string
		policy  string
		cap     uint8
		wantErr error
	}{
		{"delegated_n_missing_cap", "delegated_n", 0, ErrRedistributionCapMalformed},
		{"none_with_cap", "none", 5, ErrRedistributionCapMalformed},
		{"transitive_with_cap", "transitive", 5, ErrRedistributionCapMalformed},
		{"empty_policy_with_cap", "", 5, ErrRedistributionPolicyMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
			m.Routes[0].RedistributionPolicy = c.policy
			m.Routes[0].RedistributionCap = c.cap
			data := mustSignedBundle(t, m, nil)
			b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
			if err := VerifyBundle(b); !errors.Is(err, c.wantErr) {
				t.Errorf("got %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestSBPv1_DelegatedShareRequiresChainAndCaps — a bundle whose
// type is "delegated_share" but lacks chain/caps rejects;
// conversely, a non-delegated_share bundle that carries chain
// fields rejects.
func TestSBPv1_DelegatedShareRequiresChainAndCaps(t *testing.T) {
	t.Run("share_missing_chain", func(t *testing.T) {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		m.Bundle.Type = "delegated_share"
		// No chain / caps populated.
		data := mustSignedBundle(t, m, nil)
		b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err := VerifyBundle(b); !errors.Is(err, ErrRedistributionChainBroken) {
			t.Errorf("got %v, want ErrRedistributionChainBroken", err)
		}
	})
	t.Run("provider_with_chain", func(t *testing.T) {
		m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
		// bundle.type stays "provider" by default.
		m.RedistributionChain = []RedistributionChainHop{{
			DelegateFPHex:  "abc",
			DelegatePub:    "pub",
			SignedAt:       time.Now().UTC().Format(time.RFC3339),
			RecipientFPHex: "rcp",
			SignatureB64:   "sig",
		}}
		m.DelegateCaps = []DelegateCapEntry{{RouteID: "x", CapAtSignTime: 5}}
		data := mustSignedBundle(t, m, nil)
		b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
		if err := VerifyBundle(b); !errors.Is(err, ErrRedistributionChainBroken) {
			t.Errorf("got %v, want ErrRedistributionChainBroken", err)
		}
	})
}

// TestSBPv1_RedistributionChainTooDeepRejected — a 6-hop chain
// rejects with the depth error (locked at 5).
func TestSBPv1_RedistributionChainTooDeepRejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.Type = "delegated_share"
	hops := []RedistributionChainHop{}
	for i := 0; i < 6; i++ {
		hops = append(hops, RedistributionChainHop{
			DelegateFPHex:  "fp",
			DelegatePub:    "pub",
			SignedAt:       time.Now().UTC().Format(time.RFC3339),
			RecipientFPHex: "rcp",
			SignatureB64:   "sig",
		})
	}
	m.RedistributionChain = hops
	m.DelegateCaps = []DelegateCapEntry{{RouteID: "route-test", CapAtSignTime: 10}}
	data := mustSignedBundle(t, m, nil)
	b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); !errors.Is(err, ErrRedistributionChainTooDeep) {
		t.Errorf("got %v, want ErrRedistributionChainTooDeep", err)
	}
}

// TestSBPv1_DelegateCapExceededRejected — an entry whose count
// >= cap rejects.
func TestSBPv1_DelegateCapExceededRejected(t *testing.T) {
	m := baseManifest(t, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.Type = "delegated_share"
	m.RedistributionChain = []RedistributionChainHop{{
		DelegateFPHex:  "fp",
		DelegatePub:    "pub",
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
		RecipientFPHex: "rcp",
		SignatureB64:   "sig",
	}}
	m.DelegateCaps = []DelegateCapEntry{{
		RouteID:                   "route-test",
		SharedWithCountAtSignTime: 10,
		CapAtSignTime:             10,
	}}
	data := mustSignedBundle(t, m, nil)
	b, _ := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err := VerifyBundle(b); !errors.Is(err, ErrRedistributionCapExceeded) {
		t.Errorf("got %v, want ErrRedistributionCapExceeded", err)
	}
}

// TestSBPv1_DelegatedShareRoundTripsTrustClass — the share's
// publisher fields (forwarded by the engine on re-share) DO
// NOT lose the original publisher signature: the parser
// admits the cap+chain envelope on top of the existing 0B
// signature path.
func TestSBPv1_DelegatedShareRoundTripsTrustClass(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := baseManifestWithKey(t, pub, "normal", "vless-reality", time.Now().Add(24*time.Hour))
	m.Bundle.Type = "delegated_share"
	m.RedistributionChain = []RedistributionChainHop{{
		DelegateFPHex:  "abc",
		DelegatePub:    "pub",
		SignedAt:       time.Now().UTC().Format(time.RFC3339),
		RecipientFPHex: "rcp",
		SignatureB64:   "sig",
	}}
	m.DelegateCaps = []DelegateCapEntry{{
		RouteID: "route-test", SharedWithCountAtSignTime: 0, CapAtSignTime: 5,
	}}
	profiles := map[string][]byte{"profiles/route.json": []byte(`{"type":"direct"}`)}
	data, err := BuildSignedBundle(m, profiles, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSBP(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(b); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Manifest.Bundle.Type != "delegated_share" {
		t.Errorf("type round-trip: %q", b.Manifest.Bundle.Type)
	}
	if len(b.Manifest.RedistributionChain) != 1 {
		t.Errorf("chain round-trip: %d", len(b.Manifest.RedistributionChain))
	}
	if len(b.Manifest.DelegateCaps) != 1 {
		t.Errorf("caps round-trip: %d", len(b.Manifest.DelegateCaps))
	}
}
