package rendezvous

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// Phase 3B push rendezvous protocol tests.
//
// Canonical regressions called out in
// specs/push-rendezvous-v1.md "Verifier":
//
//   - TestPush_VerifyValidPayload
//   - TestPush_RejectsUnpinnedPublisher
//   - TestPush_RejectsBadSignature
//   - TestPush_RejectsStaleTimestamp
//   - TestPushQueue_BoundedCap
//   - TestPushSolicitor_DrainsQueue

func makePayload(t *testing.T, priv ed25519.PrivateKey, pubKey []byte, drift time.Duration) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pl := PushPayload{
		Bridge:         "203.0.113.5:443",
		FingerprintHex: "deadbeef",
		NotAfter:       time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		IssuedAt:       time.Now().Add(drift).UTC().Format(time.RFC3339),
		PublisherKey:   hex.EncodeToString(pubKey),
		HintVersion:    1,
	}
	body, err := json.Marshal(&pl)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, body)
	pl.Signature = base64.RawURLEncoding.EncodeToString(sig)
	out, _ := json.Marshal(&pl)
	return out, ed25519.PublicKey(pubKey)
}

func TestPush_VerifyValidPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := makePayload(t, priv, pub, 0)
	resolver := func(fp string) ([]byte, bool) {
		if fp == hex.EncodeToString(pub) {
			return pub, true
		}
		return nil, false
	}
	pl, err := VerifyPushPayload(raw, resolver, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if pl.Bridge != "203.0.113.5:443" {
		t.Errorf("bridge: got %q", pl.Bridge)
	}
}

func TestPush_RejectsUnpinnedPublisher(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := makePayload(t, priv, pub, 0)
	resolver := func(fp string) ([]byte, bool) {
		return nil, false // never pinned
	}
	_, err := VerifyPushPayload(raw, resolver, time.Now())
	if !errors.Is(err, ErrPushNoPinnedPublisher) {
		t.Fatalf("got %v, want ErrPushNoPinnedPublisher", err)
	}
}

func TestPush_RejectsBadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw, _ := makePayload(t, priv, pub, 0)

	// Tamper with the bridge field after signing.
	var pl PushPayload
	_ = json.Unmarshal(raw, &pl)
	pl.Bridge = "evil.attacker:443"
	tampered, _ := json.Marshal(&pl)

	resolver := func(fp string) ([]byte, bool) {
		if fp == hex.EncodeToString(pub) {
			return pub, true
		}
		return nil, false
	}
	_, err := VerifyPushPayload(tampered, resolver, time.Now())
	if !errors.Is(err, ErrPushSignatureInvalid) {
		t.Fatalf("tampered: got %v, want ErrPushSignatureInvalid", err)
	}
}

func TestPush_RejectsStaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// 10 minutes in the past — beyond MaxPushDrift (5m).
	raw, _ := makePayload(t, priv, pub, -10*time.Minute)
	resolver := func(fp string) ([]byte, bool) {
		if fp == hex.EncodeToString(pub) {
			return pub, true
		}
		return nil, false
	}
	_, err := VerifyPushPayload(raw, resolver, time.Now())
	if !errors.Is(err, ErrPushPayloadStale) {
		t.Fatalf("stale: got %v, want ErrPushPayloadStale", err)
	}
}

func TestPush_RejectsMalformed(t *testing.T) {
	resolver := func(fp string) ([]byte, bool) { return nil, false }
	_, err := VerifyPushPayload(nil, resolver, time.Now())
	if !errors.Is(err, ErrPushPayloadMalformed) {
		t.Errorf("nil: got %v", err)
	}
	_, err = VerifyPushPayload([]byte("not-json"), resolver, time.Now())
	if !errors.Is(err, ErrPushPayloadMalformed) {
		t.Errorf("not-json: got %v", err)
	}
	// Missing required fields.
	_, err = VerifyPushPayload([]byte(`{"hint_version":1}`), resolver, time.Now())
	if !errors.Is(err, ErrPushPayloadMalformed) {
		t.Errorf("incomplete: got %v", err)
	}
}

func TestPushQueue_BoundedCap(t *testing.T) {
	q := NewPushQueue(2)
	for i := 0; i < 5; i++ {
		q.Enqueue(PushPayload{Bridge: "b" + string(rune('0'+i))})
	}
	if q.Len() != 2 {
		t.Fatalf("len: got %d want 2 (cap)", q.Len())
	}
	// Oldest dropped — first remaining should be "b3".
	p, _ := q.Dequeue()
	if p.Bridge != "b3" {
		t.Errorf("after-drop head: got %q want b3", p.Bridge)
	}
}

func TestPushSolicitor_DrainsQueue(t *testing.T) {
	q := NewPushQueue(0)
	q.Enqueue(PushPayload{
		Bridge:         "x:443",
		FingerprintHex: "abcd",
		NotAfter:       "2026-12-01T00:00:00Z",
	})
	sol := NewPushSolicitor(q)

	hint, err := sol(context.Background(), Request{})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if hint.ChannelID != ChannelPush || hint.BridgeFP != "abcd" {
		t.Errorf("hint: got %+v", hint)
	}
}

func TestPushSolicitor_BlocksUntilContextDone(t *testing.T) {
	q := NewPushQueue(0)
	sol := NewPushSolicitor(q)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := sol(ctx, Request{})
	if err == nil {
		t.Error("empty queue + cancelled context must error")
	}
}
