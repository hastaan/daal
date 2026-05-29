package share

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"daal/bundle-go/bundle"
)

func newIdent(t *testing.T) PublisherIdentity {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PublisherIdentity{
		DisplayName:  "Alice",
		PublicKey:    pub,
		PrivateKey:   priv,
		TrustClass:   "tofu_friend",
		KeyCreatedAt: time.Now().UTC(),
	}
}

func TestExportRefusesNonRedistributable(t *testing.T) {
	ident := newIdent(t)
	_, err := BuildShareBundle([]ExportInput{{
		RouteID:           "r-1",
		TransportFamily:   "vless-reality",
		ScarcityClass:     "normal",
		ProfileBytes:      []byte(`{"type":"vless"}`),
		ValidFrom:         time.Now().UTC(),
		ValidUntil:        time.Now().UTC().Add(24 * time.Hour),
		AllowRedistribute: false,
	}}, ident, time.Now().UTC())
	if err == nil {
		t.Errorf("expected refusal on non-redistributable route")
	}
}

func TestExportRoundTrip(t *testing.T) {
	ident := newIdent(t)
	body, err := BuildShareBundle([]ExportInput{{
		RouteID:           "share-r1",
		TransportFamily:   "vless-reality",
		ScarcityClass:     "normal",
		ProfileBytes:      []byte(`{"type":"vless","server":"x","server_port":443,"uuid":"u"}`),
		ValidFrom:         time.Now().UTC(),
		ValidUntil:        time.Now().UTC().Add(24 * time.Hour),
		AllowRedistribute: true,
	}}, ident, time.Now().UTC())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	parsed, err := bundle.ParseSBP(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := bundle.VerifyBundle(parsed); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Manifest.Bundle.Type != "friend_share" {
		t.Errorf("type: %s", parsed.Manifest.Bundle.Type)
	}
	if len(parsed.Manifest.Routes) != 1 || parsed.Manifest.Routes[0].ID != "share-r1" {
		t.Errorf("routes: %+v", parsed.Manifest.Routes)
	}
}

func TestStaticQR(t *testing.T) {
	png, err := EncodeStaticQR("vless://uuid@example.com:443?security=reality&pbk=K&sid=S#tag", 256)
	if err != nil {
		t.Fatalf("qr: %v", err)
	}
	if len(png) < 100 {
		t.Errorf("png too small: %d", len(png))
	}
}

func TestStaticQRTooLong(t *testing.T) {
	long := bytes.Repeat([]byte("A"), 2000)
	_, err := EncodeStaticQR(string(long), 256)
	if err == nil {
		t.Errorf("expected too-long error")
	}
}
