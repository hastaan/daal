package share

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"strconv"
	"testing"
	"time"

	"daal/bundle-go/bundle"
	bundleshare "daal/bundle-go/share"
)

func newIdent(t *testing.T) bundleshare.PublisherIdentity {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return bundleshare.PublisherIdentity{
		DisplayName:  "TestPhone",
		PublicKey:    pub,
		PrivateKey:   priv,
		TrustClass:   "tofu_friend",
		KeyCreatedAt: time.Now().UTC(),
	}
}

func sampleRoute() bundleshare.ExportInput {
	return bundleshare.ExportInput{
		RouteID:           "r-1",
		TransportFamily:   "vless-reality",
		ScarcityClass:     "normal",
		ProfileBytes:      []byte(`{"type":"vless","server":"x","server_port":443,"uuid":"u"}`),
		ValidFrom:         time.Now().UTC(),
		ValidUntil:        time.Now().UTC().Add(24 * time.Hour),
		AllowRedistribute: true,
	}
}

func TestSessionLifecycle(t *testing.T) {
	mgr := NewManager(newIdent(t), nil)
	sess, err := mgr.BeginShare(BeginInput{
		Routes:      []bundleshare.ExportInput{sampleRoute()},
		StartLAN:    true,
		StaticQRURI: "vless://uuid@example.com:443?security=reality&pbk=K&sid=S#tag",
		QRSizePx:    256,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if len(sess.Pin) != 6 {
		t.Errorf("pin length: %s", sess.Pin)
	}
	if len(sess.LANAddrs) == 0 {
		t.Fatalf("no LAN addrs")
	}
	if sess.StaticQRBytes == nil {
		t.Errorf("expected QR bytes")
	}
	// Verify the bundle parses.
	parsed, err := bundle.ParseSBP(bytes.NewReader(sess.BundleBytes), int64(len(sess.BundleBytes)))
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	if len(parsed.Manifest.Routes) != 1 {
		t.Errorf("route count: %d", len(parsed.Manifest.Routes))
	}
	if sess.LANSPKI == "" {
		t.Fatalf("session published no SPKI pin")
	}
	if len(sess.LANURIs) != len(sess.LANAddrs) {
		t.Fatalf("LANURIs %d != LANAddrs %d", len(sess.LANURIs), len(sess.LANAddrs))
	}
	// Pull from the LAN endpoint with a wrong PIN — should fail.
	addr := sess.LANAddrs[0]
	host, port := splitHostPort(t, addr)
	_, err = PullURL(host, port, "999999", sess.ID, sess.LANSPKI, 2000)
	if err == nil {
		t.Errorf("expected unauthorized with wrong PIN")
	}
	// Pull with correct PIN.
	got, err := PullURL(host, port, sess.Pin, sess.ID, sess.LANSPKI, 2000)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !bytes.Equal(got, sess.BundleBytes) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(got), len(sess.BundleBytes))
	}
	if err := mgr.EndShare(sess.ID); err != nil {
		t.Errorf("end: %v", err)
	}
	// Bundle should be wiped.
	if !allZero(sess.BundleBytes) {
		t.Errorf("bundle not wiped after end")
	}
}

func TestTokenDerivationDeterministic(t *testing.T) {
	a := DeriveBearerToken("123456", "s-abc")
	b := DeriveBearerToken("123456", "s-abc")
	if a != b {
		t.Errorf("non-deterministic")
	}
	c := DeriveBearerToken("123457", "s-abc")
	if a == c {
		t.Errorf("PIN-bound token same for different PIN")
	}
	d := DeriveBearerToken("123456", "s-xyz")
	if a == d {
		t.Errorf("session-id-bound token same for different session")
	}
}

func TestDetectClipboardURIs(t *testing.T) {
	hits := DetectURIs("vless://uuid@example.com:443#a\nss://aes-256-gcm:secret@1.2.3.4:8388\nirrelevant text")
	if len(hits) != 2 {
		t.Fatalf("hits: %d", len(hits))
	}
	if hits[1].Preview == "" || containsSecret(hits[1].Preview) {
		t.Errorf("preview leaks secret: %q", hits[1].Preview)
	}
}

func TestFountainSessionRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte("ABCDEFGH"), 64) // 512 bytes
	send := NewSenderSession("s", payload, 32, 1)
	recv := NewReceiverSession("s")
	for i := 0; i < 100; i++ {
		f, err := send.NextFrame()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		out, done, err := recv.FeedFrame(f)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if done {
			if !bytes.Equal(out, payload) {
				t.Errorf("payload mismatch")
			}
			return
		}
	}
	t.Fatalf("did not decode within 100 frames")
}

func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	// url.Parse + Hostname() correctly strips IPv6 brackets;
	// the previous hand-rolled scan returned "[fe80::...]" which then
	// produced "[[fe80::...]]:port" when re-joined via JoinHostPort.
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port from %q: %v", raw, err)
	}
	return u.Hostname(), port
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}

func containsSecret(s string) bool {
	return bytes.Contains([]byte(s), []byte("secret"))
}
