package freshness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func twoMirrors() []Mirror {
	return []Mirror{
		{Provider: ProviderR2, URL: "https://f.example.com/rp.json"},
		{Provider: ProviderGHPages, URL: "https://frp.github.io/f/rp.json"},
	}
}

// The central invariant of the whole design: one URL is not a
// representable freshness configuration.
func TestNewMirrorSet_RefusesSingleURL(t *testing.T) {
	_, err := NewMirrorSet([]Mirror{{Provider: ProviderR2, URL: "https://f.example.com/rp.json"}})
	if !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("want ErrTooFewMirrors, got %v", err)
	}
	if _, err := NewMirrorSet(nil); !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("want ErrTooFewMirrors on nil, got %v", err)
	}
}

// Two buckets in one account are one failure domain wearing two
// URLs. The label is the unit of independence, so a duplicate
// label is refused even when the URLs differ.
func TestNewMirrorSet_RefusesSameProviderTwice(t *testing.T) {
	_, err := NewMirrorSet([]Mirror{
		{Provider: ProviderR2, URL: "https://a.example.com/rp.json"},
		{Provider: ProviderR2, URL: "https://b.example.com/rp.json"},
	})
	if !errors.Is(err, ErrDuplicateProvider) {
		t.Fatalf("want ErrDuplicateProvider, got %v", err)
	}
}

func TestNewMirrorSet_RefusesSameHostTwice(t *testing.T) {
	_, err := NewMirrorSet([]Mirror{
		{Provider: ProviderR2, URL: "https://same.example.com/a.json"},
		{Provider: ProviderGHPages, URL: "https://same.example.com/b.json"},
	})
	if !errors.Is(err, ErrDuplicateHost) {
		t.Fatalf("want ErrDuplicateHost, got %v", err)
	}
}

// Order in, order out: the pack embeds these bytes and BindAndSign
// promises byte-identical output for identical inputs.
func TestNewMirrorSet_OrderIndependent(t *testing.T) {
	a, err := NewMirrorSet(twoMirrors())
	if err != nil {
		t.Fatal(err)
	}
	rev := twoMirrors()
	rev[0], rev[1] = rev[1], rev[0]
	b, err := NewMirrorSet(rev)
	if err != nil {
		t.Fatal(err)
	}
	if a.LegacyScalarURL() != b.LegacyScalarURL() {
		t.Fatalf("scalar depends on input order: %q vs %q", a.LegacyScalarURL(), b.LegacyScalarURL())
	}
	if a.Mirrors()[0] != b.Mirrors()[0] || a.Mirrors()[1] != b.Mirrors()[1] {
		t.Fatal("member order depends on input order")
	}
}

func TestValidateMirrorURL_Rejects(t *testing.T) {
	bad := []string{
		"http://f.example.com/rp.json",                       // not https
		"https://user:pw@f.example.com/x",                    // credentials
		"https://10.0.0.1/rp.json",                           // IP literal
		"https://localhost/rp.json",                          // loopback
		"https://nodots/rp.json",                             // not an FQDN
		" https://f.example.com/rp.json",                     // whitespace
		"https:///rp.json",                                   // no host
		"https://f.example.com/" + strings.Repeat("a", 2048), // too long
	}
	for _, u := range bad {
		if err := ValidateMirrorURL(u); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if err := ValidateMirrorURL("https://f.example.com/rp.json"); err != nil {
		t.Errorf("rejected a good URL: %v", err)
	}
}

func TestSignVerifyMirrors_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, err := NewMirrorSet(twoMirrors())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	body, err := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyMirrors(body, pub, "rp-1", now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Len() != 2 {
		t.Fatalf("len = %d", got.Len())
	}
	// Deterministic: the same inputs must produce the same bytes,
	// or the enclosing .sbp stops being reproducible.
	again, err := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(body) {
		t.Fatal("SignMirrors is not deterministic")
	}
}

// A mirror document lifted out of one pack must not be usable in
// another, or a censor who can swap archive entries can point a
// recipient at endpoints from an older, retired pack.
func TestVerifyMirrors_RefusesForeignPack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewMirrorSet(twoMirrors())
	now := time.Now().UTC()
	body, _ := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))
	if _, err := VerifyMirrors(body, pub, "rp-2", now); !errors.Is(err, ErrMirrorsMismatch) {
		t.Fatalf("want ErrMirrorsMismatch, got %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyMirrors(body, other, "rp-1", now); err == nil {
		t.Fatal("verified under the wrong publisher key")
	}
}

func TestVerifyMirrors_TamperedURL(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewMirrorSet(twoMirrors())
	now := time.Now().UTC()
	body, _ := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))
	tampered := []byte(strings.Replace(string(body), "f.example.com", "evil.example.com", 1))
	if _, err := VerifyMirrors(tampered, pub, "rp-1", now); err == nil {
		t.Fatal("accepted a tampered mirror URL")
	}
}

// A document that has been stripped down to one mirror must not
// verify into a usable set: degrading N to 1 is exactly the
// downgrade the type system prevents on the publisher side, and
// the recipient side has to refuse it too.
func TestVerifyMirrors_RefusesDowngradedSet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewMirrorSet(twoMirrors())
	now := time.Now().UTC()
	body, _ := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))

	// Re-sign a one-mirror document with the publisher's own key:
	// the attacker here is a compromised or careless publisher
	// tool, not a network attacker, and the check must still hold.
	var doc MirrorDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Mirrors = doc.Mirrors[:1]
	doc.SignatureHex = ""
	sigBody, err := canonicalExcluding(doc, "signature_hex")
	if err != nil {
		t.Fatal(err)
	}
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, sigBody))
	reSigned, err := canonicalAll(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMirrors(reSigned, pub, "rp-1", now); !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("want ErrTooFewMirrors, got %v", err)
	}
}

// Forward compatibility: a field a FUTURE publisher adds must not
// vanish from the bytes this side verifies. Verifying over a
// re-marshal of the local struct is the trap that makes every
// schema addition a flag day (it is why the recipient's copy of
// the freshness document has to change in lockstep); this test
// pins the raw-bytes behaviour so the same trap is not re-created
// here.
func TestVerifyMirrors_UnknownFieldSurvives(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set, _ := NewMirrorSet(twoMirrors())
	now := time.Now().UTC()

	var obj map[string]any
	body, _ := SignMirrors(set, "rp-1", pub, priv, nil, now, now.Add(90*24*time.Hour))
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatal(err)
	}
	obj["future_field"] = "hello"
	delete(obj, "signature_hex")
	raw, _ := json.Marshal(obj)
	sigBody, err := canonicalRawExcluding(raw, "signature_hex")
	if err != nil {
		t.Fatal(err)
	}
	obj["signature_hex"] = hex.EncodeToString(ed25519.Sign(priv, sigBody))
	raw, _ = json.Marshal(obj)

	if _, err := VerifyMirrors(raw, pub, "rp-1", now); err != nil {
		t.Fatalf("a document with an unknown field must still verify: %v", err)
	}
}

// The mirror document must ride the same FRP-7.5 chain the pack
// does, or a publisher operating on a sub-key could sign their
// pack but not its endpoint set.
func TestSignMirrors_WithSubkey(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()

	cert := subkeyCertWire{
		V:                  1,
		Kind:               "subkey_cert",
		RootFingerprintHex: publisherFingerprintHex(rootPub),
		SubkeyPubHex:       hex.EncodeToString(subPub),
		ValidFrom:          now.Add(-time.Hour).Format(time.RFC3339),
		ValidUntil:         now.Add(48 * time.Hour).Format(time.RFC3339),
		Label:              "test",
	}
	certBody, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, certBody))
	certJSON, _ := json.Marshal(cert)

	set, _ := NewMirrorSet(twoMirrors())
	body, err := SignMirrors(set, "rp-1", rootPub, subPriv, certJSON, now, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMirrors(body, rootPub, "rp-1", now); err != nil {
		t.Fatalf("sub-key-signed mirror document must verify against the root: %v", err)
	}
	// Outside the cert window it must not.
	if _, err := VerifyMirrors(body, rootPub, "rp-1", now.Add(72*time.Hour)); err == nil {
		t.Fatal("accepted a document signed by an expired sub-key")
	}
}
