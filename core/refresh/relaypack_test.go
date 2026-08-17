package refresh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// signFreshnessDoc mirrors publisher/deploy/freshness.signDoc: canonical
// bytes with signature_hex removed are signed, then the whole document
// is emitted canonically. It is duplicated here rather than imported
// because core/ cannot import publisher/ — the same reason the document
// struct is duplicated — and the shape is pinned by
// TestFreshnessCanonicalBytes_Golden below.
func signFreshnessDoc(t *testing.T, doc *FreshnessDocument, priv ed25519.PrivateKey) []byte {
	t.Helper()
	doc.SignatureHex = ""
	body, err := canonicalStructExcluding(doc, "signature_hex")
	if err != nil {
		t.Fatal(err)
	}
	doc.SignatureHex = hex.EncodeToString(ed25519.Sign(priv, body))
	raw, err := canonicalStructExcluding(doc, "")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func baseDoc(pub ed25519.PublicKey, now time.Time) *FreshnessDocument {
	return &FreshnessDocument{
		Kind:                FreshnessKind,
		RelayPackID:         "rp-1",
		Sequence:            10,
		CurrentBundleSHA256: repeatHex("de"),
		CurrentSignedURL:    "https://frp.example.com/current.sbp",
		LastModified:        now.Format(time.RFC3339),
		NotAfter:            now.Add(72 * time.Hour).Format(time.RFC3339),
		Mirrors:             []FreshnessMirror{},
		PublisherPubHex:     hex.EncodeToString(pub),
	}
}

func TestVerifyFreshnessDocument_RootSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	raw := signFreshnessDoc(t, baseDoc(pub, now), priv)

	got, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now, ExpectRelayPackID: "rp-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 10 || got.RelayPackID != "rp-1" {
		t.Errorf("round-trip lost data: %+v", got)
	}
}

// A v1 document is refused explicitly. v1 had no expiry and no
// sequence, so accepting one would silently disable both the freeze
// bound and the rollback protection on that pack.
func TestVerifyFreshnessDocument_V1Refused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	raw := []byte(`{"kind":"daal/freshness-v1","relay_pack_id":"rp-1"}`)
	_, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{PublisherRootPub: pub})
	if !errors.Is(err, ErrFreshnessVersion) {
		t.Fatalf("want ErrFreshnessVersion, got %v", err)
	}
}

func TestVerifyFreshnessDocument_BadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	doc := baseDoc(pub, now)
	doc.SignatureHex = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	raw, _ := canonicalStructExcluding(doc, "")
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now,
	}); !errors.Is(err, ErrFreshnessSignature) {
		t.Fatalf("want ErrFreshnessSignature, got %v", err)
	}
}

// HOSTILE CASE: the document is signed by a real publisher — just not
// this pack's. The recipient has several pinned publishers, so
// "verifies under some key we trust" is not a check at all.
func TestVerifyFreshnessDocument_WrongPublisher(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	doc := baseDoc(otherPub, now) // claims the other publisher's key
	raw := signFreshnessDoc(t, doc, priv)
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: otherPub, Now: now,
	}); !errors.Is(err, ErrFreshnessSignature) {
		t.Fatalf("a document signed by the wrong key must fail, got %v", err)
	}
}

// HOSTILE CASE: replay. The captured document is genuinely signed, so
// only the persisted high-water mark can refuse it.
func TestVerifyFreshnessDocument_ReplayedOlderSequence(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	doc := baseDoc(pub, now)
	doc.Sequence = 9
	raw := signFreshnessDoc(t, doc, priv)
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now, MinSequence: 10,
	}); !errors.Is(err, ErrFreshnessRollback) {
		t.Fatalf("want ErrFreshnessRollback, got %v", err)
	}
	// Equal is accepted: it is the same document we already have, and
	// refusing it would break every re-poll between publishes.
	doc2 := baseDoc(pub, now)
	doc2.Sequence = 10
	raw2 := signFreshnessDoc(t, doc2, priv)
	if _, err := VerifyFreshnessDocument(raw2, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now, MinSequence: 10,
	}); err != nil {
		t.Fatalf("re-serving the current sequence must be accepted: %v", err)
	}
}

// HOSTILE CASE: freeze. A captured document served forever must stop
// being believed at not_after, which is what turns a silent freeze into
// a visible failure the recipient escalates on.
func TestVerifyFreshnessDocument_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	issued := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	raw := signFreshnessDoc(t, baseDoc(pub, issued), priv)

	// Inside the window (+ skew): fine.
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: issued.Add(71 * time.Hour),
	}); err != nil {
		t.Fatalf("document must be valid inside its window: %v", err)
	}
	// Past not_after + skew: refused.
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: issued.Add(73 * time.Hour),
	}); !errors.Is(err, ErrFreshnessExpired) {
		t.Fatalf("want ErrFreshnessExpired, got %v", err)
	}
}

// HOSTILE CASE: splicing. One of the publisher's own documents, for a
// different pack of theirs, served at this pack's endpoint.
func TestVerifyFreshnessDocument_WrongPack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	doc := baseDoc(pub, now)
	doc.RelayPackID = "rp-OTHER"
	raw := signFreshnessDoc(t, doc, priv)
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now, ExpectRelayPackID: "rp-1",
	}); !errors.Is(err, ErrFreshnessWrongPack) {
		t.Fatalf("want ErrFreshnessWrongPack, got %v", err)
	}
}

// HOSTILE CASE: truncation. A body cut short must fail as malformed,
// never as "a document with fewer fields".
func TestVerifyFreshnessDocument_Truncated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	raw := signFreshnessDoc(t, baseDoc(pub, now), priv)
	for _, cut := range []int{1, len(raw) / 3, len(raw) / 2, len(raw) - 1} {
		if _, err := VerifyFreshnessDocument(raw[:cut], FreshnessVerifyOpts{
			PublisherRootPub: pub, Now: now,
		}); err == nil {
			t.Fatalf("truncation at %d was accepted", cut)
		}
	}
}

// An unknown field added by a future publisher must NOT break
// verification: the signature is checked over the canonicalised
// RECEIVED bytes, not over a re-marshal of this module's struct. That
// property is what stops every field addition from being a flag day.
func TestVerifyFreshnessDocument_UnknownFieldSurvives(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	doc := baseDoc(pub, now)
	asMap := map[string]any{}
	body, _ := json.Marshal(doc)
	_ = json.Unmarshal(body, &asMap)
	asMap["future_field"] = "a publisher two versions ahead"
	delete(asMap, "signature_hex")
	unsigned, _ := json.Marshal(asMap)
	canonUnsigned, err := canonicalRawExcluding(unsigned, "signature_hex")
	if err != nil {
		t.Fatal(err)
	}
	asMap["signature_hex"] = hex.EncodeToString(ed25519.Sign(priv, canonUnsigned))
	full, _ := json.Marshal(asMap)
	raw, err := canonicalRawExcluding(full, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: pub, Now: now,
	}); err != nil {
		t.Fatalf("an unknown field broke verification: %v", err)
	}
}

func TestVerifyFreshnessDocument_SubkeySigned(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	certJSON := makeSubkeyCert(t, rootPub, rootPriv, subPub,
		now.Add(-time.Hour), now.Add(48*time.Hour))

	doc := baseDoc(rootPub, now)
	doc.SubkeyCert = certJSON
	raw := signFreshnessDoc(t, doc, subPriv)

	got, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: rootPub, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SubkeyCert) == 0 {
		t.Error("subkey cert not preserved")
	}
}

func TestVerifyFreshnessDocument_SubkeyCertOutOfWindowRejected(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	certJSON := makeSubkeyCert(t, rootPub, rootPriv, subPub,
		now.Add(-48*time.Hour), now.Add(-time.Hour))
	doc := baseDoc(rootPub, now)
	doc.SubkeyCert = certJSON
	raw := signFreshnessDoc(t, doc, subPriv)

	if _, err := VerifyFreshnessDocument(raw, FreshnessVerifyOpts{
		PublisherRootPub: rootPub, Now: now,
	}); err == nil {
		t.Fatal("want error on out-of-window cert")
	}
}

// The fingerprint binding is the only thing standing between "a
// document that carries a key" and "a document from the publisher this
// device pinned" — the store keeps no key bytes, only the fingerprint.
func TestPublisherKeyForFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	fp := hex.EncodeToString(sum[:])

	got, err := PublisherKeyForFingerprint(hex.EncodeToString(pub), fp)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("valid key rejected: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := PublisherKeyForFingerprint(hex.EncodeToString(other), fp); !errors.Is(err, ErrFreshnessPublisher) {
		t.Fatal("a key that does not hash to the pinned fingerprint was accepted")
	}
	if _, err := PublisherKeyForFingerprint("zzzz", fp); !errors.Is(err, ErrFreshnessPublisher) {
		t.Fatal("garbage hex was accepted")
	}
}

// A mirror set that has degraded to one provider must not be usable:
// the whole value of the set is that no single host can turn the
// recovery mechanism off.
func TestValidateMirrorSet_RefusesSingleAndDuplicates(t *testing.T) {
	if _, err := ValidateMirrorSet([]FreshnessMirror{
		{Provider: "r2", URL: "https://a.example.com/f.json"},
	}); err == nil {
		t.Fatal("a one-mirror set was accepted")
	}
	if _, err := ValidateMirrorSet([]FreshnessMirror{
		{Provider: "r2", URL: "https://a.example.com/f.json"},
		{Provider: "r2", URL: "https://b.example.com/f.json"},
	}); err == nil {
		t.Fatal("two mirrors on one provider label were accepted")
	}
	if _, err := ValidateMirrorSet([]FreshnessMirror{
		{Provider: "r2", URL: "https://a.example.com/f.json"},
		{Provider: "ghpages", URL: "https://a.example.com/g.json"},
	}); err == nil {
		t.Fatal("two mirrors on one host were accepted")
	}
	set, err := ValidateMirrorSet([]FreshnessMirror{
		{Provider: "r2", URL: "https://a.example.com/f.json"},
		{Provider: "ghpages", URL: "https://b.example.com/g.json"},
	})
	if err != nil || len(set) != 2 {
		t.Fatalf("valid set rejected: %v", err)
	}
}

func TestVerifyMirrorDocument_RoundTripAndHostileCases(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	build := func(signPub ed25519.PublicKey, signPriv ed25519.PrivateKey, packID string) []byte {
		doc := MirrorDocument{
			Kind:            MirrorsKind,
			RelayPackID:     packID,
			PublisherPubHex: hex.EncodeToString(signPub),
			IssuedAt:        now.Format(time.RFC3339),
			NotAfter:        now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
			Mirrors: []FreshnessMirror{
				{Provider: "ghpages", URL: "https://b.example.com/g.json"},
				{Provider: "r2", URL: "https://a.example.com/f.json"},
			},
		}
		body, err := canonicalStructExcluding(doc, "signature_hex")
		if err != nil {
			t.Fatal(err)
		}
		doc.SignatureHex = hex.EncodeToString(ed25519.Sign(signPriv, body))
		raw, err := canonicalStructExcluding(doc, "")
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	good := build(pub, priv, "rp-1")
	mirrors, err := VerifyMirrorDocument(good, pub, "rp-1", now)
	if err != nil || len(mirrors) != 2 {
		t.Fatalf("valid mirror document rejected: %v", err)
	}

	// A mirror document lifted out of ANOTHER pack of the same
	// publisher: refused, or a retired host comes back from the dead.
	if _, err := VerifyMirrorDocument(build(pub, priv, "rp-OTHER"), pub, "rp-1", now); !errors.Is(err, ErrFreshnessWrongPack) {
		t.Fatalf("want ErrFreshnessWrongPack, got %v", err)
	}
	// Another publisher's mirror document.
	if _, err := VerifyMirrorDocument(build(otherPub, otherPriv, "rp-1"), pub, "rp-1", now); !errors.Is(err, ErrFreshnessPublisher) {
		t.Fatalf("want ErrFreshnessPublisher, got %v", err)
	}
	// Truncated.
	if _, err := VerifyMirrorDocument(good[:len(good)/2], pub, "rp-1", now); err == nil {
		t.Fatal("a truncated mirror document was accepted")
	}
}

// TestFreshnessCanonicalBytes_Golden pins the canonicalisation this
// module uses against a literal. If it changes, the publisher-side
// signer and this verifier have silently diverged and every signature
// in the field stops verifying — a failure that looks exactly like
// censorship and is not.
func TestFreshnessCanonicalBytes_Golden(t *testing.T) {
	doc := &FreshnessDocument{
		Kind:                FreshnessKind,
		RelayPackID:         "rp-1",
		Sequence:            7,
		CurrentBundleSHA256: repeatHex("ab"),
		CurrentSignedURL:    "https://frp.example.com/c.sbp",
		LastModified:        "2026-08-17T12:00:00Z",
		NotAfter:            "2026-08-20T12:00:00Z",
		Mirrors:             []FreshnessMirror{{Provider: "r2", URL: "https://a.example.com/f.json"}},
		Supersedes:          []string{"rp-0"},
		PublisherPubHex:     "aa",
		Pad:                 "00",
	}
	got, err := canonicalStructExcluding(doc, "signature_hex")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"current_bundle_sha256":"` + repeatHex("ab") + `",` +
		`"current_signed_url":"https://frp.example.com/c.sbp",` +
		`"kind":"daal/freshness-v2",` +
		`"last_modified":"2026-08-17T12:00:00Z",` +
		`"mirrors":[{"provider":"r2","url":"https://a.example.com/f.json"}],` +
		`"not_after":"2026-08-20T12:00:00Z",` +
		`"pad":"00",` +
		`"publisher_pub_hex":"aa",` +
		`"relay_pack_id":"rp-1",` +
		`"sequence":7,` +
		`"supersedes":["rp-0"]}`
	if string(got) != want {
		t.Fatalf("canonical bytes drifted:\n got %s\nwant %s", got, want)
	}
}

func TestEqualHex_CaseInsensitive(t *testing.T) {
	if !equalHex("ABcd", "abCD") {
		t.Error("equalHex should be case-insensitive")
	}
	if equalHex("ab", "abc") {
		t.Error("len mismatch should fail")
	}
}

func makeSubkeyCert(t *testing.T, rootPub ed25519.PublicKey, rootPriv ed25519.PrivateKey,
	subPub ed25519.PublicKey, from, until time.Time) []byte {
	t.Helper()
	cert := struct {
		V                  int    `json:"v"`
		Kind               string `json:"kind"`
		RootFingerprintHex string `json:"root_fingerprint_hex"`
		SubkeyPubHex       string `json:"subkey_pub_hex"`
		ValidFrom          string `json:"valid_from"`
		ValidUntil         string `json:"valid_until"`
		Label              string `json:"label"`
		SignatureHex       string `json:"signature_hex"`
	}{
		V: 1, Kind: "subkey_cert",
		SubkeyPubHex: hex.EncodeToString(subPub),
		ValidFrom:    from.Format(time.RFC3339),
		ValidUntil:   until.Format(time.RFC3339),
	}
	sum := sha256.Sum256(rootPub)
	cert.RootFingerprintHex = hex.EncodeToString(sum[:])
	body, err := canonicalCertBytesExcludingSignature(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.SignatureHex = hex.EncodeToString(ed25519.Sign(rootPriv, body))
	certJSON, err := canonicalStructExcluding(cert, "")
	if err != nil {
		t.Fatal(err)
	}
	return certJSON
}

func repeatHex(pair string) string {
	out := ""
	for len(out) < 64 {
		out += pair
	}
	return out[:64]
}
