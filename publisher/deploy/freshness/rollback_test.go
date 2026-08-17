package freshness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func signedDoc(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey,
	seq uint64, sha string, at time.Time) []byte {
	t.Helper()
	set, err := NewMirrorSet(twoMirrors())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Build(BuildOpts{
		RelayPackID:         "rp-1",
		Sequence:            seq,
		CurrentBundleSHA256: sha,
		CurrentSignedURL:    "https://f.example.com/rp-1.sbp",
		PublisherPubHex:     hex.EncodeToString(pub),
		Mirrors:             set,
		LastModified:        at,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := Sign(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// THE ROLLBACK ATTACK, end to end.
//
// The censor does not forge anything. They capture the document
// the publisher signed BEFORE a rotation and keep serving it after
// the rotation. Every signature check passes. Without a sequence
// high-water mark the recipient sees "the current bundle digest
// differs from mine" and installs the OLD pack — walking itself
// back onto credentials the rotation revoked.
func TestVerifyDocument_ReplayedOlderDocumentIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t0 := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

	old := signedDoc(t, priv, pub, 100, shaA, t0)
	fresh := signedDoc(t, priv, pub, 101, shaB, t0.Add(time.Hour))

	// The recipient accepts the new one and records its sequence.
	got, err := VerifyDocument(fresh, VerifyOpts{
		PublisherRootPub: pub, Now: t0.Add(2 * time.Hour),
		ExpectRelayPackID: "rp-1", MinSequence: 100,
	})
	if err != nil {
		t.Fatalf("fresh document rejected: %v", err)
	}
	if got.Sequence != 101 {
		t.Fatalf("sequence = %d", got.Sequence)
	}

	// Now the censor replays the pre-rotation document. It is
	// genuinely signed by the publisher and still inside its TTL.
	_, err = VerifyDocument(old, VerifyOpts{
		PublisherRootPub: pub, Now: t0.Add(2 * time.Hour),
		ExpectRelayPackID: "rp-1", MinSequence: got.Sequence,
	})
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("want ErrRollback on a replayed pre-rotation document, got %v", err)
	}
}

// Equal sequence is a re-fetch of the same document, not an
// attack: mirrors are inconsistent by construction and a
// recipient will see the same sequence repeatedly.
func TestVerifyDocument_SameSequenceAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	body := signedDoc(t, priv, pub, 7, shaA, now)
	if _, err := VerifyDocument(body, VerifyOpts{
		PublisherRootPub: pub, Now: now, ExpectRelayPackID: "rp-1", MinSequence: 7,
	}); err != nil {
		t.Fatalf("same-sequence re-fetch rejected: %v", err)
	}
}

// The freeze half: a captured document cannot be served forever.
func TestVerifyDocument_ExpiredIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t0 := time.Now().UTC()
	body := signedDoc(t, priv, pub, 1, shaA, t0)

	if _, err := VerifyDocument(body, VerifyOpts{
		PublisherRootPub: pub, Now: t0.Add(DefaultTTL - time.Hour), ExpectRelayPackID: "rp-1",
	}); err != nil {
		t.Fatalf("document inside its window rejected: %v", err)
	}
	if _, err := VerifyDocument(body, VerifyOpts{
		PublisherRootPub: pub, Now: t0.Add(DefaultTTL + time.Hour), ExpectRelayPackID: "rp-1",
	}); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired past not_after, got %v", err)
	}
}

// Splice: one of the publisher's own documents, for a different
// pack, dropped in front of this recipient.
func TestVerifyDocument_WrongPackIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	body := signedDoc(t, priv, pub, 1, shaA, now)
	if _, err := VerifyDocument(body, VerifyOpts{
		PublisherRootPub: pub, Now: now, ExpectRelayPackID: "rp-OTHER",
	}); !errors.Is(err, ErrWrongPack) {
		t.Fatalf("want ErrWrongPack, got %v", err)
	}
}

// The policy checks must be unreachable without a valid
// signature, so an unauthenticated blob can never steer them.
func TestVerifyDocument_TamperedSequenceFailsSignatureFirst(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	body := signedDoc(t, priv, pub, 100, shaA, now)
	tampered := []byte(strings.Replace(string(body), `"sequence":100`, `"sequence":999`, 1))
	if string(tampered) == string(body) {
		t.Fatal("test setup: sequence not found in canonical body")
	}
	_, err := VerifyDocument(tampered, VerifyOpts{
		PublisherRootPub: pub, Now: now, ExpectRelayPackID: "rp-1", MinSequence: 100,
	})
	if err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("want a signature failure, got %v", err)
	}
}

// v1 had no expiry and no counter. Accepting it would mean
// accepting a document with no rollback protection at all, so the
// refusal is explicit rather than incidental.
func TestVerifyDocument_RefusesV1Kind(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v1 := `{"kind":"daal/freshness-v1","relay_pack_id":"rp-1",` +
		`"current_bundle_sha256":"` + shaA + `","current_signed_url":"https://f.example.com/x.sbp",` +
		`"last_modified":"2026-08-17T00:00:00Z","publisher_pub_hex":"aa","signature_hex":""}`
	_, err := VerifyDocument([]byte(v1), VerifyOpts{PublisherRootPub: pub})
	if err == nil || !strings.Contains(err.Error(), "v1") {
		t.Fatalf("want an explicit v1 refusal, got %v", err)
	}
}

func TestBuild_RequiresSequence(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, err := Build(BuildOpts{
		RelayPackID:         "rp-1",
		CurrentBundleSHA256: shaA,
		CurrentSignedURL:    "https://f.example.com/x.sbp",
		PublisherPubHex:     hex.EncodeToString(pub),
	})
	if err == nil {
		t.Fatal("a document without a sequence must not be buildable")
	}
}

// Sequences above 2^53-1 do not survive the canonical writer's
// float64 round-trip, and the failure mode would be "every
// signature is invalid, on every device". Refuse at build time.
func TestBuild_RefusesUnrepresentableSequence(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Build(BuildOpts{
		RelayPackID: "rp-1", Sequence: maxSequence + 1,
		CurrentBundleSHA256: shaA,
		CurrentSignedURL:    "https://f.example.com/x.sbp",
		PublisherPubHex:     hex.EncodeToString(pub),
	}); err == nil {
		t.Fatal("want a range error")
	}
	// The boundary itself must round-trip through sign+verify.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	body := signedDoc(t, priv2, pub2, maxSequence, shaA, time.Now().UTC())
	got, err := VerifyDocument(body, VerifyOpts{PublisherRootPub: pub2, ExpectRelayPackID: "rp-1"})
	if err != nil {
		t.Fatalf("max sequence failed to verify: %v", err)
	}
	if got.Sequence != maxSequence {
		t.Fatalf("sequence round-trip: got %d want %d", got.Sequence, maxSequence)
	}
}

// Size normalisation: the published object must be the same
// length whether or not a rotation just happened, whether the
// URLs are long or short, and whether a sub-key cert is present.
func TestSign_PadsToConstantSize(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()

	short := signedDoc(t, priv, pub, 1, shaA, now)
	if len(short)%padBucket != 0 {
		t.Fatalf("document length %d is not a multiple of %d", len(short), padBucket)
	}

	longSet, err := NewMirrorSet([]Mirror{
		{Provider: ProviderR2, URL: "https://a-considerably-longer-hostname.example.com/" + strings.Repeat("p", 60)},
		{Provider: ProviderGHPages, URL: "https://frp.github.io/" + strings.Repeat("q", 60)},
		{Provider: "static", URL: "https://third.example.org/" + strings.Repeat("r", 60)},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Build(BuildOpts{
		RelayPackID: "rp-1", Sequence: 2,
		CurrentBundleSHA256: shaB,
		CurrentSignedURL:    "https://f.example.com/" + strings.Repeat("s", 60) + ".sbp",
		PublisherPubHex:     hex.EncodeToString(pub),
		Mirrors:             longSet, LastModified: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	long, err := Sign(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(long) != len(short) {
		t.Fatalf("rotation is visible in the object size: %d vs %d bytes", len(long), len(short))
	}
	if _, err := VerifyDocument(long, VerifyOpts{PublisherRootPub: pub, ExpectRelayPackID: "rp-1"}); err != nil {
		t.Fatalf("padded document must still verify: %v", err)
	}
}

// ---- publish ---------------------------------------------------

type fakeBackend struct {
	url  string
	err  error
	puts int
}

func (f *fakeBackend) PublicURL() string { return f.url }
func (f *fakeBackend) Put(_ context.Context, b []byte) error {
	f.puts++
	if f.err != nil {
		return f.err
	}
	if len(b) == 0 {
		return errors.New("empty")
	}
	return nil
}

func TestPublishAll_RefusesASingleTarget(t *testing.T) {
	_, err := PublishAll(context.Background(), []byte("{}"),
		[]Target{{Provider: ProviderR2, Backend: &fakeBackend{url: "https://a/x"}}})
	if !errors.Is(err, ErrTooFewMirrors) {
		t.Fatalf("want ErrTooFewMirrors, got %v", err)
	}
}

// A publish that only lands on one mirror has silently downgraded
// every recipient to a single point of failure. It must be an
// error — but the other mirror's success still has to be
// reported, and the failing one still has to be attempted.
func TestPublishAll_PartialFailureIsDegradedNotSilent(t *testing.T) {
	ok := &fakeBackend{url: "https://a/x"}
	bad := &fakeBackend{url: "https://b/x", err: errors.New("403 forbidden")}
	results, err := PublishAll(context.Background(), []byte("{}"), []Target{
		{Provider: ProviderR2, Backend: ok},
		{Provider: ProviderGHPages, Backend: bad},
	})
	if !errors.Is(err, ErrPublishDegraded) {
		t.Fatalf("want ErrPublishDegraded, got %v", err)
	}
	if len(results) != 2 || !results[0].OK || results[1].OK {
		t.Fatalf("per-target detail lost: %+v", results)
	}
	if bad.puts != 1 {
		t.Fatal("a failing mirror must still be attempted")
	}
	if results[1].Error == "" {
		t.Fatal("the failure reason must reach the operator")
	}
}

func TestPublishAll_AllSucceed(t *testing.T) {
	a := &fakeBackend{url: "https://a/x"}
	b := &fakeBackend{url: "https://b/x"}
	results, err := PublishAll(context.Background(), []byte("{}"), []Target{
		{Provider: ProviderR2, Backend: a},
		{Provider: ProviderGHPages, Backend: b},
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(results) != 2 || !results[0].OK || !results[1].OK {
		t.Fatalf("results: %+v", results)
	}
}
