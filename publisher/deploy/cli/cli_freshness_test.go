package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"daal/publisher/deploy/freshness"
)

func writeTemp(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A caller still passing the retired single-URL flag must fail
// loudly. The alternative — ignoring it — mints a pack with no
// freshness path at all while reporting success, which is the
// silent-degradation failure this wave exists to avoid.
func TestBindAndSign_RetiredFreshnessURLFlagFailsLoudly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"bind-and-sign",
		"--operator-record", "/nonexistent.json",
		"--priv-key", "/nonexistent.key",
		"--output", "/nonexistent.sbp",
		"--freshness-url", "https://one.example.com/rp.json",
	}, &stdout, &stderr)
	if rc == 0 {
		t.Fatal("rc=0 with the retired flag; expected nonzero")
	}
	if !strings.Contains(stderr.String(), "--freshness-mirror") {
		t.Fatalf("the error must point at the replacement flag: %s", stderr.String())
	}
}

func TestParseFreshnessMirrors(t *testing.T) {
	set, err := parseFreshnessMirrors([]string{
		"r2=https://f.example.com/rp.json",
		"ghpages=https://frp.github.io/f/rp.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 {
		t.Fatalf("len = %d", set.Len())
	}

	// One mirror is not a configuration.
	if _, err := parseFreshnessMirrors([]string{"r2=https://f.example.com/rp.json"}); err == nil {
		t.Fatal("a single mirror must be refused at the CLI boundary too")
	}
	// Malformed pair.
	if _, err := parseFreshnessMirrors([]string{"https://f.example.com/rp.json"}); err == nil {
		t.Fatal("want an error on a pair with no provider label")
	}
	// No mirrors at all is legal: a pack without a freshness path.
	set, err = parseFreshnessMirrors(nil)
	if err != nil || set != nil {
		t.Fatalf("empty list: set=%v err=%v", set, err)
	}
}

// publish-freshness must produce a v2 document: signed, sequenced,
// expiring, and verifiable with the same code a recipient runs.
func TestPublishFreshness_EmitsVerifiableV2Document(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := writeTemp(t, "root.key", priv)
	outPath := filepath.Join(t.TempDir(), "freshness.json")

	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"publish-freshness",
		"--relay-pack-id", "rp-1",
		"--current-bundle-sha256", strings.Repeat("ab", 32),
		"--current-signed-url", "https://f.example.com/rp-1.sbp",
		"--publisher-pub-hex", hex.EncodeToString(pub),
		"--root-priv-file", privPath,
		"--out-file", outPath,
		"--now-unix", "1755400000",
		"--mirror", "r2=https://f.example.com/rp.json",
		"--mirror", "ghpages=https://frp.github.io/f/rp.json",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}

	var res struct {
		Sequence uint64 `json:"sequence"`
		NotAfter string `json:"not_after"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Sequence != 1755400000 {
		t.Fatalf("sequence = %d; want it derived from the publish timestamp", res.Sequence)
	}
	if res.NotAfter == "" {
		t.Fatal("no not_after in the result")
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := freshness.VerifyDocument(body, freshness.VerifyOpts{
		PublisherRootPub:  pub,
		Now:               time.Unix(1755400000, 0).UTC(),
		ExpectRelayPackID: "rp-1",
		MinSequence:       1755400000,
	})
	if err != nil {
		t.Fatalf("the published document does not verify: %v", err)
	}
	if doc.AdvertisedMirrors().Len() != 2 {
		t.Fatal("advertised mirror set missing from the document")
	}

	// No credentials were supplied, so nothing was uploaded — and
	// the operator has to be told, because an unpublished document
	// looks exactly like a successful one on stdout.
	if !strings.Contains(stderr.String(), "NOT published") {
		t.Fatalf("a build-only run must say so: %s", stderr.String())
	}
}

// A half-supplied credential group is an error, not a silently
// skipped mirror: skipping one leaves the pack promising two
// endpoints and only one being written.
func TestFreshnessTargets_PartialCredentialsRefused(t *testing.T) {
	_, err := freshnessTargets(freshnessTargetArgs{r2Account: "acct"})
	if err == nil {
		t.Fatal("want an error on partial R2 credentials")
	}
	if _, err := freshnessTargets(freshnessTargetArgs{ghOwner: "o", ghRepo: "r"}); err == nil {
		t.Fatal("want an error on partial GitHub credentials")
	}
	targets, err := freshnessTargets(freshnessTargetArgs{})
	if err != nil || len(targets) != 0 {
		t.Fatalf("no credentials must yield no targets: %v %v", targets, err)
	}
}

// THE COUNTER HAS TO HAVE AN OWNER.
//
// The sequence is the whole of the anti-rollback story: a recipient
// persists the highest value it has accepted and refuses anything
// below it, forever, across restarts. Deriving it from the publish
// timestamp works only while the clock moves forward — and an NTP
// correction after a dead RTC, a restored VM snapshot, or a second
// laptop that lags all produce a LOWER value than recipients already
// hold. Every one of them then rejects every document, on every
// mirror, until wall time catches up, while this command exits 0 and
// the panel shows a green publish. Nothing on either side noticed.
func TestPublishFreshness_RefusesASequenceThatDoesNotAdvance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := writeTemp(t, "root.key", priv)
	outPath := filepath.Join(t.TempDir(), "freshness.json")

	args := func(extra ...string) []string {
		return append([]string{
			"publish-freshness",
			"--relay-pack-id", "rp-1",
			"--current-bundle-sha256", strings.Repeat("ab", 32),
			"--current-signed-url", "https://f.example.com/rp-1.sbp",
			"--publisher-pub-hex", hex.EncodeToString(pub),
			"--root-priv-file", privPath,
			"--out-file", outPath,
			"--mirror", "r2=https://f.example.com/rp.json",
			"--mirror", "ghpages=https://frp.github.io/f/rp.json",
		}, extra...)
	}

	// An explicit sequence at or below the caller's last published
	// value is refused outright rather than uploaded.
	var stdout, stderr bytes.Buffer
	rc := Run(args("--sequence", "1000", "--min-sequence", "1000"), &stdout, &stderr)
	if rc == 0 {
		t.Fatal("published a sequence that does not advance; every recipient at 1000 would refuse it")
	}
	if !strings.Contains(stderr.String(), "rollback") {
		t.Errorf("the refusal does not explain the consequence: %q", stderr.String())
	}

	// A backwards CLOCK, on the other hand, must not lock the operator
	// out of publishing at all — a relay they cannot recover is worse
	// than a counter that has run ahead of wall time. The counter wins,
	// loudly.
	stdout.Reset()
	stderr.Reset()
	rc = Run(args("--now-unix", "1000", "--min-sequence", "9000"), &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("a lagging clock must not block a publish: rc=%d %s", rc, stderr.String())
	}
	var res struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Sequence != 9001 {
		t.Fatalf("sequence = %d, want 9001 (one past the caller's high-water mark)", res.Sequence)
	}
	if !strings.Contains(stderr.String(), "clock") {
		t.Errorf("a backwards clock must be reported: %q", stderr.String())
	}
}

// The supersedes list is what makes the document reach anybody after a
// rotation: the pack id is a hash of the fields the ladder changes, so
// the rung that repairs a relay renames its pack.
func TestPublishFreshness_CarriesSupersededPackIDs(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privPath := writeTemp(t, "root.key", priv)
	outPath := filepath.Join(t.TempDir(), "freshness.json")

	var stdout, stderr bytes.Buffer
	rc := Run([]string{
		"publish-freshness",
		"--relay-pack-id", "rp-new",
		"--current-bundle-sha256", strings.Repeat("ab", 32),
		"--current-signed-url", "https://f.example.com/rp-1.sbp",
		"--publisher-pub-hex", hex.EncodeToString(pub),
		"--root-priv-file", privPath,
		"--out-file", outPath,
		"--now-unix", "1755400000",
		"--supersedes", "rp-old",
		"--supersedes", "rp-older",
		// A repeat of the current id must be dropped, not signed: it
		// would make the recipient's two acceptance branches overlap
		// and hide a publisher bug behind a tautology.
		"--supersedes", "rp-new",
		"--mirror", "r2=https://f.example.com/rp.json",
		"--mirror", "ghpages=https://frp.github.io/f/rp.json",
	}, &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("rc=%d stderr=%s", rc, stderr.String())
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	// A holder of the OLD pack accepts it. That is the entire point.
	if _, err := freshness.VerifyDocument(body, freshness.VerifyOpts{
		PublisherRootPub:  pub,
		Now:               time.Unix(1755400000, 0).UTC(),
		ExpectRelayPackID: "rp-old",
	}); err != nil {
		t.Fatalf("a recipient of the superseded pack rejected the document that repairs it: %v", err)
	}
	// A holder of some unrelated pack does not.
	if _, err := freshness.VerifyDocument(body, freshness.VerifyOpts{
		PublisherRootPub:  pub,
		Now:               time.Unix(1755400000, 0).UTC(),
		ExpectRelayPackID: "rp-unrelated",
	}); !errors.Is(err, freshness.ErrWrongPack) {
		t.Fatalf("want ErrWrongPack for an unrelated pack, got %v", err)
	}
	var doc struct {
		Supersedes []string `json:"supersedes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	for _, id := range doc.Supersedes {
		if id == "rp-new" {
			t.Fatal("the document claims to supersede itself")
		}
	}
	if len(doc.Supersedes) != 2 {
		t.Fatalf("supersedes = %v, want the two prior ids", doc.Supersedes)
	}
}
